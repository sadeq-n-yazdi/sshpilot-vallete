// Command valletd is the sshpilot-vallet HTTPS server.
//
// It loads and validates operator configuration, opens the datastore, and
// serves the API over TLS until it receives SIGINT or SIGTERM, at which point
// it drains in-flight requests within a bounded window and exits.
package main

import (
	"context"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/config"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/erasure"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/logging"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/migrate"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/storage/postgres"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/storage/sqlite"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/sweep"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/telemetry"
	httpserver "github.com/sadeq-n-yazdi/sshpilot-vallete/internal/transport/http"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/version"
)

// shutdownGrace bounds the drain after a termination signal. Long enough for a
// normal request to finish, short enough that an orchestrator's own kill
// timeout is never the thing that stops the process.
const shutdownGrace = 15 * time.Second

// telemetryDrain bounds the final exporter flush. It is well inside
// shutdownGrace so that a collector which has stopped answering cannot be the
// reason the process outlives its orchestrator's kill timeout.
const telemetryDrain = 5 * time.Second

// main stays deliberately thin: it only translates run's error into an exit
// code, so all startup logic remains ordinary testable Go.
func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "valletd: %v\n", err)
		os.Exit(1)
	}
}

// run performs the full startup sequence and blocks until shutdown completes.
//
// The order matters and is fail-closed at every step: configuration is
// validated before anything is opened, the datastore is opened before its
// schema is brought up to date, the schema is migrated before the store is
// built on top of it, and the server is constructed (which is where TLS policy
// is enforced) before a single connection is accepted. Any failure returns an
// error and the process exits non-zero rather than serving degraded. In
// particular a database whose schema cannot be migrated is a startup failure,
// never something a live server discovers at the first request.
func run(args []string, stdout, stderr io.Writer) error {
	// Subcommands are dispatched before flag parsing so their own flag sets own
	// their arguments. Only a leading bare word is treated as a subcommand, so
	// the flags-only invocation that serves traffic is unchanged.
	if len(args) > 0 && args[0] == bootstrapOwnerCmd {
		return runBootstrapOwner(args[1:], stdout, stderr)
	}
	if len(args) > 0 && args[0] == bootstrapAdminCmd {
		return runBootstrapAdmin(args[1:], stdout, stderr)
	}

	fs := flag.NewFlagSet("valletd", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", "", "path to the configuration file (env and defaults are used when empty)")
	showVersion := fs.Bool("version", false, "print the version and exit")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *showVersion {
		_, _ = fmt.Fprintln(stderr, version.String())
		return nil
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}

	logger, err := newLogger(cfg, stderr)
	if err != nil {
		return err
	}

	db, err := openDatabase(cfg)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()

	// Bring the schema up to date before anything is built on top of it. A live
	// server must never serve traffic against a database it does not match, so a
	// migration that cannot be applied fails startup here rather than surfacing
	// as errors at the first request. This mirrors the bootstrap subcommand,
	// which runs the same migrations through the same helper.
	if err := migrateDatabase(context.Background(), cfg, db); err != nil {
		return err
	}

	store, err := newStore(cfg, db)
	if err != nil {
		return err
	}

	// Bring the stored handle look-alike folds current before anything is built
	// that could accept a create or rename. This is fail-closed ordering: the
	// adapter refuses those operations while any fold is stale, and this pass —
	// run after migrations and before the listener binds — is what lifts that
	// refusal. It also quarantines any pre-existing confusable pair's newer
	// member (ADR-0030). A failure fails startup rather than serving stale folds.
	if res, err := runFoldRecompute(context.Background(), store, store.AuditAppender()); err != nil {
		return err
	} else if res.Recomputed > 0 || res.Quarantined > 0 {
		logger.Info("recomputed handle look-alike folds",
			slog.Int("recomputed", res.Recomputed),
			slog.Int("quarantined", res.Quarantined))
	}

	// Secrets are resolved before anything is constructed from them, and every
	// failure is aggregated, so an operator fixes one startup error rather than
	// discovering the next missing reference on the following attempt. Which
	// references are required is decided by cfg (see RequiredSecretRefs): a
	// deployment that enabled no feature needing a secret resolves none. The
	// access key grace sweep is the consumer here; the bearer-token verifier
	// resolves the same pepper independently in buildServer (see accessKeyPepper).
	resolved, err := resolveSecrets(cfg)
	if err != nil {
		return err
	}

	// Built before the listener binds, so a bad retention policy fails startup
	// rather than surfacing at the first tick of a server already taking
	// traffic. Repos().Audit is the full port (the purge needs PurgeOlderThan);
	// AuditAppender() is the insert-only one handed to the recorder.
	purge, err := newRetentionScheduler(cfg, logger, store.Repos().Audit, store.AuditAppender())
	if err != nil {
		return err
	}

	// Likewise built before the listener binds: a sweep that cannot be
	// constructed is a startup failure, not something to discover at the first
	// tick of a server already taking traffic.
	sweeps, err := newSweepRunner(cfg, logger, store, store.AuditAppender(),
		resolved[accessKeyPepperField])
	if err != nil {
		return err
	}

	// The shared rate-limit counter store (Redis/Valkey with in-memory
	// failover), or nil when the deployment runs single-node counters. Built
	// here so run() owns its lifecycle: the closer stops the reprobe goroutine
	// and releases the connection pool, and it is deferred so the drain in serve
	// completes -- the limiter is still consulted while requests finish -- before
	// anything is torn down. A redis backend that is unreachable is NOT a startup
	// failure: the store degrades to memory, which is the whole point.
	counterStore, closeCounterStore, err := newSharedCounterStore(cfg, logger, resolved)
	if err != nil {
		return err
	}
	defer func() { _ = closeCounterStore() }()

	// Telemetry is built before the server so the handler can carry the
	// middleware, and it never returns an error: an exporter that cannot be
	// constructed is logged and omitted (see telemetry.New). A monitoring
	// backend must not be able to keep this process from serving.
	tel := telemetry.New(cfg, logger)
	defer shutdownTelemetry(tel, logger)

	// The application listener. In every TLS-terminating mode this is the
	// HTTPS *httpserver.Server. In upstream mode (tls.mode: upstream) the process
	// holds no certificate -- the proxy terminates TLS -- so there is no HTTPS
	// listener to bind and the app is served by the guarded plaintext
	// *httpserver.UpstreamServer instead (ADR-0015, Decision 31). Exactly one is
	// built; both satisfy appServer, so serve() is agnostic to which.
	var srv appServer
	if cfg.TLS.Mode == "upstream" {
		srv, err = buildUpstreamServer(context.Background(), cfg, logger, db, store, tel, counterStore)
	} else {
		srv, err = buildServer(context.Background(), cfg, logger, db, store, tel, counterStore)
	}
	if err != nil {
		return err
	}

	// The Prometheus scrape endpoint, when one is configured, gets its own
	// listener. It is nil unless the operator named an address for it, and
	// there is no arrangement of config that puts it on srv's listener.
	metricsSrv := telemetry.NewMetricsServer(cfg, tel, logger)

	// The plaintext health-probe listener (ADR-0015, Decision 43). It is nil
	// unless the operator named a loopback/private address for it, and it serves
	// ONLY /healthz and /readyz -- a probe-friendly path for orchestrators that
	// dial the pod/instance IP and cannot complete a TLS handshake against a
	// certificate their client does not trust (Cloudflare Origin CA, self-signed).
	// Its readiness reflects the same database ping the HTTPS listener reports.
	healthSrv := httpserver.NewHealthServer(cfg, logger, db)

	warnUnimplementedOnboardingMode(cfg, logger)

	logger.Info("starting valletd",
		slog.String("version", version.String()),
		slog.String("environment", cfg.Server.Environment),
		slog.String("addr", srv.Addr()),
		slog.String("tls_mode", cfg.TLS.Mode),
	)

	return serve(srv, metricsSrv, healthSrv, logger, purge, sweeps)
}

// warnUnimplementedOnboardingMode consumes cfg.Onboarding.Mode at startup.
//
// onboarding.mode "open" (public self-signup) is a configured intent this build
// does not yet implement: only admin-provisioned onboarding is wired (ADR-0033,
// Phase-1 decision #14 defers open self-signup). Warn loudly so an operator who
// set "open" expecting a public signup route learns the route is not there
// rather than discovering it by a 404. "invite" (the default) is the implemented
// mode and stays quiet.
func warnUnimplementedOnboardingMode(cfg *config.Config, logger *slog.Logger) {
	if cfg.Onboarding.Mode != "open" {
		return
	}
	logger.Warn("onboarding.mode is \"open\" but public self-signup is not implemented; only admin-provisioned onboarding is active",
		slog.String("component", "onboarding"),
		slog.String("config_field", "onboarding.mode"),
		slog.String("active_mode", "invite (admin-provisioned)"),
	)
}

// shutdownTelemetry flushes the exporters on the way out, under its own bounded
// deadline.
//
// The error is logged, never returned. Telemetry that failed to flush has lost
// some spans; a process that reported a failed exit because a collector was
// down would tell an orchestrator the deployment failed when the service ran
// correctly the whole time.
func shutdownTelemetry(tel *telemetry.Provider, logger *slog.Logger) {
	ctx, cancel := context.WithTimeout(context.Background(), telemetryDrain)
	defer cancel()
	if err := tel.Shutdown(ctx); err != nil {
		logger.Warn("telemetry shutdown incomplete",
			slog.String("component", "telemetry"), slog.String("error", err.Error()))
	}
}

// serve runs the server until a termination signal arrives, then drains.
//
// signal.NotifyContext restores the default disposition on return, so a second
// SIGINT during the drain terminates the process immediately -- an operator who
// asks twice should not have to wait out the grace period.
// appServer is the application listener contract serve() drives, satisfied by
// both *httpserver.Server (HTTPS, the TLS-terminating modes) and
// *httpserver.UpstreamServer (plaintext behind a proxy, upstream mode). Defining
// it here lets run() build exactly one of the two and hand it over without serve
// needing to know which -- and keeps the two concrete types separate, so the
// HTTPS type never grows a plaintext path.
type appServer interface {
	ListenAndServe() error
	Shutdown(context.Context) error
	Addr() string
}

func serve(srv appServer, metricsSrv *telemetry.MetricsServer, healthSrv *httpserver.HealthServer, logger *slog.Logger, purge *erasure.Scheduler, sweeps *sweep.Runner) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// The retention purge shares the signal context, so the same SIGTERM that
	// drains the listener also stops the purge -- and is joined before serve
	// returns, so no purge is still holding a transaction when run closes the
	// database.
	joinPurge := startRetention(ctx, purge)
	// The maintenance sweeps share the same signal context and the same join
	// discipline, for the same reason: a release holds a write transaction and
	// must be finished before run closes the database.
	joinSweeps := startSweeps(ctx, sweeps)
	// stop() is called before the join, and both are in one deferred func on
	// purpose. Deferred calls run last-registered-first, so a plain
	// "defer joinPurge()" here would run before the "defer stop()" above and
	// wait forever on a context nothing had canceled yet -- deadlocking every
	// exit path that does not reach the explicit stop() below, in particular
	// the one where the listener fails on its own. stop is idempotent, so
	// calling it here as well as there is safe.
	defer func() {
		stop()
		joinPurge()
		joinSweeps()
	}()

	errCh := make(chan error, 1)
	go func() { errCh <- srv.ListenAndServe() }()

	// The scrape listener runs alongside the API listener but is NOT allowed
	// to decide the process's fate: if it cannot bind -- a port already taken,
	// a permission problem -- that is logged and the API keeps serving. The
	// inverse would let a monitoring misconfiguration take down the service
	// that monitoring exists to watch. A nil metricsSrv serves nothing and
	// returns nil, which is the default deployment.
	go func() {
		if err := metricsSrv.ListenAndServe(); err != nil {
			logger.Error("metrics scrape endpoint stopped; the API is unaffected",
				slog.String("component", "telemetry"),
				slog.String("addr", metricsSrv.Addr()),
				slog.String("error", err.Error()))
		}
	}()

	// The health-probe listener runs alongside the API listener under the same
	// rule as the scrape endpoint: it is NOT allowed to decide the process's
	// fate. If it cannot bind, that is logged and the API keeps serving -- a
	// probe listener that took down the service would be the monitoring path
	// causing the outage it exists to detect. A nil healthSrv serves nothing and
	// returns nil, which is the default deployment.
	go func() {
		if err := healthSrv.ListenAndServe(); err != nil {
			logger.Error("health probe endpoint stopped; the API is unaffected",
				slog.String("component", "health"),
				slog.String("addr", healthSrv.Addr()),
				slog.String("error", err.Error()))
		}
	}()

	select {
	case err := <-errCh:
		// The listener stopped on its own; that is always a failure here,
		// since a clean Shutdown only happens on the signal path below.
		return err
	case <-ctx.Done():
	}

	logger.Info("shutdown signal received, draining", slog.Duration("grace", shutdownGrace))
	stop()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
	defer cancel()

	if err := metricsSrv.Shutdown(shutdownCtx); err != nil {
		logger.Warn("metrics scrape endpoint shutdown incomplete",
			slog.String("component", "telemetry"), slog.String("error", err.Error()))
	}
	if err := healthSrv.Shutdown(shutdownCtx); err != nil {
		logger.Warn("health probe endpoint shutdown incomplete",
			slog.String("component", "health"), slog.String("error", err.Error()))
	}
	if err := srv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("graceful shutdown: %w", err)
	}
	if err := <-errCh; err != nil {
		return err
	}

	logger.Info("shutdown complete")
	return nil
}

// newLogger builds the structured, secret-redacting logger from telemetry
// config. Logs go to stderr so that stdout stays free for anything the process
// is asked to emit as data, and so container runtimes capture them by default.
//
// It returns an error rather than falling back. The previous implementation
// defaulted an unrecognized level to info on the stated grounds that "config
// validation already rejects bad levels" -- which it did not: validateTelemetry
// checked the OTLP endpoints and never looked at the level or format at all.
// The comment described the intended invariant and the code silently supplied
// the opposite, so every typo'd level ran at a volume the operator had not
// asked for. Validation now covers both fields (see internal/config), and this
// path fails closed as well so the guarantee does not rest on one caller
// remembering to call Validate first.
func newLogger(cfg *config.Config, w io.Writer) (*slog.Logger, error) {
	logger, err := logging.New(w, cfg.Telemetry.Log.Level, cfg.Telemetry.Log.Format)
	if err != nil {
		return nil, fmt.Errorf("telemetry.log: %w", err)
	}
	return logger, nil
}

// migrateDatabase applies pending forward migrations to db using the dialect
// for the configured driver, reusing the same applyMigrations helper the
// bootstrap subcommands run. Only forward migrations are applied: nothing here
// reverts, and destructive gating is never enabled.
//
// The driver switch mirrors openDatabase and newStore: each engine has one case,
// and any unknown driver fails closed. config.Validate rejects an unknown driver
// first, so the default here is defense in depth.
func migrateDatabase(ctx context.Context, cfg *config.Config, db *sql.DB) error {
	switch cfg.Database.Driver {
	case "sqlite":
		return applyMigrations(ctx, sqlite.NewMigrateDB(db), migrate.EngineSQLite)
	case "postgres":
		return applyMigrations(ctx, postgres.NewMigrateDB(db), migrate.EnginePostgres)
	default:
		return fmt.Errorf("database driver %q is not supported", cfg.Database.Driver)
	}
}

// openDatabase opens the configured datastore and verifies it answers before
// the server starts, so a misconfigured path fails at startup instead of
// showing up later as a permanently unready instance.
//
// The driver switch mirrors migrateDatabase and newStore. The unknown-driver
// default fails closed; config.Validate rejects it first, so this is defense in
// depth.
func openDatabase(cfg *config.Config) (*sql.DB, error) {
	switch cfg.Database.Driver {
	case "sqlite":
		return openAndPing(sqlite.Open(sqlite.Options{Path: cfg.Database.SQLite.Path}))
	case "postgres":
		return openPostgres(cfg)
	default:
		return nil, fmt.Errorf("database driver %q is not supported", cfg.Database.Driver)
	}
}

// openPostgres resolves the DSN secret and opens the pgx-backed handle. The DSN
// is a secret reference and is resolved here, near the open, rather than in
// run()'s later resolveSecrets pass -- the same posture accessKeyPepper takes for
// the pepper it resolves independently in buildServer. The resolved value stays a
// secrets.Redacted and is revealed only at the postgres.Open call boundary, so no
// error or log on this path can echo the connection string.
func openPostgres(cfg *config.Config) (*sql.DB, error) {
	ctx, cancel := context.WithTimeout(context.Background(), secretResolveTimeout)
	defer cancel()
	dsn, err := postgresDSN(ctx, cfg)
	if err != nil {
		return nil, err
	}
	// dsn.Reveal() is passed inline and never bound to a named variable, so the
	// plaintext connection string cannot reach a later log or error. postgres.Open
	// itself does not echo the DSN on a parse failure (see its doc), so wrapping
	// its error below is safe.
	return openAndPing(postgres.Open(postgres.Options{DSN: dsn.Reveal()}))
}

// openAndPing verifies an already-opened handle answers within a bounded window
// so a misconfigured datastore fails at startup rather than at the first request.
// It takes the (db, err) pair straight from an adapter Open so both driver cases
// share the one ping-and-close discipline. A ping failure joins the close error
// so a leaked handle is never masked. The ping error is wrapped with %w only
// because neither adapter's connect error echoes the secret: sqlite has no
// credentials, and pgx redacts the DSN password (rendering it "xxxxxx") in every
// error it produces, so the wrapped text carries only host/user/database
// diagnostics, never the connection secret.
func openAndPing(db *sql.DB, openErr error) (*sql.DB, error) {
	if openErr != nil {
		return nil, openErr
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		return nil, errors.Join(fmt.Errorf("ping database: %w", err), db.Close())
	}
	return db, nil
}
