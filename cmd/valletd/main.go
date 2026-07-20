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
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/service/publish"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/storage/sqlite"
	httpserver "github.com/sadeq-n-yazdi/sshpilot-vallete/internal/transport/http"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/version"
)

// shutdownGrace bounds the drain after a termination signal. Long enough for a
// normal request to finish, short enough that an orchestrator's own kill
// timeout is never the thing that stops the process.
const shutdownGrace = 15 * time.Second

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
// validated before anything is opened, the datastore is opened before the
// listener binds, and the server is constructed (which is where TLS policy is
// enforced) before a single connection is accepted. Any failure returns an
// error and the process exits non-zero rather than serving degraded.
func run(args []string, stdout, stderr io.Writer) error {
	// Subcommands are dispatched before flag parsing so their own flag sets own
	// their arguments. Only a leading bare word is treated as a subcommand, so
	// the flags-only invocation that serves traffic is unchanged.
	if len(args) > 0 && args[0] == bootstrapOwnerCmd {
		return runBootstrapOwner(args[1:], stdout, stderr)
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

	store := sqlite.NewStore(db)

	publisher, err := publish.New(store.Repos())
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

	// SEAM: the authenticated management surface is mounted but not yet wired.
	//
	// httpserver.NewHandler registers the device, public key and key set
	// management routes unconditionally, and with no httpserver.WithAuthorizer
	// here they are guarded by an authorizer that refuses every credential. That
	// is the intended interim state: the routes exist, they are documented, and
	// they answer 401 to everyone, so no request is ever served unauthenticated.
	//
	// Completing the wiring needs an *auth.Guard, which needs the token
	// verifier and the credential denylist, whose storage adapters are still in
	// review (the auth/pairing adapters). When they land, this call gains
	//
	//	httpserver.WithAuthorizer(guard),
	//	httpserver.WithDeviceService(deviceSvc),
	//	httpserver.WithPublicKeyService(keySvc),
	//	httpserver.WithKeySetService(setSvc),
	//
	// and nothing else here changes.
	//
	// SEAM: the key set service needs a *nameguard.Guard, which is the ONLY way
	// the reserved-identifier blocklist (ADR-0017, Fb4) reaches a set-name
	// create or rename. keyset.New refuses a nil one, so the service cannot be
	// built without it and there is no unchecked path to build. But no matcher
	// is constructed in this function today -- nameguard.Default() is called
	// only by the bootstrap-owner subcommand -- and constructing one here would
	// pick a source (the curated defaults, or the defaults plus the operator's
	// configured extra and allow lists via listadmin.ApplySeed) that is a
	// deployment decision tracked separately. So the choice is deliberately not
	// made here; setSvc above is built by whoever completes this wiring, with
	// the guard the blocklist-wiring task settles on.
	//
	// The behavior described above is pinned by
	// TestManagementRoutesFailClosedWithoutAnAuthorizer, which builds a handler
	// with no authorizer -- this function's exact option set -- and asserts every
	// management route answers 401. This wiring in main is not itself under test.
	srv, err := httpserver.New(cfg, logger, db, publisher)
	if err != nil {
		return err
	}

	logger.Info("starting valletd",
		slog.String("version", version.String()),
		slog.String("environment", cfg.Server.Environment),
		slog.String("addr", srv.Addr()),
		slog.String("tls_mode", cfg.TLS.Mode),
	)

	return serve(srv, logger, purge)
}

// serve runs the server until a termination signal arrives, then drains.
//
// signal.NotifyContext restores the default disposition on return, so a second
// SIGINT during the drain terminates the process immediately -- an operator who
// asks twice should not have to wait out the grace period.
func serve(srv *httpserver.Server, logger *slog.Logger, purge *erasure.Scheduler) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// The retention purge shares the signal context, so the same SIGTERM that
	// drains the listener also stops the purge -- and is joined before serve
	// returns, so no purge is still holding a transaction when run closes the
	// database.
	joinPurge := startRetention(ctx, purge)
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
	}()

	errCh := make(chan error, 1)
	go func() { errCh <- srv.ListenAndServe() }()

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

// openDatabase opens the configured datastore and verifies it answers before
// the server starts, so a misconfigured path fails at startup instead of
// showing up later as a permanently unready instance.
func openDatabase(cfg *config.Config) (*sql.DB, error) {
	if cfg.Database.Driver != "sqlite" {
		return nil, fmt.Errorf("database driver %q is not supported yet", cfg.Database.Driver)
	}

	db, err := sqlite.Open(sqlite.Options{Path: cfg.Database.SQLite.Path})
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		return nil, errors.Join(fmt.Errorf("ping database: %w", err), db.Close())
	}
	return db, nil
}
