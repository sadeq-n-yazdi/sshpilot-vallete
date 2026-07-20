package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/audit"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/config"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/secrets"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/service/accesskey"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/service/publish"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/storage/sqlite"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/telemetry"
	httpserver "github.com/sadeq-n-yazdi/sshpilot-vallete/internal/transport/http"
)

// buildServer assembles the serving stack: the access key verifier (when a
// pepper is configured), the publish service that consults it, and the HTTPS
// server carrying both.
//
// It is a separate function from run so the assembly is reachable from a test
// without binding a port or standing up TLS -- the whole gate is only as good
// as the proof that the serving handler actually consults it, and a test that
// cannot reach this construction cannot produce that proof.
//
// Every failure here is returned, never logged-and-continued. In particular a
// pepper that was named and could not be turned into an adequate key stops the
// process; see accessKeyPepper.
func buildServer(
	ctx context.Context,
	cfg *config.Config,
	logger *slog.Logger,
	db *sql.DB,
	store *sqlite.Store,
	tel *telemetry.Provider,
) (*httpserver.Server, error) {
	publisher, err := newPublisher(ctx, cfg, logger, store)
	if err != nil {
		return nil, err
	}

	// SEAM: the authenticated management surface is mounted but not yet wired.
	//
	// httpserver.NewHandler registers the device and public key management
	// routes unconditionally, and with no httpserver.WithAuthorizer below they
	// are guarded by an authorizer that refuses every credential. That is the
	// intended interim state: the routes exist, they are documented, and they
	// answer 401 to everyone, so no request is ever served unauthenticated.
	//
	// Completing the wiring needs an *auth.Guard, which needs the token verifier
	// and the credential denylist, whose storage adapters are still in review
	// (the auth/pairing adapters). When they land, this call gains
	//
	//	httpserver.WithAuthorizer(guard),
	//	httpserver.WithDeviceService(deviceSvc),
	//	httpserver.WithPublicKeyService(keySvc),
	//
	// and nothing else here changes. (This comment moved here with the call it
	// annotates when the publish gate was wired; the publish-side SEAM it used
	// to sit beside is resolved.)
	//
	// The behavior described above is pinned by
	// TestManagementRoutesFailClosedWithoutAnAuthorizer, which builds a handler
	// with no authorizer -- this function's exact option set -- and asserts every
	// management route answers 401.
	return httpserver.New(cfg, logger, db, publisher, httpserver.WithTelemetry(tel))
}

// newPublisher builds the publish service, wiring the access key verifier that
// unlocks protected key sets whenever a pepper is available.
//
// Without a verifier the publish service resolves no protected set for anybody,
// credentialed or not: every one answers the same 404 an absent set gets. That
// is the fail-closed direction, and it is the only thing an absent pepper is
// ever allowed to select -- an inadequate pepper selects a startup failure
// instead, because a digest keyed by a weak or empty key is one nothing
// downstream would ever notice was weak.
func newPublisher(ctx context.Context, cfg *config.Config, logger *slog.Logger, store *sqlite.Store) (*publish.Service, error) {
	pepper, err := accessKeyPepper(ctx, cfg)
	if err != nil {
		return nil, err
	}
	if pepper == "" {
		// Reachable only outside production (accessKeyPepper refuses an unset
		// reference there). It is warned about at every startup rather than
		// noted once at configuration time: the symptom -- protected sets that
		// 404 for a consumer holding a valid-looking token -- looks exactly
		// like a credential problem, and an operator debugging it needs this
		// line in the log they are already reading.
		logger.Warn("no access key pepper configured; NO protected key set will be served to anyone",
			slog.String("component", "accesskey"),
			slog.String("config_field", "auth.access_key_pepper_ref"),
			slog.String("environment", cfg.Server.Environment),
		)
		return publish.New(store.Repos())
	}

	// The auto-commit, insert-only audit sink: mint and revoke leave a record,
	// and the service that writes them cannot reach the purge or pseudonymize
	// operations on the full audit port.
	emitter, err := audit.NewEmitter(store.AuditAppender())
	if err != nil {
		return nil, fmt.Errorf("access key audit emitter: %w", err)
	}

	repos := store.Repos()
	// accesskey.New copies the pepper, so nothing here retains a second live
	// reference to the key material past this call.
	keySvc, err := accesskey.New(repos.AccessKeys, repos.KeySets, emitter, []byte(pepper.Reveal()))
	if err != nil {
		// This is where an under-length pepper lands. The error names the
		// requirement, and pepper is a secrets.Redacted, so nothing here can
		// print the value: accesskey.New is handed the bytes and reports only a
		// length rule.
		return nil, fmt.Errorf("access key service (auth.access_key_pepper_ref): %w", err)
	}
	return publish.New(repos, publish.WithVerifier(keySvc))
}

// accessKeyPepper resolves the HMAC pepper that keys every stored access key
// digest, or returns "" when the deployment has deliberately selected the
// verifier-less mode.
//
// The value comes from internal/secrets and from nowhere else: there is no
// config literal, no default, no generated-if-missing fallback. A generated
// default would be the worst of the options -- every restart would silently
// invalidate every access key while the server reported a clean start.
//
// The three outcomes:
//
//   - reference set, resolves to a value -> that value. Whether it is long
//     enough is accesskey.New's ruling, not this function's, so there is one
//     length rule in the tree and it lives next to the HMAC that depends on it.
//   - reference set, does not resolve -> error. An operator who named a
//     reference asked for verification; a missing environment variable or an
//     unreadable file is a deployment fault, and continuing without a verifier
//     would answer it by quietly switching the feature off.
//   - reference unset -> "" in development, error in production. Production is
//     refused because a deployment serving protected key sets to nobody, with no
//     complaint, is indistinguishable from one that works until a consumer
//     reports it. Development is permitted so a checkout runs with no secret
//     material at all, and it warns loudly (see newPublisher).
//
// The returned value is a secrets.Redacted throughout, so a log line or an
// error that reached it would print a marker rather than the key.
func accessKeyPepper(ctx context.Context, cfg *config.Config) (secrets.Redacted, error) {
	ref := cfg.Auth.AccessKeyPepperRef
	if ref.IsZero() {
		if cfg.Server.Environment == "production" {
			// Checked here as well as in config.Validate on purpose, matching
			// newLogger: this path must not depend on some caller having
			// remembered to validate first, or a second entry point added later
			// would silently reintroduce the unverified mode in production.
			return "", errors.New("auth.access_key_pepper_ref is required in production: " +
				"without it no access key verifies and every protected key set answers 404")
		}
		return "", nil
	}

	// The file provider's permission posture follows the environment, the same
	// split internal/transport/http makes for the Cloudflare origin credential:
	// production refuses a world-readable pepper file, because a key any local
	// account can read must be treated as already copied.
	permMode := secrets.PermError
	if cfg.Server.Environment != "production" {
		permMode = secrets.PermWarn
	}
	resolver, err := secrets.NewResolver(secrets.Builtin(secrets.FileOptions{PermMode: permMode})...)
	if err != nil {
		return "", err
	}
	pepper, err := resolver.Resolve(ctx, ref)
	if err != nil {
		return "", fmt.Errorf("auth.access_key_pepper_ref: %w", err)
	}
	return pepper, nil
}
