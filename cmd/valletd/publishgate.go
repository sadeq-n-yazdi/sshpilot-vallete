package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/audit"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/auth"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/config"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/counter"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/secrets"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/service/accesskey"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/service/device"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/service/keyset"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/service/listadmin"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/service/publickey"
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
	counterStore counter.Store,
) (*httpserver.Server, error) {
	publisher, opts, err := buildAPIDeps(ctx, cfg, logger, store, tel, counterStore)
	if err != nil {
		return nil, err
	}
	return httpserver.New(cfg, logger, db, publisher, opts...)
}

// buildUpstreamServer assembles the SAME serving stack behind the guarded
// plaintext listener that upstream-termination mode uses (ADR-0015, Decision
// 31). It shares buildAPIDeps with buildServer so the plaintext listener serves
// the identical publish + management surface -- there is no reduced handler on
// the upstream path -- and the only difference is the socket: plaintext, bound
// to a fenced private address, wrapped in the require-secure-transport gate that
// NewUpstreamServer installs.
//
// It is a separate constructor from buildServer, not a mode flag threaded
// through it, so that *httpserver.Server keeps ServeTLS as its only serve method
// and the HTTPS type can never emit plaintext -- the plaintext path lives only
// on the distinct UpstreamServer type.
func buildUpstreamServer(
	ctx context.Context,
	cfg *config.Config,
	logger *slog.Logger,
	db *sql.DB,
	store *sqlite.Store,
	tel *telemetry.Provider,
	counterStore counter.Store,
) (*httpserver.UpstreamServer, error) {
	publisher, opts, err := buildAPIDeps(ctx, cfg, logger, store, tel, counterStore)
	if err != nil {
		return nil, err
	}
	return httpserver.NewUpstreamServer(cfg, logger, db, publisher, opts...)
}

// buildAPIDeps assembles the publisher and the handler options that both the
// HTTPS server and the plaintext upstream server are built from. Factoring it
// out is what guarantees the two listeners serve the same surface: a management
// option added here reaches both, and neither can silently drift to a narrower
// handler than the other.
func buildAPIDeps(
	ctx context.Context,
	cfg *config.Config,
	logger *slog.Logger,
	store *sqlite.Store,
	tel *telemetry.Provider,
	counterStore counter.Store,
) (*publish.Service, []httpserver.HandlerOption, error) {
	publisher, err := newPublisher(ctx, cfg, logger, store)
	if err != nil {
		return nil, nil, err
	}

	// The authenticated OWNER management surface (device / public key / key set
	// services) is wired below, once the access-token signing key resolves; see
	// mountOwnerManagement. It verifies bearer access tokens through an
	// *auth.Guard and runs the real owner-scoped services, so the reserved-
	// identifier policy composed here is enforced on the live create/rename
	// paths, not only at bootstrap.
	//
	// Token ISSUANCE (enrollment / device pairing) is a separate track and is NOT
	// mounted here, so the surface verifies but is not yet reachable end to end by
	// an external client until that lands. WithAdminIdentifier is left unset on
	// purpose: no admin authenticator exists yet (a separate ADR), so the admin
	// list routes stay fail-closed.
	//
	// The reserved-identifier policy (ADR-0017, Fb4) is composed ONCE here:
	// newNamePolicy builds one blocklist.Matcher from the curated defaults, the
	// operator's seed, and the persisted runtime overrides, and pairs it with a
	// nameguard.Guard reading that same matcher. This is what closes the
	// disconnected-matcher seam the SEAM above used to describe: there is no
	// longer a deferred "pick a source" decision -- it is made here, and both
	// the enforcement guard and the runtime editor share the one matcher.
	policy, err := newNamePolicy(ctx, cfg, store.Repos().ListOverrides)
	if err != nil {
		return nil, nil, err
	}

	// The runtime list editor. It edits policy.Matcher through the matcher's
	// own atomic swappers, so an edit is observed by policy.Guard with no
	// re-wiring, and it authorizes+audits+persists every edit. The insert-only
	// appender is used, not the full audit port: this code accounts for policy
	// changes and has no business being able to erase the record of them.
	emitter, err := audit.NewEmitter(store.AuditAppender())
	if err != nil {
		return nil, nil, fmt.Errorf("audit sink: %w", err)
	}
	listAdmin, err := listadmin.New(listadmin.Params{
		Admins:    store.Repos().Admins,
		Overrides: store.Repos().ListOverrides,
		Emitter:   emitter,
		Matcher:   policy.Matcher,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("list admin service: %w", err)
	}

	// The admin list routes ARE mounted below via WithListAdminService. Their
	// administrator identity seam is left at its fail-closed default (no
	// WithAdminIdentifier): every edit is refused until an admin authenticator
	// exists, which is a separate decision with its own ADR. Pinned by
	// TestAdminListRoutesFailClosedWithoutAnIdentifier.
	//
	// counterStore is appended only when the shared backend is configured; a nil
	// one (the single-node default) leaves the option set unchanged, so the
	// fail-closed tests are unaffected.
	opts := []httpserver.HandlerOption{
		httpserver.WithTelemetry(tel),
		httpserver.WithListAdminService(listAdmin),
	}
	if counterStore != nil {
		opts = append(opts, httpserver.WithCounterStore(counterStore))
	}

	// The authenticated OWNER management surface. mountOwnerManagement returns
	// the four options that flip device / public key / key set routes from the
	// fail-closed 401 stub to real access-token verification plus the real
	// owner-scoped services -- or none of them when no signing key is configured
	// (development only), which leaves those routes refusing every credential.
	// The mount is all-or-nothing; see mountOwnerManagement.
	ownerOpts, err := mountOwnerManagement(ctx, cfg, logger, store, emitter, policy, counterStore)
	if err != nil {
		return nil, nil, err
	}
	opts = append(opts, ownerOpts...)

	return publisher, opts, nil
}

// mountOwnerManagement builds the option set that wires the authenticated owner
// management surface: the access-token authorizer and the three owner-scoped
// services behind it. It returns all four options when an adequate signing key
// resolves, and NONE when the deployment has deliberately selected the
// signing-key-less development mode.
//
// The mount is all-or-nothing on purpose. Wiring the authorizer without the
// services, or the services without the authorizer, would be a half-open door;
// the routes are guarded as a unit, so they are wired as a unit.
//
// The three outcomes mirror accessKeyPepper exactly, because the failure a
// missing signing key produces is the same shape: a surface that silently does
// not work. A reference that is SET but does not resolve is a startup error, not
// a quiet downgrade to the refuse-everyone stub; a reference UNSET in production
// is refused (defense in depth over config.Validate); a reference UNSET in
// development leaves the surface at its fail-closed 401 stub and warns loudly.
func mountOwnerManagement(
	ctx context.Context,
	cfg *config.Config,
	logger *slog.Logger,
	store *sqlite.Store,
	emitter *audit.Emitter,
	policy *namePolicy,
	counterStore counter.Store,
) ([]httpserver.HandlerOption, error) {
	keyBytes, err := tokenSigningKey(ctx, cfg)
	if err != nil {
		return nil, err
	}
	if keyBytes == "" {
		// Reachable only outside production (tokenSigningKey refuses an unset
		// reference there). Warned about at every startup, not once at
		// configuration time: the symptom -- every owner management call
		// answering 401 with a token the operator believes is valid -- looks
		// exactly like a credential fault, and an operator debugging it needs
		// this line in the log they are already reading.
		logger.Warn("no access token signing key configured; the owner management API is DISABLED and answers 401 to everyone",
			slog.String("component", "auth"),
			slog.String("config_field", "auth.token_signing_key_ref"),
			slog.String("environment", cfg.Server.Environment),
		)
		return nil, nil
	}

	// Length is auth.NewAccessTokenSigner's ruling (MinSigningKeyLen), not this
	// function's, so a resolved-but-too-short key surfaces as a returned startup
	// error rather than a swallowed downgrade -- the same division newPublisher
	// makes with accesskey.New.
	signer, err := auth.NewAccessTokenSigner([]byte(keyBytes.Reveal()))
	if err != nil {
		// keyBytes is a secrets.Redacted and the signer never echoes key bytes,
		// so this reports only the length rule and the field to set.
		return nil, fmt.Errorf("access token signer (auth.token_signing_key_ref): %w", err)
	}

	// The revocation denylist shares the rate limiter's counter store when a
	// shared backend is configured (it domain-separates its own keys); on the
	// single-node default it gets an in-process store, because auth.NewDenylist
	// refuses a nil one. Note-forward: an in-memory store cannot carry
	// revocations across a restart or between replicas -- correct now, since no
	// tokens are issued yet, but it must be revisited when the issuance track
	// lands.
	dlStore := counterStore
	if dlStore == nil {
		mem, memErr := counter.NewMemoryStore(time.Now)
		if memErr != nil {
			return nil, fmt.Errorf("token denylist counter store: %w", memErr)
		}
		dlStore = mem
	}
	denylist, err := auth.NewDenylist(dlStore)
	if err != nil {
		return nil, fmt.Errorf("token denylist: %w", err)
	}
	guard, err := auth.NewGuard(signer, denylist)
	if err != nil {
		return nil, fmt.Errorf("access token guard: %w", err)
	}

	// The owner-scoped services. deviceSvc and setSvc take policy.Guard, so the
	// reserved-identifier policy composed in buildAPIDeps enforces on their live
	// create/rename paths. keySvc takes no guard: a public key carries no
	// user-chosen name to blocklist.
	deviceSvc, err := device.New(store.Repos().Devices, emitter, policy.Guard)
	if err != nil {
		return nil, fmt.Errorf("device service: %w", err)
	}
	keySvc, err := publickey.New(store.Repos().PublicKeys, store.Repos().Devices, emitter)
	if err != nil {
		return nil, fmt.Errorf("public key service: %w", err)
	}
	setSvc, err := keyset.New(store, policy.Guard, emitter)
	if err != nil {
		return nil, fmt.Errorf("key set service: %w", err)
	}

	return []httpserver.HandlerOption{
		httpserver.WithAuthorizer(guard),
		httpserver.WithDeviceService(deviceSvc),
		httpserver.WithPublicKeyService(keySvc),
		httpserver.WithKeySetService(setSvc),
	}, nil
}

// tokenSigningKey resolves the symmetric key that signs and verifies every
// access token, or returns "" when a development deployment has deliberately
// selected the management-API-disabled mode.
//
// It mirrors accessKeyPepper outcome for outcome, and for the same reasons:
// there is no config literal, no default, and above all no generated-if-missing
// fallback. A generated key would be the worst option -- every restart would
// silently invalidate every access token while the server reported a clean
// start, exactly the anti-pattern accessKeyPepper's own doc names.
//
// The three outcomes:
//
//   - reference set, resolves -> that value. Whether it is long enough is
//     auth.NewAccessTokenSigner's ruling, so the one length rule lives next to
//     the HMAC that depends on it.
//   - reference set, does not resolve -> error. An operator who named a
//     reference asked for a verifying management API; a missing environment
//     variable or unreadable file is a deployment fault, and continuing would
//     answer it by quietly leaving the surface refusing everyone.
//   - reference unset -> "" in development, error in production. Production is
//     refused (config.Validate enforces it too; this is defense in depth so a
//     future entry point cannot reintroduce the disabled mode). Development is
//     permitted so a checkout runs with no secret material, and it warns loudly
//     (see mountOwnerManagement).
//
// The value is a secrets.Redacted throughout, so a log line or error that
// reached it prints a marker rather than the key.
func tokenSigningKey(ctx context.Context, cfg *config.Config) (secrets.Redacted, error) {
	ref := cfg.Auth.TokenSigningKeyRef
	if ref.IsZero() {
		if cfg.Server.Environment == "production" {
			// Checked here as well as in config.Validate on purpose, matching
			// accessKeyPepper: this path must not depend on some caller having
			// validated first, or a second entry point added later would
			// silently reintroduce the disabled management API in production.
			return "", errors.New("auth.token_signing_key_ref is required in production: " +
				"without it no access token verifies and the owner management API answers 401 to everyone")
		}
		return "", nil
	}

	// The file provider's permission posture follows the environment, the same
	// split accessKeyPepper makes: production refuses a world-readable signing
	// key file, because a key any local account can read must be treated as
	// already copied.
	permMode := secrets.PermError
	if cfg.Server.Environment != "production" {
		permMode = secrets.PermWarn
	}
	resolver, err := secrets.NewResolver(secrets.Builtin(secrets.FileOptions{PermMode: permMode})...)
	if err != nil {
		return "", err
	}
	key, err := resolver.Resolve(ctx, ref)
	if err != nil {
		return "", fmt.Errorf("auth.token_signing_key_ref: %w", err)
	}
	return key, nil
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
	// reference to the key material past this call. It takes the whole store so
	// the rotate-with-grace path can run its read and update in one transaction.
	keySvc, err := accesskey.New(store, emitter, []byte(pepper.Reveal()))
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
