// Package config defines the operator/instance configuration for the
// sshpilot-vallet backend and loads it with the precedence env > file >
// built-in defaults (ADR-0022). Secret values never live in config; fields
// that reference a secret are of type secrets.Ref (a "scheme:opaque"
// reference), resolved separately at startup.
//
// # Backward-compatible extension rule
//
// This schema is versioned by convention, not by a version field. Later tracks
// extend it, and MUST do so compatibly:
//
//   - Add new fields to an existing section, or add a whole new section to
//     Config; never rename, remove, or change the type of an existing yaml key.
//   - Every new field requires: (1) a default in Default() (defaults.go),
//     (2) an environment binding in the binding table (env.go), and
//     (3) Validate() coverage (validate.go) if it has any constraint.
//   - Optional secret references are secrets.Ref and default to "".
//
// Keeping these invariants means old config files keep loading, `go test`'s
// env-binding convention test keeps the table in lockstep with the structs,
// and the startup validator remains the single fail-closed gate.
package config

import "github.com/sadeq-n-yazdi/sshpilot-vallete/internal/secrets"

// Config is the complete operator configuration.
type Config struct {
	Server     ServerConfig     `yaml:"server"`
	TLS        TLSConfig        `yaml:"tls"`
	Database   DatabaseConfig   `yaml:"database"`
	Auth       AuthConfig       `yaml:"auth"`
	RateLimit  RateLimitConfig  `yaml:"rate_limit"`
	Telemetry  TelemetryConfig  `yaml:"telemetry"`
	Onboarding OnboardingConfig `yaml:"onboarding"`
	Blocklist  BlocklistConfig  `yaml:"blocklist"`
	Retention  RetentionConfig  `yaml:"retention"`
	Install    InstallConfig    `yaml:"install"`
	Docs       DocsConfig       `yaml:"docs"`
}

// ServerConfig holds HTTP server and environment settings.
type ServerConfig struct {
	Environment    string   `yaml:"environment"`
	ListenAddr     string   `yaml:"listen_addr"`
	PublicBaseURL  string   `yaml:"public_base_url"`
	TrustedProxies []string `yaml:"trusted_proxies"`
}

// TLSConfig configures transport security and certificate provisioning. It is a
// stub that later TLS tracks extend; the mode selects which sub-struct applies.
type TLSConfig struct {
	Mode                        string                 `yaml:"mode"`
	MinVersion                  string                 `yaml:"min_version"`
	ACME                        ACMEConfig             `yaml:"acme"`
	CloudflareOrigin            CloudflareOriginConfig `yaml:"cloudflare_origin"`
	Manual                      ManualTLSConfig        `yaml:"manual"`
	CSR                         CSRTLSConfig           `yaml:"csr"`
	Upstream                    UpstreamTLSConfig      `yaml:"upstream"`
	AllowSelfSignedInProduction bool                   `yaml:"allow_self_signed_in_production"`
	Domain                      string                 `yaml:"domain"`
	SANs                        []string               `yaml:"sans"`
}

// ACMEConfig configures ACME certificate issuance.
type ACMEConfig struct {
	// DirectoryURL is the CA's ACME directory endpoint. It defaults to Let's
	// Encrypt production (ADR-0015 §2 names Let's Encrypt as the phase-1 CA)
	// and is configurable so another ACME CA can be pointed at — including a
	// staging endpoint while an operator is bringing a deployment up.
	DirectoryURL string `yaml:"directory_url"`

	Solver string `yaml:"solver"`

	// AccountKeyFile is where the long-lived ACME account key lives, written
	// 0600. It is deliberately operator-chosen with no default, for the same
	// reason CSRTLSConfig.KeyFile is: a key file an operator does not know
	// their server created is a key file nobody protects or backs up.
	//
	// The account key is not the certificate key. It is the identity the CA
	// binds issued certificates and rate-limit accounting to, so losing it
	// means re-registering, and leaking it lets the holder revoke this
	// deployment's certificates.
	AccountKeyFile string `yaml:"account_key_file"`

	// CacheDir is the directory holding the issued certificate and its private
	// key between restarts.
	//
	// Persisting is not an optimization, it is the primary rate-limit control.
	// Without it every restart is a fresh issuance, so a crash-looping process
	// becomes an ACME request flood, and Let's Encrypt's duplicate-certificate
	// limit is measured in a rolling WEEK. A cached certificate that is still
	// valid is reused and no ACME request is made at all.
	CacheDir string `yaml:"cache_dir"`

	// ContactEmail is the optional address the CA uses for expiry warnings. It
	// is sent to the CA as a mailto: contact at registration. Empty means no
	// contact is registered, which every supported CA permits.
	ContactEmail string `yaml:"contact_email"`

	// AcceptTOS records that the operator accepts the CA's terms of service.
	//
	// It defaults to false and registration is refused without it. RFC 8555
	// requires the client to assert agreement, and asserting it on an
	// operator's behalf because they selected a mode would be making a legal
	// commitment they never made. The refusal is a config error at startup, so
	// nobody discovers it from a failed issuance.
	AcceptTOS bool `yaml:"accept_tos"`

	DNS ACMEDNSConfig `yaml:"dns"`
}

// ACMEDNSConfig configures the DNS-01 solver.
type ACMEDNSConfig struct {
	Mode           string      `yaml:"mode"`
	Provider       string      `yaml:"provider"`
	CredentialsRef secrets.Ref `yaml:"credentials_ref"`
}

// CloudflareOriginConfig configures Cloudflare Origin certificates.
//
// # Read this before selecting the mode
//
// A Cloudflare Origin CA certificate is signed by a private Cloudflare CA that
// ONLY the Cloudflare edge trusts. No browser, no curl, no Go client trusts it.
// It is usable for exactly one topology: the origin sits behind the Cloudflare
// proxy (orange cloud) and every client reaches it through that proxy.
//
// If the origin is reachable directly, this mode is a misconfiguration trap, and
// the damaging part is not the failed handshake — it is what an operator does
// next. The visible symptom is "certificate signed by unknown authority" from
// every direct client, and the obvious fix an operator reaches for is to tell
// callers to pass `curl -k` / disable verification. That fix removes precisely
// the MITM protection on the key-publish path that ADR-0015 exists to provide:
// an attacker who can alter published keys gets unauthorized SSH access. So the
// mode is gated rather than merely documented; see Server.TrustedProxies below
// and the provider in internal/transport/http.
type CloudflareOriginConfig struct {
	// APITokenRef references the Origin CA credential.
	//
	// Naming note: this field is called api_token_ref, but Cloudflare's Origin
	// CA endpoint is primarily authenticated by a DEDICATED "Origin CA Key",
	// which is a different credential from an ordinary API token — it is issued
	// from the dashboard's API-tokens page as a separate item and its value
	// always begins "v1.0-". Cloudflare now also accepts a scoped API token on
	// this endpoint, so both are supported and the provider selects the header
	// from the credential's shape. The field name is kept as-is because it is
	// already load-bearing in env.go, secretsref.go and validate.go.
	//
	// It is a REFERENCE, never the value: ADR-0015 §3 requires provider
	// credentials to come from the secret provider (ADR-0022) and forbids them
	// in the config file, the database, and logs.
	APITokenRef secrets.Ref `yaml:"api_token_ref"`

	// CacheDir holds the issued certificate and its private key between
	// restarts, written 0600 in a 0700 directory.
	//
	// Required, not defaulted, for the same reason tls.acme.cache_dir is: it is
	// the restart-storm control. Without it every restart requests a new
	// certificate, so a crash-looping process becomes a request flood against
	// Cloudflare's API. It matters more here than for ACME, because the key on
	// disk is the only copy — there is no re-download of an issued Origin CA
	// certificate that would let the server recover one it discarded.
	CacheDir string `yaml:"cache_dir"`

	// ValidityDays is the requested certificate lifetime. Cloudflare accepts
	// only 7, 30, 90, 365, 730, 1095 or 5475 days; anything else is refused at
	// validation rather than discovered as an API error.
	//
	// The default is 365 and deliberately NOT Cloudflare's 5475-day (15-year)
	// maximum, even though the dashboard offers it. A 15-year certificate means
	// a private key sitting on an origin disk for 15 years with no scheduled
	// moment at which it is replaced, and no practical revocation story — the
	// renewal machinery would effectively never run, so the one control that
	// bounds the damage of a silently copied key would never fire. A year keeps
	// the renew-ahead loop (ADR-0015 §4) real: it re-keys at ~8 months.
	ValidityDays int `yaml:"validity_days"`
}

// ManualTLSConfig configures operator-supplied certificate files.
type ManualTLSConfig struct {
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
}

// CSRTLSConfig configures the generate-a-CSR-for-external-signing mode.
//
// The app owns the private key and never emits it; the operator receives only
// the CSR, has it signed by any CA, and drops the returned chain at CertFile.
// All three paths are operator-chosen with no defaults, because a default key
// path is a file an operator can be unaware their server created.
type CSRTLSConfig struct {
	// KeyFile is where the generated private key lives, written 0600. It is
	// created once and reused: regenerating it would invalidate a certificate
	// the operator already had signed.
	KeyFile string `yaml:"key_file"`

	// CSRFile is where the certificate signing request is written for the
	// operator to collect. It contains only the public key and subject, both
	// of which appear in the issued certificate, so it is not a secret.
	CSRFile string `yaml:"csr_file"`

	// CertFile is where the operator installs the signed chain. Until it
	// exists the server refuses to start — there is no certificate to serve
	// and ADR-0015 forbids falling back to plaintext or self-signed.
	CertFile string `yaml:"cert_file"`
}

// UpstreamTLSConfig configures TLS termination by an upstream proxy.
type UpstreamTLSConfig struct {
	RequireForwardedProto bool `yaml:"require_forwarded_proto"`
}

// DatabaseConfig selects and configures the data store.
type DatabaseConfig struct {
	Driver   string         `yaml:"driver"`
	SQLite   SQLiteConfig   `yaml:"sqlite"`
	Postgres PostgresConfig `yaml:"postgres"`
}

// SQLiteConfig configures the SQLite driver.
type SQLiteConfig struct {
	Path string `yaml:"path"`
}

// PostgresConfig configures the PostgreSQL driver.
type PostgresConfig struct {
	DSNRef secrets.Ref `yaml:"dsn_ref"`
}

// AuthConfig configures management authentication. It is a stub extended by the
// auth track.
type AuthConfig struct {
	AccessTokenTTL     Duration    `yaml:"access_token_ttl"`
	RefreshTokenMaxAge Duration    `yaml:"refresh_token_max_age"`
	TokenSigningKeyRef secrets.Ref `yaml:"token_signing_key_ref"`

	// AccessKeyPepperRef references the HMAC pepper that keys the stored digest
	// of every key-set access key (ADR-0016). It must resolve to at least
	// accesskey.MinPepperLen (32) bytes; a shorter or unresolvable value is a
	// startup failure, never a downgrade.
	//
	// OPERATIONAL CONSEQUENCE: the pepper is part of every digest, so changing
	// it invalidates EVERY existing access key at once. Every consumer of every
	// protected key set stops verifying the moment the new pepper is loaded and
	// must be re-issued a freshly minted token. Rotate deliberately, not as
	// cleanup.
	//
	// Required in production, where its absence is refused. Left empty in
	// development the server still starts, with no verifier at all: protected
	// key sets then answer the same 404 an absent set gets, for everyone.
	AccessKeyPepperRef secrets.Ref `yaml:"access_key_pepper_ref"`

	Providers AuthProviders `yaml:"providers"`
}

// AuthProviders toggles the available authentication providers.
type AuthProviders struct {
	APIToken APITokenProvider `yaml:"api_token"`
	Passkey  PasskeyProvider  `yaml:"passkey"`
	OIDC     OIDCProvider     `yaml:"oidc"`
}

// APITokenProvider toggles API-token authentication.
type APITokenProvider struct {
	Enabled bool `yaml:"enabled"`
}

// PasskeyProvider toggles passkey authentication.
type PasskeyProvider struct {
	Enabled bool `yaml:"enabled"`
}

// OIDCProvider toggles OIDC authentication.
type OIDCProvider struct {
	Enabled bool `yaml:"enabled"`
}

// RateLimitConfig configures rate limiting and abuse controls (ADR-0023).
type RateLimitConfig struct {
	Enabled bool                  `yaml:"enabled"`
	Store   string                `yaml:"store"`
	Shared  SharedRateLimitConfig `yaml:"shared"`
	Tiers   RateLimitTiers        `yaml:"tiers"`
}

// SharedRateLimitConfig configures the shared (external) rate-limit store.
type SharedRateLimitConfig struct {
	Address     string      `yaml:"address"`
	PasswordRef secrets.Ref `yaml:"password_ref"`
}

// RateLimitTiers holds the per-category rate-limit tiers.
type RateLimitTiers struct {
	Auth       Tier `yaml:"auth"`
	Publish    Tier `yaml:"publish"`
	Management Tier `yaml:"management"`
	Admin      Tier `yaml:"admin"`
}

// Tier is a single rate-limit bucket: Requests per Window.
type Tier struct {
	Requests int      `yaml:"requests"`
	Window   Duration `yaml:"window"`
}

// TelemetryConfig configures logging, metrics, and tracing (ADR-0025). Stub.
type TelemetryConfig struct {
	Log     LogConfig     `yaml:"log"`
	Metrics MetricsConfig `yaml:"metrics"`
	Traces  TracesConfig  `yaml:"traces"`
}

// LogConfig configures structured logging.
type LogConfig struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
}

// MetricsConfig configures metrics exporters.
type MetricsConfig struct {
	Prometheus PrometheusConfig  `yaml:"prometheus"`
	OTLP       OTLPMetricsConfig `yaml:"otlp"`
}

// PrometheusConfig configures the Prometheus exporter and its scrape endpoint.
//
// # Exposure model: a separate listener, off by default
//
// The scrape endpoint is served ONLY on its own listener, at ListenAddr, and it
// is never registered on the public API mux. An empty ListenAddr -- the default
// -- means the endpoint is not served at all: metrics are still collected and
// still exported over OTLP if that is configured, but nothing answers a scrape.
//
// This is the fail-closed direction, and it is chosen over the more convenient
// alternative of mounting /metrics on the main listener for three reasons.
//
//  1. The main listener is the public internet-facing one (ADR-0010 assumes
//     strangers reach it with curl) and it has no authentication in front of
//     the unauthenticated publish routes. A metrics endpoint mounted there is
//     an unauthenticated disclosure of request volumes, error rates, route
//     inventory, Go runtime internals and process uptime to anyone who asks.
//  2. Sharing the listener makes the endpoint's reachability implicit. Here it
//     is a single explicit address an operator had to type, which is also the
//     thing they can bind to 127.0.0.1 or to a private interface. The insecure
//     configuration -- reachable from the internet -- cannot be arrived at by
//     leaving a field blank; it takes a deliberate wildcard bind.
//  3. Scrape traffic and public traffic get different timeouts and different
//     firewall rules in every real deployment, which needs two sockets anyway.
//
// Enabled and ListenAddr are separate switches because they answer different
// questions: Enabled selects whether metrics are COLLECTED (and thus available
// to the OTLP push path), ListenAddr selects whether they are SERVED.
type PrometheusConfig struct {
	Enabled bool `yaml:"enabled"`

	// ListenAddr is the dedicated address for the scrape endpoint, e.g.
	// "127.0.0.1:9090". Empty (default) means the endpoint is not served.
	ListenAddr string `yaml:"listen_addr"`

	// Path is the scrape path on that listener. It must be absolute, and it is
	// the only path that listener answers; everything else there is a 404.
	Path string `yaml:"path"`
}

// OTLPMetricsConfig configures the OTLP metrics exporter.
type OTLPMetricsConfig struct {
	Enabled    bool        `yaml:"enabled"`
	Endpoint   string      `yaml:"endpoint"`
	HeadersRef secrets.Ref `yaml:"headers_ref"`
}

// TracesConfig configures distributed tracing.
type TracesConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Endpoint string `yaml:"endpoint"`

	// SampleRatio is the head-sampling probability in [0,1], applied only to
	// traces this process roots; a sampling decision arriving from an upstream
	// caller is respected instead. It defaults to 1 (sample everything)
	// because spans here carry only the four access-log fields, so the volume
	// is one span per request and an operator who wants less can say so.
	SampleRatio float64 `yaml:"sample_ratio"`
}

// OnboardingConfig configures owner onboarding (ADR-0012).
type OnboardingConfig struct {
	Mode string `yaml:"mode"`
}

// BlocklistConfig configures the reserved-identifier blocklist (ADR-0017).
type BlocklistConfig struct {
	SeedFile     string   `yaml:"seed_file"`
	ExtraEntries []string `yaml:"extra_entries"`
	AllowEntries []string `yaml:"allow_entries"`
}

// RetentionConfig configures audit retention and erasure windows (ADR-0024).
//
// # Why the window and the schedule are separate knobs
//
// AuditRetention says how much history is kept; the AuditPurge* fields say how
// the purge that enforces it is paced. They are deliberately not collapsed into
// one setting because they fail in opposite directions. A too-small retention
// window destroys evidence irrecoverably, so it is validated as strictly
// positive and there is no value that means "purge everything". A too-small or
// absent schedule merely lets history accumulate, which is recoverable, so the
// schedule — and only the schedule — carries the off switch.
type RetentionConfig struct {
	HandleQuarantine Duration `yaml:"handle_quarantine"`

	// AuditRetention is the age at which an audit record becomes eligible for
	// purging. It MUST be > 0: zero would place the cutoff at the present
	// moment and make every record eligible, so validation rejects it rather
	// than treating it as "keep nothing" or silently substituting a default.
	// To stop purging entirely, set AuditPurgeInterval to 0; never this.
	AuditRetention Duration `yaml:"audit_retention"`

	// AuditPurgeInterval is how often a retention pass runs. 0 disables
	// purging altogether (records accumulate and are logged about at startup);
	// any positive value schedules a pass at that cadence. This is the only
	// retention field whose zero value is a valid operating mode, because the
	// consequence of it — keeping too much — is reversible.
	AuditPurgeInterval Duration `yaml:"audit_purge_interval"`

	// AuditPurgeBatch is how many records one purge transaction removes. It
	// bounds how long a single DELETE holds a write lock, so a large backlog
	// does not stall every other writer for the duration of one statement.
	AuditPurgeBatch int `yaml:"audit_purge_batch"`

	// AuditPurgeMaxPerRun caps the total records one pass may remove. Without
	// it a huge backlog would keep a pass batching indefinitely; with it the
	// backlog is drained across successive passes instead of monopolising the
	// database in one.
	AuditPurgeMaxPerRun int `yaml:"audit_purge_max_per_run"`

	MaxSetsPerOwner int `yaml:"max_sets_per_owner"`
}

// InstallConfig configures exposure of the served helper installer (ADR-0013,
// ADR-0029).
//
// Enabled defaults to true, which ADR-0013 decides explicitly: the installer is
// the documented bootstrap path for a host that has nothing from this project
// yet, so gating it behind a credential the host does not have would make it
// useless for the one job it exists to do. The script is not secret -- it is
// byte-identical for every requester and contains no keys, host names, or
// information about who uses the deployment.
//
// Deployers who do not accept an unauthenticated route set enabled: false, and
// both install routes then answer exactly as any unrouted path does, so a probe
// cannot even learn that the feature exists to be disabled.
type InstallConfig struct {
	Enabled bool `yaml:"enabled"`
}

// DocsConfig configures exposure of the self-served API documentation
// (ADR-0021).
//
// Enabled defaults to true, which ADR-0021 decides explicitly: the API
// contract is not a secret, the service is meant to be consumed by strangers
// with curl, and a contract nobody can fetch is a contract nobody can
// implement against. The reconnaissance value of the document is real but
// small — it describes route shapes, not credentials — and it is bounded by
// the spec only ever describing endpoints that are already reachable.
//
// Deployers who do not accept that trade (internal-only installations, or
// anyone minimizing an unauthenticated attack surface) set enabled: false and
// the routes stop existing, indistinguishably from any other unknown path.
//
// ADR-0021 also contemplates a third posture — docs served but behind
// authentication. That is deliberately not implemented here: it needs the
// scope model to say which scope may read the contract, and shipping a
// half-answer to that question is worse than shipping the boolean.
type DocsConfig struct {
	Enabled bool `yaml:"enabled"`
}
