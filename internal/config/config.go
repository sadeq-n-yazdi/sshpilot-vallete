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
type CloudflareOriginConfig struct {
	APITokenRef secrets.Ref `yaml:"api_token_ref"`
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
	AccessTokenTTL     Duration      `yaml:"access_token_ttl"`
	RefreshTokenMaxAge Duration      `yaml:"refresh_token_max_age"`
	TokenSigningKeyRef secrets.Ref   `yaml:"token_signing_key_ref"`
	Providers          AuthProviders `yaml:"providers"`
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

// PrometheusConfig configures the Prometheus exporter.
type PrometheusConfig struct {
	Enabled    bool   `yaml:"enabled"`
	ListenAddr string `yaml:"listen_addr"`
	Path       string `yaml:"path"`
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
type RetentionConfig struct {
	HandleQuarantine Duration `yaml:"handle_quarantine"`
	AuditRetention   Duration `yaml:"audit_retention"`
	MaxSetsPerOwner  int      `yaml:"max_sets_per_owner"`
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
