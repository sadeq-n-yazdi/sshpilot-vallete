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
	Upstream                    UpstreamTLSConfig      `yaml:"upstream"`
	AllowSelfSignedInProduction bool                   `yaml:"allow_self_signed_in_production"`
	Domain                      string                 `yaml:"domain"`
	SANs                        []string               `yaml:"sans"`
}

// ACMEConfig configures ACME certificate issuance.
type ACMEConfig struct {
	DirectoryURL string        `yaml:"directory_url"`
	Solver       string        `yaml:"solver"`
	DNS          ACMEDNSConfig `yaml:"dns"`
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
