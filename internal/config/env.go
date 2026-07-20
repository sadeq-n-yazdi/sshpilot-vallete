package config

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/secrets"
)

// envPrefix is prepended to the upper-snake-cased yaml path of every field to
// form its environment variable name.
const envPrefix = "VALLET_"

// binding maps an environment variable name to a setter that parses the string
// value and writes it into the Config. The table is explicit (not reflective)
// so that the mapping is auditable; a reflection-based convention test
// (env_convention_test.go) asserts the table stays in lockstep with the struct
// yaml tags and cannot drift.
type binding struct {
	name string
	set  func(*Config, string) error
}

// applyEnv overlays environment values onto cfg using the binding table. env is
// the lookup function (os.LookupEnv in production). Only variables that are set
// are applied; parse failures for all bindings are collected and joined so an
// operator sees every problem at once.
func applyEnv(cfg *Config, env func(string) (string, bool)) error {
	var errs []error
	for _, b := range bindings() {
		raw, ok := env(b.name)
		if !ok {
			continue
		}
		if err := b.set(cfg, raw); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", b.name, err))
		}
	}
	return errors.Join(errs...)
}

// --- typed setter helpers -------------------------------------------------
//
// Each helper takes a selector returning a pointer to the target field and
// returns a setter that parses the raw string into that field.

func setString(sel func(*Config) *string) func(*Config, string) error {
	return func(c *Config, v string) error { *sel(c) = v; return nil }
}

func setRef(sel func(*Config) *secrets.Ref) func(*Config, string) error {
	return func(c *Config, v string) error { *sel(c) = secrets.Ref(v); return nil }
}

func setBool(sel func(*Config) *bool) func(*Config, string) error {
	return func(c *Config, v string) error {
		b, err := strconv.ParseBool(strings.TrimSpace(v))
		if err != nil {
			return fmt.Errorf("invalid bool %q", v)
		}
		*sel(c) = b
		return nil
	}
}

func setInt(sel func(*Config) *int) func(*Config, string) error {
	return func(c *Config, v string) error {
		n, err := strconv.Atoi(strings.TrimSpace(v))
		if err != nil {
			return fmt.Errorf("invalid int %q", v)
		}
		*sel(c) = n
		return nil
	}
}

func setDuration(sel func(*Config) *Duration) func(*Config, string) error {
	return func(c *Config, v string) error {
		d, err := parseDuration(v)
		if err != nil {
			return err
		}
		*sel(c) = d
		return nil
	}
}

func setStringSlice(sel func(*Config) *[]string) func(*Config, string) error {
	return func(c *Config, v string) error {
		*sel(c) = splitList(v)
		return nil
	}
}

// splitList splits a comma-separated env value, trimming spaces and dropping
// empty items. An all-empty value yields an empty (non-nil) slice.
func splitList(v string) []string {
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// bindings returns the full environment binding table. Names are VALLET_ plus
// the upper-snake-cased yaml path of the field.
func bindings() []binding {
	return []binding{
		// server
		{"VALLET_SERVER_ENVIRONMENT", setString(func(c *Config) *string { return &c.Server.Environment })},
		{"VALLET_SERVER_LISTEN_ADDR", setString(func(c *Config) *string { return &c.Server.ListenAddr })},
		{"VALLET_SERVER_PUBLIC_BASE_URL", setString(func(c *Config) *string { return &c.Server.PublicBaseURL })},
		{"VALLET_SERVER_TRUSTED_PROXIES", setStringSlice(func(c *Config) *[]string { return &c.Server.TrustedProxies })},

		// tls
		{"VALLET_TLS_MODE", setString(func(c *Config) *string { return &c.TLS.Mode })},
		{"VALLET_TLS_MIN_VERSION", setString(func(c *Config) *string { return &c.TLS.MinVersion })},
		{"VALLET_TLS_ACME_DIRECTORY_URL", setString(func(c *Config) *string { return &c.TLS.ACME.DirectoryURL })},
		{"VALLET_TLS_ACME_SOLVER", setString(func(c *Config) *string { return &c.TLS.ACME.Solver })},
		{"VALLET_TLS_ACME_DNS_MODE", setString(func(c *Config) *string { return &c.TLS.ACME.DNS.Mode })},
		{"VALLET_TLS_ACME_DNS_PROVIDER", setString(func(c *Config) *string { return &c.TLS.ACME.DNS.Provider })},
		{"VALLET_TLS_ACME_DNS_CREDENTIALS_REF", setRef(func(c *Config) *secrets.Ref { return &c.TLS.ACME.DNS.CredentialsRef })},
		{"VALLET_TLS_CLOUDFLARE_ORIGIN_API_TOKEN_REF", setRef(func(c *Config) *secrets.Ref { return &c.TLS.CloudflareOrigin.APITokenRef })},
		{"VALLET_TLS_MANUAL_CERT_FILE", setString(func(c *Config) *string { return &c.TLS.Manual.CertFile })},
		{"VALLET_TLS_MANUAL_KEY_FILE", setString(func(c *Config) *string { return &c.TLS.Manual.KeyFile })},
		{"VALLET_TLS_CSR_KEY_FILE", setString(func(c *Config) *string { return &c.TLS.CSR.KeyFile })},
		{"VALLET_TLS_CSR_CSR_FILE", setString(func(c *Config) *string { return &c.TLS.CSR.CSRFile })},
		{"VALLET_TLS_CSR_CERT_FILE", setString(func(c *Config) *string { return &c.TLS.CSR.CertFile })},
		{"VALLET_TLS_UPSTREAM_REQUIRE_FORWARDED_PROTO", setBool(func(c *Config) *bool { return &c.TLS.Upstream.RequireForwardedProto })},
		{"VALLET_TLS_ALLOW_SELF_SIGNED_IN_PRODUCTION", setBool(func(c *Config) *bool { return &c.TLS.AllowSelfSignedInProduction })},
		{"VALLET_TLS_DOMAIN", setString(func(c *Config) *string { return &c.TLS.Domain })},
		{"VALLET_TLS_SANS", setStringSlice(func(c *Config) *[]string { return &c.TLS.SANs })},

		// database
		{"VALLET_DATABASE_DRIVER", setString(func(c *Config) *string { return &c.Database.Driver })},
		{"VALLET_DATABASE_SQLITE_PATH", setString(func(c *Config) *string { return &c.Database.SQLite.Path })},
		{"VALLET_DATABASE_POSTGRES_DSN_REF", setRef(func(c *Config) *secrets.Ref { return &c.Database.Postgres.DSNRef })},

		// auth
		{"VALLET_AUTH_ACCESS_TOKEN_TTL", setDuration(func(c *Config) *Duration { return &c.Auth.AccessTokenTTL })},
		{"VALLET_AUTH_REFRESH_TOKEN_MAX_AGE", setDuration(func(c *Config) *Duration { return &c.Auth.RefreshTokenMaxAge })},
		{"VALLET_AUTH_TOKEN_SIGNING_KEY_REF", setRef(func(c *Config) *secrets.Ref { return &c.Auth.TokenSigningKeyRef })},
		{"VALLET_AUTH_PROVIDERS_API_TOKEN_ENABLED", setBool(func(c *Config) *bool { return &c.Auth.Providers.APIToken.Enabled })},
		{"VALLET_AUTH_PROVIDERS_PASSKEY_ENABLED", setBool(func(c *Config) *bool { return &c.Auth.Providers.Passkey.Enabled })},
		{"VALLET_AUTH_PROVIDERS_OIDC_ENABLED", setBool(func(c *Config) *bool { return &c.Auth.Providers.OIDC.Enabled })},

		// rate_limit
		{"VALLET_RATE_LIMIT_ENABLED", setBool(func(c *Config) *bool { return &c.RateLimit.Enabled })},
		{"VALLET_RATE_LIMIT_STORE", setString(func(c *Config) *string { return &c.RateLimit.Store })},
		{"VALLET_RATE_LIMIT_SHARED_ADDRESS", setString(func(c *Config) *string { return &c.RateLimit.Shared.Address })},
		{"VALLET_RATE_LIMIT_SHARED_PASSWORD_REF", setRef(func(c *Config) *secrets.Ref { return &c.RateLimit.Shared.PasswordRef })},
		{"VALLET_RATE_LIMIT_TIERS_AUTH_REQUESTS", setInt(func(c *Config) *int { return &c.RateLimit.Tiers.Auth.Requests })},
		{"VALLET_RATE_LIMIT_TIERS_AUTH_WINDOW", setDuration(func(c *Config) *Duration { return &c.RateLimit.Tiers.Auth.Window })},
		{"VALLET_RATE_LIMIT_TIERS_PUBLISH_REQUESTS", setInt(func(c *Config) *int { return &c.RateLimit.Tiers.Publish.Requests })},
		{"VALLET_RATE_LIMIT_TIERS_PUBLISH_WINDOW", setDuration(func(c *Config) *Duration { return &c.RateLimit.Tiers.Publish.Window })},
		{"VALLET_RATE_LIMIT_TIERS_MANAGEMENT_REQUESTS", setInt(func(c *Config) *int { return &c.RateLimit.Tiers.Management.Requests })},
		{"VALLET_RATE_LIMIT_TIERS_MANAGEMENT_WINDOW", setDuration(func(c *Config) *Duration { return &c.RateLimit.Tiers.Management.Window })},
		{"VALLET_RATE_LIMIT_TIERS_ADMIN_REQUESTS", setInt(func(c *Config) *int { return &c.RateLimit.Tiers.Admin.Requests })},
		{"VALLET_RATE_LIMIT_TIERS_ADMIN_WINDOW", setDuration(func(c *Config) *Duration { return &c.RateLimit.Tiers.Admin.Window })},

		// telemetry
		{"VALLET_TELEMETRY_LOG_LEVEL", setString(func(c *Config) *string { return &c.Telemetry.Log.Level })},
		{"VALLET_TELEMETRY_LOG_FORMAT", setString(func(c *Config) *string { return &c.Telemetry.Log.Format })},
		{"VALLET_TELEMETRY_METRICS_PROMETHEUS_ENABLED", setBool(func(c *Config) *bool { return &c.Telemetry.Metrics.Prometheus.Enabled })},
		{"VALLET_TELEMETRY_METRICS_PROMETHEUS_LISTEN_ADDR", setString(func(c *Config) *string { return &c.Telemetry.Metrics.Prometheus.ListenAddr })},
		{"VALLET_TELEMETRY_METRICS_PROMETHEUS_PATH", setString(func(c *Config) *string { return &c.Telemetry.Metrics.Prometheus.Path })},
		{"VALLET_TELEMETRY_METRICS_OTLP_ENABLED", setBool(func(c *Config) *bool { return &c.Telemetry.Metrics.OTLP.Enabled })},
		{"VALLET_TELEMETRY_METRICS_OTLP_ENDPOINT", setString(func(c *Config) *string { return &c.Telemetry.Metrics.OTLP.Endpoint })},
		{"VALLET_TELEMETRY_METRICS_OTLP_HEADERS_REF", setRef(func(c *Config) *secrets.Ref { return &c.Telemetry.Metrics.OTLP.HeadersRef })},
		{"VALLET_TELEMETRY_TRACES_ENABLED", setBool(func(c *Config) *bool { return &c.Telemetry.Traces.Enabled })},
		{"VALLET_TELEMETRY_TRACES_ENDPOINT", setString(func(c *Config) *string { return &c.Telemetry.Traces.Endpoint })},

		// onboarding
		{"VALLET_ONBOARDING_MODE", setString(func(c *Config) *string { return &c.Onboarding.Mode })},

		// blocklist
		{"VALLET_BLOCKLIST_SEED_FILE", setString(func(c *Config) *string { return &c.Blocklist.SeedFile })},
		{"VALLET_BLOCKLIST_EXTRA_ENTRIES", setStringSlice(func(c *Config) *[]string { return &c.Blocklist.ExtraEntries })},
		{"VALLET_BLOCKLIST_ALLOW_ENTRIES", setStringSlice(func(c *Config) *[]string { return &c.Blocklist.AllowEntries })},

		// retention
		{"VALLET_RETENTION_HANDLE_QUARANTINE", setDuration(func(c *Config) *Duration { return &c.Retention.HandleQuarantine })},
		{"VALLET_RETENTION_AUDIT_RETENTION", setDuration(func(c *Config) *Duration { return &c.Retention.AuditRetention })},
		{"VALLET_RETENTION_MAX_SETS_PER_OWNER", setInt(func(c *Config) *int { return &c.Retention.MaxSetsPerOwner })},

		// docs
		{"VALLET_DOCS_ENABLED", setBool(func(c *Config) *bool { return &c.Docs.Enabled })},
	}
}
