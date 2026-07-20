package config

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/secrets"
)

// ValidationError is a single configuration problem: the offending field (its
// yaml path) and a human-readable message.
type ValidationError struct {
	Field string
	Msg   string
}

func (e ValidationError) Error() string {
	return fmt.Sprintf("%s: %s", e.Field, e.Msg)
}

// ValidationErrors is an aggregate of every problem found in one Validate pass.
type ValidationErrors []ValidationError

func (e ValidationErrors) Error() string {
	parts := make([]string, len(e))
	for i, ve := range e {
		parts[i] = ve.Error()
	}
	return "invalid config:\n  " + strings.Join(parts, "\n  ")
}

// validator accumulates problems so Validate can report every issue at once.
type validator struct {
	errs ValidationErrors
}

func (v *validator) add(field, format string, args ...any) {
	v.errs = append(v.errs, ValidationError{Field: field, Msg: fmt.Sprintf(format, args...)})
}

// Validate checks the config for internal consistency and fail-closed safety.
// It is pure: no IO, environment, or network access. It collects ALL problems
// and returns them as ValidationErrors, or nil (explicitly) when the config is
// valid — never a non-nil zero-length aggregate.
func (c *Config) Validate() error {
	v := &validator{}
	prod := c.Server.Environment == "production"

	c.validateServer(v, prod)
	c.validateTLS(v, prod)
	c.validateDatabase(v)
	c.validateAuth(v, prod)
	c.validateRateLimit(v)
	c.validateTelemetry(v)
	c.validateOnboarding(v)
	c.validateRetention(v)
	c.validateRefs(v)

	if len(v.errs) == 0 {
		return nil
	}
	return v.errs
}

func (c *Config) validateServer(v *validator, prod bool) {
	switch c.Server.Environment {
	case "production", "development":
	default:
		v.add("server.environment", "must be production or development, got %q", c.Server.Environment)
	}
	if prod {
		if c.Server.PublicBaseURL == "" {
			v.add("server.public_base_url", "required in production")
		} else if !strings.HasPrefix(c.Server.PublicBaseURL, "https://") {
			v.add("server.public_base_url", "must use https:// in production, got %q", c.Server.PublicBaseURL)
		}
	}
	c.validateTrustedProxies(v)
}

// validateTrustedProxies fails closed on malformed reverse-proxy trust entries:
// every entry must parse as either a bare IP or a CIDR block, or a downstream
// trust decision could be weakened by an entry that silently matches nothing (or
// the wrong thing). The offending index and value are named; the value is
// operator-supplied config, not a secret, so echoing it aids diagnosis.
func (c *Config) validateTrustedProxies(v *validator) {
	for i, entry := range c.Server.TrustedProxies {
		field := fmt.Sprintf("server.trusted_proxies[%d]", i)
		if entry == "" {
			v.add(field, "must not be empty; want an IP or CIDR")
			continue
		}
		if net.ParseIP(entry) != nil {
			continue
		}
		if _, _, err := net.ParseCIDR(entry); err != nil {
			v.add(field, "must be an IP or CIDR, got %q", entry)
		}
	}
}

// tlsModes is the set of accepted TLS modes.
var tlsModes = map[string]bool{
	"acme": true, "cloudflare_origin": true, "manual": true,
	"csr": true, "upstream": true, "self_signed": true,
}

// tlsMinVersions is the set of accepted minimum TLS versions. ADR-0015 sets the
// floor at TLS 1.2, so 1.0 and 1.1 are not selectable: an operator who asks for
// one is asking to weaken the transport, and an unrecognized string would leave
// the floor to whatever the TLS stack defaults to.
var tlsMinVersions = map[string]bool{"1.2": true, "1.3": true}

func (c *Config) validateTLS(v *validator, prod bool) {
	t := c.TLS
	if !tlsMinVersions[t.MinVersion] {
		v.add("tls.min_version", "must be 1.2 or 1.3, got %q", t.MinVersion)
	}
	if t.Mode == "" {
		v.add("tls.mode", "required (one of acme, cloudflare_origin, manual, csr, upstream, self_signed)")
		return
	}
	if !tlsModes[t.Mode] {
		v.add("tls.mode", "unknown mode %q", t.Mode)
		return
	}
	switch t.Mode {
	case "acme":
		c.validateACME(v, prod)
	case "cloudflare_origin":
		if t.CloudflareOrigin.APITokenRef.IsZero() {
			v.add("tls.cloudflare_origin.api_token_ref", "required for cloudflare_origin mode")
		}
	case "manual":
		if t.Manual.CertFile == "" {
			v.add("tls.manual.cert_file", "required for manual mode")
		}
		if t.Manual.KeyFile == "" {
			v.add("tls.manual.key_file", "required for manual mode")
		}
	case "csr":
		if t.Domain == "" {
			v.add("tls.domain", "required for csr mode")
		}
	case "upstream":
		if len(c.Server.TrustedProxies) == 0 {
			v.add("server.trusted_proxies", "at least one required for upstream TLS mode")
		}
	case "self_signed":
		if prod && !t.AllowSelfSignedInProduction {
			v.add("tls.mode", "self_signed refused in production unless allow_self_signed_in_production is set")
		}
	}
}

func (c *Config) validateACME(v *validator, prod bool) {
	a := c.TLS.ACME
	if c.TLS.Domain == "" {
		v.add("tls.domain", "required for acme mode")
	} else if prod && !isFQDN(c.TLS.Domain) {
		v.add("tls.domain", "must be a fully-qualified domain (not an IP, localhost, or dotless name) in production, got %q", c.TLS.Domain)
	}
	switch a.Solver {
	case "tls_alpn_01", "dns_01":
	case "":
		v.add("tls.acme.solver", "required for acme mode (tls_alpn_01 or dns_01)")
	default:
		v.add("tls.acme.solver", "unknown solver %q", a.Solver)
	}
	if a.Solver == "dns_01" {
		c.validateACMEDNS(v)
	}
}

// validateACMEDNS fails closed on the DNS-01 solving mode. ADR-0015 defines
// exactly two: "manual" (emit the _acme-challenge TXT records and wait for the
// operator) and "api" (drive a DNS provider's API). There is deliberately no
// default: an unset or unrecognized mode previously fell through this function
// silently, leaving the solver with no way to answer the challenge and skipping
// the provider/credentials requirements below, so a misconfigured issuance path
// reached production and only failed at renewal time.
func (c *Config) validateACMEDNS(v *validator) {
	d := c.TLS.ACME.DNS
	switch d.Mode {
	case "manual":
	case "api":
		if d.Provider == "" {
			v.add("tls.acme.dns.provider", "required for dns_01 api mode")
		}
		if d.CredentialsRef.IsZero() {
			v.add("tls.acme.dns.credentials_ref", "required for dns_01 api mode")
		}
	case "":
		v.add("tls.acme.dns.mode", "required for dns_01 solver (manual or api)")
	default:
		v.add("tls.acme.dns.mode", "unknown mode %q (want manual or api)", d.Mode)
	}
}

// isFQDN reports whether host is a fully-qualified domain name: it contains a
// dot, is not an IP literal, and is not localhost.
func isFQDN(host string) bool {
	if host == "" || host == "localhost" {
		return false
	}
	if net.ParseIP(host) != nil {
		return false
	}
	return strings.Contains(host, ".")
}

// ValidateDatabase validates ONLY the database section.
//
// It exists for offline administrative commands that open the datastore but
// never bind a listener or issue a token. Running the full Validate there would
// demand a TLS mode, a public base URL, and a token signing key that such a
// command has no use for, which would either block a legitimate operation or —
// far worse — push an operator into inventing throwaway production values just
// to get past the check. Narrowing the gate to what the command actually
// touches keeps the strict whole-config validation meaningful for the server
// path, where every one of those settings is load-bearing.
func (c *Config) ValidateDatabase() error {
	v := &validator{}
	c.validateDatabase(v)
	if len(v.errs) == 0 {
		return nil
	}
	return v.errs
}

func (c *Config) validateDatabase(v *validator) {
	switch c.Database.Driver {
	case "sqlite":
		if c.Database.SQLite.Path == "" {
			v.add("database.sqlite.path", "required for sqlite driver")
		}
	case "postgres":
		if c.Database.Postgres.DSNRef.IsZero() {
			v.add("database.postgres.dsn_ref", "required for postgres driver")
		}
	default:
		v.add("database.driver", "unknown driver %q (want sqlite or postgres)", c.Database.Driver)
	}
}

func (c *Config) validateAuth(v *validator, prod bool) {
	a := c.Auth
	ttl := a.AccessTokenTTL.Std()
	if ttl <= 0 || ttl > 24*time.Hour {
		v.add("auth.access_token_ttl", "must be in (0, 24h], got %v", ttl)
	}
	if a.RefreshTokenMaxAge.Std() <= ttl {
		v.add("auth.refresh_token_max_age", "must be greater than access_token_ttl (%v)", ttl)
	}
	if !a.Providers.APIToken.Enabled && !a.Providers.Passkey.Enabled && !a.Providers.OIDC.Enabled {
		v.add("auth.providers", "at least one authentication provider must be enabled")
	}
	if prod && a.TokenSigningKeyRef.IsZero() {
		v.add("auth.token_signing_key_ref", "required in production")
	}
}

func (c *Config) validateRateLimit(v *validator) {
	r := c.RateLimit
	if !r.Enabled {
		return
	}
	if r.Store == "shared" && r.Shared.Address == "" {
		v.add("rate_limit.shared.address", "required when store is shared")
	}
	if r.Store != "memory" && r.Store != "shared" {
		v.add("rate_limit.store", "unknown store %q (want memory or shared)", r.Store)
	}
	tiers := map[string]Tier{
		"auth": r.Tiers.Auth, "publish": r.Tiers.Publish,
		"management": r.Tiers.Management, "admin": r.Tiers.Admin,
	}
	for name, t := range tiers {
		if t.Requests <= 0 {
			v.add("rate_limit.tiers."+name+".requests", "must be > 0, got %d", t.Requests)
		}
		if t.Window.Std() <= 0 {
			v.add("rate_limit.tiers."+name+".window", "must be > 0, got %v", t.Window.Std())
		}
	}
}

func (c *Config) validateTelemetry(v *validator) {
	if c.Telemetry.Metrics.OTLP.Enabled && c.Telemetry.Metrics.OTLP.Endpoint == "" {
		v.add("telemetry.metrics.otlp.endpoint", "required when otlp metrics are enabled")
	}
	if c.Telemetry.Traces.Enabled && c.Telemetry.Traces.Endpoint == "" {
		v.add("telemetry.traces.endpoint", "required when traces are enabled")
	}
}

func (c *Config) validateOnboarding(v *validator) {
	switch c.Onboarding.Mode {
	case "invite", "open":
	default:
		v.add("onboarding.mode", "must be invite or open, got %q", c.Onboarding.Mode)
	}
}

func (c *Config) validateRetention(v *validator) {
	if c.Retention.HandleQuarantine.Std() <= 0 {
		v.add("retention.handle_quarantine", "must be > 0")
	}
	// Strictly positive, with no "disabled" reading. A cutoff of now-0 makes
	// every record eligible, so accepting 0 here would turn a one-character
	// config typo into the irreversible destruction of the audit log — the very
	// record an operator would need to investigate the incident. Purging is
	// switched off through retention.audit_purge_interval instead.
	if c.Retention.AuditRetention.Std() <= 0 {
		v.add("retention.audit_retention", "must be > 0 (set retention.audit_purge_interval to 0 to disable purging; 0 here does not mean \"keep nothing\")")
	}
	// 0 is a valid value here and means "never run a purge". Negative is not a
	// mode, it is a mistake, and is rejected rather than clamped: silently
	// repairing it would hide a misconfiguration the operator needs to see.
	if c.Retention.AuditPurgeInterval.Std() < 0 {
		v.add("retention.audit_purge_interval", "must be >= 0 (0 disables purging)")
	}
	if c.Retention.AuditPurgeBatch < 1 {
		v.add("retention.audit_purge_batch", "must be >= 1, got %d", c.Retention.AuditPurgeBatch)
	}
	if c.Retention.AuditPurgeMaxPerRun < 1 {
		v.add("retention.audit_purge_max_per_run", "must be >= 1, got %d", c.Retention.AuditPurgeMaxPerRun)
	}
	if c.Retention.MaxSetsPerOwner < 1 {
		v.add("retention.max_sets_per_owner", "must be >= 1, got %d", c.Retention.MaxSetsPerOwner)
	}
}

// validateRefs checks that every non-empty secret reference in the config is
// syntactically well-formed (scheme:opaque). Empty refs are allowed here;
// mode-specific requiredness is enforced by the per-section validators above.
//
// The error deliberately does NOT include the offending value, and does not
// wrap the underlying secrets error, which quotes it. A reference is normally
// not sensitive, but the branch that reports one as malformed is exactly the
// branch an operator reaches by pasting the secret itself into a *_ref field
// (a raw DSN into database.postgres.dsn_ref, a token into a token ref). Echoing
// the value there would copy credential material into startup logs, so the
// message names the field and the expected shape instead.
func (c *Config) validateRefs(v *validator) {
	for _, r := range c.allRefs() {
		if r.ref.IsZero() {
			continue
		}
		if err := r.ref.Validate(); err != nil {
			v.add(r.field, "malformed secret reference: want scheme:opaque (for example env:VAR or file:/path)")
		}
	}
}

// refField pairs a yaml field path with the secrets.Ref stored there.
type refField struct {
	field string
	ref   secrets.Ref
}

// allRefs enumerates every secret reference field in the config.
func (c *Config) allRefs() []refField {
	return []refField{
		{"tls.acme.dns.credentials_ref", c.TLS.ACME.DNS.CredentialsRef},
		{"tls.cloudflare_origin.api_token_ref", c.TLS.CloudflareOrigin.APITokenRef},
		{"database.postgres.dsn_ref", c.Database.Postgres.DSNRef},
		{"auth.token_signing_key_ref", c.Auth.TokenSigningKeyRef},
		{"rate_limit.shared.password_ref", c.RateLimit.Shared.PasswordRef},
		{"telemetry.metrics.otlp.headers_ref", c.Telemetry.Metrics.OTLP.HeadersRef},
	}
}
