package config

import (
	"fmt"
	"math"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/logging"
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
	if c.Server.HealthListenAddr != "" {
		validatePrivateBindAddr(v, "server.health_listen_addr", c.Server.HealthListenAddr)
	}
}

// validatePrivateBindAddr is the single fence shared by the two guarded
// plaintext listeners (ADR-0015, Decisions 31 and 43): the loopback health
// probe endpoint and the upstream-termination request listener. Both open a
// PLAINTEXT socket, so both must refuse to bind anywhere an unauthenticated
// request could reach from the internet, and factoring the check here means the
// two exceptions cannot drift into two different definitions of "private".
//
// It fails closed: the host must classify as loopback or private, and anything
// it cannot classify — a wildcard, a public address, a bare hostname it cannot
// resolve to a category — is refused rather than assumed safe. The one non-IP
// host allowed is the literal "localhost", which every platform maps to a
// loopback interface; any other name is rejected because a rule that accepts
// names would depend on resolution the validator deliberately never performs.
func validatePrivateBindAddr(v *validator, field, addr string) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		v.add(field, "must be a host:port address, got %q", addr)
		return
	}
	if host == "localhost" {
		return
	}
	ip := net.ParseIP(host)
	if ip == nil {
		// An empty host is the ":8080" wildcard form; any other unparseable host
		// is a name the fence will not resolve. Both are refused, and the message
		// names the safe forms rather than guessing what the operator meant.
		v.add(field, "must bind a loopback or private address (127.0.0.0/8, ::1, "+
			"RFC1918, or ULA), got %q", addr)
		return
	}
	if ip.IsUnspecified() {
		v.add(field, "must not bind a wildcard address (%q reaches every interface); "+
			"use a loopback or private address", addr)
		return
	}
	if ip.IsLoopback() || ip.IsPrivate() {
		return
	}
	v.add(field, "must bind a loopback or private address (127.0.0.0/8, ::1, "+
		"RFC1918, or ULA), got a globally-routable address %q", addr)
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
		c.validateCloudflareOrigin(v, prod)
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
		// All three paths are required. Defaulting any of them would have the
		// server create or read key material at a location the operator never
		// chose, and a key nobody knows exists is a key nobody protects.
		if t.CSR.KeyFile == "" {
			v.add("tls.csr.key_file", "required for csr mode")
		}
		if t.CSR.CSRFile == "" {
			v.add("tls.csr.csr_file", "required for csr mode")
		}
		if t.CSR.CertFile == "" {
			v.add("tls.csr.cert_file", "required for csr mode")
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

// originValidityDays is the set of certificate lifetimes Cloudflare's Origin CA
// endpoint accepts. Anything else is rejected by the API with an opaque error,
// so it is caught here instead, at startup, where the operator can fix it.
var originValidityDays = map[int]bool{
	7: true, 30: true, 90: true, 365: true, 730: true, 1095: true, 5475: true,
}

// validateCloudflareOrigin fails closed on the Cloudflare Origin CA mode.
//
// # The trusted_proxies requirement is the misconfiguration gate
//
// An Origin CA certificate is trusted ONLY by the Cloudflare edge (see
// CloudflareOriginConfig). The mode is therefore correct exactly when every
// client arrives through the Cloudflare proxy, and a trap otherwise.
//
// The process cannot prove from the inside that it is unreachable directly from
// the internet — any such check would be a guess, and a security control that
// guesses is worse than none because it is believed. So this does not try to
// detect the topology. It requires the operator to DECLARE it, by listing the
// Cloudflare edge ranges in server.trusted_proxies, and that declaration is then
// enforced on every handshake by the provider, which refuses to hand the origin
// certificate to a peer outside the list.
//
// That makes the list load-bearing rather than advisory: it is the same field
// the upstream mode already requires, it has a single meaning ("these are the
// peers that may front this origin"), and an empty one now fails startup instead
// of silently producing an origin that answers the whole internet with a
// certificate none of it trusts.
func (c *Config) validateCloudflareOrigin(v *validator, prod bool) {
	o := c.TLS.CloudflareOrigin

	if o.APITokenRef.IsZero() {
		v.add("tls.cloudflare_origin.api_token_ref", "required for cloudflare_origin mode")
	}
	if o.CacheDir == "" {
		// Refused rather than defaulted, as tls.acme.cache_dir is: without a
		// cache every restart requests a new certificate, and the issued key is
		// the only copy, so a crash loop both floods the API and churns keys.
		v.add("tls.cloudflare_origin.cache_dir", "required for cloudflare_origin mode (it is the restart-storm control)")
	}
	if !originValidityDays[o.ValidityDays] {
		v.add("tls.cloudflare_origin.validity_days",
			"must be one of 7, 30, 90, 365, 730, 1095, 5475 (Cloudflare's accepted values), got %d", o.ValidityDays)
	}
	if c.TLS.Domain == "" {
		v.add("tls.domain", "required for cloudflare_origin mode")
	} else if prod && !isFQDN(c.TLS.Domain) {
		v.add("tls.domain",
			"must be a fully-qualified domain (not an IP, localhost, or dotless name) in production, got %q", c.TLS.Domain)
	}
	if len(c.Server.TrustedProxies) == 0 {
		v.add("server.trusted_proxies",
			"at least one required for cloudflare_origin mode: an Origin CA certificate is trusted only by the "+
				"Cloudflare edge, so the Cloudflare IP ranges must be declared and the origin must not be served directly")
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

	// The remaining settings are required by BOTH solvers, because they are
	// properties of holding an ACME account rather than of answering a
	// particular challenge. They are checked for any acme mode so that a later
	// solver cannot be added without them.
	if a.DirectoryURL == "" {
		// Only reachable when an operator explicitly blanks the default. An
		// empty URL would silently fall through to the acme package's built-in
		// Let's Encrypt endpoint, which is exactly the accidental production
		// traffic this mode has to avoid.
		v.add("tls.acme.directory_url", "required for acme mode")
	}
	if a.AccountKeyFile == "" {
		v.add("tls.acme.account_key_file", "required for acme mode")
	}
	if a.CacheDir == "" {
		// Refused rather than defaulted. Without a cache every restart
		// re-issues, and the CA's duplicate-certificate limit is measured over
		// a rolling week, so a crash loop turns into a week-long lockout.
		v.add("tls.acme.cache_dir", "required for acme mode (it is the restart-storm rate-limit control)")
	}
	if !a.AcceptTOS {
		v.add("tls.acme.accept_tos", "must be true: the CA requires the operator to accept its terms of service")
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
		validateACMEDNSCredentials(v, d)
	case "":
		v.add("tls.acme.dns.mode", "required for dns_01 solver (manual or api)")
	default:
		v.add("tls.acme.dns.mode", "unknown mode %q (want manual or api)", d.Mode)
	}
}

// validateACMEDNSCredentials fails closed on the DNS-01 api-mode credential.
//
// A credential is required and comes from exactly ONE source: the single
// credentials_ref, or the named credentials_refs map. Setting both is refused
// rather than silently preferring one, because which one wins would be a
// security decision taken by precedence rules an operator cannot see. Setting
// neither is refused because api mode cannot authenticate without a credential.
//
// Only presence and non-emptiness are checked here; each reference's
// scheme:opaque well-formedness is enforced once, for every ref in the config,
// by validateRefs. No message quotes a reference value — a secrets.Ref renders
// redacted through every formatting path.
func validateACMEDNSCredentials(v *validator, d ACMEDNSConfig) {
	hasSingle := !d.CredentialsRef.IsZero()
	hasNamed := len(d.CredentialsRefs) > 0

	switch {
	case hasSingle && hasNamed:
		v.add("tls.acme.dns.credentials_refs",
			"set either credentials_ref or credentials_refs, not both")
	case !hasSingle && !hasNamed:
		v.add("tls.acme.dns.credentials_ref",
			"required for dns_01 api mode (set credentials_ref or credentials_refs)")
	case hasNamed:
		for _, name := range SortedRefNames(d.CredentialsRefs) {
			if strings.TrimSpace(name) == "" {
				v.add("tls.acme.dns.credentials_refs", "credential name must not be empty")
				continue
			}
			if d.CredentialsRefs[name].IsZero() {
				v.add("tls.acme.dns.credentials_refs."+name, "must not be empty")
			}
		}
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
	// A non-positive grace window is rejected here rather than normalized to a
	// default, because both of its plausible silent readings are wrong: zero
	// as "no deadline" leaves a rotated credential live forever, and zero as
	// "no overlap" quietly turns rotation into something the operator did not
	// ask for. Neither is a value to guess at, so a misconfigured window stops
	// startup. The upper bound exists for the same reason the token TTL has
	// one: a window measured in months is a second live credential nobody is
	// tracking, which defeats the point of rotating.
	if w := a.AccessKeyGraceWindow.Std(); w <= 0 || w > 30*24*time.Hour {
		v.add("auth.access_key_grace_window", "must be in (0, 720h], got %v", w)
	}
	if !a.Providers.APIToken.Enabled && !a.Providers.Passkey.Enabled && !a.Providers.OIDC.Enabled {
		v.add("auth.providers", "at least one authentication provider must be enabled")
	}
	if prod && a.TokenSigningKeyRef.IsZero() {
		v.add("auth.token_signing_key_ref", "required in production")
	}
	// Without a pepper no access key can be verified, so every protected key set
	// answers 404 to everyone. That is safe but it is also silent, and a
	// production deployment that believes it is serving protected sets and is
	// not should be told at startup rather than by a consumer's ticket.
	// Development is allowed the verifier-less mode so a checkout runs with no
	// secret material at all.
	if prod && a.AccessKeyPepperRef.IsZero() {
		v.add("auth.access_key_pepper_ref", "required in production")
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
	if r.Store == "shared" && r.Shared.Address != "" {
		// ADR-0022 is an at-rest rule: secrets never live in the config file. A
		// Redis URL can smuggle an AUTH password into its userinfo
		// (redis://:pass@host), which would sit in the file on disk, in version
		// control and in backups -- exactly what password_ref exists to prevent.
		// Reject it fail-closed at startup; the operator must move the secret to
		// rate_limit.shared.password_ref. A username with no password
		// (redis://user@host, a Redis 6+ ACL username) is not a secret and is
		// allowed. The redacted address never echoes the password back.
		if hasPassword, redacted := inspectRedisAddress(r.Shared.Address); hasPassword {
			v.add("rate_limit.shared.address",
				"must not embed an AUTH password (got %s); set it via rate_limit.shared.password_ref instead (ADR-0022: secrets never in the config file)",
				redacted)
		}
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

// inspectRedisAddress reports whether a shared-store Redis address embeds an
// AUTH password in its userinfo, and returns the address with any such password
// masked for safe inclusion in a validation error. A bare "host:port" is
// normalized to a redis:// URL first, matching how the store parses it. It uses
// the standard library's url.Redacted -- the same primitive redisstore's
// RedactAddress wraps -- rather than importing redisstore, so config keeps its
// minimal dependency footprint (it does not pull in the Redis client library).
func inspectRedisAddress(address string) (hasPassword bool, redacted string) {
	raw := address
	if !strings.Contains(raw, "://") {
		raw = "redis://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		// Unparseable here is caught fail-closed when the store is built; this
		// path only decides the password question, so report "no password" and
		// never echo the raw string (url.Parse's own error would quote it).
		return false, "[unparseable redis address]"
	}
	if u.User != nil {
		_, hasPassword = u.User.Password()
	}
	return hasPassword, u.Redacted()
}

func (c *Config) validateTelemetry(v *validator) {
	// The level and format names are checked against internal/logging's own
	// tables rather than a switch repeated here. A copy would drift, and the
	// direction it drifts in is "validation accepts a name the logger then
	// cannot parse", which is exactly the silent fallback this rejects.
	if _, err := logging.ParseLevel(c.Telemetry.Log.Level); err != nil {
		v.add("telemetry.log.level", "%v", err)
	}
	if err := logging.ValidateFormat(c.Telemetry.Log.Format); err != nil {
		v.add("telemetry.log.format", "%v", err)
	}
	if c.Telemetry.Metrics.OTLP.Enabled {
		if c.Telemetry.Metrics.OTLP.Endpoint == "" {
			v.add("telemetry.metrics.otlp.endpoint", "required when otlp metrics are enabled")
		} else {
			validateExportEndpoint(v, "telemetry.metrics.otlp.endpoint", c.Telemetry.Metrics.OTLP.Endpoint)
		}
	}
	if c.Telemetry.Traces.Enabled {
		if c.Telemetry.Traces.Endpoint == "" {
			v.add("telemetry.traces.endpoint", "required when traces are enabled")
		} else {
			validateExportEndpoint(v, "telemetry.traces.endpoint", c.Telemetry.Traces.Endpoint)
		}
	}
	if r := c.Telemetry.Traces.SampleRatio; r < 0 || r > 1 || math.IsNaN(r) {
		v.add("telemetry.traces.sample_ratio", "must be between 0 and 1, got %v", r)
	}
	c.validatePrometheus(v)
}

// validateExportEndpoint checks a telemetry export endpoint.
//
// It must be an absolute http:// or https:// URL, and it must carry no
// userinfo. Rejecting "https://user:password@collector/v1/traces" is the point:
// an endpoint with embedded credentials is a secret sitting in a plain config
// field, which then reaches error messages, process listings and any dump of
// the effective configuration. The credential belongs in the headers reference,
// which is a secrets.Ref and redacts itself everywhere.
func validateExportEndpoint(v *validator, field, endpoint string) {
	u, err := url.Parse(endpoint)
	if err != nil {
		// The parse error would quote the offending URL, so it is deliberately
		// not echoed here -- that is the one string in this function that may
		// contain a password.
		v.add(field, "must be a valid URL")
		return
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		v.add(field, "must be an http:// or https:// URL")
	}
	if u.Host == "" {
		v.add(field, "must include a host")
	}
	if u.User != nil {
		v.add(field, "must not embed credentials in the URL; use headers_ref instead")
	}
}

// validatePrometheus enforces the scrape endpoint's exposure model (ADR-0025).
//
// Two rules, both fail-closed:
//
//   - The scrape listener may not share an address with the public API
//     listener. Serving both from one socket is exactly the unauthenticated
//     public exposure the separate-listener design exists to prevent, and an
//     operator who pastes the same address into both fields has expressed it by
//     accident. Refusing at startup is the only place that mistake is cheap.
//   - The path must be absolute, since it is registered on a mux and a relative
//     pattern would silently never match, leaving an operator with a listener
//     that answers 404 to their scraper for no visible reason.
//
// Binding the scrape listener to a wildcard address is NOT rejected: a
// container platform that scrapes across the pod network requires it, and a
// rule that forces every Kubernetes deployer to disable a check teaches them to
// disable checks. The safe posture is set by the default (unserved) and the
// loopback example in vallet.example.yaml; what must be impossible is arriving
// at public exposure by leaving a field blank, and it is.
func (c *Config) validatePrometheus(v *validator) {
	p := c.Telemetry.Metrics.Prometheus
	if p.ListenAddr == "" {
		return
	}
	if _, _, err := net.SplitHostPort(p.ListenAddr); err != nil {
		v.add("telemetry.metrics.prometheus.listen_addr", "must be a host:port address, got %q", p.ListenAddr)
	}
	if addrsOverlap(p.ListenAddr, c.Server.ListenAddr) {
		v.add("telemetry.metrics.prometheus.listen_addr",
			"must not overlap server.listen_addr; the scrape endpoint is served on its own listener and is never mounted on the public API")
	}
	if !strings.HasPrefix(p.Path, "/") {
		v.add("telemetry.metrics.prometheus.path", "must be an absolute path beginning with /, got %q", p.Path)
	}
}

// addrsOverlap reports whether two listen addresses would end up serving the
// same socket.
//
// A string comparison is not enough, and the gap is not cosmetic: ":8443" and
// "0.0.0.0:8443" are different strings that bind the identical socket, so an
// operator who wrote one in each field would defeat the check entirely and get
// the scrape endpoint on the public API port -- precisely the outcome the check
// exists to make unreachable. The ports must match for any overlap to be
// possible; given that, a wildcard on either side covers every interface the
// other could name, and two equal hosts are the same interface.
//
// Malformed input is reported as NOT overlapping, because the caller has
// already flagged it as unparseable and a second error on the same field would
// describe a conflict that is not what is wrong with it.
func addrsOverlap(a, b string) bool {
	ah, ap, err := net.SplitHostPort(a)
	if err != nil {
		return false
	}
	bh, bp, err := net.SplitHostPort(b)
	if err != nil {
		return false
	}
	if ap != bp {
		return false
	}
	return isWildcardHost(ah) || isWildcardHost(bh) || ah == bh
}

// isWildcardHost reports whether a host from a listen address binds every
// interface. An empty host is the ":8443" form.
func isWildcardHost(h string) bool {
	return h == "" || h == "0.0.0.0" || h == "::"
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
	// 0 disables the release sweep; negative is a mistake, not a mode. See the
	// field for why an off switch is safe on this sweep specifically.
	if c.Retention.HandleQuarantineSweepInterval.Std() < 0 {
		v.add("retention.handle_quarantine_sweep_interval", "must be >= 0 (0 disables the quarantine release sweep)")
	}
	// Strictly positive even when the sweep is disabled: a non-positive batch
	// has no safe reading, and the repository would coerce it to a page-size
	// default rather than refuse it, so an operator's 0 would silently become
	// a batch nobody chose.
	if c.Retention.HandleQuarantineSweepBatch < 1 {
		v.add("retention.handle_quarantine_sweep_batch", "must be >= 1, got %d", c.Retention.HandleQuarantineSweepBatch)
	}
	// 0 disables the grace sweep and is the default; negative is a mistake.
	if c.Retention.AccessKeyGraceSweepInterval.Std() < 0 {
		v.add("retention.access_key_grace_sweep_interval", "must be >= 0 (0 disables the access key grace sweep)")
	}
	// Strictly positive even when disabled, and unlike the handle batch this is
	// not merely tidiness: the access key repository rejects a non-positive
	// limit rather than coercing it, so a 0 here would make every pass fail.
	if c.Retention.AccessKeyGraceSweepBatch < 1 {
		v.add("retention.access_key_grace_sweep_batch", "must be >= 1, got %d", c.Retention.AccessKeyGraceSweepBatch)
	}
	// The pepper is required exactly when the sweep is on, and this is checked
	// at validation rather than left to fail at construction so that an
	// operator who enables the sweep learns the requirement from a config error
	// naming the field, not from a startup crash. Failing closed at startup
	// either way is the point: a sweep the operator switched on must not run
	// with the process quietly deciding it could not be built.
	if c.Retention.AccessKeyGraceSweepInterval.Std() > 0 && c.Auth.AccessKeyPepperRef.IsZero() {
		v.add("auth.access_key_pepper_ref", "is required when retention.access_key_grace_sweep_interval is set")
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

// allRefs enumerates every secret reference field in the config, including each
// named DNS credential reference. The named refs are appended in sorted key
// order so validation errors over them are deterministic.
func (c *Config) allRefs() []refField {
	refs := []refField{
		{"tls.acme.dns.credentials_ref", c.TLS.ACME.DNS.CredentialsRef},
		{"tls.cloudflare_origin.api_token_ref", c.TLS.CloudflareOrigin.APITokenRef},
		{"database.postgres.dsn_ref", c.Database.Postgres.DSNRef},
		{"auth.token_signing_key_ref", c.Auth.TokenSigningKeyRef},
		{"auth.access_key_pepper_ref", c.Auth.AccessKeyPepperRef},
		{"rate_limit.shared.password_ref", c.RateLimit.Shared.PasswordRef},
		{"telemetry.metrics.otlp.headers_ref", c.Telemetry.Metrics.OTLP.HeadersRef},
	}
	for _, name := range SortedRefNames(c.TLS.ACME.DNS.CredentialsRefs) {
		refs = append(refs, refField{
			"tls.acme.dns.credentials_refs." + name,
			c.TLS.ACME.DNS.CredentialsRefs[name],
		})
	}
	return refs
}
