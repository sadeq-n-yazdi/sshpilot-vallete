package config

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/secrets"
)

// SortedRefNames returns the keys of a named secret-reference map in sorted
// order, so every enumeration of the map (validation errors, required-secret
// resolution) is deterministic regardless of Go's randomized map iteration.
func SortedRefNames(m map[string]secrets.Ref) []string {
	names := make([]string, 0, len(m))
	for name := range m {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// RefRequirement is a secret reference the running configuration depends on,
// paired with the yaml field it came from (for error messages).
type RefRequirement struct {
	Field string
	Ref   secrets.Ref
}

// RequiredSecretRefs returns only the secret references actually needed by the
// SELECTED modes and toggles, so startup resolution fails closed on exactly the
// secrets this configuration requires and ignores irrelevant ones.
//
// Gating:
//   - postgres driver              -> database.postgres.dsn_ref
//   - tls mode cloudflare_origin   -> tls.cloudflare_origin.api_token_ref
//   - acme + dns_01 + dns api mode -> tls.acme.dns.credentials_ref
//   - production environment       -> auth.token_signing_key_ref
//   - production, or ref set       -> auth.access_key_pepper_ref
//   - shared rate-limit store      -> rate_limit.shared.password_ref (if set)
//   - otlp metrics enabled         -> telemetry.metrics.otlp.headers_ref (if set)
//
// Optional-if-set entries (shared password, otlp headers) are included only
// when non-empty; the others are always included so a missing required ref is
// caught at resolution time as well as by Validate.
func (c *Config) RequiredSecretRefs() []RefRequirement {
	var reqs []RefRequirement
	add := func(field string, ref secrets.Ref) {
		reqs = append(reqs, RefRequirement{Field: field, Ref: ref})
	}

	if c.Database.Driver == "postgres" {
		add("database.postgres.dsn_ref", c.Database.Postgres.DSNRef)
	}
	switch c.TLS.Mode {
	case "cloudflare_origin":
		add("tls.cloudflare_origin.api_token_ref", c.TLS.CloudflareOrigin.APITokenRef)
	case "acme":
		if c.TLS.ACME.Solver == "dns_01" && c.TLS.ACME.DNS.Mode == "api" {
			d := c.TLS.ACME.DNS
			// The single ref and the named refs are mutually exclusive (Validate
			// refuses both); resolution mirrors that so the preflight resolves
			// exactly the references this provider will actually use.
			if len(d.CredentialsRefs) > 0 {
				for _, name := range SortedRefNames(d.CredentialsRefs) {
					add("tls.acme.dns.credentials_refs."+name, d.CredentialsRefs[name])
				}
			} else {
				add("tls.acme.dns.credentials_ref", d.CredentialsRef)
			}
		}
	}
	if c.Server.Environment == "production" {
		add("auth.token_signing_key_ref", c.Auth.TokenSigningKeyRef)
	}
	// The pepper is required in production, and required to RESOLVE wherever it
	// was named. The second half is the load-bearing one: an operator who set
	// the reference asked for access key verification, so a reference that does
	// not resolve is a failure, not a license to fall back to the verifier-less
	// mode. Only an unset reference outside production selects that mode.
	//
	// The access key grace sweep needs the pepper too, but adds no gate here:
	// Validate requires the ref whenever the sweep is on, so a sweep-enabled
	// deployment always has a non-zero ref and is already covered by the clause
	// above.
	if c.Server.Environment == "production" || !c.Auth.AccessKeyPepperRef.IsZero() {
		add("auth.access_key_pepper_ref", c.Auth.AccessKeyPepperRef)
	}
	if c.RateLimit.Enabled && c.RateLimit.Store == "shared" && !c.RateLimit.Shared.PasswordRef.IsZero() {
		add("rate_limit.shared.password_ref", c.RateLimit.Shared.PasswordRef)
	}
	if c.Telemetry.Metrics.OTLP.Enabled && !c.Telemetry.Metrics.OTLP.HeadersRef.IsZero() {
		add("telemetry.metrics.otlp.headers_ref", c.Telemetry.Metrics.OTLP.HeadersRef)
	}
	return reqs
}

// ResolvedSecret is a startup-resolved secret keyed by its config field. The
// value is a secrets.Redacted, so it is safe to log the slice; the raw value is
// reachable only via Redacted.Reveal.
type ResolvedSecret struct {
	Field string
	Value secrets.Redacted
}

// ResolveRequiredSecrets resolves every reference from RequiredSecretRefs using
// the given resolver, aggregating all failures so startup fails closed with a
// complete picture. Resolved values are returned; they are NOT written back
// into the Config. Errors name the field and reference, never the value.
func (c *Config) ResolveRequiredSecrets(ctx context.Context, r *secrets.Resolver) ([]ResolvedSecret, error) {
	reqs := c.RequiredSecretRefs()
	resolved := make([]ResolvedSecret, 0, len(reqs))
	var errs []error
	for _, req := range reqs {
		val, err := r.Resolve(ctx, req.Ref)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", req.Field, err))
			continue
		}
		resolved = append(resolved, ResolvedSecret{Field: req.Field, Value: val})
	}
	if len(errs) > 0 {
		return nil, fmt.Errorf("config: unresolved required secrets: %w", errors.Join(errs...))
	}
	return resolved, nil
}
