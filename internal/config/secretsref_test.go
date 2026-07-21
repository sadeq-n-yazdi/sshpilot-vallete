package config

import (
	"context"
	"strings"
	"testing"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/secrets"
)

func fieldSet(reqs []RefRequirement) map[string]secrets.Ref {
	m := make(map[string]secrets.Ref, len(reqs))
	for _, r := range reqs {
		m[r.Field] = r.Ref
	}
	return m
}

func TestRequiredSecretRefsGating(t *testing.T) {
	c := validConfig() // production + acme(tls_alpn_01) + signing key
	got := fieldSet(c.RequiredSecretRefs())
	if _, ok := got["auth.token_signing_key_ref"]; !ok {
		t.Error("production should require signing key ref")
	}
	// acme with tls_alpn_01 does NOT need dns creds.
	if _, ok := got["tls.acme.dns.credentials_ref"]; ok {
		t.Error("tls_alpn_01 must not require dns creds")
	}
	// sqlite default does NOT need a dsn.
	if _, ok := got["database.postgres.dsn_ref"]; ok {
		t.Error("sqlite must not require dsn ref")
	}
}

func TestRequiredSecretRefsSelectedModes(t *testing.T) {
	c := validConfig()
	c.Database.Driver = "postgres"
	c.Database.Postgres.DSNRef = "env:PG"
	c.TLS.Mode = "cloudflare_origin"
	c.TLS.CloudflareOrigin.APITokenRef = "env:CF"
	c.RateLimit.Store = "shared"
	c.RateLimit.Shared.Address = "redis:6379"
	c.RateLimit.Shared.PasswordRef = "env:REDIS"
	c.Telemetry.Metrics.OTLP.Enabled = true
	c.Telemetry.Metrics.OTLP.Endpoint = "otel:4317"
	c.Telemetry.Metrics.OTLP.HeadersRef = "env:OTLP"

	got := fieldSet(c.RequiredSecretRefs())
	for _, field := range []string{
		"database.postgres.dsn_ref",
		"tls.cloudflare_origin.api_token_ref",
		"auth.token_signing_key_ref",
		"rate_limit.shared.password_ref",
		"telemetry.metrics.otlp.headers_ref",
	} {
		if _, ok := got[field]; !ok {
			t.Errorf("expected required ref for %s", field)
		}
	}
}

func TestRequiredSecretRefsDNS01Api(t *testing.T) {
	c := validConfig()
	c.TLS.ACME.Solver = "dns_01"
	c.TLS.ACME.DNS.Mode = "api"
	c.TLS.ACME.DNS.Provider = "cloudflare"
	c.TLS.ACME.DNS.CredentialsRef = "env:DNS"
	got := fieldSet(c.RequiredSecretRefs())
	if _, ok := got["tls.acme.dns.credentials_ref"]; !ok {
		t.Error("dns_01 api mode should require dns creds")
	}
}

func TestRequiredSecretRefsOptionalWhenUnset(t *testing.T) {
	c := validConfig()
	c.RateLimit.Store = "shared"
	c.RateLimit.Shared.Address = "redis:6379"
	// PasswordRef intentionally empty: an auth-less redis needs no secret.
	got := fieldSet(c.RequiredSecretRefs())
	if _, ok := got["rate_limit.shared.password_ref"]; ok {
		t.Error("empty shared password ref must not be required")
	}
}

func TestResolveRequiredSecrets(t *testing.T) {
	t.Setenv("VALLET_SIGNING_KEY", "the-signing-secret")
	t.Setenv("VALLET_ACCESS_KEY_PEPPER", "0123456789abcdef0123456789abcdef")
	c := validConfig() // production: the signing key and the access key pepper

	resolver, err := secrets.NewResolver(secrets.Builtin(secrets.FileOptions{})...)
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	resolved, err := c.ResolveRequiredSecrets(context.Background(), resolver)
	if err != nil {
		t.Fatalf("ResolveRequiredSecrets: %v", err)
	}
	got := make(map[string]string, len(resolved))
	for _, r := range resolved {
		got[r.Field] = r.Value.Reveal()
	}
	if len(got) != 2 {
		t.Fatalf("resolved %d secrets, want 2: %v", len(got), resolved)
	}
	if got["auth.token_signing_key_ref"] != "the-signing-secret" {
		t.Errorf("signing key not resolved correctly")
	}
	if got["auth.access_key_pepper_ref"] != "0123456789abcdef0123456789abcdef" {
		t.Errorf("access key pepper not resolved correctly")
	}
	// Config must not be mutated with the resolved value.
	if c.Auth.TokenSigningKeyRef != "env:VALLET_SIGNING_KEY" {
		t.Errorf("config ref was overwritten: %q", c.Auth.TokenSigningKeyRef)
	}
}

func TestResolveRequiredSecretsAggregatesFailures(t *testing.T) {
	c := validConfig()
	c.Database.Driver = "postgres"
	c.Database.Postgres.DSNRef = "env:VALLET_MISSING_DSN"
	c.Auth.TokenSigningKeyRef = "env:VALLET_MISSING_KEY"

	resolver, err := secrets.NewResolver(secrets.Builtin(secrets.FileOptions{})...)
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	_, err = c.ResolveRequiredSecrets(context.Background(), resolver)
	if err == nil {
		t.Fatal("expected aggregated resolution failure")
	}
	// Both failing fields must appear; no secret value can leak.
	for _, field := range []string{"database.postgres.dsn_ref", "auth.token_signing_key_ref"} {
		if !strings.Contains(err.Error(), field) {
			t.Errorf("error missing field %s: %v", field, err)
		}
	}
}
