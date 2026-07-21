package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/secrets"
)

// writeYAML writes s to a temp file and returns its path.
func writeYAML(t *testing.T, s string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(s), 0o600); err != nil {
		t.Fatalf("write temp yaml: %v", err)
	}
	return path
}

// TestLoadNamedDNSCredentials round-trips the credentials_refs map through the
// YAML loader: the operator-chosen keys and their references must survive
// decoding into the map exactly.
func TestLoadNamedDNSCredentials(t *testing.T) {
	path := writeYAML(t, `
tls:
  acme:
    dns:
      mode: api
      provider: route53
      credentials_refs:
        access_key_id: env:AWS_KEY
        secret_access_key: env:AWS_SECRET
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	got := cfg.TLS.ACME.DNS.CredentialsRefs
	want := map[string]secrets.Ref{
		"access_key_id":     "env:AWS_KEY",
		"secret_access_key": "env:AWS_SECRET",
	}
	if len(got) != len(want) {
		t.Fatalf("credentials_refs = %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("credentials_refs[%q] = %q, want %q", k, got[k], v)
		}
	}
	// The single ref is left unset when only the named map is supplied.
	if !cfg.TLS.ACME.DNS.CredentialsRef.IsZero() {
		t.Errorf("credentials_ref = %q, want unset", cfg.TLS.ACME.DNS.CredentialsRef)
	}
}

// TestLoadRejectsUnknownDNSKey proves the strict-unknown-key gate still fires
// under the dns subtree after the new field was added: a typo in a credential
// key name that ended up as a struct key would be a silent misconfiguration.
func TestLoadRejectsUnknownDNSKey(t *testing.T) {
	path := writeYAML(t, `
tls:
  acme:
    dns:
      mode: api
      provider: route53
      credentials_reffs: env:oops
`)
	if _, err := Load(path); err == nil {
		t.Fatal("expected an unknown-key rejection for credentials_reffs")
	}
}

// TestValidateAcceptsNamedDNSCredentials is the positive case for the new
// validation branch: a route53 config authenticated by the named map alone is
// valid.
func TestValidateAcceptsNamedDNSCredentials(t *testing.T) {
	c := validConfig()
	c.TLS.ACME.Solver = "dns_01"
	c.TLS.ACME.DNS.Mode = "api"
	c.TLS.ACME.DNS.Provider = "route53"
	c.TLS.ACME.DNS.CredentialsRefs = map[string]secrets.Ref{
		"access_key_id":     "env:AWS_KEY",
		"secret_access_key": "env:AWS_SECRET",
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("Validate rejected a valid named-credential config: %v", err)
	}
}

// TestValidateRejectsMalformedNamedDNSRef proves the per-ref well-formedness
// sweep reaches the named refs: a value that is not scheme:opaque is caught,
// keyed by its own field path.
func TestValidateRejectsMalformedNamedDNSRef(t *testing.T) {
	c := validConfig()
	c.TLS.ACME.Solver = "dns_01"
	c.TLS.ACME.DNS.Mode = "api"
	c.TLS.ACME.DNS.Provider = "route53"
	c.TLS.ACME.DNS.CredentialsRefs = map[string]secrets.Ref{
		"access_key_id":     "env:AWS_KEY",
		"secret_access_key": "notaref",
	}
	err := c.Validate()
	if err == nil {
		t.Fatal("expected a malformed-reference error")
	}
	if !strings.Contains(err.Error(), "tls.acme.dns.credentials_refs.secret_access_key") {
		t.Errorf("error %q does not name the offending field", err)
	}
}

// TestRequiredSecretRefsNamedDNS proves the startup preflight resolves every
// named reference (and not the unset single one) in api mode.
func TestRequiredSecretRefsNamedDNS(t *testing.T) {
	c := validConfig()
	c.TLS.ACME.Solver = "dns_01"
	c.TLS.ACME.DNS.Mode = "api"
	c.TLS.ACME.DNS.Provider = "route53"
	c.TLS.ACME.DNS.CredentialsRefs = map[string]secrets.Ref{
		"access_key_id":     "env:AWS_KEY",
		"secret_access_key": "env:AWS_SECRET",
	}

	got := map[string]secrets.Ref{}
	for _, r := range c.RequiredSecretRefs() {
		got[r.Field] = r.Ref
	}
	for _, name := range []string{"access_key_id", "secret_access_key"} {
		field := "tls.acme.dns.credentials_refs." + name
		if _, ok := got[field]; !ok {
			t.Errorf("required refs missing %q", field)
		}
	}
	if _, ok := got["tls.acme.dns.credentials_ref"]; ok {
		t.Error("named-credential mode must not require the single credentials_ref")
	}
}
