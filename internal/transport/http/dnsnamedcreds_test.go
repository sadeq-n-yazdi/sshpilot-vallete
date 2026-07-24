package httpserver

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/secrets"
)

// TestNewDNSProviderResolvesNamedCredentials pins the named-credential
// resolution branch of resolveDNSCredentials (issue #54): a provider that needs
// several credentials names each one under tls.acme.dns.credentials_refs, and
// each reference is resolved through the secret provider into the
// [dns01.Credentials] set threaded to the constructor.
//
// Route 53 is the compiled-in multi-credential provider; it takes named
// access_key_id and secret_access_key. Reaching a built provider proves the
// whole named path -- resolve each ref, build NewNamedCredentials, pack them in
// route53Credential -- works end to end. Every existing DNS test drives the
// single credentials_ref, so without this row the named branch has no coverage
// despite being TLS-enforcement wiring.
func TestNewDNSProviderResolvesNamedCredentials(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	// File-backed references rather than env: t.Setenv forbids t.Parallel, and
	// the value must RESOLVE for the row to reach the route53 constructor.
	idFile := filepath.Join(dir, "access-key-id")
	secretFile := filepath.Join(dir, "secret-access-key")
	if err := os.WriteFile(idFile, []byte("AKIAEXAMPLE"), 0o600); err != nil {
		t.Fatalf("write id file: %v", err)
	}
	if err := os.WriteFile(secretFile, []byte("secret-value"), 0o600); err != nil {
		t.Fatalf("write secret file: %v", err)
	}

	cfg := acmeTestConfig(t)
	cfg.TLS.ACME.Solver = "dns_01"
	cfg.TLS.ACME.DNS.Mode = "api"
	cfg.TLS.ACME.DNS.Provider = "route53"
	cfg.TLS.ACME.DNS.CredentialsRefs = map[string]secrets.Ref{
		"access_key_id":     secrets.Ref("file:" + idFile),
		"secret_access_key": secrets.Ref("file:" + secretFile),
	}

	provider, err := newDNSProvider(t.Context(), cfg, nil)
	if err != nil {
		t.Fatalf("newDNSProvider() error = %v, want nil", err)
	}
	if provider == nil {
		t.Fatal("newDNSProvider() = nil provider, want a route53 provider")
	}
	if got, want := provider.Name(), "route53"; got != want {
		t.Errorf("provider.Name() = %q, want %q", got, want)
	}
}

// TestNewDNSProviderNamedCredentialFailsClosed proves the named branch fails
// closed and names the offending FIELD, never a value: an unresolvable named
// reference refuses startup with the certificate-invalid sentinel and reports
// which credential name failed, so an operator can fix the reference without the
// error leaking the credentials that did resolve.
func TestNewDNSProviderNamedCredentialFailsClosed(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	idFile := filepath.Join(dir, "access-key-id")
	const resolvableSecret = "AKIA-should-not-appear-in-error"
	if err := os.WriteFile(idFile, []byte(resolvableSecret), 0o600); err != nil {
		t.Fatalf("write id file: %v", err)
	}

	cfg := acmeTestConfig(t)
	cfg.TLS.ACME.Solver = "dns_01"
	cfg.TLS.ACME.DNS.Mode = "api"
	cfg.TLS.ACME.DNS.Provider = "route53"
	cfg.TLS.ACME.DNS.CredentialsRefs = map[string]secrets.Ref{
		"access_key_id":     secrets.Ref("file:" + idFile),
		"secret_access_key": secrets.Ref("file:" + filepath.Join(dir, "missing")),
	}

	_, err := newDNSProvider(t.Context(), cfg, nil)
	if !errors.Is(err, ErrTLSCertificateInvalid) {
		t.Fatalf("newDNSProvider() error = %v, want ErrTLSCertificateInvalid", err)
	}
	if !strings.Contains(err.Error(), "credentials_refs.secret_access_key") {
		t.Errorf("error = %q, want it to name the failing field credentials_refs.secret_access_key", err)
	}
	if strings.Contains(err.Error(), resolvableSecret) {
		t.Errorf("error leaked a resolved credential value: %q", err)
	}
}
