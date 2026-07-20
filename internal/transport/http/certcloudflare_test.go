package httpserver

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/config"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/secrets"
)

// --- test doubles ----------------------------------------------------------

// doerFunc adapts a function to httpDoer, which is the seam every Cloudflare
// API call goes through.
type doerFunc func(*http.Request) (*http.Response, error)

func (f doerFunc) Do(req *http.Request) (*http.Response, error) { return f(req) }

// jsonResponse builds an API response with the given status and body.
func jsonResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     make(http.Header),
	}
}

// fakeOriginCA is a stand-in for Cloudflare's Origin CA: a private root that
// signs whatever CSR it is handed.
//
// It mirrors the real product's defining property, which is the point of using
// one rather than a self-signed leaf: the issued certificate chains to a root
// that no public trust store contains, exactly like a real Origin CA
// certificate.
type fakeOriginCA struct {
	key  *ecdsa.PrivateKey
	cert *x509.Certificate
}

func newFakeOriginCA(t *testing.T) *fakeOriginCA {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ca key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Fake Cloudflare Origin CA"},
		NotBefore:             time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2036, 1, 1, 0, 0, 0, 0, time.UTC),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create ca cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse ca cert: %v", err)
	}
	return &fakeOriginCA{key: key, cert: cert}
}

// sign issues a certificate for the CSR in the request body, with the validity
// window the caller asks for, and returns Cloudflare's response envelope.
func (ca *fakeOriginCA) sign(t *testing.T, req *http.Request, notBefore, notAfter time.Time) *http.Response {
	t.Helper()

	var payload struct {
		CSR       string   `json:"csr"`
		Hostnames []string `json:"hostnames"`
	}
	body, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("read request body: %v", err)
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatalf("decode request body: %v", err)
	}

	block, _ := pem.Decode([]byte(payload.CSR))
	if block == nil {
		t.Fatal("request carried no PEM CSR")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatalf("parse csr: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      csr.Subject,
		DNSNames:     csr.DNSNames,
		IPAddresses:  csr.IPAddresses,
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, csr.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("sign csr: %v", err)
	}

	leaf := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	envelope, err := json.Marshal(map[string]any{
		"success": true,
		"result":  map[string]any{"certificate": string(leaf)},
	})
	if err != nil {
		t.Fatalf("encode envelope: %v", err)
	}
	return jsonResponse(http.StatusOK, string(envelope))
}

// originTestConfig returns a valid cloudflare_origin configuration.
func originTestConfig(t *testing.T) *config.Config {
	t.Helper()

	cfg := config.Default()
	cfg.Server.Environment = "development"
	cfg.Server.TrustedProxies = []string{"192.0.2.0/24"}
	cfg.TLS.Mode = "cloudflare_origin"
	cfg.TLS.Domain = "vallet.example.com"
	cfg.TLS.CloudflareOrigin.APITokenRef = "env:VALLET_TEST_ORIGIN_CA_KEY"
	cfg.TLS.CloudflareOrigin.CacheDir = t.TempDir()
	cfg.TLS.CloudflareOrigin.ValidityDays = 365
	return &cfg
}

// helloFrom builds a ClientHelloInfo whose peer is the given address, which is
// what the trusted-proxy check reads.
func helloFrom(addr string) *tls.ClientHelloInfo {
	return &tls.ClientHelloInfo{
		ServerName: "vallet.example.com",
		Conn:       stubConn{remote: stringAddr(addr)},
	}
}

// stringAddr is a net.Addr carrying a literal "host:port", which is the form
// trustedPeers.trusts parses.
type stringAddr string

func (a stringAddr) Network() string { return "tcp" }
func (a stringAddr) String() string  { return string(a) }

// stubConn is a net.Conn that exists only to carry a remote address.
type stubConn struct {
	net.Conn
	remote net.Addr
}

func (c stubConn) RemoteAddr() net.Addr { return c.remote }

// staticSecret returns a resolver yielding a fixed credential.
func staticSecret(value string) secretResolver {
	return func(context.Context, secrets.Ref) (secrets.Redacted, error) {
		return secrets.NewRedacted(value), nil
	}
}

// newOriginTestProvider builds a provider against a fake CA that signs with the
// given validity window.
func newOriginTestProvider(
	t *testing.T, cfg *config.Config, now time.Time, notBefore, notAfter time.Time,
) *originCAProvider {
	t.Helper()

	ca := newFakeOriginCA(t)
	p, err := newOriginCAProviderWithClient(t.Context(), cfg, staticClock(now),
		secrets.NewRedacted("v1.0-testkey"),
		doerFunc(func(req *http.Request) (*http.Response, error) {
			return ca.sign(t, req, notBefore, notAfter), nil
		}))
	if err != nil {
		t.Fatalf("build provider: %v", err)
	}
	t.Cleanup(func() { _ = p.Close() })
	return p
}

// --- successful issuance ---------------------------------------------------

// TestOriginCAIssuesAndServesCertificate covers the happy path end to end: a
// CSR is sent, the signed certificate comes back, and it is served.
//
// The assertion is that the served certificate's public key matches the private
// key the provider generated, re-derived from the DER rather than read off the
// struct. "A certificate was returned" would pass even if the provider served
// something it could not sign with.
func TestOriginCAIssuesAndServesCertificate(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	cfg := originTestConfig(t)
	p := newOriginTestProvider(t, cfg, now, now.Add(-time.Hour), now.Add(365*24*time.Hour))

	cert, err := p.GetCertificate(helloFrom("192.0.2.10:44321"))
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	if err := validateCertificate(cert, now); err != nil {
		t.Fatalf("served certificate must pass the guard: %v", err)
	}

	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	if got := leaf.DNSNames; len(got) != 1 || got[0] != "vallet.example.com" {
		t.Errorf("leaf DNSNames = %v, want [vallet.example.com]", got)
	}
}

// TestOriginCASendsTheConfiguredRequest checks the request Cloudflare actually
// receives: the CSR must carry the configured names, the validity must be the
// configured one, and the request type must match the key that was generated.
//
// The request_type assertion is not cosmetic. Asking for origin-rsa while
// generating a P-256 key yields a certificate whose public key is not ours,
// which the guard would refuse — so a mismatch here is an outage, and it is
// invisible in any test that only looks at the response.
func TestOriginCASendsTheConfiguredRequest(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	cfg := originTestConfig(t)
	cfg.TLS.SANs = []string{"api.vallet.example.com"}
	cfg.TLS.CloudflareOrigin.ValidityDays = 90

	ca := newFakeOriginCA(t)
	var seen struct {
		hostnames   []string
		requestType string
		validity    int
		authHeader  string
		bearer      string
		csrHasKey   bool
		csrIsPEM    bool
	}

	p, err := newOriginCAProviderWithClient(t.Context(), cfg, staticClock(now),
		secrets.NewRedacted("v1.0-testkey"),
		doerFunc(func(req *http.Request) (*http.Response, error) {
			body, err := io.ReadAll(req.Body)
			if err != nil {
				t.Fatalf("read body: %v", err)
			}
			var payload struct {
				CSR       string   `json:"csr"`
				Hostnames []string `json:"hostnames"`
				Type      string   `json:"request_type"`
				Validity  int      `json:"requested_validity"`
			}
			if err := json.Unmarshal(body, &payload); err != nil {
				t.Fatalf("decode body: %v", err)
			}
			seen.hostnames = payload.Hostnames
			seen.requestType = payload.Type
			seen.validity = payload.Validity
			seen.authHeader = req.Header.Get("X-Auth-User-Service-Key")
			seen.bearer = req.Header.Get("Authorization")
			seen.csrIsPEM = strings.Contains(payload.CSR, "BEGIN CERTIFICATE REQUEST")
			// The single most important assertion in this file: no private key
			// may appear in anything sent to Cloudflare.
			seen.csrHasKey = strings.Contains(payload.CSR, "PRIVATE KEY")

			req.Body = io.NopCloser(strings.NewReader(string(body)))
			return ca.sign(t, req, now.Add(-time.Hour), now.Add(90*24*time.Hour)), nil
		}))
	if err != nil {
		t.Fatalf("build provider: %v", err)
	}
	t.Cleanup(func() { _ = p.Close() })

	if len(seen.hostnames) != 2 || seen.hostnames[0] != "vallet.example.com" ||
		seen.hostnames[1] != "api.vallet.example.com" {
		t.Errorf("hostnames = %v, want the domain and its SAN", seen.hostnames)
	}
	if seen.requestType != "origin-ecc" {
		t.Errorf("request_type = %q, want origin-ecc to match the generated P-256 key", seen.requestType)
	}
	if seen.validity != 90 {
		t.Errorf("requested_validity = %d, want 90", seen.validity)
	}
	if seen.authHeader != "v1.0-testkey" {
		t.Errorf("X-Auth-User-Service-Key = %q, want the Origin CA key", seen.authHeader)
	}
	if seen.bearer != "" {
		t.Errorf("an Origin CA key must not also be sent as a bearer token, got %q", seen.bearer)
	}
	if !seen.csrIsPEM {
		t.Error("the request must carry a PEM CSR")
	}
	if seen.csrHasKey {
		t.Fatal("the private key must never be transmitted to Cloudflare")
	}
}

// TestOriginCAAuthHeaderSelection covers both credential shapes Cloudflare
// accepts. Sending either in the other's header simply fails to authenticate.
func TestOriginCAAuthHeaderSelection(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		token     string
		wantName  string
		wantValue string
	}{
		{"origin ca key", "v1.0-abc123", "X-Auth-User-Service-Key", "v1.0-abc123"},
		{"scoped api token", "abc123", "Authorization", "Bearer abc123"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			name, value := originCAAuthHeader(secrets.NewRedacted(tt.token))
			if name != tt.wantName || value != tt.wantValue {
				t.Errorf("header = %q: %q, want %q: %q", name, value, tt.wantName, tt.wantValue)
			}
		})
	}
}

// --- fail-closed: the direct-origin misconfiguration trap -------------------

// TestOriginCAWithholdsCertificateFromDirectClients is the central security
// test of this provider.
//
// An Origin CA certificate is trusted only by the Cloudflare edge. A handshake
// from any other peer means the origin is directly reachable — the topology in
// which this mode is unsafe — so the certificate is withheld rather than
// served. Handing it over is what leads an operator to disable verification,
// which removes the MITM protection on the key-publish path.
//
// The assertion is on the SENTINEL and on no certificate being returned, not
// merely on "an error happened": a provider that failed for an unrelated reason
// would satisfy a weaker check while leaving the real gap open.
func TestOriginCAWithholdsCertificateFromDirectClients(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	cfg := originTestConfig(t)
	p := newOriginTestProvider(t, cfg, now, now.Add(-time.Hour), now.Add(365*24*time.Hour))

	// The provider does hold a valid certificate: proven here so the refusals
	// below cannot be explained by there being nothing to serve.
	if _, err := p.GetCertificate(helloFrom("192.0.2.10:44321")); err != nil {
		t.Fatalf("the trusted proxy must be served: %v", err)
	}

	tests := []struct {
		name  string
		hello *tls.ClientHelloInfo
	}{
		{"peer outside the trusted range", helloFrom("198.51.100.7:1234")},
		{"loopback is not a proxy either", helloFrom("127.0.0.1:1234")},
		{"peer address unavailable", &tls.ClientHelloInfo{ServerName: "vallet.example.com"}},
		{"connection with no remote address", &tls.ClientHelloInfo{
			ServerName: "vallet.example.com",
			Conn:       stubConn{remote: nil},
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cert, err := p.GetCertificate(tt.hello)
			if !errors.Is(err, ErrOriginCADirectClient) {
				t.Fatalf("err = %v, want ErrOriginCADirectClient", err)
			}
			if cert != nil {
				t.Fatal("the origin certificate must not be handed to a non-proxy peer")
			}
		})
	}
}

// TestOriginCAPeerErrorDoesNotEchoTheAddress checks that an attacker-controlled
// peer address is not quoted into the error.
//
// This path runs before any request logging or rate limiting, so an
// internet-wide origin scan must not be able to write chosen bytes into the
// server's error paths.
func TestOriginCAPeerErrorDoesNotEchoTheAddress(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	cfg := originTestConfig(t)
	p := newOriginTestProvider(t, cfg, now, now.Add(-time.Hour), now.Add(365*24*time.Hour))

	_, err := p.GetCertificate(helloFrom("198.51.100.7:1234"))
	if err == nil {
		t.Fatal("want a refusal")
	}
	if strings.Contains(err.Error(), "198.51.100.7") {
		t.Errorf("error must not echo the peer address: %v", err)
	}
}

// TestOriginCARefusesWithoutTrustedProxies checks the construction-time half of
// the gate. With no declared proxy there is nothing to recognize the Cloudflare
// edge by, so the provider must not exist at all rather than serve everyone.
func TestOriginCARefusesWithoutTrustedProxies(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	cfg := originTestConfig(t)
	cfg.Server.TrustedProxies = nil

	p, err := newOriginCAProviderWithClient(t.Context(), cfg, staticClock(now),
		secrets.NewRedacted("v1.0-testkey"),
		doerFunc(func(*http.Request) (*http.Response, error) {
			t.Fatal("no certificate may be requested without a declared proxy")
			return nil, nil
		}))
	if !errors.Is(err, ErrOriginCADirectClient) {
		t.Fatalf("err = %v, want ErrOriginCADirectClient", err)
	}
	if p != nil {
		t.Fatal("a provider that cannot recognize the edge must not be built")
	}
}

// TestConfigRefusesOriginModeWithoutTrustedProxies checks the same rule at the
// config layer, where an operator meets it first.
func TestConfigRefusesOriginModeWithoutTrustedProxies(t *testing.T) {
	t.Parallel()

	cfg := originTestConfig(t)
	cfg.Server.TrustedProxies = nil

	err := cfg.Validate()
	if err == nil {
		t.Fatal("cloudflare_origin with no trusted proxies must not validate")
	}
	if !strings.Contains(err.Error(), "server.trusted_proxies") {
		t.Errorf("error must name the field an operator has to fix: %v", err)
	}
}

// TestOriginCAWiringResolvesCredentialsThroughTheRealPath exercises
// newCertProvider — the dispatch case and builtinSecretResolver — rather than
// the constructor the other tests inject into.
//
// Every other test in this file reaches newOriginCAProviderWithClient directly
// with a stub resolver, so a regression in the mode dispatch or in the way the
// secret resolver is built would pass all of them silently. This one drives an
// unset reference through the production path and requires the credential
// failure to surface as ErrOriginCACredential.
func TestOriginCAWiringResolvesCredentialsThroughTheRealPath(t *testing.T) {
	t.Parallel()

	cfg := originTestConfig(t)
	// Deliberately unset: resolving it must fail, not fall back to a default.
	cfg.TLS.CloudflareOrigin.APITokenRef = "env:VALLET_TEST_UNSET_ORIGIN_CA_KEY"

	// Only the error is asserted here; the interface nil-ness of every failing
	// mode, this one included, is pinned by
	// TestNewCertProviderReturnsNilInterfaceOnError. That claim IS one the
	// package makes now: every case returns through asCertProvider.
	_, err := newCertProvider(context.Background(), cfg, time.Now)
	if !errors.Is(err, ErrOriginCACredential) {
		t.Fatalf("err = %v, want ErrOriginCACredential", err)
	}
}
