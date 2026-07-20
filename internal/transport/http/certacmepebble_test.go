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
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/acme"
)

// TestACMEEndToEndAgainstPebble drives the whole issuance flow against Pebble,
// the Let's Encrypt project's own ACME test server.
//
// The unit tests in certacme_test.go carry the security invariants, because
// they can force states — no certificate, a stale cache, an unsafe key mode —
// that a live CA will not produce on demand. This test exists for the property
// they cannot show: that the pieces actually interoperate with a real RFC 8555
// implementation performing a real TLS-ALPN-01 validation against a real
// listener.
//
// It never touches Let's Encrypt. Pebble runs locally, issues from a throwaway
// root, and is deliberately not a public CA. It is skipped when the binary is
// absent, so CI without Pebble does not report it as passing.
//
// A real clock is used throughout: the acme package stamps the challenge
// certificate with wall-clock validity, so a fake clock in the guard would
// reject material Pebble considers fine.
func TestACMEEndToEndAgainstPebble(t *testing.T) {
	pebbleBin, err := exec.LookPath("pebble")
	if err != nil {
		if home, hErr := os.UserHomeDir(); hErr == nil {
			candidate := filepath.Join(home, "go", "bin", "pebble")
			if _, sErr := os.Stat(candidate); sErr == nil {
				pebbleBin = candidate
			}
		}
	}
	if pebbleBin == "" {
		t.Skip("pebble not installed; install github.com/letsencrypt/pebble/v2/cmd/pebble to run this test")
	}

	dir := t.TempDir()

	// The listener the CA will validate against must exist first, so its port
	// can be handed to Pebble as the port its validation authority dials.
	challengeLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = challengeLn.Close() }()
	challengePort := challengeLn.Addr().(*net.TCPAddr).Port

	pebbleURL, pebbleRoot := startPebble(t, pebbleBin, dir, challengePort)

	cfg := devConfig()
	cfg.TLS.Mode = "acme"
	// "localhost" resolves to 127.0.0.1, which is where Pebble's validation
	// authority will connect. Production forbids a non-FQDN here; this config
	// is a development one, which is what makes a local CA testable at all.
	cfg.TLS.Domain = "localhost"
	cfg.TLS.SANs = nil
	cfg.TLS.ACME.Solver = "tls_alpn_01"
	cfg.TLS.ACME.DirectoryURL = pebbleURL
	cfg.TLS.ACME.AccountKeyFile = filepath.Join(dir, "account.key")
	cfg.TLS.ACME.CacheDir = filepath.Join(dir, "cache")
	cfg.TLS.ACME.AcceptTOS = true

	if err := os.MkdirAll(cfg.TLS.ACME.CacheDir, acmeCacheDirMode); err != nil {
		t.Fatalf("mkdir cache: %v", err)
	}

	accountKey, err := loadOrCreateKey(cfg.TLS.ACME.AccountKeyFile)
	if err != nil {
		t.Fatalf("account key: %v", err)
	}

	// Pebble's API certificate is issued by a throwaway root, so the client
	// trusts exactly that root and nothing else.
	client := &acme.Client{
		Key:          accountKey,
		DirectoryURL: pebbleURL,
		HTTPClient: &http.Client{
			Transport: &http.Transport{TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
				RootCAs:    pebbleRoot,
			}},
		},
	}

	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()

	p, err := newACMEProviderWithClient(ctx, client, cfg, time.Now)
	if err != nil {
		t.Fatalf("newACMEProviderWithClient: %v", err)
	}
	defer func() { _ = p.Close() }()

	// Quiesce the renewal loop. It starts an order immediately, and this test
	// drives issuance explicitly so it can assert each step; leaving the loop
	// running would race the before-issuance refusal below against a background
	// order, and would place orders this test never asked for against a real
	// CA's rate limits. Close is idempotent, so the deferred one still holds.
	p.stop()
	<-p.done

	// The listener serves through the production path: the guard in front of
	// the provider, and the challenge ALPN advertised only because the provider
	// asked for it.
	guard := newCertGuard(p, time.Now)
	srv := &http.Server{
		Handler:           http.NewServeMux(),
		ReadHeaderTimeout: readHeaderTimeout,
		TLSConfig: &tls.Config{
			MinVersion:     tls.VersionTLS12,
			GetCertificate: guard.GetCertificate,
			NextProtos:     append([]string{"h2", "http/1.1"}, p.challengeALPNProtos()...),
		},
	}
	go func() { _ = srv.ServeTLS(challengeLn, "", "") }()
	defer func() { _ = srv.Close() }()

	// Before issuance the server is up and REFUSES ordinary traffic. This is
	// the fail-closed posture observed end to end rather than in a unit: a live
	// listener that will not serve, instead of one quietly serving self-signed.
	if _, err := guard.GetCertificate(&tls.ClientHelloInfo{
		ServerName:      "localhost",
		SupportedProtos: []string{"h2"},
	}); err == nil {
		t.Fatal("server served a certificate before issuance completed")
	}

	if err := p.obtain(ctx); err != nil {
		t.Fatalf("obtain: %v", err)
	}

	// After issuance the same guard serves a Pebble-issued certificate, and it
	// is a real one: issued by a CA, not the self-signed challenge certificate.
	got, err := guard.GetCertificate(&tls.ClientHelloInfo{
		ServerName:      "localhost",
		SupportedProtos: []string{"h2"},
	})
	if err != nil {
		t.Fatalf("GetCertificate after issuance: %v", err)
	}
	if hasACMEIdentifier(t, got) {
		t.Fatal("ordinary traffic was served the challenge certificate")
	}

	leaf, err := x509.ParseCertificate(got.Certificate[0])
	if err != nil {
		t.Fatalf("parse issued leaf: %v", err)
	}
	if err := leaf.VerifyHostname("localhost"); err != nil {
		t.Errorf("issued certificate does not cover the requested name: %v", err)
	}
	if leaf.Issuer.String() == leaf.Subject.String() {
		t.Error("issued certificate is self-signed; it did not come from the CA")
	}

	// Issuance must have persisted, so a restart reuses it instead of ordering
	// again — the control that keeps a crash loop from becoming a rate-limit
	// lockout.
	if _, err := os.Stat(filepath.Join(cfg.TLS.ACME.CacheDir, acmeCertFile)); err != nil {
		t.Errorf("issued certificate was not cached: %v", err)
	}

	// Renewal without a restart, against real material: a second order on the
	// same running provider replaces the served certificate.
	before := got.Certificate[0]
	if err := p.obtain(ctx); err != nil {
		t.Fatalf("renewal order: %v", err)
	}
	after, err := guard.GetCertificate(&tls.ClientHelloInfo{
		ServerName:      "localhost",
		SupportedProtos: []string{"h2"},
	})
	if err != nil {
		t.Fatalf("GetCertificate after renewal: %v", err)
	}
	if bytesEqual(before, after.Certificate[0]) {
		t.Error("renewal did not replace the served certificate on a running server")
	}
}

// startPebble launches a local Pebble ACME server and returns its directory URL
// and the root that signs its API certificate.
//
// tlsPort is the port Pebble's validation authority dials for TLS-ALPN-01, so
// it is the test listener's port. dnsserver is left unset, which makes Pebble
// use the system resolver — "localhost" resolves to 127.0.0.1, where the test
// listener is bound.
func startPebble(t *testing.T, bin, dir string, tlsPort int) (string, *x509.CertPool) {
	t.Helper()

	apiCert, apiKey, root := pebbleAPICert(t, dir)

	apiPort := freePort(t)
	mgmtPort := freePort(t)

	cfgPath := filepath.Join(dir, "pebble.json")
	cfgData, err := json.Marshal(map[string]any{
		"pebble": map[string]any{
			"listenAddress":           fmt.Sprintf("127.0.0.1:%d", apiPort),
			"managementListenAddress": fmt.Sprintf("127.0.0.1:%d", mgmtPort),
			"certificate":             apiCert,
			"privateKey":              apiKey,
			// httpPort is set to an unused port: HTTP-01 is never used here,
			// and ADR-0015 forbids it outright.
			"httpPort":         freePort(t),
			"tlsPort":          tlsPort,
			"ocspResponderURL": "",
			"strict":           false,
		},
	})
	if err != nil {
		t.Fatalf("marshal pebble config: %v", err)
	}
	if err := os.WriteFile(cfgPath, cfgData, 0o600); err != nil {
		t.Fatalf("write pebble config: %v", err)
	}

	cmd := exec.Command(bin, "-config", cfgPath)
	// PEBBLE_VA_NOSLEEP removes the random validation delay Pebble adds to
	// mimic a real CA, which would otherwise make this test slow for no signal.
	cmd.Env = append(os.Environ(), "PEBBLE_VA_NOSLEEP=1")
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start pebble: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})

	addr := fmt.Sprintf("127.0.0.1:%d", apiPort)
	waitForListener(t, addr)

	return "https://" + addr + "/dir", root
}

// pebbleAPICert generates the certificate Pebble serves its own ACME API on,
// and returns the paths plus a pool containing the signing root.
func pebbleAPICert(t *testing.T, dir string) (certPath, keyPath string, root *x509.CertPool) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate pebble key: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "pebble-test-api"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create pebble cert: %v", err)
	}

	certPath = filepath.Join(dir, "pebble-api.pem")
	keyPath = filepath.Join(dir, "pebble-api.key")

	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatalf("write pebble cert: %v", err)
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal pebble key: %v", err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatalf("write pebble key: %v", err)
	}

	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse pebble cert: %v", err)
	}
	root = x509.NewCertPool()
	root.AddCert(leaf)

	return certPath, keyPath, root
}

// freePort returns a port nothing is listening on. There is an unavoidable race
// between closing the probe listener and the port being reused, which is
// acceptable in a test and is why the ports are drawn immediately before use.
func freePort(t *testing.T) int {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("probe listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	if err := ln.Close(); err != nil {
		t.Fatalf("probe close: %v", err)
	}
	return port
}

// waitForListener blocks until something accepts on addr, so the test does not
// race Pebble's startup.
func waitForListener(t *testing.T, addr string) {
	t.Helper()

	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, time.Second)
		if err == nil {
			_ = conn.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("pebble did not start listening on %s", addr)
}
