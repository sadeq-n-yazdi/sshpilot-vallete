package httpserver

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/config"
)

// devConfig returns a valid development configuration serving a self-signed
// certificate on an ephemeral port.
func devConfig() *config.Config {
	cfg := config.Default()
	cfg.Server.Environment = "development"
	cfg.Server.ListenAddr = "127.0.0.1:0"
	cfg.TLS.Mode = "self_signed"
	cfg.TLS.MinVersion = "1.2"
	return &cfg
}

func TestNewRefusesSelfSignedInProduction(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		environment string
		allow       bool
		wantErr     error
	}{
		{name: "development allows self-signed", environment: "development", allow: false},
		{name: "production refuses by default", environment: "production", allow: false, wantErr: ErrSelfSignedInProduction},
		{name: "production allows with explicit override", environment: "production", allow: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			cfg := devConfig()
			cfg.Server.Environment = tc.environment
			cfg.TLS.AllowSelfSignedInProduction = tc.allow

			srv, err := New(cfg, nil, okPinger{}, stubPublisher{})
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("err = %v, want %v", err, tc.wantErr)
				}
				if srv != nil {
					t.Error("a refused configuration must not yield a server")
				}
				if !strings.Contains(err.Error(), "allow_self_signed_in_production") {
					t.Errorf("error should name the override knob: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			assertServesCertificate(t, srv)
		})
	}
}

func TestNewTLSConfigHardening(t *testing.T) {
	t.Parallel()

	srv, err := New(devConfig(), nil, okPinger{}, stubPublisher{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	tlsCfg := srv.TLSConfig()
	if tlsCfg.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion = %#x, want TLS 1.2 (%#x)", tlsCfg.MinVersion, tls.VersionTLS12)
	}
	if srv.Addr() != "127.0.0.1:0" {
		t.Errorf("Addr = %q, want the configured listen address", srv.Addr())
	}
	if srv.Handler() == nil {
		t.Error("Handler is nil")
	}

	// Timeouts: every one of these must be set, or a slow peer can hold a
	// connection open indefinitely (ReadHeaderTimeout guards Slowloris).
	s := srv.httpSrv
	for _, tc := range []struct {
		name string
		got  time.Duration
	}{
		{"ReadHeaderTimeout", s.ReadHeaderTimeout},
		{"ReadTimeout", s.ReadTimeout},
		{"WriteTimeout", s.WriteTimeout},
		{"IdleTimeout", s.IdleTimeout},
	} {
		if tc.got <= 0 {
			t.Errorf("%s = %v, want a positive bound", tc.name, tc.got)
		}
	}
	if s.MaxHeaderBytes <= 0 || s.MaxHeaderBytes > 1<<20 {
		t.Errorf("MaxHeaderBytes = %d, want a positive value at or below the 1 MiB default", s.MaxHeaderBytes)
	}
}

func TestParseMinVersion(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		in      string
		want    uint16
		wantErr bool
	}{
		{name: "empty defaults to 1.2", in: "", want: tls.VersionTLS12},
		{name: "1.2", in: "1.2", want: tls.VersionTLS12},
		{name: "1.3", in: "1.3", want: tls.VersionTLS13},
		{name: "1.0 refused", in: "1.0", wantErr: true},
		{name: "1.1 refused", in: "1.1", wantErr: true},
		{name: "garbage refused", in: "tls1.2", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := parseMinVersion(tc.in)
			if tc.wantErr {
				if !errors.Is(err, ErrTLSMinVersion) {
					t.Fatalf("err = %v, want ErrTLSMinVersion", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseMinVersion(%q): %v", tc.in, err)
			}
			if got != tc.want {
				t.Errorf("got %#x, want %#x", got, tc.want)
			}
		})
	}
}

func TestNewRejectsBadTLSConfiguration(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		mutate  func(*config.Config)
		wantErr error
	}{
		{
			name:    "downgraded min version",
			mutate:  func(c *config.Config) { c.TLS.MinVersion = "1.1" },
			wantErr: ErrTLSMinVersion,
		},
		{
			name:    "acme is a later track",
			mutate:  func(c *config.Config) { c.TLS.Mode = "acme" },
			wantErr: ErrTLSModeUnsupported,
		},
		{
			name:    "upstream plaintext termination unsupported",
			mutate:  func(c *config.Config) { c.TLS.Mode = "upstream" },
			wantErr: ErrTLSModeUnsupported,
		},
		{
			name:    "empty mode",
			mutate:  func(c *config.Config) { c.TLS.Mode = "" },
			wantErr: ErrTLSModeUnsupported,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			cfg := devConfig()
			tc.mutate(cfg)
			if _, err := New(cfg, nil, okPinger{}, stubPublisher{}); !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestManualTLSMode(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	certFile := filepath.Join(dir, "cert.pem")
	keyFile := filepath.Join(dir, "key.pem")
	writeKeyPair(t, certFile, keyFile)

	cfg := devConfig()
	cfg.TLS.Mode = "manual"
	cfg.TLS.Manual.CertFile = certFile
	cfg.TLS.Manual.KeyFile = keyFile

	srv, err := New(cfg, nil, okPinger{}, stubPublisher{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	assertServesCertificate(t, srv)

	cfg.TLS.Manual.CertFile = filepath.Join(dir, "missing.pem")
	if _, err := New(cfg, nil, okPinger{}, stubPublisher{}); err == nil {
		t.Fatal("a missing certificate file must fail startup")
	}
}

func TestSelfSignedCertificateContents(t *testing.T) {
	t.Parallel()

	now := time.Now()
	cert, err := newSelfSignedCert([]string{"vallet.example.com", "127.0.0.1"}, now)
	if err != nil {
		t.Fatalf("newSelfSignedCert: %v", err)
	}

	leaf := cert.Leaf
	if leaf == nil {
		t.Fatal("Leaf is nil; the handshake would have to re-parse the DER")
	}
	if got := leaf.NotAfter.Sub(now); got > selfSignedValidity+time.Minute {
		t.Errorf("validity %v exceeds the %v cap", got, selfSignedValidity)
	}
	if !leaf.NotBefore.Before(now) {
		t.Error("NotBefore should allow for a little clock skew")
	}
	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != "vallet.example.com" {
		t.Errorf("DNSNames = %v, want the configured domain", leaf.DNSNames)
	}
	if len(leaf.IPAddresses) != 1 || !leaf.IPAddresses[0].Equal(net.ParseIP("127.0.0.1")) {
		t.Errorf("IPAddresses = %v, want 127.0.0.1", leaf.IPAddresses)
	}
	if err := leaf.VerifyHostname("vallet.example.com"); err != nil {
		t.Errorf("certificate does not cover its own domain: %v", err)
	}
	// A serving certificate must not also be a CA: if a developer trusts this
	// cert, it must not gain the power to vouch for other names.
	if leaf.IsCA {
		t.Error("development certificate is marked as a CA")
	}
	if leaf.KeyUsage&x509.KeyUsageCertSign != 0 {
		t.Error("development certificate carries the certificate-signing usage")
	}
}

func TestCertHostsDefaultsToLoopback(t *testing.T) {
	t.Parallel()

	cfg := devConfig()
	if got := certHosts(cfg); len(got) == 0 || got[0] != "localhost" {
		t.Errorf("certHosts = %v, want a loopback default", got)
	}

	cfg.TLS.Domain = "vallet.test"
	cfg.TLS.SANs = []string{"alt.vallet.test"}
	got := certHosts(cfg)
	if strings.Join(got, ",") != "vallet.test,alt.vallet.test" {
		t.Errorf("certHosts = %v, want the domain followed by its SANs", got)
	}
}

// TestServeIsHTTPSOnly starts a real listener and proves that (a) TLS works and
// (b) a plaintext request is never answered with application data, then shuts
// the server down cleanly. It is deterministic: the listener is bound before
// any request, and shutdown is awaited rather than slept on.
func TestServeIsHTTPSOnlyAndShutsDownGracefully(t *testing.T) {
	t.Parallel()

	srv, err := New(devConfig(), nil, okPinger{}, stubPublisher{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()

	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(ln) }()

	client := &http.Client{Transport: &http.Transport{
		// The development certificate is self-signed by design; this test
		// asserts the transport is encrypted, not that the chain is trusted.
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // self-signed dev cert under test.
	}}

	resp, err := client.Get("https://" + addr + "/healthz")
	if err != nil {
		t.Fatalf("https request: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("https /healthz = %d, want 200", resp.StatusCode)
	}
	if !strings.Contains(string(body), `"status":"ok"`) {
		t.Errorf("unexpected body: %q", body)
	}
	if resp.TLS == nil {
		t.Fatal("connection was not TLS")
	}
	if resp.TLS.Version < tls.VersionTLS12 {
		t.Errorf("negotiated TLS version %#x is below the 1.2 floor", resp.TLS.Version)
	}
	if resp.Header.Get(RequestIDHeader) == "" {
		t.Error("response is missing the request ID header")
	}

	// Plaintext must never yield application data. Go's TLS server answers a
	// plaintext request with a 400 and closes; what matters is that no 200 and
	// no health payload is ever produced over an unencrypted connection.
	plain := &http.Client{Timeout: 5 * time.Second}
	plainResp, err := plain.Get("http://" + addr + "/healthz") //nolint:bodyclose // closed below when non-nil.
	if err == nil {
		plainBody, _ := io.ReadAll(plainResp.Body)
		_ = plainResp.Body.Close()
		if plainResp.StatusCode == http.StatusOK {
			t.Errorf("plaintext request was served: %d %q", plainResp.StatusCode, plainBody)
		}
		if strings.Contains(string(plainBody), `"status":"ok"`) {
			t.Errorf("health payload leaked over plaintext: %q", plainBody)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}

	// A clean shutdown is not an error: Serve must return nil, not
	// http.ErrServerClosed.
	select {
	case err := <-serveErr:
		if err != nil {
			t.Errorf("Serve returned %v, want nil after a clean shutdown", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Serve did not return after Shutdown")
	}

	// The socket must be released, so a restart can rebind immediately.
	if _, err := client.Get("https://" + addr + "/healthz"); err == nil {
		t.Error("server still answers after shutdown")
	}
}

func TestListenAndServeRejectsABadAddress(t *testing.T) {
	t.Parallel()

	cfg := devConfig()
	cfg.Server.ListenAddr = "127.0.0.1:not-a-port"
	srv, err := New(cfg, nil, okPinger{}, stubPublisher{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := srv.ListenAndServe(); err == nil {
		t.Fatal("ListenAndServe accepted an unbindable address")
	}
}

// writeKeyPair writes a PEM certificate/key pair for the manual-mode test.
func writeKeyPair(t *testing.T, certFile, keyFile string) {
	t.Helper()

	cert, err := newSelfSignedCert([]string{"localhost"}, time.Now())
	if err != nil {
		t.Fatalf("newSelfSignedCert: %v", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(certFile, certPEM, 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
}

// assertServesCertificate proves the server can actually produce a certificate
// for a handshake.
//
// E2 moved the certificate from tls.Config.Certificates to the GetCertificate
// callback so that material can be renewed and re-validated per handshake, and
// Certificates is deliberately left nil so nothing bypasses the validating
// guard. Asserting through the callback is therefore both the only way to see
// the certificate and a stronger check than the old field inspection: it
// exercises the real code path a client triggers.
func assertServesCertificate(t *testing.T, srv *Server) {
	t.Helper()

	tlsCfg := srv.TLSConfig()
	if len(tlsCfg.Certificates) != 0 {
		t.Error("Certificates must stay nil so no certificate bypasses the guard")
	}
	if tlsCfg.GetCertificate == nil {
		t.Fatal("server has no certificate callback")
	}
	cert, err := tlsCfg.GetCertificate(nil)
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	if cert == nil || len(cert.Certificate) == 0 {
		t.Error("server produced no certificate")
	}
}
