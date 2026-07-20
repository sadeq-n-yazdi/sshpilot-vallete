package httpserver

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// --- helpers ---------------------------------------------------------------

// writeCertPair writes a PEM cert/key pair with an explicit validity window, so
// expiry cases are constructed directly rather than by waiting.
//
// It uses ECDSA P-256 rather than the Ed25519 helper in server_test.go because
// these tests negotiate TLS 1.2 explicitly, and an ECDSA leaf exercises the
// ECDHE_ECDSA suites in the allowlist on every Go version without depending on
// Ed25519's TLS 1.2 signature-algorithm support.
func writeCertPair(t *testing.T, dir string, notBefore, notAfter time.Time) (certFile, keyFile string) {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	certFile, keyFile = writeCertForKey(t, dir, priv, notBefore, notAfter)
	return certFile, keyFile
}

// writeCertForKey writes a certificate for the given key plus that key's PEM.
// Splitting this out lets the mismatch test write a certificate for one key and
// the private key of another.
func writeCertForKey(
	t *testing.T, dir string, priv *ecdsa.PrivateKey, notBefore, notAfter time.Time,
) (certFile, keyFile string) {
	t.Helper()

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{Organization: []string{"vallet test"}},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}

	certFile = filepath.Join(dir, "cert.pem")
	keyFile = filepath.Join(dir, "key.pem")
	writeFile(t, certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	writeFile(t, keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	return certFile, keyFile
}

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	// 0600: ADR-0015 §3 requires cert/key files to be operator-readable only.
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// serveTLS starts a TLS listener with the server's real config and returns its
// address. Tests dial it with a real client so assertions describe what was
// actually negotiated, not what a struct field says.
func serveTLS(t *testing.T, tlsCfg *tls.Config) string {
	t.Helper()

	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				// Drive the handshake so the client's error (or success) is the
				// server's policy decision and not an accept-loop artifact.
				_ = conn.(*tls.Conn).Handshake()
			}()
		}
	}()
	return ln.Addr().String()
}

// serverTLSConfig builds the production TLS config for a manual-mode server
// backed by a freshly generated, currently-valid certificate.
func serverTLSConfig(t *testing.T) *tls.Config {
	t.Helper()

	now := time.Now()
	certFile, keyFile := writeCertPair(t, t.TempDir(), now.Add(-time.Hour), now.Add(24*time.Hour))

	cfg := devConfig()
	cfg.TLS.Mode = "manual"
	cfg.TLS.Manual.CertFile = certFile
	cfg.TLS.Manual.KeyFile = keyFile

	tlsCfg, err := buildTLSConfig(cfg, now)
	if err != nil {
		t.Fatalf("buildTLSConfig: %v", err)
	}
	return tlsCfg
}

// --- negotiated-policy tests (real handshakes) -----------------------------

// TestNegotiatedTLSPolicy proves the policy through actual handshakes against a
// real listener. Asserting on the tls.Config fields would prove only that the
// struct was populated; these cases prove what the TLS stack agrees to.
func TestNegotiatedTLSPolicy(t *testing.T) {
	t.Parallel()

	addr := serveTLS(t, serverTLSConfig(t))

	tests := []struct {
		name      string
		client    *tls.Config
		wantErr   bool
		checkConn func(*testing.T, tls.ConnectionState)
	}{
		{
			name:   "modern client negotiates TLS 1.3",
			client: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}, //nolint:gosec // test cert is self-signed by design.
			checkConn: func(t *testing.T, st tls.ConnectionState) {
				if st.Version != tls.VersionTLS13 {
					t.Errorf("version = %#x, want TLS 1.3 (%#x)", st.Version, tls.VersionTLS13)
				}
			},
		},
		{
			// The post-quantum hybrid must survive: this is the assertion that
			// would fail if someone "hardened" the config by pinning
			// CurvePreferences to a classical-only list.
			name:   "post-quantum hybrid key exchange is preserved",
			client: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13}, //nolint:gosec // test cert is self-signed by design.
			checkConn: func(t *testing.T, st tls.ConnectionState) {
				if st.CurveID != tls.X25519MLKEM768 {
					t.Errorf("curve = %v, want X25519MLKEM768; pinning CurvePreferences removes the PQ hybrid", st.CurveID)
				}
			},
		},
		{
			name: "TLS 1.2 client negotiates only an AEAD ECDHE suite",
			client: &tls.Config{ //nolint:gosec // test cert is self-signed by design.
				InsecureSkipVerify: true,
				MinVersion:         tls.VersionTLS12,
				MaxVersion:         tls.VersionTLS12,
			},
			checkConn: func(t *testing.T, st tls.ConnectionState) {
				if st.Version != tls.VersionTLS12 {
					t.Fatalf("version = %#x, want TLS 1.2", st.Version)
				}
				assertAllowlistedSuite(t, st.CipherSuite)
			},
		},
		{
			// The floor. A 1.1-only client must be turned away rather than
			// served over a deprecated protocol.
			//
			// Mutation testing showed this case survives lowering MinVersion to
			// TLS 1.0 on its own. That is not a gap in the assertion but a
			// property of the policy: TLS 1.0/1.1 define no AEAD suites, so the
			// cipher allowlist independently refuses them. The two controls are
			// each sufficient, and removing BOTH does fail this case. The
			// MinVersion field itself is additionally asserted in
			// TestTLSConfigLeavesCurvePreferencesUnset.
			name: "TLS 1.1 client is rejected",
			client: &tls.Config{ //nolint:gosec // test cert is self-signed by design.
				InsecureSkipVerify: true,
				MinVersion:         tls.VersionTLS11,
				MaxVersion:         tls.VersionTLS11,
			},
			wantErr: true,
		},
		{
			name: "TLS 1.0 client is rejected",
			client: &tls.Config{ //nolint:gosec // test cert is self-signed by design.
				InsecureSkipVerify: true,
				MinVersion:         tls.VersionTLS10,
				MaxVersion:         tls.VersionTLS10,
			},
			wantErr: true,
		},
		{
			// MaxVersion is pinned to 1.2 deliberately. A TLS 1.3 client ignores
			// CipherSuites entirely, so without this pin a CBC-only client would
			// negotiate a 1.3 AEAD suite and the test would pass while proving
			// nothing about the allowlist.
			name: "CBC-only TLS 1.2 client is rejected",
			client: &tls.Config{ //nolint:gosec // test cert is self-signed by design.
				InsecureSkipVerify: true,
				MinVersion:         tls.VersionTLS12,
				MaxVersion:         tls.VersionTLS12,
				CipherSuites: []uint16{
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
					tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				},
			},
			wantErr: true,
		},
		{
			// Static-RSA AES-GCM is AEAD but has no forward secrecy, so it is
			// excluded on purpose. This case proves the exclusion is real.
			name: "non-forward-secret static RSA client is rejected",
			client: &tls.Config{ //nolint:gosec // test cert is self-signed by design.
				InsecureSkipVerify: true,
				MinVersion:         tls.VersionTLS12,
				MaxVersion:         tls.VersionTLS12,
				CipherSuites: []uint16{
					tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
				},
			},
			wantErr: true,
		},
		{
			name: "3DES client is rejected",
			client: &tls.Config{ //nolint:gosec // test cert is self-signed by design.
				InsecureSkipVerify: true,
				MinVersion:         tls.VersionTLS12,
				MaxVersion:         tls.VersionTLS12,
				CipherSuites:       []uint16{tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA},
			},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			conn, err := tls.Dial("tcp", addr, tc.client)
			if tc.wantErr {
				if err == nil {
					_ = conn.Close()
					t.Fatal("handshake succeeded; the server must refuse this client")
				}
				return
			}
			if err != nil {
				t.Fatalf("handshake: %v", err)
			}
			defer func() { _ = conn.Close() }()
			tc.checkConn(t, conn.ConnectionState())
		})
	}
}

// assertAllowlistedSuite fails unless the negotiated TLS 1.2 suite is in the
// allowlist and is both AEAD and forward-secret.
func assertAllowlistedSuite(t *testing.T, got uint16) {
	t.Helper()

	name := tls.CipherSuiteName(got)
	var allowed bool
	for _, s := range tls12CipherSuites() {
		if s == got {
			allowed = true
			break
		}
	}
	if !allowed {
		t.Errorf("negotiated %s, which is not in the allowlist", name)
	}
	// Independent of the allowlist: the two properties themselves. If someone
	// adds a bad suite to tls12CipherSuites, the membership check above would
	// still pass — these do not.
	if !strings.Contains(name, "ECDHE") {
		t.Errorf("negotiated %s, which lacks forward secrecy", name)
	}
	if !strings.Contains(name, "GCM") && !strings.Contains(name, "CHACHA20_POLY1305") {
		t.Errorf("negotiated %s, which is not an AEAD suite", name)
	}
}

// TestCipherSuiteAllowlistContents checks the allowlist itself against Go's
// cipher-suite metadata, so a suite that Go later classifies as insecure, or a
// hand-edited addition, is caught without needing a client that speaks it.
func TestCipherSuiteAllowlistContents(t *testing.T) {
	t.Parallel()

	secure := make(map[uint16]string, len(tls.CipherSuites()))
	for _, s := range tls.CipherSuites() {
		secure[s.ID] = s.Name
	}
	insecure := make(map[uint16]string, len(tls.InsecureCipherSuites()))
	for _, s := range tls.InsecureCipherSuites() {
		insecure[s.ID] = s.Name
	}

	got := tls12CipherSuites()
	if len(got) == 0 {
		t.Fatal("allowlist is empty; the server would fall back to Go's defaults")
	}

	seen := make(map[uint16]bool, len(got))
	for _, id := range got {
		if seen[id] {
			t.Errorf("duplicate suite %s", tls.CipherSuiteName(id))
		}
		seen[id] = true

		if name, bad := insecure[id]; bad {
			t.Errorf("%s is in Go's insecure list and must not be allowlisted", name)
		}
		name, ok := secure[id]
		if !ok {
			t.Errorf("suite %#x is not among Go's secure cipher suites", id)
			continue
		}
		if !strings.Contains(name, "ECDHE") {
			t.Errorf("%s lacks forward secrecy", name)
		}
		if !strings.Contains(name, "GCM") && !strings.Contains(name, "CHACHA20_POLY1305") {
			t.Errorf("%s is not an AEAD suite", name)
		}
	}
}

// TestTLSConfigLeavesCurvePreferencesUnset guards the decision recorded in
// buildTLSConfig: pinning a curve list removes X25519MLKEM768. The negotiated
// handshake above is the primary proof; this states the intent at the source so
// a future edit trips a test that explains why.
func TestTLSConfigLeavesCurvePreferencesUnset(t *testing.T) {
	t.Parallel()

	tlsCfg := serverTLSConfig(t)
	if tlsCfg.CurvePreferences != nil {
		t.Errorf("CurvePreferences = %v, want nil: pinning a list drops the X25519MLKEM768 post-quantum hybrid",
			tlsCfg.CurvePreferences)
	}
	if tlsCfg.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion = %#x, want TLS 1.2", tlsCfg.MinVersion)
	}
}
