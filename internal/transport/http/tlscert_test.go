package httpserver

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// manualCertificate loads operator-supplied files and validates the result at a
// fixed instant, returning a usable certificate only if it passes.
//
// E2 split what used to be one function into a provider (file loading) and the
// guard (validation), because validation now also runs on every handshake rather
// than only at startup. This helper recomposes the two so the fail-closed cases
// below keep testing the behavior an operator actually experiences — load then
// validate — through the real production code path.
//
// It returns a ZERO certificate on error, which is what lets the tests assert
// that no usable material escapes alongside a failure.
func manualCertificate(certFile, keyFile string, now time.Time) (tls.Certificate, error) {
	provider, err := newManualProvider(certFile, keyFile)
	if err != nil {
		return tls.Certificate{}, err
	}
	cert, err := newCertGuard(provider, staticClock(now)).GetCertificate(nil)
	if err != nil {
		return tls.Certificate{}, err
	}
	return *cert, nil
}

// staticClock freezes time, so a validity window can be probed at a chosen
// instant instead of whenever the test happens to run.
func staticClock(now time.Time) func() time.Time {
	return func() time.Time { return now }
}

// --- fail-closed tests -----------------------------------------------------

// TestManualCertificateFailsClosed covers every way operator-supplied material
// can be unusable. Each case must prevent startup; none may degrade to
// plaintext or to a different certificate.
func TestManualCertificateFailsClosed(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.July, 19, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name    string
		setup   func(t *testing.T, dir string) (certFile, keyFile string)
		wantErr error
		wantMsg string
	}{
		{
			name: "valid certificate loads",
			setup: func(t *testing.T, dir string) (string, string) {
				return writeCertPair(t, dir, now.Add(-time.Hour), now.Add(time.Hour))
			},
		},
		{
			name: "expired certificate is refused",
			setup: func(t *testing.T, dir string) (string, string) {
				return writeCertPair(t, dir, now.Add(-48*time.Hour), now.Add(-time.Hour))
			},
			wantErr: ErrTLSCertificateExpired,
			wantMsg: "expired at",
		},
		{
			name: "not-yet-valid certificate is refused",
			setup: func(t *testing.T, dir string) (string, string) {
				return writeCertPair(t, dir, now.Add(time.Hour), now.Add(48*time.Hour))
			},
			wantErr: ErrTLSCertificateExpired,
			wantMsg: "not valid before",
		},
		{
			// Boundary: NotAfter exactly equals now. The check is now.After(),
			// so the certificate is still valid at its final instant.
			name: "certificate valid at the exact expiry instant",
			setup: func(t *testing.T, dir string) (string, string) {
				return writeCertPair(t, dir, now.Add(-time.Hour), now)
			},
		},
		{
			name: "missing certificate file is refused",
			setup: func(t *testing.T, dir string) (string, string) {
				_, keyFile := writeCertPair(t, dir, now.Add(-time.Hour), now.Add(time.Hour))
				return filepath.Join(dir, "absent.pem"), keyFile
			},
			wantErr: ErrTLSCertificateInvalid,
		},
		{
			name: "missing key file is refused",
			setup: func(t *testing.T, dir string) (string, string) {
				certFile, _ := writeCertPair(t, dir, now.Add(-time.Hour), now.Add(time.Hour))
				return certFile, filepath.Join(dir, "absent.pem")
			},
			wantErr: ErrTLSCertificateInvalid,
		},
		{
			name: "unreadable certificate file is refused",
			setup: func(t *testing.T, dir string) (string, string) {
				certFile, keyFile := writeCertPair(t, dir, now.Add(-time.Hour), now.Add(time.Hour))
				if err := os.Chmod(certFile, 0o000); err != nil {
					t.Fatalf("chmod: %v", err)
				}
				return certFile, keyFile
			},
			wantErr: ErrTLSCertificateInvalid,
		},
		{
			name: "malformed certificate PEM is refused",
			setup: func(t *testing.T, dir string) (string, string) {
				certFile, keyFile := writeCertPair(t, dir, now.Add(-time.Hour), now.Add(time.Hour))
				writeFile(t, certFile, []byte("-----BEGIN CERTIFICATE-----\nnot base64\n-----END CERTIFICATE-----\n"))
				return certFile, keyFile
			},
			wantErr: ErrTLSCertificateInvalid,
		},
		{
			name: "empty certificate file is refused",
			setup: func(t *testing.T, dir string) (string, string) {
				certFile, keyFile := writeCertPair(t, dir, now.Add(-time.Hour), now.Add(time.Hour))
				writeFile(t, certFile, nil)
				return certFile, keyFile
			},
			wantErr: ErrTLSCertificateInvalid,
		},
		{
			name: "malformed key PEM is refused",
			setup: func(t *testing.T, dir string) (string, string) {
				certFile, keyFile := writeCertPair(t, dir, now.Add(-time.Hour), now.Add(time.Hour))
				writeFile(t, keyFile, []byte("-----BEGIN PRIVATE KEY-----\ngarbage\n-----END PRIVATE KEY-----\n"))
				return certFile, keyFile
			},
			wantErr: ErrTLSCertificateInvalid,
		},
		{
			name: "key that does not match the certificate is refused",
			setup: func(t *testing.T, dir string) (string, string) {
				certFile, _ := writeCertPair(t, dir, now.Add(-time.Hour), now.Add(time.Hour))
				other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				if err != nil {
					t.Fatalf("generate key: %v", err)
				}
				keyDER, err := x509.MarshalPKCS8PrivateKey(other)
				if err != nil {
					t.Fatalf("marshal key: %v", err)
				}
				keyFile := filepath.Join(dir, "other-key.pem")
				writeFile(t, keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
				return certFile, keyFile
			},
			wantErr: ErrTLSCertificateInvalid,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			certFile, keyFile := tc.setup(t, t.TempDir())
			cert, err := manualCertificate(certFile, keyFile, now)

			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("manualCertificate: %v", err)
				}
				if len(cert.Certificate) == 0 || cert.Leaf == nil {
					t.Error("loaded certificate is incomplete")
				}
				return
			}

			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
			if tc.wantMsg != "" && !strings.Contains(err.Error(), tc.wantMsg) {
				t.Errorf("error %q should explain the defect (%q)", err, tc.wantMsg)
			}
			// Fail closed: no usable certificate may escape alongside an error.
			if len(cert.Certificate) != 0 {
				t.Error("a refused certificate must not be returned")
			}
			// The error is built from paths and timestamps only; nothing from
			// inside the key file may appear in it.
			assertNoKeyMaterial(t, err.Error(), keyFile)
		})
	}
}

// assertNoKeyMaterial fails if an error message quotes bytes from the key file.
// A private key must never reach a log, and errors are logged.
func assertNoKeyMaterial(t *testing.T, msg, keyFile string) {
	t.Helper()

	raw, err := os.ReadFile(keyFile) //nolint:gosec // test-owned temp path.
	if err != nil {
		return // Cases that never wrote a readable key have nothing to leak.
	}
	block, _ := pem.Decode(raw)
	if block == nil || len(block.Bytes) < 16 {
		return
	}
	// Look for a distinctive run of the DER body rather than the whole blob, so
	// the check survives line wrapping or partial quoting.
	needle := string(block.Bytes[8:24])
	if strings.Contains(msg, needle) {
		t.Errorf("error message contains private key material: %q", msg)
	}
	if strings.Contains(msg, "BEGIN PRIVATE KEY") {
		t.Errorf("error message contains a PEM key block: %q", msg)
	}
}

// TestNewRefusesExpiredCertificate proves the fail-closed path reaches all the
// way to server construction: an expired certificate stops New, so no listener
// is ever bound. manualCertificate is tested directly above; this asserts it is
// actually wired into the startup path rather than merely present.
func TestNewRefusesExpiredCertificate(t *testing.T) {
	t.Parallel()

	now := time.Now()
	dir := t.TempDir()
	certFile, keyFile := writeCertPair(t, dir, now.Add(-72*time.Hour), now.Add(-time.Hour))

	cfg := devConfig()
	cfg.TLS.Mode = "manual"
	cfg.TLS.Manual.CertFile = certFile
	cfg.TLS.Manual.KeyFile = keyFile

	srv, err := New(cfg, nil, okPinger{}, stubPublisher{})
	if !errors.Is(err, ErrTLSCertificateExpired) {
		t.Fatalf("err = %v, want ErrTLSCertificateExpired", err)
	}
	if srv != nil {
		t.Error("an expired certificate must not yield a server")
	}
}

// TestBuildTLSConfigUsesInjectedClock confirms the validity check honors the
// clock it is given. The same files are accepted at one instant and refused at
// another, which is what makes the expiry behavior testable at all.
func TestBuildTLSConfigUsesInjectedClock(t *testing.T) {
	t.Parallel()

	base := time.Date(2026, time.July, 19, 12, 0, 0, 0, time.UTC)
	certFile, keyFile := writeCertPair(t, t.TempDir(), base, base.Add(time.Hour))

	cfg := devConfig()
	cfg.TLS.Mode = "manual"
	cfg.TLS.Manual.CertFile = certFile
	cfg.TLS.Manual.KeyFile = keyFile

	if _, err := buildTLSConfig(cfg, staticClock(base.Add(30*time.Minute))); err != nil {
		t.Fatalf("inside the validity window: %v", err)
	}
	if _, err := buildTLSConfig(cfg, staticClock(base.Add(2*time.Hour))); !errors.Is(err, ErrTLSCertificateExpired) {
		t.Fatalf("after expiry: err = %v, want ErrTLSCertificateExpired", err)
	}
	if _, err := buildTLSConfig(cfg, staticClock(base.Add(-time.Minute))); !errors.Is(err, ErrTLSCertificateExpired) {
		t.Fatalf("before validity: err = %v, want ErrTLSCertificateExpired", err)
	}
}

// TestManualCertificateReparsesNilLeaf covers the defensive re-parse. With
// GODEBUG x509keypairleaf=0 the standard library leaves Leaf nil, which would
// turn the expiry check into a no-op if it were not handled.
func TestManualCertificateReparsesNilLeaf(t *testing.T) {
	t.Setenv("GODEBUG", "x509keypairleaf=0")

	now := time.Date(2026, time.July, 19, 12, 0, 0, 0, time.UTC)
	dir := t.TempDir()

	certFile, keyFile := writeCertPair(t, dir, now.Add(-48*time.Hour), now.Add(-time.Hour))
	if _, err := manualCertificate(certFile, keyFile, now); !errors.Is(err, ErrTLSCertificateExpired) {
		t.Fatalf("err = %v, want ErrTLSCertificateExpired even when Leaf is nil", err)
	}

	certFile2, keyFile2 := writeCertPair(t, t.TempDir(), now.Add(-time.Hour), now.Add(time.Hour))
	cert, err := manualCertificate(certFile2, keyFile2, now)
	if err != nil {
		t.Fatalf("valid pair: %v", err)
	}
	if cert.Leaf == nil {
		t.Error("Leaf must be populated after the defensive re-parse")
	}
}

// TestUnsupportedModesFailClosed re-states, at the certificate layer, that a
// configured-but-unimplemented mode never falls back to a weaker certificate.
func TestUnsupportedModesFailClosed(t *testing.T) {
	t.Parallel()

	// csr is deliberately absent: it is implemented now and has its own tests.
	for _, mode := range []string{"acme", "cloudflare_origin", "upstream", "", "nonsense"} {
		t.Run("mode="+mode, func(t *testing.T) {
			t.Parallel()

			cfg := devConfig()
			cfg.TLS.Mode = mode
			tlsCfg, err := buildTLSConfig(cfg, time.Now)
			if !errors.Is(err, ErrTLSModeUnsupported) {
				t.Fatalf("err = %v, want ErrTLSModeUnsupported", err)
			}
			if tlsCfg != nil {
				t.Error("an unsupported mode must not yield a TLS config")
			}
		})
	}
}

// TestManualCertificateChainIsPreserved checks that an intermediate following
// the leaf survives loading. Validity is judged on the leaf alone, but the chain
// must still be served or clients cannot build a path to the root.
func TestManualCertificateChainIsPreserved(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.July, 19, 12, 0, 0, 0, time.UTC)
	dir := t.TempDir()
	certFile, keyFile := writeCertPair(t, dir, now.Add(-time.Hour), now.Add(time.Hour))

	// Append an unrelated self-signed certificate standing in for an
	// intermediate. Its own dates are deliberately expired to confirm that only
	// the leaf's window is enforced.
	extraDir := t.TempDir()
	extraCert, _ := writeCertPair(t, extraDir, now.Add(-72*time.Hour), now.Add(-time.Hour))
	leafPEM, err := os.ReadFile(certFile) //nolint:gosec // test-owned temp path.
	if err != nil {
		t.Fatalf("read leaf: %v", err)
	}
	extraPEM, err := os.ReadFile(extraCert) //nolint:gosec // test-owned temp path.
	if err != nil {
		t.Fatalf("read intermediate: %v", err)
	}
	writeFile(t, certFile, append(leafPEM, extraPEM...))

	cert, err := manualCertificate(certFile, keyFile, now)
	if err != nil {
		t.Fatalf("manualCertificate: %v", err)
	}
	if len(cert.Certificate) != 2 {
		t.Errorf("chain length = %d, want 2 (leaf plus intermediate)", len(cert.Certificate))
	}
}
