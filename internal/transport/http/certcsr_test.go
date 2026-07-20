package httpserver

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io/fs"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/config"
)

// csrConfig builds a csr-mode config pointing at a fresh temp directory.
func csrConfig(t *testing.T) *config.Config {
	t.Helper()

	dir := t.TempDir()
	cfg := devConfig()
	cfg.TLS.Mode = "csr"
	cfg.TLS.Domain = "vallet.example.com"
	cfg.TLS.CSR.KeyFile = filepath.Join(dir, "vallet.key")
	cfg.TLS.CSR.CSRFile = filepath.Join(dir, "vallet.csr")
	cfg.TLS.CSR.CertFile = filepath.Join(dir, "vallet.crt")
	return cfg
}

// signCSR acts as the external CA the operator would visit: it reads the emitted
// CSR and issues a certificate for it, which is exactly the round trip this mode
// exists to support.
func signCSR(t *testing.T, cfg *config.Config, notBefore, notAfter time.Time) []byte {
	t.Helper()

	raw, err := os.ReadFile(cfg.TLS.CSR.CSRFile) //nolint:gosec // test-owned temp path.
	if err != nil {
		t.Fatalf("read csr: %v", err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		t.Fatal("csr file contains no PEM block")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatalf("parse csr: %v", err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Fatalf("csr signature: %v", err)
	}

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ca key: %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test ca"},
		NotBefore:             notBefore.Add(-time.Hour),
		NotAfter:              notAfter.Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create ca: %v", err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse ca: %v", err)
	}

	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      csr.Subject,
		DNSNames:     csr.DNSNames,
		IPAddresses:  csr.IPAddresses,
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, ca, csr.PublicKey, caKey)
	if err != nil {
		t.Fatalf("sign leaf: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
}

// TestCSRKeyFileMode is the explicit permission assertion. A private key
// readable by any other account on the host is compromised no matter how
// carefully this process handles it in memory.
func TestCSRKeyFileMode(t *testing.T) {
	t.Parallel()

	cfg := csrConfig(t)

	// The first run cannot succeed (nothing has signed the CSR yet), but it
	// must still have produced the key — that is the point of the run.
	if _, err := newCSRProvider(cfg); !errors.Is(err, ErrTLSCSRPending) {
		t.Fatalf("err = %v, want ErrTLSCSRPending on a first run", err)
	}

	info, err := os.Stat(cfg.TLS.CSR.KeyFile)
	if err != nil {
		t.Fatalf("stat key: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("key file mode = %#o, want %#o", got, 0o600)
	}

	// Nothing group- or world-accessible may be left in the directory either:
	// a temporary file that still held the key would defeat the mode on the
	// final file entirely.
	entries, err := os.ReadDir(filepath.Dir(cfg.TLS.CSR.KeyFile))
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".vallet-tmp-") {
			t.Errorf("temporary file %s was left behind", e.Name())
		}
	}
}

// TestCSRWriteIsAtomicAndNeverWorldReadable inspects atomicWriteFile directly,
// because the transient window it closes is invisible once the write finishes.
func TestCSRWriteIsAtomicAndNeverWorldReadable(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "secret.key")

	if err := atomicWriteFile(path, []byte("material"), keyFileMode); err != nil {
		t.Fatalf("atomicWriteFile: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("mode = %#o, want %#o", got, 0o600)
	}

	// Overwriting must replace the content wholesale and keep the mode. A
	// rename-based write is what makes a concurrent reader see the old file or
	// the new one, never a half-written key.
	if err := atomicWriteFile(path, []byte("replaced"), keyFileMode); err != nil {
		t.Fatalf("atomicWriteFile (overwrite): %v", err)
	}
	got, err := os.ReadFile(path) //nolint:gosec // test-owned temp path.
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != "replaced" {
		t.Errorf("content = %q, want the replacement", got)
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("mode after overwrite = %v (err %v), want 0600", info.Mode().Perm(), err)
	}

	// A directory that does not exist must fail rather than silently write
	// somewhere else.
	if err := atomicWriteFile(filepath.Join(dir, "absent", "k"), []byte("x"), keyFileMode); err == nil {
		t.Error("writing into a missing directory must fail")
	}
}

// TestAtomicWriteReplacesRatherThanRewrites pins the two properties that
// distinguish a rename from an in-place write, both of which are invisible if
// you only inspect the finished file.
//
// This test exists because a plain os.WriteFile passes every other assertion
// here — same content, and on a NEW file the same mode — while being neither
// atomic nor safe on an existing file. Two observable consequences separate
// them:
//
//   - Identity. rename(2) points the name at a different inode, so the file
//     before and after a write are not the same file. A truncate-in-place keeps
//     the inode, which is precisely the window in which a concurrent reader can
//     observe a half-written key.
//   - Mode enforcement. os.WriteFile applies its perm argument only when it
//     CREATES the file; rewriting an existing 0666 key file leaves it 0666. The
//     temp-and-rename path always installs a freshly created 0600 file, so a
//     previously loose key file is tightened rather than silently preserved.
func TestAtomicWriteReplacesRatherThanRewrites(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "replace.key")

	if err := atomicWriteFile(path, []byte("first"), keyFileMode); err != nil {
		t.Fatalf("atomicWriteFile: %v", err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}

	if err := atomicWriteFile(path, []byte("second"), keyFileMode); err != nil {
		t.Fatalf("atomicWriteFile: %v", err)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}

	if os.SameFile(before, after) {
		t.Error("the write must replace the file via rename, not rewrite it in place")
	}

	// A pre-existing, dangerously loose file must come out at 0600.
	loose := filepath.Join(dir, "loose.key")
	if err := os.WriteFile(loose, []byte("old"), 0o666); err != nil { //nolint:gosec // deliberately loose, then tightened.
		t.Fatalf("seed loose file: %v", err)
	}
	if err := atomicWriteFile(loose, []byte("new"), keyFileMode); err != nil {
		t.Fatalf("atomicWriteFile: %v", err)
	}
	info, err := os.Stat(loose)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("mode over a pre-existing 0666 file = %#o, want %#o", got, 0o600)
	}
}

// TestCSREmitsSigningRequest checks the operator actually gets a usable CSR
// covering the configured names.
func TestCSREmitsSigningRequest(t *testing.T) {
	t.Parallel()

	cfg := csrConfig(t)
	cfg.TLS.SANs = []string{"alt.example.com", "10.0.0.7"}

	if _, err := newCSRProvider(cfg); !errors.Is(err, ErrTLSCSRPending) {
		t.Fatalf("err = %v, want ErrTLSCSRPending", err)
	}

	raw, err := os.ReadFile(cfg.TLS.CSR.CSRFile) //nolint:gosec // test-owned temp path.
	if err != nil {
		t.Fatalf("read csr: %v", err)
	}
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		t.Fatal("csr file must contain a CERTIFICATE REQUEST PEM block")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatalf("parse csr: %v", err)
	}
	// A CSR is self-signed by the requesting key; a CA rejects one whose
	// signature does not verify, so an unverifiable CSR is a broken mode.
	if err := csr.CheckSignature(); err != nil {
		t.Fatalf("csr signature does not verify: %v", err)
	}
	if csr.Subject.CommonName != "vallet.example.com" {
		t.Errorf("CommonName = %q, want the configured domain", csr.Subject.CommonName)
	}
	if len(csr.DNSNames) != 2 || csr.DNSNames[0] != "vallet.example.com" {
		t.Errorf("DNSNames = %v, want the domain and its DNS SAN", csr.DNSNames)
	}
	if len(csr.IPAddresses) != 1 || csr.IPAddresses[0].String() != "10.0.0.7" {
		t.Errorf("IPAddresses = %v, want the IP SAN", csr.IPAddresses)
	}

	// The CSR must not be a private key under a misleading label.
	if bytes.Contains(raw, []byte("PRIVATE KEY")) {
		t.Error("the emitted CSR must never contain private key material")
	}
}

// TestCSRServesSignedChain is the happy path: the operator installs the signed
// certificate and the server starts and serves it.
func TestCSRServesSignedChain(t *testing.T) {
	t.Parallel()

	cfg := csrConfig(t)
	now := time.Now()

	if _, err := newCSRProvider(cfg); !errors.Is(err, ErrTLSCSRPending) {
		t.Fatalf("first run: err = %v, want ErrTLSCSRPending", err)
	}

	keyBefore, err := os.ReadFile(cfg.TLS.CSR.KeyFile) //nolint:gosec // test-owned temp path.
	if err != nil {
		t.Fatalf("read key: %v", err)
	}

	signed := signCSR(t, cfg, now.Add(-time.Hour), now.Add(24*time.Hour))
	if err := os.WriteFile(cfg.TLS.CSR.CertFile, signed, 0o644); err != nil { //nolint:gosec // a certificate is public.
		t.Fatalf("install certificate: %v", err)
	}

	srv, err := New(cfg, nil, okPinger{}, stubPublisher{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	assertServesCertificate(t, srv)

	// The key must be REUSED, not regenerated: a new key would silently
	// invalidate the certificate the operator just had signed.
	keyAfter, err := os.ReadFile(cfg.TLS.CSR.KeyFile) //nolint:gosec // test-owned temp path.
	if err != nil {
		t.Fatalf("read key: %v", err)
	}
	if !bytes.Equal(keyBefore, keyAfter) {
		t.Error("an existing key must be reused across restarts")
	}
}

// TestCSRRejectsUntrustworthyChains proves an operator-installed file gets no
// trust for having come from an operator. Each case must refuse startup.
func TestCSRRejectsUntrustworthyChains(t *testing.T) {
	t.Parallel()

	now := time.Now()

	tests := []struct {
		name    string
		install func(t *testing.T, cfg *config.Config)
		wantErr error
	}{
		{
			name: "certificate for a different key is refused",
			install: func(t *testing.T, cfg *config.Config) {
				// Sign a CSR generated from an unrelated key, then install the
				// result. It is a perfectly valid certificate — just not ours.
				other := csrConfig(t)
				if _, err := newCSRProvider(other); !errors.Is(err, ErrTLSCSRPending) {
					t.Fatalf("prepare foreign csr: %v", err)
				}
				foreign := signCSR(t, other, now.Add(-time.Hour), now.Add(24*time.Hour))
				writeFile(t, cfg.TLS.CSR.CertFile, foreign)
			},
			wantErr: ErrTLSCertificateInvalid,
		},
		{
			name: "expired certificate is refused",
			install: func(t *testing.T, cfg *config.Config) {
				writeFile(t, cfg.TLS.CSR.CertFile, signCSR(t, cfg, now.Add(-48*time.Hour), now.Add(-time.Hour)))
			},
			wantErr: ErrTLSCertificateExpired,
		},
		{
			name: "not-yet-valid certificate is refused",
			install: func(t *testing.T, cfg *config.Config) {
				writeFile(t, cfg.TLS.CSR.CertFile, signCSR(t, cfg, now.Add(time.Hour), now.Add(48*time.Hour)))
			},
			wantErr: ErrTLSCertificateExpired,
		},
		{
			name: "a file with no certificate block is refused",
			install: func(t *testing.T, cfg *config.Config) {
				writeFile(t, cfg.TLS.CSR.CertFile, []byte("not a certificate\n"))
			},
			wantErr: ErrTLSCertificateInvalid,
		},
		{
			name: "a private key installed as the certificate is refused",
			install: func(t *testing.T, cfg *config.Config) {
				key, err := os.ReadFile(cfg.TLS.CSR.KeyFile) //nolint:gosec // test-owned temp path.
				if err != nil {
					t.Fatalf("read key: %v", err)
				}
				writeFile(t, cfg.TLS.CSR.CertFile, key)
			},
			wantErr: ErrTLSCertificateInvalid,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			cfg := csrConfig(t)
			if _, err := newCSRProvider(cfg); !errors.Is(err, ErrTLSCSRPending) {
				t.Fatalf("prepare: %v", err)
			}
			tc.install(t, cfg)

			srv, err := New(cfg, nil, okPinger{}, stubPublisher{})
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
			if srv != nil {
				t.Error("a refused certificate must not yield a server")
			}
			assertNoKeyMaterial(t, err.Error(), cfg.TLS.CSR.KeyFile)
		})
	}
}

// TestCSRRefusesUnsafeKeyPermissions covers the fail-closed response to a key
// other accounts can read. Tightening it silently would serve with material that
// must be considered compromised and hide that it ever leaked.
func TestCSRRefusesUnsafeKeyPermissions(t *testing.T) {
	t.Parallel()

	for _, mode := range []fs.FileMode{0o644, 0o640, 0o604, 0o660, 0o666} {
		t.Run(mode.String(), func(t *testing.T) {
			t.Parallel()

			cfg := csrConfig(t)
			if _, err := newCSRProvider(cfg); !errors.Is(err, ErrTLSCSRPending) {
				t.Fatalf("prepare: %v", err)
			}
			if err := os.Chmod(cfg.TLS.CSR.KeyFile, mode); err != nil {
				t.Fatalf("chmod: %v", err)
			}

			_, err := newCSRProvider(cfg)
			if !errors.Is(err, ErrTLSKeyPermissions) {
				t.Fatalf("err = %v, want ErrTLSKeyPermissions for mode %v", err, mode)
			}
			assertNoKeyMaterial(t, err.Error(), cfg.TLS.CSR.KeyFile)
		})
	}
}

// TestCSRRejectsUnusableKeyFiles covers malformed and wrong-type key material.
func TestCSRRejectsUnusableKeyFiles(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		content []byte
	}{
		{name: "not PEM at all", content: []byte("just some bytes")},
		{name: "PEM with garbage body", content: []byte("-----BEGIN PRIVATE KEY-----\nnope\n-----END PRIVATE KEY-----\n")},
		{name: "empty file", content: nil},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			cfg := csrConfig(t)
			if err := os.WriteFile(cfg.TLS.CSR.KeyFile, tc.content, keyFileMode); err != nil {
				t.Fatalf("write key: %v", err)
			}

			_, err := newCSRProvider(cfg)
			if !errors.Is(err, ErrTLSCertificateInvalid) {
				t.Fatalf("err = %v, want ErrTLSCertificateInvalid", err)
			}
			assertNoKeyMaterial(t, err.Error(), cfg.TLS.CSR.KeyFile)
		})
	}
}

// TestCSRErrorsNeverLeakKeyMaterial is the redaction backstop. Errors are
// logged, so an error that quoted the key would put it in the log.
func TestCSRErrorsNeverLeakKeyMaterial(t *testing.T) {
	t.Parallel()

	cfg := csrConfig(t)
	_, err := newCSRProvider(cfg)
	if err == nil {
		t.Fatal("a first run must not succeed")
	}

	raw, readErr := os.ReadFile(cfg.TLS.CSR.KeyFile) //nolint:gosec // test-owned temp path.
	if readErr != nil {
		t.Fatalf("read key: %v", readErr)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		t.Fatal("generated key is not PEM")
	}
	if strings.Contains(err.Error(), string(block.Bytes[8:24])) {
		t.Error("error message contains private key material")
	}
	// The CSR path is named so the operator knows where to collect it.
	if !strings.Contains(err.Error(), cfg.TLS.CSR.CertFile) {
		t.Errorf("error should name the certificate path, got %q", err)
	}
}

// TestCSRRefusesNonSignerKey covers a key file that parses cleanly but holds a
// key that cannot sign — an X25519 key-agreement key, which PKCS#8 can carry.
//
// It must be refused rather than reaching the point where the certificate is
// paired with it: a key that cannot sign cannot complete a handshake, and
// discovering that per-connection instead of at startup turns a config mistake
// into an outage with no obvious cause.
func TestCSRRefusesNonSignerKey(t *testing.T) {
	t.Parallel()

	agreement, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate x25519 key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(agreement)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	cfg := csrConfig(t)
	writeFile(t, cfg.TLS.CSR.KeyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	if err := os.Chmod(cfg.TLS.CSR.KeyFile, keyFileMode); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	_, err = newCSRProvider(cfg)
	if !errors.Is(err, ErrTLSCertificateInvalid) {
		t.Fatalf("err = %v, want ErrTLSCertificateInvalid", err)
	}
	if !strings.Contains(err.Error(), "cannot sign") {
		t.Errorf("error %q should say the key cannot sign", err)
	}
}

// TestCSRFailsClosedOnUnusablePaths covers the I/O failures. Every one must
// refuse startup: a provider that cannot persist or read its own key must not
// leave the server serving with something improvised.
func TestCSRFailsClosedOnUnusablePaths(t *testing.T) {
	t.Parallel()

	t.Run("key path is a directory", func(t *testing.T) {
		t.Parallel()

		cfg := csrConfig(t)
		if err := os.Mkdir(cfg.TLS.CSR.KeyFile, 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if _, err := newCSRProvider(cfg); !errors.Is(err, ErrTLSCertificateInvalid) {
			t.Fatalf("err = %v, want ErrTLSCertificateInvalid", err)
		}
	})

	t.Run("certificate path is a directory", func(t *testing.T) {
		t.Parallel()

		cfg := csrConfig(t)
		if err := os.Mkdir(cfg.TLS.CSR.CertFile, 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if _, err := newCSRProvider(cfg); !errors.Is(err, ErrTLSCertificateInvalid) {
			t.Fatalf("err = %v, want ErrTLSCertificateInvalid", err)
		}
	})

	t.Run("key directory is not writable", func(t *testing.T) {
		t.Parallel()

		dir := t.TempDir()
		if err := os.Chmod(dir, 0o500); err != nil {
			t.Fatalf("chmod: %v", err)
		}
		t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

		cfg := csrConfig(t)
		cfg.TLS.CSR.KeyFile = filepath.Join(dir, "vallet.key")
		if _, err := newCSRProvider(cfg); !errors.Is(err, ErrTLSCertificateInvalid) {
			t.Fatalf("err = %v, want ErrTLSCertificateInvalid", err)
		}
	})

	t.Run("csr directory is not writable", func(t *testing.T) {
		t.Parallel()

		dir := t.TempDir()
		cfg := csrConfig(t)
		cfg.TLS.CSR.CSRFile = filepath.Join(dir, "sub", "vallet.csr")
		if _, err := newCSRProvider(cfg); err == nil {
			t.Fatal("an unwritable csr path must fail startup")
		}
	})
}
