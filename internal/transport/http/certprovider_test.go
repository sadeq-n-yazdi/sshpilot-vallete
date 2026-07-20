package httpserver

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/config"
)

// certTestBase is the fixed instant the guard tests judge validity against.
var certTestBase = time.Date(2026, time.July, 19, 12, 0, 0, 0, time.UTC)

// fakeProvider is a CertProvider under the test's control, so the guard can be
// shown what it does with material no honest provider would return.
type fakeProvider struct {
	name  string
	cert  *tls.Certificate
	err   error
	calls int

	closed   bool
	closeErr error
}

func (f *fakeProvider) Name() string {
	if f.name == "" {
		return "fake"
	}
	return f.name
}

func (f *fakeProvider) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	f.calls++
	return f.cert, f.err
}

// closableProvider adds the optional Close the guard discovers by assertion.
type closableProvider struct{ *fakeProvider }

func (c closableProvider) Close() error {
	c.closed = true
	return c.closeErr
}

// mustSelfSigned builds a valid ephemeral certificate for the tests to mangle.
func mustSelfSigned(t *testing.T, now time.Time) *tls.Certificate {
	t.Helper()

	cert, err := newSelfSignedCert([]string{"localhost"}, now)
	if err != nil {
		t.Fatalf("newSelfSignedCert: %v", err)
	}
	return &cert
}

// TestCertGuardRejectsBadCertificates is the core security test: it enumerates
// the ways a provider can hand over material that must never be presented to a
// client, and requires the guard to refuse each one.
//
// Every case here would otherwise be served. crypto/tls does not check whether
// a GetCertificate result is expired or whether its key matches, so without this
// guard a buggy or hostile provider decides what the server presents.
func TestCertGuardRejectsBadCertificates(t *testing.T) {
	t.Parallel()

	valid := mustSelfSigned(t, certTestBase)

	tests := []struct {
		name    string
		build   func(t *testing.T) *fakeProvider
		wantErr error
		wantMsg string
	}{
		{
			name:  "valid certificate passes",
			build: func(*testing.T) *fakeProvider { return &fakeProvider{cert: valid} },
		},
		{
			name: "provider error refuses, never downgrades",
			build: func(*testing.T) *fakeProvider {
				return &fakeProvider{err: errors.New("acme order failed")}
			},
			wantErr: ErrTLSCertificateUnavailable,
			wantMsg: "acme order failed",
		},
		{
			name:    "nil certificate with nil error refuses",
			build:   func(*testing.T) *fakeProvider { return &fakeProvider{} },
			wantErr: ErrTLSCertificateUnavailable,
			wantMsg: "returned no certificate",
		},
		{
			name: "empty chain refuses",
			build: func(*testing.T) *fakeProvider {
				return &fakeProvider{cert: &tls.Certificate{PrivateKey: valid.PrivateKey}}
			},
			wantErr: ErrTLSCertificateInvalid,
			wantMsg: "chain is empty",
		},
		{
			name: "unparseable leaf DER refuses",
			build: func(*testing.T) *fakeProvider {
				return &fakeProvider{cert: &tls.Certificate{
					Certificate: [][]byte{[]byte("not a certificate")},
					PrivateKey:  valid.PrivateKey,
				}}
			},
			wantErr: ErrTLSCertificateInvalid,
			wantMsg: "parse leaf",
		},
		{
			name: "missing private key refuses",
			build: func(*testing.T) *fakeProvider {
				return &fakeProvider{cert: &tls.Certificate{Certificate: valid.Certificate}}
			},
			wantErr: ErrTLSCertificateInvalid,
			wantMsg: "no private key",
		},
		{
			name: "key that does not match the certificate refuses",
			build: func(t *testing.T) *fakeProvider {
				other := mustSelfSigned(t, certTestBase)
				return &fakeProvider{cert: &tls.Certificate{
					Certificate: valid.Certificate,
					PrivateKey:  other.PrivateKey,
				}}
			},
			wantErr: ErrTLSCertificateInvalid,
			wantMsg: "does not match",
		},
		{
			name: "key of an unrelated algorithm refuses",
			build: func(t *testing.T) *fakeProvider {
				ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				if err != nil {
					t.Fatalf("generate key: %v", err)
				}
				return &fakeProvider{cert: &tls.Certificate{
					Certificate: valid.Certificate,
					PrivateKey:  ec,
				}}
			},
			wantErr: ErrTLSCertificateInvalid,
			wantMsg: "does not match",
		},
		{
			name: "key that cannot sign refuses",
			build: func(*testing.T) *fakeProvider {
				// A non-signer key type cannot be matched against the leaf. An
				// unestablished match must deny rather than pass unchecked.
				return &fakeProvider{cert: &tls.Certificate{
					Certificate: valid.Certificate,
					PrivateKey:  "not a key",
				}}
			},
			wantErr: ErrTLSCertificateInvalid,
			wantMsg: "cannot sign",
		},
		{
			name: "expired certificate refuses",
			build: func(t *testing.T) *fakeProvider {
				return &fakeProvider{cert: mustSelfSigned(t, certTestBase.Add(-48*time.Hour))}
			},
			wantErr: ErrTLSCertificateExpired,
			wantMsg: "expired at",
		},
		{
			name: "not-yet-valid certificate refuses",
			build: func(t *testing.T) *fakeProvider {
				return &fakeProvider{cert: mustSelfSigned(t, certTestBase.Add(48*time.Hour))}
			},
			wantErr: ErrTLSCertificateExpired,
			wantMsg: "not valid before",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			guard := newCertGuard(tc.build(t), staticClock(certTestBase))
			cert, err := guard.GetCertificate(nil)

			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("GetCertificate: %v", err)
				}
				if cert == nil {
					t.Fatal("a valid certificate must be returned")
				}
				return
			}

			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantMsg) {
				t.Errorf("error %q should explain the defect (%q)", err, tc.wantMsg)
			}
			// Fail closed: refusing while still handing back usable material
			// would let crypto/tls serve it anyway.
			if cert != nil {
				t.Error("a refused certificate must not be returned")
			}
		})
	}
}

// TestCertGuardIgnoresProviderSuppliedLeaf covers the case a naive guard misses.
//
// tls.Certificate.Leaf is an ordinary struct field. A provider can set it to a
// perfectly valid certificate while the DER chain clients actually verify is
// expired. Trusting Leaf would validate the wrong object entirely and serve the
// expired chain, so the guard re-parses Certificate[0] and judges that.
func TestCertGuardIgnoresProviderSuppliedLeaf(t *testing.T) {
	t.Parallel()

	expired := mustSelfSigned(t, certTestBase.Add(-48*time.Hour))
	fresh := mustSelfSigned(t, certTestBase)

	// The lie: expired DER, valid-looking Leaf.
	lying := &tls.Certificate{
		Certificate: expired.Certificate,
		PrivateKey:  expired.PrivateKey,
		Leaf:        fresh.Leaf,
	}

	guard := newCertGuard(&fakeProvider{cert: lying}, staticClock(certTestBase))
	if _, err := guard.GetCertificate(nil); !errors.Is(err, ErrTLSCertificateExpired) {
		t.Fatalf("err = %v, want ErrTLSCertificateExpired: the DER chain must be judged, not the Leaf field", err)
	}
}

// TestCertGuardNamesTheFailingProvider checks the diagnostic carries the mode.
// With several providers configurable, an operator must be able to tell which
// one failed without attaching a debugger.
func TestCertGuardNamesTheFailingProvider(t *testing.T) {
	t.Parallel()

	guard := newCertGuard(&fakeProvider{name: "acme", err: errors.New("boom")}, staticClock(certTestBase))
	_, err := guard.GetCertificate(nil)
	if err == nil || !strings.Contains(err.Error(), "acme") {
		t.Fatalf("err = %v, want the provider name", err)
	}
}

// TestCertGuardValidatesEveryHandshake is the property a one-shot startup load
// cannot have, and the reason CertProvider has GetCertificate's signature.
//
// The same provider and the same certificate are accepted before expiry and
// refused after it, with nothing but the clock changing. This is ADR-0015 §4's
// fail-closed-on-expiry applied while the process runs — the gap tls.go
// documented E1 as leaving open.
func TestCertGuardValidatesEveryHandshake(t *testing.T) {
	t.Parallel()

	cert := mustSelfSigned(t, certTestBase)
	now := certTestBase
	provider := &fakeProvider{cert: cert}
	guard := newCertGuard(provider, func() time.Time { return now })

	if _, err := guard.GetCertificate(nil); err != nil {
		t.Fatalf("inside the validity window: %v", err)
	}

	// Move past the certificate's expiry. No restart, no reload, no new
	// material: the very next handshake must be refused.
	now = certTestBase.Add(selfSignedValidity + time.Hour)
	if _, err := guard.GetCertificate(nil); !errors.Is(err, ErrTLSCertificateExpired) {
		t.Fatalf("err = %v, want ErrTLSCertificateExpired on a later handshake", err)
	}

	// The provider was consulted on BOTH handshakes. If the guard cached the
	// first result instead of asking again, a renewing provider's fresh
	// certificate would never be picked up.
	if provider.calls != 2 {
		t.Errorf("provider consulted %d times, want once per handshake", provider.calls)
	}
}

// TestCertGuardClose checks the optional-Closer plumbing that lets a renewing
// provider (ACME) shut down a background loop without every provider having to
// carry an empty method.
func TestCertGuardClose(t *testing.T) {
	t.Parallel()

	t.Run("provider without Close", func(t *testing.T) {
		t.Parallel()

		if err := newCertGuard(&fakeProvider{}, staticClock(certTestBase)).Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
	})

	t.Run("provider with Close is closed", func(t *testing.T) {
		t.Parallel()

		inner := &fakeProvider{}
		if err := newCertGuard(closableProvider{inner}, staticClock(certTestBase)).Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		if !inner.closed {
			t.Error("the provider's Close must be called")
		}
	})

	t.Run("Close error propagates", func(t *testing.T) {
		t.Parallel()

		want := errors.New("shutdown failed")
		guard := newCertGuard(closableProvider{&fakeProvider{closeErr: want}}, staticClock(certTestBase))
		if err := guard.Close(); !errors.Is(err, want) {
			t.Fatalf("err = %v, want %v", err, want)
		}
	})
}

// TestProviderFailureRefusesToServe proves the fail-closed rule end to end, at
// the TLS layer rather than in a unit: a client handshaking against a server
// whose provider is broken gets NO connection.
//
// The distinction that matters is refusal versus downgrade. A server that
// answered this handshake with a self-signed certificate, or that fell back to
// plaintext, would be "working" from the operator's point of view while giving
// clients no way to authenticate it. The assertion is therefore that the
// handshake fails, and additionally that no certificate was received.
func TestProviderFailureRefusesToServe(t *testing.T) {
	t.Parallel()

	guard := newCertGuard(
		&fakeProvider{name: "broken", err: errors.New("provider is down")},
		staticClock(certTestBase),
	)
	addr := serveTLS(t, &tls.Config{
		MinVersion:     tls.VersionTLS12,
		GetCertificate: guard.GetCertificate,
		CipherSuites:   tls12CipherSuites(),
		NextProtos:     []string{"h2", "http/1.1"},
	})

	conn, err := tls.Dial("tcp", addr, &tls.Config{
		MinVersion: tls.VersionTLS12,
		// Verification is disabled so that the test fails on the SERVER
		// refusing to provide a certificate, not on the client rejecting one.
		// Without this, a downgrade to a self-signed certificate would also
		// produce an error and the test would pass for the wrong reason.
		InsecureSkipVerify: true, //nolint:gosec // see comment: isolates server-side refusal.
	})
	if err == nil {
		state := conn.ConnectionState()
		_ = conn.Close()
		t.Fatalf("handshake succeeded with %d certificate(s); a provider failure must refuse, not downgrade",
			len(state.PeerCertificates))
	}
}

// uncomparableSigner is a crypto.Signer whose public key does NOT implement the
// Equal method every standard key type provides.
//
// It exists to reach the branch where a key/certificate match cannot be
// established. That branch must DENY: an unrecognized key type means the match
// is unknown, and passing unknown material through would let a provider install
// a certificate whose key was never checked against it.
type uncomparableSigner struct{}

type uncomparablePublicKey struct{}

func (uncomparableSigner) Public() crypto.PublicKey { return uncomparablePublicKey{} }

func (uncomparableSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, errors.New("not implemented")
}

// TestCertGuardRefusesUncomparableKey covers that deny-on-unknown branch.
func TestCertGuardRefusesUncomparableKey(t *testing.T) {
	t.Parallel()

	valid := mustSelfSigned(t, certTestBase)
	guard := newCertGuard(&fakeProvider{cert: &tls.Certificate{
		Certificate: valid.Certificate,
		PrivateKey:  uncomparableSigner{},
	}}, staticClock(certTestBase))

	_, err := guard.GetCertificate(nil)
	if !errors.Is(err, ErrTLSCertificateInvalid) {
		t.Fatalf("err = %v, want ErrTLSCertificateInvalid", err)
	}
	if !strings.Contains(err.Error(), "cannot be compared") {
		t.Errorf("error %q should say the key could not be compared", err)
	}
}

// TestProviderNames pins the operator-facing mode names. They appear in startup
// diagnostics, so a silent rename would break an operator's grep.
func TestProviderNames(t *testing.T) {
	t.Parallel()

	cfg := &config.Config{}
	cfg.Server.Environment = "development"
	selfSigned, err := newSelfSignedProvider(cfg, staticClock(certTestBase))
	if err != nil {
		t.Fatalf("newSelfSignedProvider: %v", err)
	}
	if got := selfSigned.Name(); got != "self_signed" {
		t.Errorf("Name() = %q, want %q", got, "self_signed")
	}
	if got := (&manualProvider{}).Name(); got != "manual" {
		t.Errorf("Name() = %q, want %q", got, "manual")
	}
}
