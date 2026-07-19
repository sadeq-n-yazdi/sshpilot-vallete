package keys

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
)

// stubPub is a minimal ssh.PublicKey used to exercise the defensive branches of
// strength that a well-formed key can never reach.
type stubPub struct {
	typ    string
	crypto crypto.PublicKey // nil means "does not implement CryptoPublicKey"
}

func (s stubPub) Type() string                        { return s.typ }
func (s stubPub) Marshal() []byte                     { return []byte(s.typ) }
func (s stubPub) Verify([]byte, *ssh.Signature) error { return nil }
func (s stubPub) CryptoPublicKey() crypto.PublicKey   { return s.crypto }

// stubNoCrypto omits CryptoPublicKey entirely so the type assertion fails.
type stubNoCrypto struct{ typ string }

func (s stubNoCrypto) Type() string                        { return s.typ }
func (s stubNoCrypto) Marshal() []byte                     { return []byte(s.typ) }
func (s stubNoCrypto) Verify([]byte, *ssh.Signature) error { return nil }

func TestStrengthDefensiveBranches(t *testing.T) {
	t.Run("rsa-not-crypto-public-key", func(t *testing.T) {
		_, err := strength(domain.AlgRSA, stubNoCrypto{typ: "ssh-rsa"})
		if !errors.Is(err, ErrMalformed) {
			t.Fatalf("err = %v, want ErrMalformed", err)
		}
	})
	t.Run("rsa-wrong-crypto-type", func(t *testing.T) {
		pub, _, _ := ed25519.GenerateKey(rand.Reader)
		_, err := strength(domain.AlgRSA, stubPub{typ: "ssh-rsa", crypto: pub})
		if !errors.Is(err, ErrMalformed) {
			t.Fatalf("err = %v, want ErrMalformed", err)
		}
	})
	t.Run("unsupported-alg-default", func(t *testing.T) {
		_, err := strength(domain.Algorithm("bogus"), stubNoCrypto{typ: "bogus"})
		if !errors.Is(err, ErrUnsupportedAlgorithm) {
			t.Fatalf("err = %v, want ErrUnsupportedAlgorithm", err)
		}
	})
}

// TestParseKeyLineRejectsTrailingRest covers the defense-in-depth rest check in
// parseKeyLine. Production callers strip line breaks before calling it, so this
// exercises the branch directly by passing two newline-separated valid keys:
// ParseAuthorizedKey returns the second as rest, which must be rejected.
func TestParseKeyLineRejectsTrailingRest(t *testing.T) {
	a := ed25519Fixture(t).line("")
	b := ecdsaFixtureP256(t).line("")
	multi := append(append(append([]byte{}, a...), '\n'), b...)
	_, err := parseKeyLine(multi)
	if !errors.Is(err, ErrMultipleKeys) {
		t.Fatalf("err = %v, want ErrMultipleKeys", err)
	}
}

func TestCheckInvariants(t *testing.T) {
	const goodFP = "SHA256:0000000000000000000000000000000000000000000"
	if err := domain.ValidateFingerprint(goodFP); err != nil {
		t.Fatalf("test fingerprint invalid: %v", err)
	}
	cases := []struct {
		name string
		k    ParsedKey
		want error
	}{
		{"ok", ParsedKey{Algorithm: domain.AlgEd25519, Fingerprint: goodFP, Comment: "ok"}, nil},
		{"bad-alg", ParsedKey{Algorithm: domain.Algorithm("nope"), Fingerprint: goodFP}, ErrUnsupportedAlgorithm},
		{"bad-fp", ParsedKey{Algorithm: domain.AlgEd25519, Fingerprint: "not-a-fingerprint"}, ErrMalformed},
		{"bad-comment", ParsedKey{Algorithm: domain.AlgEd25519, Fingerprint: goodFP, Comment: "bad\x01"}, ErrBadComment},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := checkInvariants(tc.k)
			if tc.want == nil {
				if err != nil {
					t.Fatalf("err = %v, want nil", err)
				}
				return
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}
