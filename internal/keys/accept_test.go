package keys

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
)

func TestParseAccepts(t *testing.T) {
	for _, f := range acceptFixtures(t) {
		t.Run(f.name, func(t *testing.T) {
			k, err := Parse(f.line(""))
			if err != nil {
				t.Fatalf("Parse: unexpected error: %v", err)
			}
			if k.Algorithm != f.alg {
				t.Errorf("Algorithm = %q, want %q", k.Algorithm, f.alg)
			}
			if k.BitLen != f.bitLen {
				t.Errorf("BitLen = %d, want %d", k.BitLen, f.bitLen)
			}
			if !k.Algorithm.IsValid() {
				t.Errorf("Algorithm %q not valid", k.Algorithm)
			}
			if err := domain.ValidateFingerprint(k.Fingerprint); err != nil {
				t.Errorf("fingerprint %q invalid: %v", k.Fingerprint, err)
			}
			if got, want := k.Fingerprint, ssh.FingerprintSHA256(f.pub); got != want {
				t.Errorf("Fingerprint = %q, want %q", got, want)
			}
			if !bytes.Equal(k.Blob, f.pub.Marshal()) {
				t.Errorf("Blob is not pub.Marshal()")
			}
			if k.Comment != "" {
				t.Errorf("Comment = %q, want empty", k.Comment)
			}
		})
	}
}

// TestParseTrailingNewlines confirms that a single trailing "\n" or "\r\n" is
// tolerated on an otherwise valid single-key line.
func TestParseTrailingNewlines(t *testing.T) {
	f := ed25519Fixture(t)
	for name, suffix := range map[string]string{"lf": "\n", "crlf": "\r\n"} {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse(append(f.line(""), suffix...)); err != nil {
				t.Fatalf("Parse: %v", err)
			}
		})
	}
}

func TestParseCommentVariants(t *testing.T) {
	f := ed25519Fixture(t)
	accept := []struct{ name, comment, want string }{
		{"interior-spaces", "user@host laptop 2026", "user@host laptop 2026"},
		{"utf8", "café-ключ-🔑", "café-ключ-🔑"},
		{"trim-surrounding", "  trimmed  ", "trimmed"},
		{"max-256-runes", strings.Repeat("é", 256), strings.Repeat("é", 256)},
	}
	for _, tc := range accept {
		t.Run("accept/"+tc.name, func(t *testing.T) {
			k, err := Parse(f.line(tc.comment))
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if k.Comment != tc.want {
				t.Errorf("Comment = %q, want %q", k.Comment, tc.want)
			}
			if err := domain.ValidateKeyComment(k.Comment); err != nil {
				t.Errorf("comment invalid: %v", err)
			}
		})
	}
	reject := []struct{ name, comment string }{
		{"257-runes", strings.Repeat("a", 257)},
		{"tab", "has\ttab"},
		{"c1-control", "c1\u0085here"},
		{"invalid-utf8", "bad\xffutf8"},
	}
	for _, tc := range reject {
		t.Run("reject/"+tc.name, func(t *testing.T) {
			_, err := Parse(f.line(tc.comment))
			if !errors.Is(err, ErrBadComment) {
				t.Fatalf("err = %v, want ErrBadComment", err)
			}
			assertNoInput(t, err, tc.comment)
		})
	}
}

// TestParseSameLineTrailingIsComment documents a deliberate, security-relevant
// decision: SSH treats everything after the key blob on one line as the
// comment. A comment that merely begins with an algorithm name (e.g. a user
// describing "ssh-rsa old laptop") must be accepted, and the trailing text can
// never become a second authorized key because reconstruction emits only one.
func TestParseSameLineTrailingIsComment(t *testing.T) {
	f := ed25519Fixture(t)
	k, err := Parse(f.line("ssh-rsa old laptop key"))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if k.Comment != "ssh-rsa old laptop key" {
		t.Fatalf("Comment = %q, want %q", k.Comment, "ssh-rsa old laptop key")
	}
	if k.Algorithm != domain.AlgEd25519 {
		t.Errorf("Algorithm = %q, want ed25519", k.Algorithm)
	}
}

// TestAlgorithmConstantsPinned guards against an x/crypto upgrade drifting the
// wire-format algorithm names out from under the domain allowlist.
func TestAlgorithmConstantsPinned(t *testing.T) {
	pins := []struct {
		x   string
		dom domain.Algorithm
	}{
		{ssh.KeyAlgoED25519, domain.AlgEd25519},
		{ssh.KeyAlgoECDSA256, domain.AlgECDSA256},
		{ssh.KeyAlgoECDSA384, domain.AlgECDSA384},
		{ssh.KeyAlgoECDSA521, domain.AlgECDSA521},
		{ssh.KeyAlgoRSA, domain.AlgRSA},
		{ssh.KeyAlgoSKED25519, domain.AlgSKEd25519},
		{ssh.KeyAlgoSKECDSA256, domain.AlgSKECDSA256},
	}
	for _, p := range pins {
		if p.x != string(p.dom) {
			t.Errorf("ssh const %q != domain %q", p.x, p.dom)
		}
		if !p.dom.IsValid() {
			t.Errorf("domain %q not valid", p.dom)
		}
	}
	// ssh-dss must remain absent from the allowlist. The literal is used
	// deliberately: x/crypto's DSA constant is deprecated.
	if domain.Algorithm("ssh-dss").IsValid() {
		t.Error("ssh-dss must not be valid")
	}
}
