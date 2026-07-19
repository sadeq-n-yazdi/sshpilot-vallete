package keys

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
)

func TestAuthorizedKeyLineRoundTrip(t *testing.T) {
	for _, f := range acceptFixtures(t) {
		for _, comment := range []string{"", "laptop", "user@host with spaces"} {
			t.Run(f.name+"/"+commentLabel(comment), func(t *testing.T) {
				k, err := Parse(f.line(comment))
				if err != nil {
					t.Fatalf("Parse: %v", err)
				}
				line, err := AuthorizedKeyLine(k)
				if err != nil {
					t.Fatalf("AuthorizedKeyLine: %v", err)
				}
				assertCanonical(t, line, comment)

				// Byte-equal to x/crypto for the algorithm+blob portion.
				want := string(ssh.MarshalAuthorizedKey(f.pub)) // "<alg> <b64>\n"
				if comment == "" {
					if line != want {
						t.Errorf("line = %q, want %q", line, want)
					}
				} else {
					prefix := strings.TrimSuffix(want, "\n")
					if !strings.HasPrefix(line, prefix+" ") {
						t.Errorf("line %q lacks canonical prefix %q", line, prefix)
					}
				}

				// Re-parsing the reconstructed line yields an identical key.
				k2, err := Parse([]byte(line))
				if err != nil {
					t.Fatalf("re-Parse: %v", err)
				}
				if k2.Algorithm != k.Algorithm || k2.Comment != k.Comment ||
					k2.Fingerprint != k.Fingerprint || k2.BitLen != k.BitLen ||
					!bytes.Equal(k2.Blob, k.Blob) {
					t.Errorf("round-trip mismatch: %+v vs %+v", k2, k)
				}
			})
		}
	}
}

func TestAuthorizedKeyLineFromRejects(t *testing.T) {
	f := ed25519Fixture(t)
	good := f.pub.Marshal()

	t.Run("invalid-algorithm", func(t *testing.T) {
		_, err := AuthorizedKeyLineFrom(domain.Algorithm("ssh-dss"), good, "")
		if !errors.Is(err, ErrUnsupportedAlgorithm) {
			t.Fatalf("err = %v, want ErrUnsupportedAlgorithm", err)
		}
	})
	t.Run("unparseable-blob", func(t *testing.T) {
		_, err := AuthorizedKeyLineFrom(domain.AlgEd25519, []byte("not a blob"), "")
		if !errors.Is(err, ErrMalformed) {
			t.Fatalf("err = %v, want ErrMalformed", err)
		}
	})
	t.Run("tampered-blob-type", func(t *testing.T) {
		// A valid ed25519 blob presented under the ssh-rsa algorithm: the
		// re-parse detects the type disagreement and refuses.
		_, err := AuthorizedKeyLineFrom(domain.AlgRSA, good, "")
		if !errors.Is(err, ErrMalformed) {
			t.Fatalf("err = %v, want ErrMalformed", err)
		}
	})
	t.Run("weak-rsa-blob", func(t *testing.T) {
		weak := mustSSHPub(t, rsaKey(t, 2048).Public()).Marshal()
		_, err := AuthorizedKeyLineFrom(domain.AlgRSA, weak, "")
		if !errors.Is(err, ErrWeakKey) {
			t.Fatalf("err = %v, want ErrWeakKey", err)
		}
	})
	for name, comment := range map[string]string{
		"control":  "bad\x01comment",
		"newline":  "line\nbreak",
		"carriage": "line\rbreak",
		"too-long": strings.Repeat("a", 257),
	} {
		t.Run("bad-comment/"+name, func(t *testing.T) {
			_, err := AuthorizedKeyLineFrom(domain.AlgEd25519, good, comment)
			if !errors.Is(err, ErrBadComment) {
				t.Fatalf("err = %v, want ErrBadComment", err)
			}
			assertNoInput(t, err, comment)
		})
	}
}

func TestAuthorizedKeyLineTrimsComment(t *testing.T) {
	f := ed25519Fixture(t)
	line, err := AuthorizedKeyLineFrom(f.alg, f.pub.Marshal(), "  padded  ")
	if err != nil {
		t.Fatalf("AuthorizedKeyLineFrom: %v", err)
	}
	if !strings.HasSuffix(line, " padded\n") {
		t.Errorf("comment not trimmed: %q", line)
	}
}

// assertCanonical verifies the structural invariants of a reconstructed line:
// exactly one trailing newline, no carriage return, no interior newline, and
// 2 or 3 single-space-separated fields (3 iff a comment is present).
func assertCanonical(t *testing.T, line, comment string) {
	t.Helper()
	if !strings.HasSuffix(line, "\n") {
		t.Fatalf("line missing trailing newline: %q", line)
	}
	body := strings.TrimSuffix(line, "\n")
	if strings.ContainsAny(body, "\n\r") {
		t.Fatalf("line has interior line break: %q", line)
	}
	fields := strings.SplitN(body, " ", 3)
	wantFields := 2
	if comment != "" {
		wantFields = 3
	}
	if len(fields) != wantFields {
		t.Fatalf("line has %d fields, want %d: %q", len(fields), wantFields, body)
	}
}

func commentLabel(c string) string {
	if c == "" {
		return "no-comment"
	}
	return "with-comment"
}
