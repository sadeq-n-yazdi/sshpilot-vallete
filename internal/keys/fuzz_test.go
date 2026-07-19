package keys

import (
	"strings"
	"testing"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
)

// seedCorpus returns representative inputs: every accepted fixture line plus a
// spread of rejected shapes. It drives both fuzz seeds and keeps the corpus in
// one place.
func seedCorpus(f *testing.F) {
	for _, fx := range acceptFixtures(f) {
		f.Add(fx.line(""))
		f.Add(fx.line("comment here"))
	}
	rejects := [][]byte{
		nil,
		[]byte(""),
		[]byte("   "),
		[]byte("# comment"),
		[]byte("ssh-ed25519"),
		[]byte("ssh-ed25519 AAAA"),
		[]byte("not a key at all"),
		[]byte("no-pty ssh-ed25519 AAAA"),
		[]byte("-----BEGIN OPENSSH PRIVATE KEY-----"),
		[]byte("PuTTY-User-Key-File-3: ssh-ed25519"),
		[]byte("\x00\xff\xfe"),
	}
	for _, r := range rejects {
		f.Add(r)
	}
}

// assertInvariants checks the guarantees every accepted key must satisfy. It is
// shared by both fuzzers.
func assertInvariants(t *testing.T, k ParsedKey) {
	t.Helper()
	if !k.Algorithm.IsValid() {
		t.Fatalf("accepted key has invalid algorithm %q", k.Algorithm)
	}
	if err := domain.ValidateFingerprint(k.Fingerprint); err != nil {
		t.Fatalf("accepted fingerprint invalid: %v", err)
	}
	if err := domain.ValidateKeyComment(k.Comment); err != nil {
		t.Fatalf("accepted comment invalid: %v", err)
	}
	line, err := AuthorizedKeyLine(k)
	if err != nil {
		t.Fatalf("AuthorizedKeyLine failed on accepted key: %v", err)
	}
	body := strings.TrimSuffix(line, "\n")
	if strings.ContainsAny(body, "\n\r") {
		t.Fatalf("reconstructed line has interior line break: %q", line)
	}
	if n := len(strings.SplitN(body, " ", 3)); n < 2 || n > 3 {
		t.Fatalf("reconstructed line has %d fields: %q", n, body)
	}
	// Reconstruction must round-trip to an identical key.
	k2, err := Parse([]byte(line))
	if err != nil {
		t.Fatalf("re-Parse of reconstructed line failed: %v", err)
	}
	if k2.Fingerprint != k.Fingerprint || k2.Algorithm != k.Algorithm || k2.Comment != k.Comment {
		t.Fatalf("round-trip mismatch: %+v vs %+v", k2, k)
	}
}

func FuzzParse(f *testing.F) {
	seedCorpus(f)
	f.Fuzz(func(t *testing.T, raw []byte) {
		k, err := Parse(raw)
		if err != nil {
			return
		}
		assertInvariants(t, k)
	})
}

func FuzzParseAuthorizedKeys(f *testing.F) {
	seedCorpus(f)
	// A few multi-line seeds specific to the batch path.
	f.Add([]byte("# header\n\nssh-ed25519 AAAA\n"))
	f.Fuzz(func(t *testing.T, raw []byte) {
		keys, errs := ParseAuthorizedKeys(raw)
		for _, le := range errs {
			if le.Err == nil {
				t.Fatalf("LineError with nil Err at line %d", le.Line)
			}
		}
		for _, k := range keys {
			assertInvariants(t, k)
		}
	})
}
