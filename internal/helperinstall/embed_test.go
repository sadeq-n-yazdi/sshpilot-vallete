package helperinstall

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"testing"
)

// TestDigestIsTheDigestOfTheScript is the binding this package exists to
// provide: the published hash must be the hash of the published bytes.
//
// It recomputes the digest here with the standard library rather than trusting
// the value the package derived, so decoupling the two -- a hard-coded
// constant, a hash taken over a different buffer, a digest left behind by an
// earlier version of the script -- fails rather than being served as truth.
func TestDigestIsTheDigestOfTheScript(t *testing.T) {
	t.Parallel()

	sum := sha256.Sum256(Script())
	want := hex.EncodeToString(sum[:])

	if got := Digest(); got != want {
		t.Errorf("Digest() = %q, want %q", got, want)
	}
	if got, wantLine := DigestLine(), want+"  "+ScriptName+"\n"; got != wantLine {
		t.Errorf("DigestLine() = %q, want %q", got, wantLine)
	}
}

// TestScriptMatchesTheAuthoredFile is the anti-drift check against the tree.
func TestScriptMatchesTheAuthoredFile(t *testing.T) {
	t.Parallel()

	authored, err := os.ReadFile(ScriptName)
	if err != nil {
		t.Fatalf("read authored script: %v", err)
	}
	if string(Script()) != string(authored) {
		t.Error("embedded script differs from the file on disk")
	}
}

// TestScriptReturnsAnIndependentCopy checks the defensive copy is real.
//
// Script returns a slice callers could otherwise write through. Sharing one
// backing array across every request would let any caller -- a handler, a
// middleware, a test -- mutate the bytes the digest was taken over, producing a
// response whose content no longer matched the hash published beside it. That
// is the exact failure the endpoint exists to prevent, arriving from inside.
func TestScriptReturnsAnIndependentCopy(t *testing.T) {
	t.Parallel()

	first := Script()
	if len(first) == 0 {
		t.Fatal("script is empty")
	}
	original := first[0]
	first[0] = 'X'

	second := Script()
	if second[0] != original {
		t.Error("mutating the returned slice changed what later callers receive")
	}
	sum := sha256.Sum256(second)
	if hex.EncodeToString(sum[:]) != Digest() {
		t.Error("digest no longer matches the script after a caller mutated an earlier copy")
	}
}
