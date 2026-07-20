package managedblock

import (
	"errors"
	"testing"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/keys"
)

// swapHooks replaces filesystem primitives for the duration of a test. The
// failures it simulates (fsync refusing, rename refusing, a short write)
// cannot be provoked through a real filesystem, and the crash-safety test
// needs a controlled failure at a precise point in the write sequence.
//
// It returns a restore function and also registers cleanup, so a test may
// restore early -- to inspect the post-failure state with the real filesystem
// back in place -- without leaking the override.
func swapHooks(t *testing.T, mutate func(*hooks)) func() {
	t.Helper()
	prev := fsx
	next := fsx
	mutate(&next)
	fsx = next
	restore := func() { fsx = prev }
	t.Cleanup(restore)
	return restore
}

// TestDefaultSyncDir exercises the real directory-fsync helper, which the
// other tests replace.
func TestDefaultSyncDir(t *testing.T) {
	if err := defaultSyncDir(tempDir(t)); err != nil {
		t.Fatalf("defaultSyncDir: %v", err)
	}
	if err := defaultSyncDir(tempDir(t) + "/missing"); err == nil {
		t.Fatal("defaultSyncDir accepted a missing directory")
	}
}

// swapEmitLine replaces the canonicalizer for the duration of a test.
func swapEmitLine(t *testing.T, fn func(keys.ParsedKey) (string, error)) func() {
	t.Helper()
	prev := emitLine
	emitLine = fn
	restore := func() { emitLine = prev }
	t.Cleanup(restore)
	return restore
}

// TestRenderRejectsAMisbehavingCanonicalizer proves the last gate holds even
// if reconstruction is broken or subverted: a canonicalizer that emits a
// forged marker, a multi-line string, or an error must not produce a block.
func TestRenderRejectsAMisbehavingCanonicalizer(t *testing.T) {
	valid := keyLine(t, 30, "ok")
	tests := []struct {
		name string
		fn   func(keys.ParsedKey) (string, error)
	}{
		{"emits a forged END marker", func(keys.ParsedKey) (string, error) { return EndMarker + "\n", nil }},
		{"emits a smuggled second line", func(keys.ParsedKey) (string, error) {
			return "ssh-ed25519 AAAA\ncommand=\"sh\" ssh-ed25519 BBBB\n", nil
		}},
		{"fails", func(keys.ParsedKey) (string, error) { return "", errors.New("boom") }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			defer swapEmitLine(t, tc.fn)()
			got, err := Render([]string{valid})
			if err == nil {
				t.Fatalf("Render accepted a bad canonicalization: %q", got)
			}
			if got != nil {
				t.Fatalf("Render returned %q alongside an error", got)
			}
		})
	}
}
