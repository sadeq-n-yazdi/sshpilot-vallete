package managedblock

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// TestApplyRefusesEmptyingTheBlock covers the non-empty -> empty safeguard: an
// apply that would clear a populated managed block is refused with ErrWouldEmpty
// and writes nothing, unless AllowEmpty is set. Emptying is never refused when
// there is nothing to lose (no block, or an already-empty block) or when the
// render still holds keys.
func TestApplyRefusesEmptyingTheBlock(t *testing.T) {
	populated := begin + keyLine(t, 30, "a") + "\n" + keyLine(t, 31, "b") + "\n" + end
	foreignHead := "# keep me\n" + keyLine(t, 32, "mine") + "\n"

	tests := []struct {
		name       string
		initial    string
		pubkeys    []string
		allowEmpty bool
		dryRun     bool
		wantRefuse bool   // expect ErrWouldEmpty and the file left untouched
		wantResult string // exact file content when not refused (empty = don't check)
	}{
		{
			name:       "non-empty block, empty render, no flag: refused",
			initial:    foreignHead + populated,
			pubkeys:    nil,
			wantRefuse: true,
		},
		{
			name:       "non-empty block, empty render, dry-run, no flag: still refused",
			initial:    foreignHead + populated,
			pubkeys:    nil,
			dryRun:     true,
			wantRefuse: true,
		},
		{
			name:       "non-empty block, empty render, AllowEmpty: applied and emptied",
			initial:    foreignHead + populated,
			pubkeys:    nil,
			allowEmpty: true,
			wantResult: foreignHead + begin + end,
		},
		{
			name:       "no existing block, empty render: not refused",
			initial:    "own key\n",
			pubkeys:    nil,
			wantResult: "own key\n" + begin + end,
		},
		{
			name:    "already-empty block, empty render: not refused, no change",
			initial: "own\n" + begin + end,
			pubkeys: nil,
			// Idempotent: the bytes on disk are unchanged.
			wantResult: "own\n" + begin + end,
		},
		{
			name:       "non-empty block, still-non-empty render: applied normally",
			initial:    begin + keyLine(t, 33, "old") + "\n" + end,
			pubkeys:    []string{keyLine(t, 34, "new")},
			wantResult: begin + keyLine(t, 34, "new") + "\n" + end,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			setUmask(t)
			path := filepath.Join(tempDir(t), "authorized_keys")
			writeFile(t, path, tc.initial, 0o600)

			_, err := Apply(tc.pubkeys, Options{
				Path:       path,
				DryRun:     tc.dryRun,
				AllowEmpty: tc.allowEmpty,
			})

			if tc.wantRefuse {
				if !errors.Is(err, ErrWouldEmpty) {
					t.Fatalf("Apply error = %v, want ErrWouldEmpty", err)
				}
				if got := readFile(t, path); got != tc.initial {
					t.Fatalf("file was modified despite the refusal:\n got %q\nwant %q", got, tc.initial)
				}
				return
			}
			if err != nil {
				t.Fatalf("Apply: %v", err)
			}
			if got := readFile(t, path); got != tc.wantResult {
				t.Fatalf("file =\n%q\nwant\n%q", got, tc.wantResult)
			}
		})
	}
}

// TestApplyDryRunRefusalWritesNothing pins that the dry-run refusal both returns
// ErrWouldEmpty (so the process exits non-zero) and never touches the file, so a
// pending forced revocation is surfaced without being applied.
func TestApplyDryRunRefusalWritesNothing(t *testing.T) {
	setUmask(t)
	path := filepath.Join(tempDir(t), "authorized_keys")
	initial := begin + keyLine(t, 35, "k") + "\n" + end
	writeFile(t, path, initial, 0o600)

	fiBefore, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}

	if _, err := Apply(nil, Options{Path: path, DryRun: true}); !errors.Is(err, ErrWouldEmpty) {
		t.Fatalf("Apply error = %v, want ErrWouldEmpty", err)
	}
	if got := readFile(t, path); got != initial {
		t.Fatalf("dry-run refusal modified the file: %q", got)
	}
	fiAfter, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if !fiAfter.ModTime().Equal(fiBefore.ModTime()) {
		t.Fatalf("dry-run refusal rewrote the file (mtime changed)")
	}
}
