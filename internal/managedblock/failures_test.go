package managedblock

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestApplyCrashSafety proves the two crash-safety claims: the temp file lives
// in the target's own directory (so the rename can never cross a filesystem),
// and a failure at the last instant before the rename leaves the original file
// intact with no debris beside it.
func TestApplyCrashSafety(t *testing.T) {
	dir := tempDir(t)
	setUmask(t)
	path := filepath.Join(dir, "authorized_keys")
	const original = "own key\n"
	writeFile(t, path, original, 0o600)

	var sawTemp []string
	restore := swapHooks(t, func(h *hooks) {
		h.rename = func(*os.Root, string, string) error {
			entries, err := os.ReadDir(dir)
			if err != nil {
				t.Fatalf("readdir: %v", err)
			}
			for _, e := range entries {
				if e.Name() != "authorized_keys" {
					sawTemp = append(sawTemp, e.Name())
				}
			}
			// Simulate a crash at the last instant before the swap.
			return errors.New("simulated crash before rename")
		}
	})

	_, err := Apply([]string{keyLine(t, 22, "k")}, Options{Path: path})
	if err == nil || !strings.Contains(err.Error(), "rename temp file") {
		t.Fatalf("Apply error = %v, want a rename failure", err)
	}
	restore()

	if len(sawTemp) != 1 {
		t.Fatalf("expected exactly one temp file beside the target, saw %v", sawTemp)
	}
	if !strings.HasPrefix(sawTemp[0], ".authorized_keys.") {
		t.Fatalf("temp file %q is not derived from the target name", sawTemp[0])
	}
	if got := readFile(t, path); got != original {
		t.Fatalf("target was modified by the failed write: %q", got)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != "authorized_keys" {
		t.Fatalf("temp debris was left behind: %v", entries)
	}
}

// TestApplySyscallFailures covers the write-path failures that cannot be
// provoked through a real filesystem. Each must surface as a wrapped error,
// and every failure before the rename must leave the target untouched.
func TestApplySyscallFailures(t *testing.T) {
	boom := errors.New("boom")
	tests := []struct {
		name    string
		mutate  func(*hooks)
		wantMsg string
		intact  bool
	}{
		{
			name:    "temp name generation fails",
			mutate:  func(h *hooks) { h.randRead = func([]byte) (int, error) { return 0, boom } },
			wantMsg: "generate temp name",
			intact:  true,
		},
		{
			name:    "chmod of the temp file fails",
			mutate:  func(h *hooks) { h.chmodFile = func(*os.File, fs.FileMode) error { return boom } },
			wantMsg: "set temp file mode",
			intact:  true,
		},
		{
			name:    "write of the temp file fails",
			mutate:  func(h *hooks) { h.write = func(*os.File, []byte) (int, error) { return 0, boom } },
			wantMsg: "write temp file",
			intact:  true,
		},
		{
			name:    "fsync of the temp file fails",
			mutate:  func(h *hooks) { h.sync = func(*os.File) error { return boom } },
			wantMsg: "sync temp file",
			intact:  true,
		},
		{
			name:    "close of the temp file fails",
			mutate:  func(h *hooks) { h.closeFile = func(*os.File) error { return boom } },
			wantMsg: "close temp file",
			intact:  true,
		},
		{
			name:    "fsync of the directory fails",
			mutate:  func(h *hooks) { h.syncDir = func(string) error { return boom } },
			wantMsg: "sync directory",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := tempDir(t)
			setUmask(t)
			path := filepath.Join(dir, "authorized_keys")
			writeFile(t, path, "own\n", 0o600)
			restore := swapHooks(t, tc.mutate)

			_, err := Apply([]string{keyLine(t, 23, "k")}, Options{Path: path})
			restore()
			if err == nil || !strings.Contains(err.Error(), tc.wantMsg) {
				t.Fatalf("Apply error = %v, want %q", err, tc.wantMsg)
			}
			if !errors.Is(err, boom) {
				t.Fatalf("Apply error does not wrap the cause: %v", err)
			}
			if tc.intact && readFile(t, path) != "own\n" {
				t.Fatalf("target was modified by a pre-rename failure")
			}
			entries, err := os.ReadDir(dir)
			if err != nil {
				t.Fatalf("readdir: %v", err)
			}
			if len(entries) != 1 {
				t.Fatalf("temp debris was left behind: %v", entries)
			}
		})
	}
}

// TestApplyTempNameCollision exercises the O_EXCL path: with the random source
// pinned the temp name is predictable, so pre-creating it forces the failure.
func TestApplyTempNameCollision(t *testing.T) {
	dir := tempDir(t)
	setUmask(t)
	path := filepath.Join(dir, "authorized_keys")
	writeFile(t, path, "own\n", 0o600)

	defer swapHooks(t, func(h *hooks) {
		h.randRead = func(b []byte) (int, error) {
			for i := range b {
				b[i] = 0xAB
			}
			return len(b), nil
		}
	})()

	name, err := tempName("authorized_keys")
	if err != nil {
		t.Fatalf("tempName: %v", err)
	}
	writeFile(t, filepath.Join(dir, name), "squatter\n", 0o600)

	if _, err := Apply([]string{keyLine(t, 24, "k")}, Options{Path: path}); err == nil ||
		!strings.Contains(err.Error(), "create temp file") {
		t.Fatalf("Apply error = %v, want a temp-file creation failure", err)
	}
	if readFile(t, path) != "own\n" {
		t.Fatalf("target was modified")
	}
}

func TestApplyDirectoryErrors(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: permission checks do not apply")
	}

	t.Run("stat of the directory fails", func(t *testing.T) {
		parent := tempDir(t)
		locked := filepath.Join(parent, "locked")
		mkdirAll(t, locked, 0o000)
		t.Cleanup(func() { _ = os.Chmod(locked, 0o700) })
		path := filepath.Join(locked, "sub", "authorized_keys")
		if _, err := Apply(nil, Options{Path: path}); err == nil ||
			!strings.Contains(err.Error(), "stat directory") {
			t.Fatalf("Apply error = %v, want a stat-directory failure", err)
		}
	})

	t.Run("the directory cannot be created", func(t *testing.T) {
		parent := tempDir(t)
		readonly := filepath.Join(parent, "readonly")
		mkdirAll(t, readonly, 0o500)
		t.Cleanup(func() { _ = os.Chmod(readonly, 0o700) })
		path := filepath.Join(readonly, "sub", "authorized_keys")
		if _, err := Apply(nil, Options{Path: path}); err == nil ||
			!strings.Contains(err.Error(), "create directory") {
			t.Fatalf("Apply error = %v, want a create-directory failure", err)
		}
	})

	t.Run("the directory mode cannot be set", func(t *testing.T) {
		boom := errors.New("boom")
		defer swapHooks(t, func(h *hooks) {
			h.chmodPath = func(string, fs.FileMode) error { return boom }
		})()
		path := filepath.Join(tempDir(t), "sub", "authorized_keys")
		_, err := Apply(nil, Options{Path: path})
		if err == nil || !strings.Contains(err.Error(), "set directory mode") || !errors.Is(err, boom) {
			t.Fatalf("Apply error = %v, want a set-directory-mode failure", err)
		}
	})

	t.Run("the directory cannot be opened as a root", func(t *testing.T) {
		parent := tempDir(t)
		locked := filepath.Join(parent, "locked")
		mkdirAll(t, locked, 0o000)
		t.Cleanup(func() { _ = os.Chmod(locked, 0o700) })
		// A dry run stats the directory (which succeeds from the parent) and
		// then opens it, which is where the permission failure lands.
		path := filepath.Join(locked, "authorized_keys")
		if _, err := Apply(nil, Options{Path: path, DryRun: true}); err == nil ||
			!strings.Contains(err.Error(), "open directory") {
			t.Fatalf("Apply error = %v, want an open-directory failure", err)
		}
	})
}

// TestApplyCannotReadTarget covers the unreadable-target path: the file exists
// and is regular, but opening it fails.
func TestApplyCannotReadTarget(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: permission checks do not apply")
	}
	dir := tempDir(t)
	setUmask(t)
	path := filepath.Join(dir, "authorized_keys")
	writeFile(t, path, "own\n", 0o000)

	if _, err := Apply(nil, Options{Path: path}); err == nil ||
		!strings.Contains(err.Error(), "open target") {
		t.Fatalf("Apply error = %v, want an open-target failure", err)
	}
}

// TestApplyDryRunOnMissingDirectory reports a would-create without touching
// the filesystem, which is what an operator checking a fresh host sees.
func TestApplyDryRunOnMissingDirectory(t *testing.T) {
	dir := filepath.Join(tempDir(t), ".ssh")
	rep, err := Apply([]string{keyLine(t, 25, "k")}, Options{Path: filepath.Join(dir, "authorized_keys"), DryRun: true})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !rep.Changed || rep.Existed || rep.Mode != 0o600 || rep.Size == 0 {
		t.Fatalf("report = %+v", rep)
	}
	if _, err := os.Stat(dir); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("dry run created the directory: %v", err)
	}
}

// TestApplyRelativePath covers a target named without a directory component,
// which resolves against the working directory.
func TestApplyRelativePath(t *testing.T) {
	dir := tempDir(t)
	t.Chdir(dir)
	setUmask(t)

	rep, err := Apply([]string{keyLine(t, 26, "k")}, Options{Path: "authorized_keys"})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !rep.Changed || rep.Path != "authorized_keys" {
		t.Fatalf("report = %+v", rep)
	}
	if got := readFile(t, filepath.Join(dir, "authorized_keys")); !strings.HasPrefix(got, BeginMarker) {
		t.Fatalf("file = %q", got)
	}
}

// TestApplyTargetStatFails covers an lstat that fails for a reason other than
// the file being absent.
func TestApplyTargetStatFails(t *testing.T) {
	dir := tempDir(t)
	setUmask(t)
	// A name beyond NAME_MAX cannot be stat'ed, opened, or created.
	path := filepath.Join(dir, strings.Repeat("n", 300))

	if _, err := Apply(nil, Options{Path: path}); err == nil ||
		!strings.Contains(err.Error(), "stat target") {
		t.Fatalf("Apply error = %v, want a stat-target failure", err)
	}
}

// TestApplyReadFails covers an I/O error part-way through reading the existing
// file: the merge must never run on a truncated view of the user's keys.
func TestApplyReadFails(t *testing.T) {
	dir := tempDir(t)
	setUmask(t)
	path := filepath.Join(dir, "authorized_keys")
	const original = "own key\n"
	writeFile(t, path, original, 0o600)

	boom := errors.New("boom")
	defer swapHooks(t, func(h *hooks) {
		h.readAll = func(io.Reader) ([]byte, error) { return []byte("partial"), boom }
	})()

	_, err := Apply([]string{keyLine(t, 27, "k")}, Options{Path: path})
	if err == nil || !strings.Contains(err.Error(), "read target") || !errors.Is(err, boom) {
		t.Fatalf("Apply error = %v, want a read-target failure", err)
	}
	if readFile(t, path) != original {
		t.Fatalf("target was modified after a failed read")
	}
}
