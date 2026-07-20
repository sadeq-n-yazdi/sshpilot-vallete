package managedblock

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// setUmask installs a deliberately hostile umask for the duration of a test:
// 0o200 strips the owner-write bit that O_CREATE would otherwise grant, so a
// missing explicit chmod shows up as a wrong mode instead of being masked by
// the developer's umask. It is process-wide, so these tests are not parallel.
func setUmask(t *testing.T) {
	t.Helper()
	prev := syscall.Umask(0o200)
	t.Cleanup(func() { syscall.Umask(prev) })
}

// tempDir creates a scratch directory with a normal umask in force, so the
// hostile umask from setUmask cannot make the fixture itself unusable.
func tempDir(t *testing.T) string {
	t.Helper()
	prev := syscall.Umask(0o022)
	defer syscall.Umask(prev)
	return t.TempDir()
}

// mkdirAll creates a directory at exactly mode, defeating the test umask.
func mkdirAll(t *testing.T, dir string, mode fs.FileMode) {
	t.Helper()
	if err := os.MkdirAll(dir, mode); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}
	if err := os.Chmod(dir, mode); err != nil {
		t.Fatalf("chmod %s: %v", dir, err)
	}
}

func writeFile(t *testing.T, path, content string, mode fs.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatalf("chmod %s: %v", path, err)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

func TestApplyCreatesFileAndDirectory(t *testing.T) {
	setUmask(t)

	dir := filepath.Join(tempDir(t), ".ssh")
	path := filepath.Join(dir, "authorized_keys")
	line := keyLine(t, 11, "laptop")

	rep, err := Apply([]string{line}, Options{Path: path})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if rep.Existed || !rep.Changed {
		t.Fatalf("report = %+v, want Existed=false Changed=true", rep)
	}
	if want := begin + line + "\n" + end; readFile(t, path) != want {
		t.Fatalf("file = %q, want %q", readFile(t, path), want)
	}

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("file mode = %o, want 0600", fi.Mode().Perm())
	}
	di, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat dir: %v", err)
	}
	if di.Mode().Perm() != 0o700 {
		t.Fatalf("directory mode = %o, want 0700", di.Mode().Perm())
	}
	if rep.Mode != 0o600 || rep.Size != len(readFile(t, path)) {
		t.Fatalf("report = %+v", rep)
	}
}

func TestApplyIsIdempotent(t *testing.T) {
	setUmask(t)

	dir := tempDir(t)
	path := filepath.Join(dir, "authorized_keys")
	writeFile(t, path, "own key\n# comment", 0o600)
	lines := []string{keyLine(t, 12, "a"), keyLine(t, 13, "b")}

	if _, err := Apply(lines, Options{Path: path}); err != nil {
		t.Fatalf("first Apply: %v", err)
	}
	first := readFile(t, path)

	rep, err := Apply(lines, Options{Path: path})
	if err != nil {
		t.Fatalf("second Apply: %v", err)
	}
	if rep.Changed {
		t.Fatalf("second Apply reported a change")
	}
	if got := readFile(t, path); got != first {
		t.Fatalf("second Apply changed the bytes:\n%q\n%q", first, got)
	}
	// The one deliberate exception to byte-exactness: a single separator
	// newline is added on the first append and never again.
	if !strings.HasPrefix(first, "own key\n# comment\n"+BeginMarker) {
		t.Fatalf("unexpected layout: %q", first)
	}
}

func TestApplyPreservesForeignKeysOnDisk(t *testing.T) {
	setUmask(t)

	path := filepath.Join(tempDir(t), "authorized_keys")
	mine := keyLine(t, 14, "my-own-laptop")
	original := "# keep me\r\n" + mine + "\n\n"
	writeFile(t, path, original+begin+"stale\n"+end+"# tail\n", 0o600)

	if _, err := Apply([]string{keyLine(t, 15, "new")}, Options{Path: path}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	got := readFile(t, path)
	if !strings.HasPrefix(got, original) || !strings.HasSuffix(got, "# tail\n") {
		t.Fatalf("foreign content was not preserved: %q", got)
	}
	if !strings.Contains(got, mine) {
		t.Fatalf("the user's own key was lost: %q", got)
	}
}

func TestApplyPermissions(t *testing.T) {
	tests := []struct {
		name    string
		initial fs.FileMode
		want    fs.FileMode
	}{
		{"world readable is narrowed", 0o644, 0o600},
		{"group writable is narrowed", 0o660, 0o600},
		{"already correct is kept", 0o600, 0o600},
		{"narrower is preserved, never widened", 0o400, 0o400},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			setUmask(t)
			path := filepath.Join(tempDir(t), "authorized_keys")
			writeFile(t, path, "own\n", tc.initial)

			if _, err := Apply([]string{keyLine(t, 16, "k")}, Options{Path: path}); err != nil {
				t.Fatalf("Apply: %v", err)
			}
			fi, err := os.Stat(path)
			if err != nil {
				t.Fatalf("stat: %v", err)
			}
			if fi.Mode().Perm() != tc.want {
				t.Fatalf("mode = %o, want %o", fi.Mode().Perm(), tc.want)
			}
		})
	}
}

func TestApplyDryRunWritesNothing(t *testing.T) {
	setUmask(t)

	dir := filepath.Join(tempDir(t), ".ssh")
	path := filepath.Join(dir, "authorized_keys")

	rep, err := Apply([]string{keyLine(t, 17, "k")}, Options{Path: path, DryRun: true})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !rep.Changed || rep.Existed {
		t.Fatalf("report = %+v, want Changed=true Existed=false", rep)
	}
	if _, err := os.Stat(dir); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("dry run created the directory: %v", err)
	}

	// And on an already up-to-date file it reports no change.
	mkdirAll(t, dir, 0o700)
	writeFile(t, path, begin+keyLine(t, 17, "k")+"\n"+end, 0o600)
	before := readFile(t, path)
	rep, err = Apply([]string{keyLine(t, 17, "k")}, Options{Path: path, DryRun: true})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if rep.Changed || !rep.Existed {
		t.Fatalf("report = %+v, want Changed=false Existed=true", rep)
	}
	if readFile(t, path) != before {
		t.Fatalf("dry run modified the file")
	}
}

func TestApplyLeavesFileUntouchedOnMalformedMarkers(t *testing.T) {
	setUmask(t)

	path := filepath.Join(tempDir(t), "authorized_keys")
	original := end + keyLine(t, 18, "mine") + "\n" + begin
	writeFile(t, path, original, 0o600)

	_, err := Apply([]string{keyLine(t, 19, "new")}, Options{Path: path})
	if !errors.Is(err, ErrMalformedBlock) {
		t.Fatalf("Apply error = %v, want ErrMalformedBlock", err)
	}
	if readFile(t, path) != original {
		t.Fatalf("the file was modified despite the refusal")
	}
}

func TestApplyRejectsInvalidTargets(t *testing.T) {
	setUmask(t)

	t.Run("symlink is refused rather than followed", func(t *testing.T) {
		dir := tempDir(t)
		outside := filepath.Join(dir, "outside")
		writeFile(t, outside, "untouched\n", 0o600)
		path := filepath.Join(dir, "authorized_keys")
		if err := os.Symlink(outside, path); err != nil {
			t.Fatalf("symlink: %v", err)
		}
		_, err := Apply([]string{keyLine(t, 20, "k")}, Options{Path: path})
		if !errors.Is(err, ErrNotRegularFile) {
			t.Fatalf("Apply error = %v, want ErrNotRegularFile", err)
		}
		if readFile(t, outside) != "untouched\n" {
			t.Fatalf("the symlink target was written through")
		}
	})

	t.Run("directory is refused", func(t *testing.T) {
		dir := tempDir(t)
		path := filepath.Join(dir, "authorized_keys")
		mkdirAll(t, path, 0o700)
		if _, err := Apply(nil, Options{Path: path}); !errors.Is(err, ErrNotRegularFile) {
			t.Fatalf("Apply error = %v, want ErrNotRegularFile", err)
		}
	})

	t.Run("path without a file name is refused", func(t *testing.T) {
		for _, p := range []string{"", "/", "..", "/"} {
			if _, err := Apply(nil, Options{Path: p}); !errors.Is(err, ErrBadPath) {
				t.Fatalf("Apply(%q) error = %v, want ErrBadPath", p, err)
			}
		}
	})

	t.Run("oversized file is refused", func(t *testing.T) {
		path := filepath.Join(tempDir(t), "authorized_keys")
		writeFile(t, path, strings.Repeat("a", MaxFileBytes+1), 0o600)
		if _, err := Apply(nil, Options{Path: path}); !errors.Is(err, ErrTooLarge) {
			t.Fatalf("Apply error = %v, want ErrTooLarge", err)
		}
	})

	t.Run("invalid key set is rejected before anything is opened", func(t *testing.T) {
		path := filepath.Join(tempDir(t), "nested", "authorized_keys")
		_, err := Apply([]string{`command="x" ` + keyLine(t, 21, "k")}, Options{Path: path})
		if err == nil {
			t.Fatal("Apply accepted an option-bearing key")
		}
		if _, statErr := os.Stat(filepath.Dir(path)); !errors.Is(statErr, fs.ErrNotExist) {
			t.Fatalf("the directory was created despite the rejection: %v", statErr)
		}
	})
}
