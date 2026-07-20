// Package build_test verifies that the release build is reproducible.
//
// The claim "our builds are reproducible" is only worth anything if something
// checks it, so this test performs the check the definition implies: run the
// real release build script twice, into two separate output directories, and
// assert the resulting binaries are byte-identical.
//
// It deliberately drives scripts/build.sh rather than reimplementing the flags.
// A test that hard-coded its own -trimpath/-ldflags would pass happily while
// the script it is meant to certify drifted underneath it.
package build_test

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

// buildScript is the path to the release build script, relative to this file's
// package directory (internal/build).
const buildScript = "../../scripts/build.sh"

// testVersion is pinned so the two builds cannot differ merely because
// `git describe` produced different output between them.
const testVersion = "0.0.0-repro-test"

// testBinName is pinned so the test knows the output file name by
// construction. The build script honors BIN_NAME from the environment, so
// without this an ambient BIN_NAME would leave the test looking for a file the
// script never wrote.
//
// The test dictates the environment rather than re-deriving the script's
// defaulting rules. Mirroring that logic here would duplicate it, and the copy
// could drift from the script -- at which point the test either fails
// spuriously or, worse, silently hashes the wrong file. It also matters that
// this test is hermetic: a reproducibility check whose own behavior varies
// with ambient environment is a poor witness for "this build is deterministic".
const testBinName = "valletd-repro-test"

func TestBuildIsReproducible(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping reproducible build check in -short mode: it compiles the binary twice")
	}
	if runtime.GOOS == "windows" {
		t.Skip("build script requires a POSIX shell")
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skipf("bash not available: %v", err)
	}
	if _, err := os.Stat(buildScript); err != nil {
		t.Fatalf("build script not found: %v", err)
	}

	first := buildOnce(t, "first")
	second := buildOnce(t, "second")

	if first != second {
		t.Errorf("build is not reproducible:\n  first  sha256=%s\n  second sha256=%s", first, second)
	}
}

// TestBinariesDifferWhenContentDiffers is the control for the test above.
//
// It proves the comparison is capable of reporting a difference at all. Without
// it, a hashing bug that made every input hash to the same value would render
// TestBuildIsReproducible a permanently green no-op -- a test that cannot fail
// is indistinguishable from no test.
func TestBinariesDifferWhenContentDiffers(t *testing.T) {
	dir := t.TempDir()

	a := filepath.Join(dir, "a")
	b := filepath.Join(dir, "b")
	if err := os.WriteFile(a, []byte("alpha"), 0o600); err != nil {
		t.Fatalf("write a: %v", err)
	}
	if err := os.WriteFile(b, []byte("beta"), 0o600); err != nil {
		t.Fatalf("write b: %v", err)
	}

	if sha256File(t, a) == sha256File(t, b) {
		t.Fatal("sha256File returned equal digests for different content; the reproducibility check cannot detect drift")
	}
}

// buildOnce runs the release build script into its own output directory and
// returns the SHA-256 of the produced binary.
func buildOnce(t *testing.T, label string) string {
	t.Helper()

	outDir := filepath.Join(t.TempDir(), label)

	cmd := exec.Command("bash", buildScript)

	// Every input the script reads is pinned explicitly, appended after
	// os.Environ() so these values win over anything ambient. That makes the
	// output path known by construction and keeps the two builds differing in
	// nothing but the directory they are written to.
	cmd.Env = append(os.Environ(),
		"OUT_DIR="+outDir,
		"VERSION="+testVersion,
		"BIN_NAME="+testBinName,
		"GOOS="+runtime.GOOS,
		"GOARCH="+runtime.GOARCH,
	)

	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("build (%s) failed: %v\n%s", label, err, out)
	}

	return sha256File(t, filepath.Join(outDir, testBinName))
}

// sha256File returns the hex-encoded SHA-256 digest of the named file.
func sha256File(t *testing.T, path string) string {
	t.Helper()

	f, err := os.Open(path) //nolint:gosec // path is constructed by the test itself
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer func() { _ = f.Close() }()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		t.Fatalf("hash %s: %v", path, err)
	}
	return hex.EncodeToString(h.Sum(nil))
}
