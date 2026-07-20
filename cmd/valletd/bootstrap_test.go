package main

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/service/bootstrap"
)

// runBootstrap drives the real subcommand against a throwaway SQLite file.
func runBootstrap(t *testing.T, args ...string) (string, error) {
	t.Helper()
	t.Setenv("VALLET_DATABASE_SQLITE_PATH", filepath.Join(t.TempDir(), "vallet.db"))
	var stdout, stderr bytes.Buffer
	err := runBootstrapOwner(args, &stdout, &stderr)
	return stdout.String(), err
}

// TestBootstrapOwnerDefaultSetFlagDoesNotBlockItself is the regression test for
// a bug this enforcement work introduced and caught: the -set flag used to
// default to the literal bootstrap.DefaultSetName, which made every invocation
// submit "default" as an explicit USER choice. "default" is itself a curated
// routing term, so the command refused to run at all.
//
// The flag must therefore default to empty, letting Seed apply the system
// fallback that is deliberately not blocklist-checked. Without this test,
// flipping the default back is a silent, total break of bootstrap-owner --
// and cmd/valletd has no other test that would notice.
func TestBootstrapOwnerDefaultSetFlagDoesNotBlockItself(t *testing.T) {
	out, err := runBootstrap(t, "-handle", "alice")
	if err != nil {
		t.Fatalf("bootstrap-owner -handle alice = %v, want success", err)
	}
	// The set actually created is the system default, and it is what gets
	// printed -- the operator must be told the real name, not the empty flag.
	if !strings.Contains(out, "set="+bootstrap.DefaultSetName+"\n") {
		t.Errorf("output %q does not report set=%s", out, bootstrap.DefaultSetName)
	}
	if !strings.Contains(out, "handle=alice\n") {
		t.Errorf("output %q does not report handle=alice", out)
	}
}

// TestBootstrapOwnerRefusesBlockedHandle proves the guard is reachable from the
// real command, not just from Seed's tests: the operator-facing entry point
// enforces the blocklist.
func TestBootstrapOwnerRefusesBlockedHandle(t *testing.T) {
	for _, handle := range []string{"admin", "adm1n", "support"} {
		out, err := runBootstrap(t, "-handle", handle)
		if err == nil {
			t.Errorf("bootstrap-owner -handle %s succeeded, want refusal", handle)
		}
		if out != "" {
			t.Errorf("refused bootstrap printed %q, want nothing", out)
		}
		// The operator-facing error must not name the matched rule either.
		if err != nil && strings.Contains(strings.ToLower(err.Error()), "routing") {
			t.Errorf("error %q leaks the list name", err)
		}
	}
}

// TestBootstrapOwnerRefusesBlockedExplicitSet pins the other half of the
// carve-out at the command level: a set name the operator actually typed is a
// user choice and is checked.
func TestBootstrapOwnerRefusesBlockedExplicitSet(t *testing.T) {
	if _, err := runBootstrap(t, "-handle", "alice", "-set", "root"); err == nil {
		t.Error("bootstrap-owner -set root succeeded, want refusal")
	}
	// An ordinary explicit set name still works.
	out, err := runBootstrap(t, "-handle", "alice", "-set", "laptops")
	if err != nil {
		t.Fatalf("bootstrap-owner -set laptops = %v, want success", err)
	}
	if !strings.Contains(out, "set=laptops\n") {
		t.Errorf("output %q does not report set=laptops", out)
	}
}
