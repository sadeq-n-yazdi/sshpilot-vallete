package migrate

import (
	"errors"
	"testing"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
)

func baseMigration() Migration {
	return Migration{
		ID:   "0001",
		Name: "create_widgets",
		Up: Steps{
			SQLite:   []string{"CREATE TABLE widgets (id TEXT)"},
			Postgres: []string{"CREATE TABLE widgets (id TEXT)"},
		},
		Down: Steps{
			SQLite:   []string{"DROP TABLE widgets"},
			Postgres: []string{"DROP TABLE widgets"},
		},
	}
}

func TestChecksumForStable(t *testing.T) {
	m := baseMigration()
	if got, want := ChecksumFor(m, EngineSQLite), ChecksumFor(m, EngineSQLite); got != want {
		t.Fatalf("checksum not stable: %q != %q", got, want)
	}
	// Known-length sanity: SHA-256 hex is 64 characters.
	if got := ChecksumFor(m, EngineSQLite); len(got) != 64 {
		t.Fatalf("checksum length = %d, want 64", len(got))
	}
}

func TestChecksumForPerEngineDiffers(t *testing.T) {
	m := baseMigration()
	m.Up.Postgres = []string{"CREATE TABLE widgets (id UUID)"}
	if ChecksumFor(m, EngineSQLite) == ChecksumFor(m, EnginePostgres) {
		t.Fatal("expected different checksums for differing per-engine steps")
	}
}

func TestChecksumForFieldSensitivity(t *testing.T) {
	base := ChecksumFor(baseMigration(), EngineSQLite)

	cases := map[string]func(m *Migration){
		"id":           func(m *Migration) { m.ID = "0002" },
		"name":         func(m *Migration) { m.Name = "create_gadgets" },
		"stmt text":    func(m *Migration) { m.Up.SQLite = []string{"CREATE TABLE widgets (id INT)"} },
		"stmt order":   func(m *Migration) { m.Up.SQLite = []string{"A", "B"} },
		"extra stmt":   func(m *Migration) { m.Up.SQLite = append(m.Up.SQLite, "VACUUM") },
		"down ignored": func(m *Migration) { m.Down.SQLite = []string{"DROP TABLE gone"} },
	}
	for name, mutate := range cases {
		m := baseMigration()
		mutate(&m)
		got := ChecksumFor(m, EngineSQLite)
		if name == "down ignored" {
			if got != base {
				t.Errorf("%s: checksum changed but down steps must not affect it", name)
			}
			continue
		}
		if got == base {
			t.Errorf("%s: checksum unchanged but input differed", name)
		}
	}
}

func TestChecksumForOrderVsConcatenation(t *testing.T) {
	// The NUL separator must prevent statement-boundary ambiguity: ["AB"]
	// and ["A","B"] must not collide.
	joined := baseMigration()
	joined.Up.SQLite = []string{"AB"}
	split := baseMigration()
	split.Up.SQLite = []string{"A", "B"}
	if ChecksumFor(joined, EngineSQLite) == ChecksumFor(split, EngineSQLite) {
		t.Fatal("statement boundaries must be unambiguous in the checksum")
	}
}

func TestSentinelsWrapDomain(t *testing.T) {
	cases := []struct {
		err    error
		target error
	}{
		{ErrInvalidRegistry, domain.ErrInvalidInput},
		{ErrChecksumMismatch, domain.ErrConflict},
		{ErrLedgerAhead, domain.ErrConflict},
		{ErrLedgerOrder, domain.ErrConflict},
		{ErrEngineMismatch, domain.ErrConflict},
		{ErrDependencyUnmet, domain.ErrConflict},
		{ErrPreconditionFailed, domain.ErrConflict},
		{ErrDestructiveBlocked, domain.ErrForbidden},
		{ErrIrreversible, domain.ErrForbidden},
		{ErrUnknownTarget, domain.ErrNotFound},
	}
	for _, tc := range cases {
		if !errors.Is(tc.err, tc.target) {
			t.Errorf("%v does not wrap %v", tc.err, tc.target)
		}
	}
}

func TestEngineValid(t *testing.T) {
	if !EngineSQLite.Valid() || !EnginePostgres.Valid() {
		t.Fatal("known engines must be valid")
	}
	if Engine("mysql").Valid() || Engine("").Valid() {
		t.Fatal("unknown/empty engines must be invalid")
	}
}
