package migrate

import (
	"errors"
	"testing"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
)

// mig builds a minimal valid migration with the given ID and name.
func mig(id, name string) Migration {
	return Migration{
		ID:   id,
		Name: name,
		Up: Steps{
			SQLite:   []string{"CREATE TABLE " + name + " (id TEXT)"},
			Postgres: []string{"CREATE TABLE " + name + " (id TEXT)"},
		},
		Down: Steps{
			SQLite:   []string{"DROP TABLE " + name},
			Postgres: []string{"DROP TABLE " + name},
		},
	}
}

func TestNewRegistryValid(t *testing.T) {
	m2 := mig("0002", "second")
	m2.Requires = []string{"0001"}
	r, err := NewRegistry(mig("0001", "first"), m2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := r.All(); len(got) != 2 {
		t.Fatalf("All len = %d, want 2", len(got))
	}
	if _, ok := r.Get("0002"); !ok {
		t.Fatal("Get(0002) missing")
	}
	if _, ok := r.Get("9999"); ok {
		t.Fatal("Get(9999) should be absent")
	}
}

func TestDefaultRegistryEmpty(t *testing.T) {
	r := Default()
	if len(r.All()) != 0 {
		t.Fatal("default registry must be empty")
	}
}

func TestNewRegistryInvalidCases(t *testing.T) {
	irreversible := func() Migration {
		m := mig("0001", "one")
		m.Down = Steps{}
		m.IrreversibleReason = "data loss"
		return m
	}

	cases := map[string][]Migration{
		"malformed id short":    {mig("001", "one")},
		"malformed id nondigit": {mig("00a1", "one")},
		"duplicate id":          {mig("0001", "one"), mig("0001", "two")},
		"not ascending":         {mig("0002", "two"), mig("0001", "one")},
		"empty name":            {mig("0001", "")},
		"empty up sqlite":       {func() Migration { m := mig("0001", "one"); m.Up.SQLite = nil; return m }()},
		"empty up postgres":     {func() Migration { m := mig("0001", "one"); m.Up.Postgres = nil; return m }()},
		"empty down reversible": {func() Migration { m := mig("0001", "one"); m.Down.SQLite = nil; return m }()},
		"unknown requires":      {func() Migration { m := mig("0001", "one"); m.Requires = []string{"0000"}; return m }()},
		"self requires":         {func() Migration { m := mig("0001", "one"); m.Requires = []string{"0001"}; return m }()},
		"forward requires": {
			func() Migration { m := mig("0001", "one"); m.Requires = []string{"0002"}; return m }(),
			mig("0002", "two"),
		},
		"empty precondition desc": {func() Migration {
			m := mig("0001", "one")
			m.Preconditions = []Precondition{{Description: ""}}
			return m
		}()},
	}

	for name, ms := range cases {
		r, err := NewRegistry(ms...)
		if err == nil {
			t.Errorf("%s: expected error, got nil registry=%v", name, r)
			continue
		}
		if !errors.Is(err, ErrInvalidRegistry) || !errors.Is(err, domain.ErrInvalidInput) {
			t.Errorf("%s: error %v does not wrap ErrInvalidRegistry/ErrInvalidInput", name, err)
		}
	}

	// Irreversible migration with no down steps is allowed.
	if _, err := NewRegistry(irreversible()); err != nil {
		t.Errorf("irreversible migration without down steps should be valid: %v", err)
	}
}

func TestNewRegistryDefensiveCopyInput(t *testing.T) {
	up := []string{"CREATE TABLE t (id TEXT)"}
	m := Migration{
		ID:   "0001",
		Name: "one",
		Up:   Steps{SQLite: up, Postgres: []string{"CREATE TABLE t (id TEXT)"}},
		Down: Steps{SQLite: []string{"DROP TABLE t"}, Postgres: []string{"DROP TABLE t"}},
	}
	r, err := NewRegistry(m)
	if err != nil {
		t.Fatal(err)
	}
	before := ChecksumFor(mustGet(t, r, "0001"), EngineSQLite)
	// Mutate the caller's slice after construction.
	up[0] = "DROP DATABASE prod"
	after := ChecksumFor(mustGet(t, r, "0001"), EngineSQLite)
	if before != after {
		t.Fatal("registry did not defensively copy input steps")
	}
}

func TestAllIsDefensiveCopy(t *testing.T) {
	r, err := NewRegistry(mig("0001", "one"))
	if err != nil {
		t.Fatal(err)
	}
	got := r.All()
	got[0].Up.SQLite[0] = "DROP DATABASE prod"
	if ChecksumFor(mustGet(t, r, "0001"), EngineSQLite) != ChecksumFor(mig("0001", "one"), EngineSQLite) {
		t.Fatal("mutating All() result affected the registry")
	}
}

func mustGet(t *testing.T, r *Registry, id string) Migration {
	t.Helper()
	m, ok := r.Get(id)
	if !ok {
		t.Fatalf("migration %q missing", id)
	}
	return m
}
