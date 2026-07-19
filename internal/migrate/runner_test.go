package migrate

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
)

var fixedClock = func() time.Time { return time.Date(2026, 7, 19, 10, 0, 0, 0, time.UTC) }

func mustRegistry(t *testing.T, ms ...Migration) *Registry {
	t.Helper()
	r, err := NewRegistry(ms...)
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	return r
}

func mustRunner(t *testing.T, db DB, engine Engine, reg *Registry, opts ...Option) *Runner {
	t.Helper()
	r, err := NewRunner(db, engine, reg, append([]Option{WithClock(fixedClock)}, opts...)...)
	if err != nil {
		t.Fatalf("NewRunner: %v", err)
	}
	return r
}

// appliedRow builds a ledger row matching a migration for the given engine.
func appliedRow(m Migration, engine Engine, at time.Time) ledgerRow {
	return ledgerRow{
		id:        m.ID,
		name:      m.Name,
		checksum:  ChecksumFor(m, engine),
		appliedAt: at.UTC().Format(time.RFC3339),
		engine:    string(engine),
	}
}

func TestNewRunnerValidation(t *testing.T) {
	reg := mustRegistry(t)
	db := newFakeDB(EngineSQLite)
	cases := []struct {
		name   string
		db     DB
		engine Engine
		reg    *Registry
	}{
		{"nil db", nil, EngineSQLite, reg},
		{"nil reg", db, EngineSQLite, nil},
		{"bad engine", db, Engine("mysql"), reg},
	}
	for _, tc := range cases {
		if _, err := NewRunner(tc.db, tc.engine, tc.reg); !errors.Is(err, domain.ErrInvalidInput) {
			t.Errorf("%s: expected ErrInvalidInput, got %v", tc.name, err)
		}
	}
	if _, err := NewRunner(db, EngineSQLite, reg); err != nil {
		t.Errorf("valid args: unexpected error %v", err)
	}
}

func TestUpHappyAndIdempotent(t *testing.T) {
	ctx := context.Background()
	reg := mustRegistry(t, mig("0001", "one"), mig("0002", "two"))
	db := newFakeDB(EngineSQLite)
	r := mustRunner(t, db, EngineSQLite, reg)

	applied, err := r.Up(ctx)
	if err != nil {
		t.Fatalf("Up: %v", err)
	}
	if len(applied) != 2 || applied[0].ID != "0001" || applied[1].ID != "0002" {
		t.Fatalf("applied = %+v, want 0001,0002", applied)
	}
	if !applied[0].AppliedAt.Equal(fixedClock()) {
		t.Errorf("applied_at = %v, want fixed clock", applied[0].AppliedAt)
	}

	// Idempotent re-run.
	applied2, err := r.Up(ctx)
	if err != nil {
		t.Fatalf("Up re-run: %v", err)
	}
	if applied2 != nil {
		t.Errorf("re-run applied = %+v, want nil", applied2)
	}
	if ids := db.appliedIDs(); len(ids) != 2 {
		t.Errorf("ledger has %v, want 2 rows", ids)
	}
}

func TestUpEmptyRegistryNoop(t *testing.T) {
	ctx := context.Background()
	r := mustRunner(t, newFakeDB(EngineSQLite), EngineSQLite, mustRegistry(t))
	applied, err := r.Up(ctx)
	if err != nil || applied != nil {
		t.Fatalf("empty Up = (%v, %v), want (nil, nil)", applied, err)
	}
}

func TestUpPreconditionFailRollsBack(t *testing.T) {
	ctx := context.Background()
	m := mig("0001", "widgets")
	m.Preconditions = []Precondition{{
		Description: "widgets table must be absent",
		Check: func(context.Context, Executor, Engine) error {
			return fmt.Errorf("table widgets already exists: %w", domain.ErrConflict)
		},
	}}
	db := newFakeDB(EngineSQLite)
	r := mustRunner(t, db, EngineSQLite, mustRegistry(t, m))

	_, err := r.Up(ctx)
	if !errors.Is(err, ErrPreconditionFailed) || !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("expected ErrPreconditionFailed, got %v", err)
	}
	if ids := db.appliedIDs(); len(ids) != 0 {
		t.Errorf("ledger not empty after precondition rollback: %v", ids)
	}
	if strings.Contains(err.Error(), "already exists") {
		t.Errorf("error leaks the check's message: %q", err)
	}
}

func TestUpMidRunAtomicity(t *testing.T) {
	ctx := context.Background()
	m1 := mig("0001", "alpha")
	m2 := mig("0002", "beta")
	m2.Up.SQLite = []string{"CREATE TABLE beta_FAILS (id TEXT)"}
	db := newFakeDB(EngineSQLite)
	db.execErr = func(query string, _ []any) error {
		if strings.Contains(query, "beta_FAILS") {
			return errors.New("disk full")
		}
		return nil
	}
	r := mustRunner(t, db, EngineSQLite, mustRegistry(t, m1, m2))

	applied, err := r.Up(ctx)
	if err == nil {
		t.Fatal("expected error from failing migration 0002")
	}
	if len(applied) != 1 || applied[0].ID != "0001" {
		t.Fatalf("applied-so-far = %+v, want just 0001", applied)
	}
	ids := db.appliedIDs()
	if len(ids) != 1 || ids[0] != "0001" {
		t.Fatalf("ledger = %v, want only 0001 committed", ids)
	}
}

func TestVerifyChecksumMismatchRefuses(t *testing.T) {
	ctx := context.Background()
	m := mig("0001", "one")
	db := newFakeDB(EngineSQLite)
	bad := appliedRow(m, EngineSQLite, fixedClock())
	bad.checksum = "deadbeef"
	db.seedLedger(bad)
	r := mustRunner(t, db, EngineSQLite, mustRegistry(t, m))

	if _, err := r.Up(ctx); !errors.Is(err, ErrChecksumMismatch) {
		t.Errorf("Up: expected ErrChecksumMismatch, got %v", err)
	}
	if _, err := r.Status(ctx); !errors.Is(err, ErrChecksumMismatch) {
		t.Errorf("Status: expected ErrChecksumMismatch, got %v", err)
	}
}

func TestVerifyLedgerAhead(t *testing.T) {
	ctx := context.Background()
	db := newFakeDB(EngineSQLite)
	db.seedLedger(ledgerRow{id: "0009", name: "ghost", checksum: "x", appliedAt: fixedClock().Format(time.RFC3339), engine: "sqlite"})
	r := mustRunner(t, db, EngineSQLite, mustRegistry(t, mig("0001", "one")))
	if _, err := r.Up(ctx); !errors.Is(err, ErrLedgerAhead) {
		t.Errorf("expected ErrLedgerAhead, got %v", err)
	}
}

func TestVerifyLedgerOrderGap(t *testing.T) {
	ctx := context.Background()
	m1, m2, m3 := mig("0001", "one"), mig("0002", "two"), mig("0003", "three")
	db := newFakeDB(EngineSQLite)
	db.seedLedger(appliedRow(m1, EngineSQLite, fixedClock()))
	db.seedLedger(appliedRow(m3, EngineSQLite, fixedClock())) // gap: 0002 missing
	r := mustRunner(t, db, EngineSQLite, mustRegistry(t, m1, m2, m3))
	if _, err := r.Up(ctx); !errors.Is(err, ErrLedgerOrder) {
		t.Errorf("expected ErrLedgerOrder, got %v", err)
	}
}

func TestVerifyEngineMismatch(t *testing.T) {
	ctx := context.Background()
	m := mig("0001", "one")
	db := newFakeDB(EngineSQLite)
	db.seedLedger(appliedRow(m, EnginePostgres, fixedClock())) // applied under postgres
	r := mustRunner(t, db, EngineSQLite, mustRegistry(t, m))
	if _, err := r.Up(ctx); !errors.Is(err, ErrEngineMismatch) {
		t.Errorf("expected ErrEngineMismatch, got %v", err)
	}
}

func TestStatusPartial(t *testing.T) {
	ctx := context.Background()
	reg := mustRegistry(t, mig("0001", "one"), mig("0002", "two"))
	db := newFakeDB(EngineSQLite)
	r := mustRunner(t, db, EngineSQLite, reg)

	st, err := r.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Applied) != 0 || len(st.Pending) != 2 {
		t.Fatalf("initial status = %+v, want 0 applied 2 pending", st)
	}

	if _, err := r.applyOne(ctx, mig("0001", "one")); err != nil {
		t.Fatal(err)
	}
	st, err = r.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Applied) != 1 || st.Applied[0].ID != "0001" {
		t.Fatalf("applied = %+v, want [0001]", st.Applied)
	}
	if len(st.Pending) != 1 || st.Pending[0] != "0002" {
		t.Fatalf("pending = %+v, want [0002]", st.Pending)
	}
}

func TestEngineSelectionPostgres(t *testing.T) {
	ctx := context.Background()
	m := Migration{
		ID:   "0001",
		Name: "one",
		Up: Steps{
			SQLite:   []string{"CREATE TABLE s_only (id TEXT)"},
			Postgres: []string{"CREATE TABLE p_only (id UUID)"},
		},
		Down: Steps{
			SQLite:   []string{"DROP TABLE s_only"},
			Postgres: []string{"DROP TABLE p_only"},
		},
	}
	db := newFakeDB(EnginePostgres)
	r := mustRunner(t, db, EnginePostgres, mustRegistry(t, m))
	applied, err := r.Up(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if applied[0].Checksum != ChecksumFor(m, EnginePostgres) {
		t.Error("ledger checksum must be the postgres checksum")
	}

	var sawPostgresDDL, sawInsertDollar bool
	for _, e := range db.execLog {
		if strings.Contains(e.query, "p_only") {
			sawPostgresDDL = true
		}
		if strings.Contains(e.query, "s_only") {
			t.Errorf("postgres run executed the sqlite statement: %q", e.query)
		}
		if strings.Contains(e.query, "INSERT INTO schema_migrations") && strings.Contains(e.query, "$1") {
			sawInsertDollar = true
		}
	}
	if !sawPostgresDDL {
		t.Error("postgres DDL not executed")
	}
	if !sawInsertDollar {
		t.Error("ledger insert did not use $N placeholders")
	}
}

func TestCheckDependenciesUnmet(t *testing.T) {
	// Direct white-box test: reachable only with a crafted pending set whose
	// requirement is neither applied nor an earlier pending migration. The
	// registry's strictly-earlier rule makes this unreachable via the public
	// API, so it is exercised here as defense-in-depth.
	pending := []Migration{{ID: "0002", Name: "two", Requires: []string{"0001"}}}
	err := checkDependencies(map[string]bool{}, pending)
	if !errors.Is(err, ErrDependencyUnmet) || !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("expected ErrDependencyUnmet, got %v", err)
	}

	// Satisfied when the requirement is applied.
	if err := checkDependencies(map[string]bool{"0001": true}, pending); err != nil {
		t.Errorf("unexpected error when requirement applied: %v", err)
	}
	// Satisfied when the requirement is an earlier pending migration.
	ok := []Migration{{ID: "0001", Name: "one"}, {ID: "0002", Requires: []string{"0001"}}}
	if err := checkDependencies(map[string]bool{}, ok); err != nil {
		t.Errorf("unexpected error when requirement is earlier pending: %v", err)
	}
}
