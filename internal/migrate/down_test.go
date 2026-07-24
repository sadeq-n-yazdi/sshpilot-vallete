package migrate

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
)

func applyAll(t *testing.T, r *Runner) {
	t.Helper()
	if _, err := r.Up(context.Background()); err != nil {
		t.Fatalf("Up: %v", err)
	}
}

func TestDownToTarget(t *testing.T) {
	ctx := context.Background()
	reg := mustRegistry(t, mig("0001", "one"), mig("0002", "two"), mig("0003", "three"))
	db := newFakeDB(EngineSQLite)
	r := mustRunner(t, db, EngineSQLite, reg)
	applyAll(t, r)

	reverted, err := r.Down(ctx, "0001")
	if err != nil {
		t.Fatalf("Down: %v", err)
	}
	// Newest-first: 0003 then 0002.
	if len(reverted) != 2 || reverted[0].ID != "0003" || reverted[1].ID != "0002" {
		t.Fatalf("reverted = %+v, want 0003 then 0002", reverted)
	}
	if ids := db.appliedIDs(); len(ids) != 1 || ids[0] != "0001" {
		t.Fatalf("ledger = %v, want [0001]", ids)
	}
}

func TestDownAll(t *testing.T) {
	ctx := context.Background()
	reg := mustRegistry(t, mig("0001", "one"), mig("0002", "two"))
	db := newFakeDB(EngineSQLite)
	r := mustRunner(t, db, EngineSQLite, reg)
	applyAll(t, r)

	reverted, err := r.Down(ctx, "")
	if err != nil {
		t.Fatalf("Down all: %v", err)
	}
	if len(reverted) != 2 {
		t.Fatalf("reverted %d, want 2", len(reverted))
	}
	if ids := db.appliedIDs(); len(ids) != 0 {
		t.Fatalf("ledger not empty after Down all: %v", ids)
	}
	// Down again with nothing applied is a no-op.
	again, err := r.Down(ctx, "")
	if err != nil || again != nil {
		t.Fatalf("second Down all = (%v, %v), want (nil, nil)", again, err)
	}
}

func TestDownUnknownTarget(t *testing.T) {
	ctx := context.Background()
	reg := mustRegistry(t, mig("0001", "one"))
	db := newFakeDB(EngineSQLite)
	r := mustRunner(t, db, EngineSQLite, reg)
	applyAll(t, r)

	if _, err := r.Down(ctx, "0099"); !errors.Is(err, ErrUnknownTarget) || !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("expected ErrUnknownTarget, got %v", err)
	}
	if ids := db.appliedIDs(); len(ids) != 1 {
		t.Errorf("ledger changed on unknown-target Down: %v", ids)
	}
}

func TestDownVerifiesFirst(t *testing.T) {
	ctx := context.Background()
	m := mig("0001", "one")
	db := newFakeDB(EngineSQLite)
	bad := appliedRow(m, EngineSQLite, fixedClock())
	bad.checksum = "tampered"
	db.seedLedger(bad)
	r := mustRunner(t, db, EngineSQLite, mustRegistry(t, m))
	if _, err := r.Down(ctx, ""); !errors.Is(err, ErrChecksumMismatch) {
		t.Fatalf("Down must verify first: got %v", err)
	}
}

func TestDownDestructiveGating(t *testing.T) {
	ctx := context.Background()
	m := mig("0001", "one")
	m.Destructive = true
	reg := mustRegistry(t, m)

	// Blocked without the option.
	db := newFakeDB(EngineSQLite)
	r := mustRunner(t, db, EngineSQLite, reg)
	applyAll(t, r)
	if _, err := r.Down(ctx, ""); !errors.Is(err, ErrDestructiveBlocked) || !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("expected ErrDestructiveBlocked, got %v", err)
	}
	if ids := db.appliedIDs(); len(ids) != 1 {
		t.Errorf("pre-flight must not touch the ledger: %v", ids)
	}

	// Allowed with AllowDestructive.
	db2 := newFakeDB(EngineSQLite)
	r2 := mustRunner(t, db2, EngineSQLite, reg, AllowDestructive())
	applyAll(t, r2)
	if _, err := r2.Down(ctx, ""); err != nil {
		t.Fatalf("Down with AllowDestructive: %v", err)
	}
	if ids := db2.appliedIDs(); len(ids) != 0 {
		t.Errorf("ledger not cleared: %v", ids)
	}
}

func TestDownIrreversibleGating(t *testing.T) {
	ctx := context.Background()
	m := mig("0001", "one")
	m.Down = Steps{}
	m.IrreversibleReason = "drops audit history"
	reg := mustRegistry(t, m)

	// Even with AllowDestructive, an irreversible migration cannot be reverted.
	db := newFakeDB(EngineSQLite)
	r := mustRunner(t, db, EngineSQLite, reg, AllowDestructive())
	applyAll(t, r)
	if _, err := r.Down(ctx, ""); !errors.Is(err, ErrIrreversible) || !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("expected ErrIrreversible, got %v", err)
	}
	if ids := db.appliedIDs(); len(ids) != 1 {
		t.Errorf("pre-flight must not touch the ledger: %v", ids)
	}
}

func TestDownPreflightRejectsWholeBatch(t *testing.T) {
	ctx := context.Background()
	m1 := mig("0001", "one")
	m2 := mig("0002", "two")
	m2.Down = Steps{}
	m2.IrreversibleReason = "no going back"
	db := newFakeDB(EngineSQLite)
	r := mustRunner(t, db, EngineSQLite, mustRegistry(t, m1, m2), AllowDestructive())
	applyAll(t, r)

	// Down all would revert 0002 (irreversible) and 0001; must refuse both.
	if _, err := r.Down(ctx, ""); !errors.Is(err, ErrIrreversible) {
		t.Fatalf("expected ErrIrreversible, got %v", err)
	}
	if ids := db.appliedIDs(); len(ids) != 2 {
		t.Errorf("pre-flight must leave both applied: %v", ids)
	}
}

func TestDownEngineSelectionPostgres(t *testing.T) {
	ctx := context.Background()
	m := Migration{
		ID:   "0001",
		Name: "one",
		Up:   Steps{SQLite: []string{"CREATE TABLE s (id TEXT)"}, Postgres: []string{"CREATE TABLE p (id UUID)"}},
		Down: Steps{SQLite: []string{"DROP TABLE s"}, Postgres: []string{"DROP TABLE p"}},
	}
	db := newFakeDB(EnginePostgres)
	r := mustRunner(t, db, EnginePostgres, mustRegistry(t, m))
	applyAll(t, r)
	if _, err := r.Down(ctx, ""); err != nil {
		t.Fatal(err)
	}
	var sawDropP, sawDeleteDollar bool
	for _, e := range db.execLog {
		if strings.Contains(e.query, "DROP TABLE p") {
			sawDropP = true
		}
		if strings.Contains(e.query, "DELETE FROM schema_migrations") && strings.Contains(e.query, "$1") {
			sawDeleteDollar = true
		}
	}
	if !sawDropP {
		t.Error("postgres down step not executed")
	}
	if !sawDeleteDollar {
		t.Error("ledger delete did not use $N placeholders")
	}
}
