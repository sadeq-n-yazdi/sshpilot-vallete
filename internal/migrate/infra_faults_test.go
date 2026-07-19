package migrate

import (
	"context"
	"errors"
	"testing"
)

// TestLoadLedgerScanErrorPropagates covers the driver-level Scan failure path
// in loadLedger: a Scan error is wrapped under a static prefix and surfaced,
// never silently dropped.
func TestLoadLedgerScanErrorPropagates(t *testing.T) {
	ctx := context.Background()
	m := mig("0001", "one")
	db := newFakeDB(EngineSQLite)
	db.seedLedger(appliedRow(m, EngineSQLite, fixedClock()))
	sentinel := errors.New("driver scan failure")
	db.scanErr = sentinel
	if _, err := loadLedger(ctx, db); !errors.Is(err, sentinel) {
		t.Fatalf("expected propagated scan error, got %v", err)
	}
}

// TestTablePresentScanErrorPropagates covers the Scan failure path inside
// tablePresent, exercised through the catalog query.
func TestTablePresentScanErrorPropagates(t *testing.T) {
	ctx := context.Background()
	db := newFakeDB(EngineSQLite)
	db.seedTable("widgets")
	sentinel := errors.New("driver scan failure")
	db.scanErr = sentinel
	if _, err := tablePresent(ctx, db, EngineSQLite, "widgets"); !errors.Is(err, sentinel) {
		t.Fatalf("expected propagated scan error, got %v", err)
	}
}

// TestTableExistsForwardsInfraError covers the error-forward branch in the
// TableExists / TableAbsent Check closures: an infrastructure failure from the
// catalog read is returned unchanged, not swallowed into a "table absent"
// answer.
func TestTableExistsForwardsInfraError(t *testing.T) {
	ctx := context.Background()
	db := newFakeDB(EngineSQLite)
	sentinel := errors.New("catalog unavailable")
	db.queryErr = func(string) error { return sentinel }
	if err := TableExists("widgets").Check(ctx, db, EngineSQLite); !errors.Is(err, sentinel) {
		t.Errorf("TableExists must forward infra error, got %v", err)
	}
	if err := TableAbsent("widgets").Check(ctx, db, EngineSQLite); !errors.Is(err, sentinel) {
		t.Errorf("TableAbsent must forward infra error, got %v", err)
	}
}

// TestVerifyLedgerLongerThanRegistry covers the fast-path guard: a ledger with
// more rows than the registry contains fails with ErrLedgerAhead before the
// per-row loop, and nothing is applied.
func TestVerifyLedgerLongerThanRegistry(t *testing.T) {
	ctx := context.Background()
	m := mig("0001", "one")
	db := newFakeDB(EngineSQLite)
	db.seedLedger(appliedRow(m, EngineSQLite, fixedClock()))
	db.seedLedger(appliedRow(mig("0002", "two"), EngineSQLite, fixedClock()))
	r := mustRunner(t, db, EngineSQLite, mustRegistry(t, m))
	if _, err := r.Up(ctx); !errors.Is(err, ErrLedgerAhead) {
		t.Fatalf("expected ErrLedgerAhead, got %v", err)
	}
	if _, err := r.Status(ctx); !errors.Is(err, ErrLedgerAhead) {
		t.Fatalf("Status expected ErrLedgerAhead, got %v", err)
	}
}

// TestStepsForEngineUnknownEngine covers the defensive default branch of
// Steps.forEngine, which yields nil for an engine the runner never constructs.
func TestStepsForEngineUnknownEngine(t *testing.T) {
	s := Steps{SQLite: []string{"CREATE TABLE t (id INTEGER)"}, Postgres: []string{"CREATE TABLE t (id INT)"}}
	if got := s.forEngine(Engine("nonexistent")); got != nil {
		t.Errorf("forEngine(unknown) = %v, want nil", got)
	}
}
