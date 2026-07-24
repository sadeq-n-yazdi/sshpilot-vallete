package migrate

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func failLedgerCreate(query string, _ []any) error {
	if strings.Contains(query, "IF NOT EXISTS schema_migrations") {
		return errors.New("permission denied")
	}
	return nil
}

func TestEnsureLedgerTableErrorPropagates(t *testing.T) {
	ctx := context.Background()
	reg := mustRegistry(t, mig("0001", "one"))
	newRunnerFor := func() (*Runner, error) {
		db := newFakeDB(EngineSQLite)
		db.execErr = failLedgerCreate
		return NewRunner(db, EngineSQLite, reg, WithClock(fixedClock))
	}
	r, err := newRunnerFor()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Up(ctx); err == nil {
		t.Error("Up should surface ledger-table creation failure")
	}
	if _, err := r.Status(ctx); err == nil {
		t.Error("Status should surface ledger-table creation failure")
	}
	if _, err := r.Down(ctx, ""); err == nil {
		t.Error("Down should surface ledger-table creation failure")
	}
}

func TestUpBeginError(t *testing.T) {
	ctx := context.Background()
	db := newFakeDB(EngineSQLite)
	db.beginErr = errors.New("cannot start transaction")
	r := mustRunner(t, db, EngineSQLite, mustRegistry(t, mig("0001", "one")))
	if _, err := r.Up(ctx); !errors.Is(err, db.beginErr) {
		t.Fatalf("expected begin error, got %v", err)
	}
}

func TestUpCommitError(t *testing.T) {
	ctx := context.Background()
	db := newFakeDB(EngineSQLite)
	db.commitErr = errors.New("commit failed")
	r := mustRunner(t, db, EngineSQLite, mustRegistry(t, mig("0001", "one")))
	applied, err := r.Up(ctx)
	if !errors.Is(err, db.commitErr) {
		t.Fatalf("expected commit error, got %v", err)
	}
	if len(applied) != 0 {
		t.Errorf("no migration should be reported applied on commit failure: %+v", applied)
	}
	if ids := db.appliedIDs(); len(ids) != 0 {
		t.Errorf("commit failure must not persist a ledger row: %v", ids)
	}
}

func TestDownCommitError(t *testing.T) {
	ctx := context.Background()
	db := newFakeDB(EngineSQLite)
	r := mustRunner(t, db, EngineSQLite, mustRegistry(t, mig("0001", "one")))
	if _, err := r.Up(ctx); err != nil {
		t.Fatal(err)
	}
	db.commitErr = errors.New("commit failed")
	if _, err := r.Down(ctx, ""); !errors.Is(err, db.commitErr) {
		t.Fatalf("expected commit error from revert, got %v", err)
	}
}

func TestDownStepError(t *testing.T) {
	ctx := context.Background()
	m := mig("0001", "one")
	m.Down.SQLite = []string{"DROP TABLE fails_here"}
	db := newFakeDB(EngineSQLite)
	r := mustRunner(t, db, EngineSQLite, mustRegistry(t, m))
	if _, err := r.Up(ctx); err != nil {
		t.Fatal(err)
	}
	db.execErr = func(q string, _ []any) error {
		if strings.Contains(q, "fails_here") {
			return errors.New("io error")
		}
		return nil
	}
	if _, err := r.Down(ctx, ""); err == nil {
		t.Fatal("expected down-step error")
	}
	if ids := db.appliedIDs(); len(ids) != 1 {
		t.Errorf("failed revert must leave the ledger row: %v", ids)
	}
}

func TestUpLedgerInsertError(t *testing.T) {
	ctx := context.Background()
	db := newFakeDB(EngineSQLite)
	db.execErr = func(q string, _ []any) error {
		if strings.Contains(q, "INSERT INTO schema_migrations") {
			return errors.New("constraint violation")
		}
		return nil
	}
	r := mustRunner(t, db, EngineSQLite, mustRegistry(t, mig("0001", "one")))
	if _, err := r.Up(ctx); err == nil {
		t.Fatal("expected ledger-insert error")
	}
	if ids := db.appliedIDs(); len(ids) != 0 {
		t.Errorf("failed insert must not persist a row: %v", ids)
	}
}

func TestUpVerifyLoadError(t *testing.T) {
	ctx := context.Background()
	db := newFakeDB(EngineSQLite)
	db.rowsErr = errors.New("ledger read failed")
	r := mustRunner(t, db, EngineSQLite, mustRegistry(t, mig("0001", "one")))
	if _, err := r.Up(ctx); !errors.Is(err, db.rowsErr) {
		t.Fatalf("expected propagated verify load error, got %v", err)
	}
}

func TestDownBeginError(t *testing.T) {
	ctx := context.Background()
	db := newFakeDB(EngineSQLite)
	r := mustRunner(t, db, EngineSQLite, mustRegistry(t, mig("0001", "one")))
	if _, err := r.Up(ctx); err != nil {
		t.Fatal(err)
	}
	db.beginErr = errors.New("cannot start transaction")
	if _, err := r.Down(ctx, ""); !errors.Is(err, db.beginErr) {
		t.Fatalf("expected begin error from revert, got %v", err)
	}
}

func TestDownLedgerDeleteError(t *testing.T) {
	ctx := context.Background()
	db := newFakeDB(EngineSQLite)
	r := mustRunner(t, db, EngineSQLite, mustRegistry(t, mig("0001", "one")))
	if _, err := r.Up(ctx); err != nil {
		t.Fatal(err)
	}
	db.execErr = func(q string, _ []any) error {
		if strings.Contains(q, "DELETE FROM schema_migrations") {
			return errors.New("io error")
		}
		return nil
	}
	if _, err := r.Down(ctx, ""); err == nil {
		t.Fatal("expected ledger-delete error")
	}
	if ids := db.appliedIDs(); len(ids) != 1 {
		t.Errorf("failed delete must leave the ledger row: %v", ids)
	}
}

func TestLoadLedgerRowsErr(t *testing.T) {
	ctx := context.Background()
	db := newFakeDB(EngineSQLite)
	db.rowsErr = errors.New("row stream broke")
	if _, err := loadLedger(ctx, db); !errors.Is(err, db.rowsErr) {
		t.Fatalf("expected rows.Err propagation, got %v", err)
	}
}

// containsAny reports whether s contains any of subs.
func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// TestErrorHygiene asserts that verification and gating error messages never
// embed SQL statement text or ledger table internals. Engine names and
// migration IDs are permitted; SQL keywords and object names are not.
func TestErrorHygiene(t *testing.T) {
	ctx := context.Background()
	m := mig("0001", "one")

	var errs []error

	// Checksum mismatch.
	{
		db := newFakeDB(EngineSQLite)
		bad := appliedRow(m, EngineSQLite, fixedClock())
		bad.checksum = "tampered"
		db.seedLedger(bad)
		r := mustRunner(t, db, EngineSQLite, mustRegistry(t, m))
		_, err := r.Up(ctx)
		errs = append(errs, err)
	}
	// Ledger ahead.
	{
		db := newFakeDB(EngineSQLite)
		db.seedLedger(ledgerRow{id: "0009", name: "x", checksum: "c", appliedAt: fixedClock().Format("2006-01-02T15:04:05Z07:00"), engine: "sqlite"})
		r := mustRunner(t, db, EngineSQLite, mustRegistry(t, m))
		_, err := r.Up(ctx)
		errs = append(errs, err)
	}
	// Engine mismatch.
	{
		db := newFakeDB(EngineSQLite)
		db.seedLedger(appliedRow(m, EnginePostgres, fixedClock()))
		r := mustRunner(t, db, EngineSQLite, mustRegistry(t, m))
		_, err := r.Up(ctx)
		errs = append(errs, err)
	}
	// Precondition failed.
	{
		mp := mig("0001", "one")
		mp.Preconditions = []Precondition{TableAbsent("secretstuff")}
		db := newFakeDB(EngineSQLite)
		db.seedTable("secretstuff")
		r := mustRunner(t, db, EngineSQLite, mustRegistry(t, mp))
		_, err := r.Up(ctx)
		errs = append(errs, err)
	}
	// Destructive and irreversible gating, unknown target.
	{
		md := mig("0001", "one")
		md.Destructive = true
		db := newFakeDB(EngineSQLite)
		r := mustRunner(t, db, EngineSQLite, mustRegistry(t, md))
		applyAll(t, r)
		_, err := r.Down(ctx, "")
		errs = append(errs, err)
		_, err = r.Down(ctx, "0099")
		errs = append(errs, err)
	}

	sqlFragments := []string{
		"CREATE TABLE", "INSERT INTO", "DELETE FROM", "SELECT ",
		"schema_migrations", "sqlite_master", "information_schema", "VALUES",
	}
	for _, err := range errs {
		if err == nil {
			t.Fatal("expected a non-nil error in hygiene battery")
		}
		if containsAny(err.Error(), sqlFragments...) {
			t.Errorf("error leaks SQL/DB internals: %q", err)
		}
	}
}
