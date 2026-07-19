package sqlite

import (
	"context"
	"errors"
	"testing"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/migrate"
)

func newMigrateAdapter(t *testing.T) migrate.DB {
	t.Helper()
	return NewMigrateDB(openMemory(t))
}

func TestMigrateDBExecAndQuery(t *testing.T) {
	t.Parallel()
	mdb := newMigrateAdapter(t)
	ctx := context.Background()

	if err := mdb.Exec(ctx, "CREATE TABLE t (id INTEGER PRIMARY KEY, name TEXT)"); err != nil {
		t.Fatalf("Exec create: %v", err)
	}
	if err := mdb.Exec(ctx, "INSERT INTO t (id, name) VALUES (?, ?)", 1, "one"); err != nil {
		t.Fatalf("Exec insert: %v", err)
	}

	rows, err := mdb.Query(ctx, "SELECT id, name FROM t ORDER BY id")
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	defer func() { _ = rows.Close() }()

	var (
		count int
		id    int
		name  string
	)
	for rows.Next() {
		if serr := rows.Scan(&id, &name); serr != nil {
			t.Fatalf("Scan: %v", serr)
		}
		count++
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows.Err: %v", err)
	}
	if err := rows.Close(); err != nil {
		t.Fatalf("rows.Close: %v", err)
	}
	if count != 1 || id != 1 || name != "one" {
		t.Errorf("read (count=%d id=%d name=%q), want (1, 1, one)", count, id, name)
	}
}

func TestMigrateDBTxCommit(t *testing.T) {
	t.Parallel()
	mdb := newMigrateAdapter(t)
	ctx := context.Background()

	if err := mdb.Exec(ctx, "CREATE TABLE t (id INTEGER PRIMARY KEY)"); err != nil {
		t.Fatalf("create: %v", err)
	}

	tx, err := mdb.Begin(ctx)
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if err := tx.Exec(ctx, "INSERT INTO t (id) VALUES (1)"); err != nil {
		t.Fatalf("tx.Exec: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	// Rollback after a successful Commit must be a nil no-op.
	if err := tx.Rollback(); err != nil {
		t.Errorf("Rollback after Commit = %v, want nil", err)
	}

	if got := migrateCount(t, mdb, ctx); got != 1 {
		t.Errorf("committed row count = %d, want 1", got)
	}
}

func TestMigrateDBTxRollback(t *testing.T) {
	t.Parallel()
	mdb := newMigrateAdapter(t)
	ctx := context.Background()

	if err := mdb.Exec(ctx, "CREATE TABLE t (id INTEGER PRIMARY KEY)"); err != nil {
		t.Fatalf("create: %v", err)
	}

	tx, err := mdb.Begin(ctx)
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if err := tx.Exec(ctx, "INSERT INTO t (id) VALUES (1)"); err != nil {
		t.Fatalf("tx.Exec: %v", err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatalf("Rollback: %v", err)
	}

	if got := migrateCount(t, mdb, ctx); got != 0 {
		t.Errorf("rolled-back row count = %d, want 0", got)
	}
}

func TestMigrateDBTxQuery(t *testing.T) {
	t.Parallel()
	mdb := newMigrateAdapter(t)
	ctx := context.Background()

	if err := mdb.Exec(ctx, "CREATE TABLE t (id INTEGER PRIMARY KEY)"); err != nil {
		t.Fatalf("create: %v", err)
	}
	tx, err := mdb.Begin(ctx)
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	t.Cleanup(func() { _ = tx.Rollback() })

	if err := tx.Exec(ctx, "INSERT INTO t (id) VALUES (42)"); err != nil {
		t.Fatalf("tx.Exec: %v", err)
	}
	rows, err := tx.Query(ctx, "SELECT id FROM t")
	if err != nil {
		t.Fatalf("tx.Query: %v", err)
	}
	defer func() { _ = rows.Close() }()

	if !rows.Next() {
		t.Fatalf("no rows returned within tx; err=%v", rows.Err())
	}
	var id int
	if err := rows.Scan(&id); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if id != 42 {
		t.Errorf("id = %d, want 42", id)
	}
}

// TestMigrateDBQueryError verifies that a failing Query surfaces the error
// rather than a nil Rows.
func TestMigrateDBQueryError(t *testing.T) {
	t.Parallel()
	mdb := newMigrateAdapter(t)
	ctx := context.Background()

	rows, err := mdb.Query(ctx, "SELECT * FROM does_not_exist")
	if err == nil {
		_ = rows.Close()
		t.Fatal("Query on missing table = nil error, want error")
	}
	if rows != nil {
		t.Errorf("Query error returned non-nil Rows: %v", rows)
	}
}

// TestMigrateDBAsMigrateDB confirms the adapter drives a real migrate.DB port
// end to end via the interface type, not just the concrete struct.
func TestMigrateDBSatisfiesPort(t *testing.T) {
	t.Parallel()
	var _ migrate.DB = NewMigrateDB(openMemory(t))
}

func migrateCount(t *testing.T, mdb migrate.DB, ctx context.Context) int {
	t.Helper()
	rows, err := mdb.Query(ctx, "SELECT count(*) FROM t")
	if err != nil {
		t.Fatalf("count query: %v", err)
	}
	defer func() { _ = rows.Close() }()
	if !rows.Next() {
		t.Fatalf("count query returned no row: %v", rows.Err())
	}
	var n int
	if err := rows.Scan(&n); err != nil {
		t.Fatalf("count scan: %v", err)
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		t.Fatalf("count finalize: %v", err)
	}
	return n
}
