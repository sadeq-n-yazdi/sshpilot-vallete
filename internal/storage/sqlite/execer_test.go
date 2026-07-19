package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"testing"
)

func createExecerTable(t *testing.T, db *sql.DB) {
	t.Helper()
	if _, err := db.ExecContext(context.Background(),
		"CREATE TABLE items (id INTEGER PRIMARY KEY)"); err != nil {
		t.Fatalf("create table: %v", err)
	}
}

func countItems(t *testing.T, db *sql.DB) int {
	t.Helper()
	var n int
	if err := db.QueryRowContext(context.Background(),
		"SELECT count(*) FROM items").Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	return n
}

func TestWithLocalTxCommitsOnSuccess(t *testing.T) {
	t.Parallel()
	db := openMemory(t)
	createExecerTable(t, db)
	ctx := context.Background()

	err := withLocalTx(ctx, db, func(e execer) error {
		_, ierr := e.ExecContext(ctx, "INSERT INTO items (id) VALUES (1)")
		return ierr
	})
	if err != nil {
		t.Fatalf("withLocalTx: %v", err)
	}
	if got := countItems(t, db); got != 1 {
		t.Errorf("row count = %d, want 1 (commit did not persist)", got)
	}
}

func TestWithLocalTxRollsBackOnError(t *testing.T) {
	t.Parallel()
	db := openMemory(t)
	createExecerTable(t, db)
	ctx := context.Background()

	sentinel := errors.New("boom")
	err := withLocalTx(ctx, db, func(e execer) error {
		if _, ierr := e.ExecContext(ctx, "INSERT INTO items (id) VALUES (1)"); ierr != nil {
			return ierr
		}
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("withLocalTx error = %v, want sentinel", err)
	}
	if got := countItems(t, db); got != 0 {
		t.Errorf("row count = %d, want 0 (rollback did not discard the insert)", got)
	}
}

// TestWithLocalTxInlineWhenTx verifies that passing a *sql.Tx runs fn inline
// against that transaction with no nested transaction: the outer transaction
// still controls commit, and a rollback of the outer tx discards fn's work.
func TestWithLocalTxInlineWhenTx(t *testing.T) {
	t.Parallel()
	db := openMemory(t)
	createExecerTable(t, db)
	ctx := context.Background()

	outer, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin outer: %v", err)
	}

	var seen execer
	err = withLocalTx(ctx, outer, func(e execer) error {
		seen = e
		_, ierr := e.ExecContext(ctx, "INSERT INTO items (id) VALUES (1)")
		return ierr
	})
	if err != nil {
		t.Fatalf("withLocalTx inline: %v", err)
	}
	if seen != outer {
		t.Errorf("fn received %p, want the outer tx %p (a nested tx was created)", seen, outer)
	}

	// The outer transaction still owns commit/rollback: rolling it back must
	// discard fn's insert.
	if rerr := outer.Rollback(); rerr != nil {
		t.Fatalf("rollback outer: %v", rerr)
	}
	if got := countItems(t, db); got != 0 {
		t.Errorf("row count = %d, want 0 (inline work was not under the outer tx)", got)
	}
}
