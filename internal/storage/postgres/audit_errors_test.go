package postgres

import (
	"context"
	"database/sql"
	"errors"
	"testing"
)

// errResult is a sql.Result whose RowsAffected fails. The driver always reports
// a row count successfully, so this stub is the only way to exercise the
// RowsAffected error branches, which must surface the failure rather than
// silently report zero rows purged or rewritten.
type errResult struct{ err error }

func (r errResult) LastInsertId() (int64, error) { return 0, r.err }
func (r errResult) RowsAffected() (int64, error) { return 0, r.err }

// countErrExecer runs statements against a real execer but replaces every Exec
// result with one whose RowsAffected fails.
type countErrExecer struct {
	execer
	err error
}

func (e countErrExecer) ExecContext(ctx context.Context, q string, args ...any) (sql.Result, error) {
	if _, err := e.execer.ExecContext(ctx, q, args...); err != nil {
		return nil, err
	}
	return errResult{err: e.err}, nil
}

// closedStore returns a store whose database has been closed, so every
// statement issued through it fails at the driver.
func closedStore(t *testing.T) *Store {
	t.Helper()
	s := newStore(t)
	if err := s.db.Close(); err != nil {
		t.Fatalf("close db: %v", err)
	}
	return s
}

func TestAuditPurgeSurfacesExecError(t *testing.T) {
	t.Parallel()
	repo := &auditRepo{e: closedStore(t).db}

	n, err := repo.PurgeOlderThan(context.Background(), testClock, 10)
	if err == nil {
		t.Fatal("PurgeOlderThan on a closed db = nil error, want error")
	}
	if n != 0 {
		t.Errorf("deleted = %d, want 0 on error", n)
	}
}

func TestAuditPurgeSurfacesRowsAffectedError(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	sentinel := errors.New("rows affected failed")
	repo := &auditRepo{e: countErrExecer{execer: s.db, err: sentinel}}

	n, err := repo.PurgeOlderThan(context.Background(), testClock, 10)
	if !errors.Is(err, sentinel) {
		t.Errorf("err = %v, want the RowsAffected failure", err)
	}
	if n != 0 {
		t.Errorf("deleted = %d, want 0 on error", n)
	}
}

func TestAuditPseudonymizeSurfacesExecError(t *testing.T) {
	t.Parallel()
	repo := &auditRepo{e: closedStore(t).db}

	n, err := repo.Pseudonymize(context.Background(), []string{"owner-a"}, "tomb")
	if err == nil {
		t.Fatal("Pseudonymize on a closed db = nil error, want error")
	}
	if n != 0 {
		t.Errorf("rewritten = %d, want 0 on error", n)
	}
}

// TestAuditPseudonymizeBatchSurfacesErrors drives the batch helper directly.
// withLocalTx only accepts a real *sql.DB or *sql.Tx, so a stub execer cannot
// reach the helper through Pseudonymize; calling it here is what exercises its
// two failure branches.
func TestAuditPseudonymizeBatchSurfacesErrors(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	sentinel := errors.New("rows affected failed")

	t.Run("rows affected", func(t *testing.T) {
		t.Parallel()
		s := newStore(t)
		n, err := pseudonymizeBatch(ctx, countErrExecer{execer: s.db, err: sentinel}, []string{"owner-a"}, "tomb")
		if !errors.Is(err, sentinel) {
			t.Errorf("err = %v, want the RowsAffected failure", err)
		}
		if n != 0 {
			t.Errorf("rewritten = %d, want 0 on error", n)
		}
	})

	t.Run("exec", func(t *testing.T) {
		t.Parallel()
		n, err := pseudonymizeBatch(ctx, closedStore(t).db, []string{"owner-a"}, "tomb")
		if err == nil {
			t.Fatal("pseudonymizeBatch on a closed db = nil error, want error")
		}
		if n != 0 {
			t.Errorf("rewritten = %d, want 0 on error", n)
		}
	})
}

// TestAuditPseudonymizeAbortsTransactionOnBatchError covers the failure inside
// the transaction: the tx begins successfully and the UPDATE then fails, so the
// error must propagate out and the transaction must roll back rather than
// leaving a half-erased set behind.
func TestAuditPseudonymizeAbortsTransactionOnBatchError(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	if _, err := s.db.ExecContext(ctx, `DROP TABLE audit_records`); err != nil {
		t.Fatalf("drop table: %v", err)
	}
	repo := &auditRepo{e: s.db}

	n, err := repo.Pseudonymize(ctx, []string{"owner-a"}, "tomb")
	if err == nil {
		t.Fatal("Pseudonymize against a missing table = nil error, want error")
	}
	if n != 0 {
		t.Errorf("rewritten = %d, want 0 on error", n)
	}
}
