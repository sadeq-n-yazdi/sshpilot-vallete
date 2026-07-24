package sqlite

import (
	"context"
	"database/sql"
	"fmt"
)

// execer is the common statement-and-query surface shared by *sql.DB and
// *sql.Tx. Repository methods take an execer so the same code runs whether or
// not the caller has already opened a transaction.
type execer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// Compile-time assertions that both concrete types satisfy execer.
var (
	_ execer = (*sql.DB)(nil)
	_ execer = (*sql.Tx)(nil)
)

// withLocalTx runs fn inside a transaction, adapting to whatever e is.
//
// When e is a *sql.DB, withLocalTx opens a private transaction, runs fn against
// it, and commits on success or rolls back on error (or panic). When e is
// already a *sql.Tx, fn runs inline against that transaction with no nested
// transaction: the caller that owns the outer transaction controls its commit
// or rollback. This lets a multi-statement repository method be atomic on its
// own yet compose into a larger caller-managed transaction.
func withLocalTx(ctx context.Context, e execer, fn func(execer) error) error {
	// Guard the pointer, not just the assertion: an execer holding a typed-nil
	// *sql.Tx or *sql.DB satisfies the assertion with ok == true, and calling a
	// method on the nil pointer (fn(tx), db.BeginTx) would panic. Treat a nil
	// pointer as an unsupported execer and fail with an error instead.
	if tx, ok := e.(*sql.Tx); ok && tx != nil {
		return fn(tx)
	}

	db, ok := e.(*sql.DB)
	if !ok || db == nil {
		return fmt.Errorf("sqlite: withLocalTx: unsupported or nil execer %T", e)
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("sqlite: begin transaction: %w", err)
	}

	// Roll back unconditionally on any early return; the rollback is a no-op
	// after a successful commit, so the deferred call is safe.
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	if err := fn(tx); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("sqlite: commit transaction: %w", err)
	}
	committed = true
	return nil
}
