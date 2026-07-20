package postgres

import (
	"context"
	"database/sql"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/migrate"
)

// MigrateDB adapts a *sql.DB to the driver-free migrate.DB port so the
// migration runner can execute against PostgreSQL without importing
// database/sql or this driver. It is a thin pass-through: it does not translate
// errors into domain sentinels, because the migration runner has its own error
// handling and treats every database failure the same way.
//
// The runner must be constructed with migrate.EnginePostgres so it selects the
// Postgres DDL variants and the "$N" bind placeholders its ledger statements
// use.
type MigrateDB struct {
	db *sql.DB
}

// Compile-time assertions that the adapters satisfy the migrate ports.
var (
	_ migrate.DB   = (*MigrateDB)(nil)
	_ migrate.Tx   = (*mtx)(nil)
	_ migrate.Rows = (*mrows)(nil)
)

// NewMigrateDB wraps db as a migrate.DB.
func NewMigrateDB(db *sql.DB) *MigrateDB {
	return &MigrateDB{db: db}
}

// Exec runs a statement that returns no rows.
func (m *MigrateDB) Exec(ctx context.Context, query string, args ...any) error {
	_, err := m.db.ExecContext(ctx, query, args...)
	return err
}

// Query runs a statement that returns rows. The caller must Close the result.
func (m *MigrateDB) Query(ctx context.Context, query string, args ...any) (migrate.Rows, error) {
	rows, err := m.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	return &mrows{rows: rows}, nil
}

// Begin starts a transaction at the server's default isolation level. Postgres
// runs DDL transactionally, so a migration step that fails mid-way rolls back
// its schema changes with it.
func (m *MigrateDB) Begin(ctx context.Context) (migrate.Tx, error) {
	tx, err := m.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	return &mtx{tx: tx}, nil
}

// mtx adapts a *sql.Tx to migrate.Tx.
type mtx struct {
	tx        *sql.Tx
	committed bool
}

// Exec runs a statement that returns no rows within the transaction.
func (t *mtx) Exec(ctx context.Context, query string, args ...any) error {
	_, err := t.tx.ExecContext(ctx, query, args...)
	return err
}

// Query runs a statement that returns rows within the transaction.
func (t *mtx) Query(ctx context.Context, query string, args ...any) (migrate.Rows, error) {
	rows, err := t.tx.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	return &mrows{rows: rows}, nil
}

// Commit makes the transaction's changes durable.
func (t *mtx) Commit() error {
	if err := t.tx.Commit(); err != nil {
		return err
	}
	t.committed = true
	return nil
}

// Rollback discards the transaction's changes. Per the migrate.Tx contract a
// Rollback after a successful Commit is a no-op that returns nil, so callers
// may defer Rollback unconditionally.
func (t *mtx) Rollback() error {
	if t.committed {
		return nil
	}
	return t.tx.Rollback()
}

// mrows adapts *sql.Rows to migrate.Rows.
type mrows struct {
	rows *sql.Rows
}

// Next advances to the next row, reporting whether one is available.
func (r *mrows) Next() bool { return r.rows.Next() }

// Scan copies the current row's columns into dest.
func (r *mrows) Scan(dest ...any) error { return r.rows.Scan(dest...) }

// Err returns the first error encountered during iteration.
func (r *mrows) Err() error { return r.rows.Err() }

// Close releases the cursor. It is safe to call more than once.
func (r *mrows) Close() error { return r.rows.Close() }
