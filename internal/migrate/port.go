package migrate

import "context"

// Executor runs statements and queries against a database or an open
// transaction. It is the only surface the migration core uses to touch a
// database; concrete adapters (F6) implement it without exposing database/sql
// to the core.
type Executor interface {
	// Exec runs a statement that returns no rows. args are bound to the
	// engine's placeholders ("?" for SQLite, "$N" for Postgres).
	Exec(ctx context.Context, query string, args ...any) error
	// Query runs a statement that returns rows. The caller must Close the
	// returned Rows.
	Query(ctx context.Context, query string, args ...any) (Rows, error)
}

// Rows is a forward-only cursor over a query result. Usage is the standard
// database/sql shape: iterate with Next, read with Scan, then check Err and
// Close.
type Rows interface {
	// Next advances to the next row, reporting whether one is available.
	Next() bool
	// Scan copies the current row's columns into dest.
	Scan(dest ...any) error
	// Err returns the first error encountered during iteration.
	Err() error
	// Close releases the cursor. It is safe to call more than once.
	Close() error
}

// Tx is an in-progress transaction. Commit and Rollback are terminal; after
// either, further use of the Tx is undefined except that a Rollback following a
// successful Commit must be a no-op so callers may defer Rollback
// unconditionally.
type Tx interface {
	Executor
	// Commit makes the transaction's changes durable.
	Commit() error
	// Rollback discards the transaction's changes. It must be safe to call
	// after a successful Commit, where it does nothing and returns nil.
	Rollback() error
}

// DB is a database handle that can start transactions.
//
// SQLite caveat: DDL is transactional, but some PRAGMA statements and
// table-rewrite operations auto-commit the surrounding transaction. Migrations
// in this package use only plain DDL and DML for that reason, and the SQLite
// adapter (F6) opens transactions with BEGIN IMMEDIATE so writers do not race.
type DB interface {
	Executor
	// Begin starts a transaction.
	Begin(ctx context.Context) (Tx, error)
}
