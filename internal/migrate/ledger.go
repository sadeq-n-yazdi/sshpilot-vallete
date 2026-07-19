package migrate

import (
	"context"
	"fmt"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
)

// Ledger is one row of the schema_migrations table: a record that a migration
// was applied under a given engine.
type Ledger struct {
	// ID is the migration ID, e.g. "0001".
	ID string
	// Name is the migration name recorded at apply time.
	Name string
	// Checksum is the migration's checksum for Engine at apply time.
	Checksum string
	// AppliedAt is when the migration was applied, in UTC.
	AppliedAt time.Time
	// Engine is the engine the migration was applied under.
	Engine Engine
}

// createLedgerSQL creates the ledger table. It is identical and idempotent on
// both engines: TEXT columns and a TEXT primary key are portable, and IF NOT
// EXISTS makes repeated runs safe. applied_at is stored as RFC3339 UTC text.
const createLedgerSQL = `CREATE TABLE IF NOT EXISTS schema_migrations (
	id TEXT PRIMARY KEY,
	name TEXT NOT NULL,
	checksum TEXT NOT NULL,
	applied_at TEXT NOT NULL,
	engine TEXT NOT NULL
)`

// selectLedgerSQL reads all ledger rows in ID order. It takes no arguments, so
// it is engine-independent.
const selectLedgerSQL = `SELECT id, name, checksum, applied_at, engine FROM schema_migrations ORDER BY id`

// insertLedgerSQL returns the ledger insert statement for engine, differing
// only in bind-placeholder syntax.
func insertLedgerSQL(engine Engine) string {
	if engine == EnginePostgres {
		return `INSERT INTO schema_migrations (id, name, checksum, applied_at, engine) VALUES ($1, $2, $3, $4, $5)`
	}
	return `INSERT INTO schema_migrations (id, name, checksum, applied_at, engine) VALUES (?, ?, ?, ?, ?)`
}

// deleteLedgerSQL returns the ledger delete statement for engine, differing
// only in bind-placeholder syntax.
func deleteLedgerSQL(engine Engine) string {
	if engine == EnginePostgres {
		return `DELETE FROM schema_migrations WHERE id = $1`
	}
	return `DELETE FROM schema_migrations WHERE id = ?`
}

// ensureLedgerTable creates the ledger table if it does not exist. It is
// idempotent on both engines and must run before any ledger read.
func ensureLedgerTable(ctx context.Context, e Executor) error {
	return e.Exec(ctx, createLedgerSQL)
}

// insertLedger records l using engine-appropriate placeholders. AppliedAt is
// written as RFC3339 UTC text.
func insertLedger(ctx context.Context, e Executor, l Ledger) error {
	return e.Exec(ctx, insertLedgerSQL(l.Engine),
		l.ID, l.Name, l.Checksum, l.AppliedAt.UTC().Format(time.RFC3339), string(l.Engine))
}

// deleteLedger removes the ledger row for id using engine-appropriate
// placeholders.
func deleteLedger(ctx context.Context, e Executor, engine Engine, id string) error {
	return e.Exec(ctx, deleteLedgerSQL(engine), id)
}

// loadLedger reads all ledger rows in ID order. A row whose applied_at is not
// valid RFC3339 is reported as a conflict identified only by its migration ID;
// no timestamp value is placed in the error.
func loadLedger(ctx context.Context, e Executor) ([]Ledger, error) {
	rows, err := e.Query(ctx, selectLedgerSQL)
	if err != nil {
		return nil, fmt.Errorf("migrate: load ledger: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []Ledger
	for rows.Next() {
		var id, name, checksum, appliedAt, engine string
		if err := rows.Scan(&id, &name, &checksum, &appliedAt, &engine); err != nil {
			return nil, fmt.Errorf("migrate: scan ledger row: %w", err)
		}
		ts, perr := time.Parse(time.RFC3339, appliedAt)
		if perr != nil {
			return nil, fmt.Errorf("migrate: ledger row %q has an invalid applied_at timestamp: %w", id, domain.ErrConflict)
		}
		out = append(out, Ledger{
			ID:        id,
			Name:      name,
			Checksum:  checksum,
			AppliedAt: ts.UTC(),
			Engine:    Engine(engine),
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("migrate: read ledger rows: %w", err)
	}
	return out, nil
}
