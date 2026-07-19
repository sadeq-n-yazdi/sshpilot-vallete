package migrate

import (
	"context"
	"fmt"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
)

// TableExists returns a precondition that holds when a table named name exists.
// The name is passed as a query argument, never interpolated into SQL.
func TableExists(name string) Precondition {
	return Precondition{
		Description: fmt.Sprintf("table %q must exist", name),
		Check: func(ctx context.Context, e Executor, engine Engine) error {
			present, err := tablePresent(ctx, e, engine, name)
			if err != nil {
				return err
			}
			if !present {
				return fmt.Errorf("migrate: required table %q is absent: %w", name, domain.ErrConflict)
			}
			return nil
		},
	}
}

// TableAbsent returns a precondition that holds when no table named name exists.
// The name is passed as a query argument, never interpolated into SQL.
func TableAbsent(name string) Precondition {
	return Precondition{
		Description: fmt.Sprintf("table %q must be absent", name),
		Check: func(ctx context.Context, e Executor, engine Engine) error {
			present, err := tablePresent(ctx, e, engine, name)
			if err != nil {
				return err
			}
			if present {
				return fmt.Errorf("migrate: table %q must be absent but exists: %w", name, domain.ErrConflict)
			}
			return nil
		},
	}
}

// tableExistsQuery returns a parameterized catalog query counting tables named
// by the single bind argument. The table name is never interpolated.
func tableExistsQuery(engine Engine) string {
	if engine == EnginePostgres {
		// to_regclass resolves the name against the session search_path and
		// PostgreSQL's identifier case-folding rules, so it does not silently
		// miss tables in a non-default schema the way a hardcoded
		// table_schema = 'public' filter on information_schema.tables would.
		// It returns NULL for an unknown name, so the count is 0.
		return `SELECT COUNT(*) FROM pg_class WHERE oid = to_regclass($1)`
	}
	return `SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?`
}

// tablePresent reports whether a table named name exists, using a parameterized
// catalog query for engine.
func tablePresent(ctx context.Context, e Executor, engine Engine, name string) (bool, error) {
	rows, err := e.Query(ctx, tableExistsQuery(engine), name)
	if err != nil {
		return false, fmt.Errorf("migrate: catalog query: %w", err)
	}
	defer func() { _ = rows.Close() }()

	present := false
	for rows.Next() {
		var n int
		if err := rows.Scan(&n); err != nil {
			return false, fmt.Errorf("migrate: catalog scan: %w", err)
		}
		if n > 0 {
			present = true
		}
	}
	if err := rows.Err(); err != nil {
		return false, fmt.Errorf("migrate: catalog rows: %w", err)
	}
	return present, nil
}
