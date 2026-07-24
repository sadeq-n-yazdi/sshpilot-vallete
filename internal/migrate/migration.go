package migrate

import "context"

// Steps holds the SQL statements for one direction (up or down) of a migration,
// one list per engine. It is a struct rather than a map so that completeness is
// a registry-validated property: an engine with an empty step list is a
// build-time error, never silently treated as "nothing to do".
type Steps struct {
	// SQLite is the ordered list of statements for the SQLite engine.
	SQLite []string
	// Postgres is the ordered list of statements for the Postgres engine.
	Postgres []string
}

// forEngine returns the statements for e. An unknown engine yields nil.
func (s Steps) forEngine(e Engine) []string {
	switch e {
	case EngineSQLite:
		return s.SQLite
	case EnginePostgres:
		return s.Postgres
	default:
		return nil
	}
}

// Precondition is a guard evaluated inside a migration's transaction before its
// up steps run. Description is a static, human-readable summary and must never
// contain data read from the database.
type Precondition struct {
	// Description states, statically, what the precondition checks.
	Description string
	// Check returns nil if the precondition holds. To signal that the
	// precondition is not met, return an error wrapping domain.ErrConflict;
	// the runner reports it as ErrPreconditionFailed and surfaces only the
	// static Description, never the error's own message (which may reference
	// database data). Any error that does not wrap domain.ErrConflict is
	// treated as an infrastructure failure (e.g. a lost connection or catalog
	// read error) and propagated unchanged rather than masquerading as a
	// precondition conflict.
	Check func(ctx context.Context, e Executor, engine Engine) error
}

// Migration is a single, ordered schema change with statements for both
// engines.
type Migration struct {
	// ID is a 4-digit zero-padded decimal string such as "0001". IDs define
	// the total order in which migrations apply.
	ID string
	// Name is a short human-readable label. It is recorded in the ledger and
	// folded into the checksum.
	Name string
	// Requires lists the IDs of migrations that must already be applied. Each
	// must refer to a strictly earlier migration.
	Requires []string
	// Preconditions are guards evaluated before the up steps, inside the same
	// transaction.
	Preconditions []Precondition
	// Up holds the forward statements for each engine.
	Up Steps
	// Down holds the reverse statements for each engine. Both engines are
	// required unless IrreversibleReason is set.
	Down Steps
	// Destructive marks a migration whose down (or up) discards data; reverting
	// it requires the runner's AllowDestructive option.
	Destructive bool
	// IrreversibleReason, when non-empty, marks a migration that cannot be
	// reverted and explains why. Such migrations need no down steps and can
	// never be reverted, even with AllowDestructive.
	IrreversibleReason string
}
