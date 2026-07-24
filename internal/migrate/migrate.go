// Package migrate is a driver-free, dual-engine (SQLite and Postgres) SQL
// migration runner for sshpilot-vallet.
//
// The package core depends only on the standard library and internal/domain.
// It never imports database/sql or any driver: all database access happens
// through the small [Executor], [Tx], and [DB] ports defined in this package,
// which concrete adapters (see F6) implement.
//
// Security posture: the runner fails closed. A registry that is malformed,
// incomplete for either engine, or out of order is rejected at construction
// time; a ledger that does not match the registry (unknown migration, engine
// mismatch, checksum drift, or non-contiguous application order) aborts every
// operation with an error rather than proceeding. Error messages carry only
// migration IDs, names, the engine, and static descriptions; they never embed
// SQL text or values read from the database.
package migrate

// Engine identifies the SQL dialect a migration and its ledger statements
// target. The zero value is not a valid engine.
type Engine string

// Supported engines.
const (
	// EngineSQLite selects the SQLite dialect and its "?" bind placeholders.
	EngineSQLite Engine = "sqlite"
	// EnginePostgres selects the Postgres dialect and its "$N" bind
	// placeholders.
	EnginePostgres Engine = "postgres"
)

// Valid reports whether e is a known engine.
func (e Engine) Valid() bool {
	switch e {
	case EngineSQLite, EnginePostgres:
		return true
	default:
		return false
	}
}
