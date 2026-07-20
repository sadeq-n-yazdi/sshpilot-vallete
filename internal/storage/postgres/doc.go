// Package postgres is the PostgreSQL storage adapter for sshpilot-vallet. It is
// the only package permitted to import a concrete PostgreSQL driver
// (github.com/jackc/pgx/v5, used through its database/sql-compatible stdlib
// mode) and the only place where engine-specific error inspection lives.
//
// It mirrors the SQLite adapter's structure and contracts; the differences are
// dialect-level only and are called out below.
//
// # Security conventions
//
// Ownership is enforced in SQL, not in application code. Every query that
// touches an owner-owned row carries the owner's identifier in its WHERE
// clause, so a caller can never read or mutate another owner's data even by
// guessing a primary key. A row that exists but belongs to a different owner is
// reported to callers as [domain.ErrNotFound]: presence is never leaked across
// ownership boundaries, and a wrong-owner lookup is indistinguishable from a
// missing row.
//
// All inspection of driver-specific error values is isolated to this package
// (see errors.go). Layers above the adapter see only the sentinel errors
// declared in internal/domain and never a *pgconn.PgError or a database/sql
// value. This keeps the driver an implementation detail and prevents engine
// error text, SQL, or bound values from escaping the storage boundary.
//
// One relationship is not expressible in the schema: key_set_members carries no
// owner_id, and its foreign keys constrain only that the referenced key set and
// public key EXIST — never that the two share an owner. keySetRepo.AddMember is
// therefore the sole enforcement point preventing a membership that links one
// owner's set to another owner's key, and it carries the reasoning inline.
//
// # Error-mapping contract
//
// Adapter methods translate driver and database/sql errors into domain
// sentinels before returning them:
//
//   - sql.ErrNoRows maps to [domain.ErrNotFound].
//   - SQLSTATE 23505 (unique_violation) maps to [domain.ErrConflict]. Postgres
//     reports a primary-key clash under the same 23505 code, so it covers what
//     SQLite splits across extended codes 2067 and 1555.
//   - Any other error, including SQLSTATE 23503 (foreign_key_violation), is
//     wrapped under a static prefix with %w so callers can still match it with
//     errors.Is while no raw SQL or bound value text leaks. This matches the
//     SQLite adapter, which likewise maps only uniqueness failures to a
//     sentinel and lets foreign-key failures fall through.
//
// # Dialect differences from the SQLite adapter
//
//   - Bind placeholders are $1, $2, … rather than ?.
//   - Booleans are real BOOLEAN columns, so Go bools bind and scan directly
//     instead of being encoded as 0/1 integers, and predicates compare against
//     TRUE/FALSE rather than 1/0.
//   - A public key's blob is a BYTEA column rather than a BLOB; the driver
//     binds and scans the []byte identically either way.
//   - Timestamps are stored as fixed-width UTC RFC3339 text, identical to the
//     SQLite adapter. This is dictated by internal/schema, whose Postgres DDL
//     declares every timestamp column TEXT so both engines share one column
//     semantics; the text encoding preserves UTC on round-trip and sorts
//     chronologically under lexical comparison.
package postgres
