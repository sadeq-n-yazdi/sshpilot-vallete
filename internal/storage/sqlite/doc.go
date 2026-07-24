// Package sqlite is the SQLite storage adapter for sshpilot-vallet. It is the
// only package permitted to import a concrete SQLite driver
// (modernc.org/sqlite, a pure-Go, CGO-free implementation) and the only place
// where engine-specific error inspection lives.
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
// declared in internal/domain and never a *sqlite.Error or a database/sql
// value. This keeps the driver an implementation detail and prevents engine
// error text, SQL, or bound values from escaping the storage boundary.
//
// # Error-mapping contract
//
// Adapter methods translate driver and database/sql errors into domain
// sentinels before returning them:
//
//   - sql.ErrNoRows maps to [domain.ErrNotFound].
//   - A UNIQUE or PRIMARY KEY constraint violation maps to
//     [domain.ErrConflict].
//   - Any other error is wrapped under a static prefix with %w so callers can
//     still match it with errors.Is while no raw SQL or value text leaks.
//
// Time values are stored as fixed-width UTC RFC3339 strings (see timefmt.go) so
// that lexical string comparison in SQL matches chronological ordering.
package sqlite
