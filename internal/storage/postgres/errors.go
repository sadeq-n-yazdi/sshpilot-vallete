package postgres

import (
	"database/sql"
	"errors"
	"fmt"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"

	"github.com/jackc/pgx/v5/pgconn"
)

// PostgreSQL SQLSTATE codes for the constraint violations this adapter
// distinguishes. SQLSTATE is the authoritative, stable classification: it is
// part of the wire protocol and does not vary by server version or locale, so
// it is matched instead of the human-readable message text.
const (
	// sqlstateUniqueViolation is 23505 unique_violation. Postgres reports both
	// a UNIQUE index clash and a PRIMARY KEY clash under this single code,
	// which together cover what SQLite splits across extended codes 2067
	// (SQLITE_CONSTRAINT_UNIQUE) and 1555 (SQLITE_CONSTRAINT_PRIMARYKEY).
	sqlstateUniqueViolation = "23505"

	// sqlstateForeignKeyViolation is 23503 foreign_key_violation. It is named
	// here for the reader's benefit but deliberately NOT mapped to a sentinel:
	// see mapError.
	sqlstateForeignKeyViolation = "23503"
)

// errPrefix is the static wrapper for errors that are neither "not found" nor a
// uniqueness conflict. It carries no SQL text or bound values, so nothing from
// the query leaks past the storage boundary.
const errPrefix = "postgres"

// mapError translates a database/sql or driver error into a domain sentinel.
//
//   - nil returns nil.
//   - sql.ErrNoRows returns domain.ErrNotFound.
//   - SQLSTATE 23505 (unique or primary-key violation) returns
//     domain.ErrConflict.
//   - anything else is wrapped under a static prefix with %w so callers can
//     still unwrap it while no query text escapes.
//
// A foreign-key violation (23503) is intentionally in that last group. The
// repository port contracts promise a sentinel only for a uniqueness clash;
// nothing in them describes a missing parent row, and the SQLite adapter
// likewise matches only its two uniqueness codes and lets foreign-key failures
// fall through to the generic wrap. Mapping 23503 to ErrConflict here would
// make the two engines disagree on the same operation, so parity wins.
//
// Wrapping with %w is safe for driver errors: pgconn.PgError.Error() renders
// only severity, message, and SQLSTATE. The message names constraints and
// relations, never bound values — those live in the error's Detail field, which
// Error() does not surface.
//
// This is the single choke point through which every adapter error passes on
// its way out of the package.
func mapError(err error) error {
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return domain.ErrNotFound
	case isUniqueViolation(err):
		return domain.ErrConflict
	default:
		return fmt.Errorf("%s: %w", errPrefix, err)
	}
}

// isUniqueViolation reports whether err is a PostgreSQL unique or primary-key
// constraint violation, identified by SQLSTATE 23505. Only that code maps to a
// conflict; NOT NULL (23502), CHECK (23514), and foreign-key (23503) failures
// deliberately fall through so they are not misreported as conflicts.
//
// This function, and errors.go, are the only places that import the driver's
// error type.
func isUniqueViolation(err error) bool {
	var perr *pgconn.PgError
	if !errors.As(err, &perr) {
		return false
	}
	return perr.Code == sqlstateUniqueViolation
}

// isForeignKeyViolation reports whether err is a PostgreSQL foreign-key
// violation (SQLSTATE 23503). It is not used by mapError, which routes 23503 to
// the generic wrap for parity with the SQLite adapter; it exists so that
// behavior is asserted by an explicit test rather than left implicit.
func isForeignKeyViolation(err error) bool {
	var perr *pgconn.PgError
	if !errors.As(err, &perr) {
		return false
	}
	return perr.Code == sqlstateForeignKeyViolation
}
