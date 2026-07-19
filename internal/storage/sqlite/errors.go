package sqlite

import (
	"database/sql"
	"errors"
	"fmt"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"

	sqlite "modernc.org/sqlite"
)

// SQLite extended and primary result codes for constraint violations. Extended
// codes are the authoritative signal for the kind of violation; the primary
// code is a coarse fallback shared by every constraint failure.
const (
	// sqliteConstraintUnique is SQLITE_CONSTRAINT_UNIQUE.
	sqliteConstraintUnique = 2067
	// sqliteConstraintPrimaryKey is SQLITE_CONSTRAINT_PRIMARYKEY.
	sqliteConstraintPrimaryKey = 1555
	// sqliteConstraintPrimary is SQLITE_CONSTRAINT, the primary code common to
	// all constraint violations (extended = primary | (n << 8)).
	sqliteConstraintPrimary = 19
)

// errPrefix is the static wrapper for errors that are neither "not found" nor a
// uniqueness conflict. It carries no SQL text or bound values, so nothing from
// the query leaks past the storage boundary.
const errPrefix = "sqlite"

// mapError translates a database/sql or driver error into a domain sentinel.
//
//   - nil returns nil.
//   - sql.ErrNoRows returns domain.ErrNotFound.
//   - a UNIQUE or PRIMARY KEY violation returns domain.ErrConflict.
//   - anything else is wrapped under a static prefix with %w so callers can
//     still unwrap it while no query text escapes.
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

// isUniqueViolation reports whether err is a SQLite UNIQUE or PRIMARY KEY
// constraint violation. It inspects the driver's *sqlite.Error result code:
// the extended codes 2067 and 1555 are checked first because they identify the
// violation precisely, and the primary code 19 is a last-resort fallback for
// builds that surface only the primary code. The primary-code fallback is
// deliberately narrow: 19 also covers NOT NULL, CHECK, and foreign-key
// failures, but those are not expected on the uniqueness paths that call this.
//
// This function, and errors.go, are the only places that import the driver's
// error type.
func isUniqueViolation(err error) bool {
	var serr *sqlite.Error
	if !errors.As(err, &serr) {
		return false
	}
	switch serr.Code() {
	case sqliteConstraintUnique, sqliteConstraintPrimaryKey:
		return true
	default:
		return serr.Code() == sqliteConstraintPrimary
	}
}
