package sqlite

import (
	"database/sql"
	"errors"
	"fmt"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"

	sqlite "modernc.org/sqlite"
)

// SQLite extended result codes for the two constraint violations that map to a
// conflict. Extended codes are the authoritative signal for the kind of
// violation; the driver (modernc.org/sqlite) always reports the extended code,
// never the bare primary code, so no primary-code fallback is needed. Relying
// on the primary code 19 would be unsafe anyway: it is shared by NOT NULL,
// CHECK, and foreign-key failures, which must not be reported as conflicts.
const (
	// sqliteConstraintUnique is SQLITE_CONSTRAINT_UNIQUE.
	sqliteConstraintUnique = 2067
	// sqliteConstraintPrimaryKey is SQLITE_CONSTRAINT_PRIMARYKEY.
	sqliteConstraintPrimaryKey = 1555
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
// constraint violation, identified by the driver's precise extended result
// codes 2067 and 1555. Only these two map to a conflict; NOT NULL, CHECK, and
// foreign-key failures deliberately fall through so they are not misreported as
// conflicts.
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
		return false
	}
}
