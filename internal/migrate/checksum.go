package migrate

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// checksumSep separates the fields of the canonical checksum input. A NUL byte
// cannot appear in a migration ID (decimal digits), a name, or SQL text, so it
// is an unambiguous separator.
const checksumSep = "\x00"

// ChecksumFor returns the lowercase hex-encoded SHA-256 of a migration's
// canonical form for engine e. The canonical form is
//
//	id \x00 name \x00 upStmt1 \x00 upStmt2 ...
//
// using e's up steps. It is exported so the ledger-drift check (F6) can
// recompute and compare a stored checksum. The result is stable across
// processes and platforms and changes if the ID, name, statement text, or
// statement order changes for that engine.
func ChecksumFor(m Migration, e Engine) string {
	steps := m.Up.forEngine(e)
	parts := make([]string, 0, len(steps)+2)
	parts = append(parts, m.ID, m.Name)
	parts = append(parts, steps...)
	sum := sha256.Sum256([]byte(strings.Join(parts, checksumSep)))
	return hex.EncodeToString(sum[:])
}
