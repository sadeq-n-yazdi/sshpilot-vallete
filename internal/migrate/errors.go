package migrate

import (
	"fmt"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
)

// Sentinel errors for the migration runner. Each wraps a domain sentinel so
// callers can classify failures with errors.Is against either this package's
// sentinel or the broader domain category.
//
// Error hygiene: every message built in this package carries only migration
// IDs, names, the engine, and static precondition descriptions. Messages never
// embed SQL text or values read from the database, and the underlying executor
// error (which may contain SQL) is never wrapped into a user-facing message.
var (
	// ErrInvalidRegistry indicates the migration set is malformed: a bad or
	// duplicate ID, out-of-order IDs, an unknown or non-earlier dependency, a
	// missing name or precondition description, or missing steps for an engine.
	ErrInvalidRegistry = fmt.Errorf("migrate: invalid registry: %w", domain.ErrInvalidInput)
	// ErrChecksumMismatch indicates a ledger row's checksum differs from the
	// registry migration's recomputed checksum for this engine.
	ErrChecksumMismatch = fmt.Errorf("migrate: checksum mismatch: %w", domain.ErrConflict)
	// ErrLedgerAhead indicates the ledger records a migration that the registry
	// does not contain.
	ErrLedgerAhead = fmt.Errorf("migrate: ledger ahead of registry: %w", domain.ErrConflict)
	// ErrLedgerOrder indicates the applied migrations are not a contiguous
	// prefix of the registry order.
	ErrLedgerOrder = fmt.Errorf("migrate: ledger order invalid: %w", domain.ErrConflict)
	// ErrEngineMismatch indicates a ledger row was applied under a different
	// engine than the runner's.
	ErrEngineMismatch = fmt.Errorf("migrate: engine mismatch: %w", domain.ErrConflict)
	// ErrDependencyUnmet indicates a pending migration's Requires are not all
	// applied. This is a defense-in-depth check; the registry already enforces
	// that dependencies are strictly earlier.
	ErrDependencyUnmet = fmt.Errorf("migrate: dependency unmet: %w", domain.ErrConflict)
	// ErrPreconditionFailed indicates a migration's precondition did not hold.
	ErrPreconditionFailed = fmt.Errorf("migrate: precondition failed: %w", domain.ErrConflict)
	// ErrDestructiveBlocked indicates a revert would run a destructive
	// migration without the AllowDestructive option.
	ErrDestructiveBlocked = fmt.Errorf("migrate: destructive migration blocked: %w", domain.ErrForbidden)
	// ErrIrreversible indicates a revert would touch a migration marked
	// irreversible, which can never be reverted.
	ErrIrreversible = fmt.Errorf("migrate: migration is irreversible: %w", domain.ErrForbidden)
	// ErrUnknownTarget indicates a Down target ID is not a known, applied
	// migration.
	ErrUnknownTarget = fmt.Errorf("migrate: unknown target: %w", domain.ErrNotFound)
)
