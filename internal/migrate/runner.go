package migrate

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
)

// Runner applies and reverts a registry's migrations against a database using a
// single engine. It verifies the ledger against the registry before every
// operation and fails closed on any inconsistency.
type Runner struct {
	db     DB
	engine Engine
	reg    *Registry
	now    func() time.Time

	allowDestructive bool
}

// Option configures a Runner at construction.
type Option func(*Runner)

// WithClock overrides the clock used to timestamp ledger rows. A nil clock is
// ignored. It exists mainly for deterministic tests.
func WithClock(now func() time.Time) Option {
	return func(r *Runner) {
		if now != nil {
			r.now = now
		}
	}
}

// AllowDestructive permits reverting migrations marked Destructive. Without it,
// Down refuses such reverts. It never permits reverting an irreversible
// migration.
func AllowDestructive() Option {
	return func(r *Runner) { r.allowDestructive = true }
}

// NewRunner returns a Runner, or an error wrapping domain.ErrInvalidInput if db
// or reg is nil or engine is unknown.
func NewRunner(db DB, engine Engine, reg *Registry, opts ...Option) (*Runner, error) {
	if db == nil {
		return nil, fmt.Errorf("migrate: nil db: %w", domain.ErrInvalidInput)
	}
	if reg == nil {
		return nil, fmt.Errorf("migrate: nil registry: %w", domain.ErrInvalidInput)
	}
	if !engine.Valid() {
		return nil, fmt.Errorf("migrate: unknown engine %q: %w", engine, domain.ErrInvalidInput)
	}
	r := &Runner{db: db, engine: engine, reg: reg, now: time.Now}
	for _, opt := range opts {
		opt(r)
	}
	return r, nil
}

// Status is a snapshot of migration state: the applied ledger rows in order and
// the IDs of pending migrations in application order.
type Status struct {
	// Applied holds the ledger rows for applied migrations, oldest first.
	Applied []Ledger
	// Pending holds the IDs of not-yet-applied migrations, in order.
	Pending []string
}

// Up applies every pending migration in ID order, each in its own transaction
// (preconditions, then up steps, then the ledger insert). It first ensures the
// ledger table exists and verifies the ledger. If a migration fails, that
// migration is rolled back and Up stops; migrations applied earlier in the same
// call remain applied, and their ledger rows are returned alongside the error.
// With nothing pending it returns (nil, nil) and is idempotent.
func (r *Runner) Up(ctx context.Context) ([]Ledger, error) {
	if err := ensureLedgerTable(ctx, r.db); err != nil {
		return nil, err
	}
	_, pending, err := r.verify(ctx)
	if err != nil {
		return nil, err
	}
	if len(pending) == 0 {
		return nil, nil
	}

	var applied []Ledger
	for _, m := range pending {
		l, err := r.applyOne(ctx, m)
		if err != nil {
			return applied, err
		}
		applied = append(applied, l)
	}
	return applied, nil
}

// applyOne applies a single migration in its own transaction.
func (r *Runner) applyOne(ctx context.Context, m Migration) (Ledger, error) {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return Ledger{}, fmt.Errorf("migrate: migration %q: begin transaction: %w", m.ID, err)
	}
	defer func() { _ = tx.Rollback() }()

	for _, pc := range m.Preconditions {
		if err := pc.Check(ctx, tx, r.engine); err != nil {
			// A genuine "precondition not met" wraps domain.ErrConflict; its
			// message may reference database data, so only the static
			// description is surfaced under ErrPreconditionFailed. Any other
			// error is an infrastructure failure (lost connection, catalog
			// read error) and must not masquerade as a precondition conflict:
			// propagate it wrapped, mirroring how up-step Exec errors flow.
			if errors.Is(err, domain.ErrConflict) {
				return Ledger{}, fmt.Errorf("migrate: migration %q precondition %q: %w", m.ID, pc.Description, ErrPreconditionFailed)
			}
			return Ledger{}, fmt.Errorf("migrate: migration %q precondition %q: %w", m.ID, pc.Description, err)
		}
	}

	for i, stmt := range m.Up.forEngine(r.engine) {
		if err := tx.Exec(ctx, stmt); err != nil {
			return Ledger{}, fmt.Errorf("migrate: migration %q up step %d: %w", m.ID, i+1, err)
		}
	}

	l := Ledger{
		ID:        m.ID,
		Name:      m.Name,
		Checksum:  ChecksumFor(m, r.engine),
		AppliedAt: r.now().UTC(),
		Engine:    r.engine,
	}
	if err := insertLedger(ctx, tx, l); err != nil {
		return Ledger{}, fmt.Errorf("migrate: migration %q: record ledger: %w", m.ID, err)
	}
	if err := tx.Commit(); err != nil {
		return Ledger{}, fmt.Errorf("migrate: migration %q: commit: %w", m.ID, err)
	}
	return l, nil
}

// Status ensures the ledger table exists, verifies the ledger, and reports
// applied and pending migrations. Verification failures are returned as errors,
// never encoded into the returned Status.
func (r *Runner) Status(ctx context.Context) (Status, error) {
	if err := ensureLedgerTable(ctx, r.db); err != nil {
		return Status{}, err
	}
	applied, pending, err := r.verify(ctx)
	if err != nil {
		return Status{}, err
	}
	pendingIDs := make([]string, len(pending))
	for i, m := range pending {
		pendingIDs[i] = m.ID
	}
	return Status{Applied: applied, Pending: pendingIDs}, nil
}

// verify loads the ledger and checks it against the registry, failing closed on
// any inconsistency. On success it returns the applied ledger rows (oldest
// first) and the pending migrations (in application order).
//
// Checks run in a fixed order so a scenario that violates exactly one invariant
// yields the matching sentinel: per-row registry membership (ErrLedgerAhead),
// engine match (ErrEngineMismatch), and checksum (ErrChecksumMismatch); then
// the global contiguous-prefix check (ErrLedgerOrder); then the pending
// dependency check (ErrDependencyUnmet).
func (r *Runner) verify(ctx context.Context) ([]Ledger, []Migration, error) {
	applied, err := loadLedger(ctx, r.db)
	if err != nil {
		return nil, nil, err
	}

	all := r.reg.ordered
	for _, row := range applied {
		m, ok := r.reg.Get(row.ID)
		if !ok {
			return nil, nil, fmt.Errorf("migrate: ledger records migration %q, absent from the registry: %w", row.ID, ErrLedgerAhead)
		}
		if row.Engine != r.engine {
			return nil, nil, fmt.Errorf("migrate: ledger migration %q was applied under engine %q but the runner uses engine %q: %w", row.ID, row.Engine, r.engine, ErrEngineMismatch)
		}
		if want := ChecksumFor(m, r.engine); row.Checksum != want {
			return nil, nil, fmt.Errorf("migrate: ledger migration %q checksum does not match the registry for engine %q: %w", row.ID, r.engine, ErrChecksumMismatch)
		}
	}

	if len(applied) > len(all) {
		return nil, nil, fmt.Errorf("migrate: ledger records more migrations than the registry contains: %w", ErrLedgerOrder)
	}
	for i, row := range applied {
		if row.ID != all[i].ID {
			return nil, nil, fmt.Errorf("migrate: applied migrations are not a contiguous registry prefix at position %d (found %q, expected %q): %w", i, row.ID, all[i].ID, ErrLedgerOrder)
		}
	}

	pending := make([]Migration, len(all)-len(applied))
	copy(pending, all[len(applied):])

	appliedSet := make(map[string]bool, len(applied))
	for _, row := range applied {
		appliedSet[row.ID] = true
	}
	if err := checkDependencies(appliedSet, pending); err != nil {
		return nil, nil, err
	}
	return applied, pending, nil
}

// Down reverts applied migrations newest-first until toID is the newest
// still-applied migration. An empty toID reverts everything (the teardown
// path). It verifies the ledger first, then, as a pre-flight before touching
// anything, refuses if any migration it would revert is irreversible
// (ErrIrreversible) or is destructive without AllowDestructive
// (ErrDestructiveBlocked). A toID that is unknown or not currently applied
// yields ErrUnknownTarget. Each revert runs the down steps and the ledger
// delete in one transaction; a failure stops Down, leaving newer already-
// reverted migrations reverted and returning their ledger rows with the error.
func (r *Runner) Down(ctx context.Context, toID string) ([]Ledger, error) {
	if err := ensureLedgerTable(ctx, r.db); err != nil {
		return nil, err
	}
	applied, _, err := r.verify(ctx)
	if err != nil {
		return nil, err
	}

	// applied is oldest-first; keep the prefix up to and including toID.
	keep := 0
	if toID != "" {
		idx := -1
		for i, l := range applied {
			if l.ID == toID {
				idx = i
				break
			}
		}
		if idx < 0 {
			return nil, fmt.Errorf("migrate: down target %q is not an applied migration: %w", toID, ErrUnknownTarget)
		}
		keep = idx + 1
	}
	toRevert := applied[keep:]
	if len(toRevert) == 0 {
		return nil, nil
	}

	// Pre-flight gating: reject the whole operation before any change.
	for _, l := range toRevert {
		m, ok := r.reg.Get(l.ID)
		if !ok {
			return nil, fmt.Errorf("migrate: ledger records migration %q, absent from the registry: %w", l.ID, ErrLedgerAhead)
		}
		if m.IrreversibleReason != "" {
			return nil, fmt.Errorf("migrate: migration %q is irreversible (%s): %w", m.ID, m.IrreversibleReason, ErrIrreversible)
		}
		if m.Destructive && !r.allowDestructive {
			return nil, fmt.Errorf("migrate: migration %q is destructive and reverting it requires AllowDestructive: %w", m.ID, ErrDestructiveBlocked)
		}
	}

	// Revert newest-first.
	var reverted []Ledger
	for i := len(toRevert) - 1; i >= 0; i-- {
		l := toRevert[i]
		m, _ := r.reg.Get(l.ID)
		if err := r.revertOne(ctx, m); err != nil {
			return reverted, err
		}
		reverted = append(reverted, l)
	}
	return reverted, nil
}

// revertOne reverts a single migration in its own transaction.
func (r *Runner) revertOne(ctx context.Context, m Migration) error {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("migrate: migration %q: begin transaction: %w", m.ID, err)
	}
	defer func() { _ = tx.Rollback() }()

	for i, stmt := range m.Down.forEngine(r.engine) {
		if err := tx.Exec(ctx, stmt); err != nil {
			return fmt.Errorf("migrate: migration %q down step %d: %w", m.ID, i+1, err)
		}
	}
	if err := deleteLedger(ctx, tx, r.engine, m.ID); err != nil {
		return fmt.Errorf("migrate: migration %q: delete ledger: %w", m.ID, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("migrate: migration %q: commit: %w", m.ID, err)
	}
	return nil
}

// checkDependencies verifies each pending migration's Requires are satisfied by
// migrations already applied or by earlier pending migrations that will be
// applied first. Because the registry already guarantees dependencies are
// strictly earlier and present, this never triggers through the public API; it
// is explicit defense-in-depth against a corrupted registry invariant.
func checkDependencies(applied map[string]bool, pending []Migration) error {
	have := make(map[string]bool, len(applied)+len(pending))
	for id := range applied {
		have[id] = true
	}
	for _, m := range pending {
		for _, req := range m.Requires {
			if !have[req] {
				return fmt.Errorf("migrate: migration %q requires %q, which is not applied: %w", m.ID, req, ErrDependencyUnmet)
			}
		}
		have[m.ID] = true
	}
	return nil
}
