package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/blocklist"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/repository"
)

// handleColumns is the fixed column list shared by every handle SELECT so the
// scan order in scanHandle stays in lockstep with the queries.
const handleColumns = `id, owner_id, name, state, quarantine_until,
flagged_for_review, quarantine_on_release, created_at, updated_at`

// handleRepo is the PostgreSQL HandleRepository. Every owner-scoped method
// carries owner_id in its WHERE clause so a row belonging to another owner is
// indistinguishable from a missing row.
type handleRepo struct {
	e execer
}

// Compile-time assertion that handleRepo satisfies the port.
var _ repository.HandleRepository = (*handleRepo)(nil)

// Register persists a new handle name-claim exactly as given. Three UNIQUE
// indexes map a clash to domain.ErrConflict: the global one on name, the one on
// name_fold that refuses a look-alike of a live claim, and the partial one that
// holds an owner to a single active claim.
//
// name_fold is written and never read back. Resolution matches the exact name,
// so a look-alike that was never registered misses rather than landing on the
// name it imitates.
func (r *handleRepo) Register(ctx context.Context, h *domain.Handle) error {
	// A nil entity is a caller programming error, not a storage fault; reject it
	// as invalid input rather than dereferencing it into a panic.
	if h == nil {
		return fmt.Errorf("%s: nil handle: %w", errPrefix, domain.ErrInvalidInput)
	}
	const q = `INSERT INTO handles (id, owner_id, name, name_fold, fold_version,
state, quarantine_until,
flagged_for_review, quarantine_on_release, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`
	// flagged_for_review and quarantine_on_release are real BOOLEAN columns
	// here, so the Go bools bind directly; the SQLite adapter has to encode
	// them as 0/1 integers to satisfy its CHECK constraints.
	_, err := r.e.ExecContext(ctx, q,
		string(h.ID),
		string(h.OwnerID),
		h.Name,
		// Derived here, from the name in this same row, so the two cannot
		// disagree. A fold supplied by the caller would let a caller that set
		// one not matching its name land a look-alike the unique index below
		// never collides with, which would leave the index guaranteeing
		// nothing against any path that did not choose to fold correctly.
		blocklist.Skeleton(h.Name),
		blocklist.TableVersion,
		string(h.State),
		encNullTime(h.QuarantineUntil),
		h.FlaggedForReview,
		h.QuarantineOnRelease,
		encTime(h.CreatedAt),
		encTime(h.UpdatedAt),
	)
	return mapError(err)
}

// GetByName returns the handle row holding the given normalized name in any
// state, or domain.ErrNotFound if the name is unclaimed.
//
// UNSCOPED: handle-name resolution is public; any caller may look up which
// handle owns a name, so this method is deliberately not owner-scoped.
func (r *handleRepo) GetByName(ctx context.Context, normalized string) (*domain.Handle, error) {
	q := `SELECT ` + handleColumns + ` FROM handles WHERE name = $1`
	return scanHandle(r.e.QueryRowContext(ctx, q, normalized))
}

// Get returns the owner's handle with the given ID, scoped by owner_id, or
// domain.ErrNotFound if it does not exist or belongs to another owner.
func (r *handleRepo) Get(ctx context.Context, ownerID domain.OwnerID, id domain.HandleID) (*domain.Handle, error) {
	q := `SELECT ` + handleColumns + ` FROM handles WHERE id = $1 AND owner_id = $2`
	return scanHandle(r.e.QueryRowContext(ctx, q, string(id), string(ownerID)))
}

// GetActiveByOwner returns the owner's single active handle, or
// domain.ErrNotFound if the owner has none.
func (r *handleRepo) GetActiveByOwner(ctx context.Context, ownerID domain.OwnerID) (*domain.Handle, error) {
	q := `SELECT ` + handleColumns + ` FROM handles WHERE owner_id = $1 AND state = $2`
	return scanHandle(r.e.QueryRowContext(ctx, q, string(ownerID), string(domain.NameStateActive)))
}

// ListByOwner returns all of the owner's handle rows in any state, ordered by
// creation time then id for a stable sequence.
func (r *handleRepo) ListByOwner(ctx context.Context, ownerID domain.OwnerID) ([]domain.Handle, error) {
	q := `SELECT ` + handleColumns + ` FROM handles WHERE owner_id = $1
ORDER BY created_at ASC, id ASC`
	rows, err := r.e.QueryContext(ctx, q, string(ownerID))
	if err != nil {
		return nil, mapError(err)
	}
	return collectHandles(rows)
}

// Update persists changes to the mutable fields of a handle, scoped by
// h.OwnerID and h.ID. Name is immutable per row: the current name is read under
// the same owner scope first, so a wrong-owner Update reports domain.ErrNotFound
// (never revealing the row) and only a same-owner Name change reports
// domain.ErrImmutable. The whole read-then-write runs atomically.
func (r *handleRepo) Update(ctx context.Context, h *domain.Handle) error {
	// A nil entity is a caller programming error, not a storage fault; reject it
	// as invalid input rather than dereferencing it into a panic. Register and
	// Create already guard this way, and Update must match: a partially applied
	// convention is worse than none, because callers stop checking.
	if h == nil {
		return fmt.Errorf("%s: nil handle: %w", errPrefix, domain.ErrInvalidInput)
	}
	return withLocalTx(ctx, r.e, func(ex execer) error {
		const sel = `SELECT name FROM handles WHERE id = $1 AND owner_id = $2`
		var current string
		// The owner-scoped read is the security gate: a row owned by another
		// owner returns sql.ErrNoRows here and is reported as ErrNotFound, so
		// the immutability check below only ever runs on the caller's own row.
		if err := ex.QueryRowContext(ctx, sel, string(h.ID), string(h.OwnerID)).Scan(&current); err != nil {
			return mapError(err)
		}
		if current != h.Name {
			return domain.ErrImmutable
		}

		const upd = `UPDATE handles
SET state = $1, quarantine_until = $2, flagged_for_review = $3,
quarantine_on_release = $4, updated_at = $5
WHERE id = $6 AND owner_id = $7`
		res, err := ex.ExecContext(ctx, upd,
			string(h.State),
			encNullTime(h.QuarantineUntil),
			h.FlaggedForReview,
			h.QuarantineOnRelease,
			encTime(h.UpdatedAt),
			string(h.ID),
			string(h.OwnerID),
		)
		if err != nil {
			return mapError(err)
		}
		return requireAffected(res)
	})
}

// ListExpiredQuarantine returns up to limit quarantined rows whose
// quarantine_until is at or before now, oldest first, for the release sweep.
// Because timestamps are fixed-width UTC text, the "<=" comparison is a lexical
// one that matches chronological order.
//
// UNSCOPED: a system-maintenance sweep across all owners; the release job acts
// on behalf of no single owner.
func (r *handleRepo) ListExpiredQuarantine(ctx context.Context, now time.Time, limit int) ([]domain.Handle, error) {
	// A non-positive limit has no safe interpretation. Reading it as "unbounded"
	// would turn a caller's zero value into a full-table scan, which is the
	// accident this API's batching exists to prevent, so it is rejected as
	// invalid input instead.
	if limit <= 0 {
		return nil, fmt.Errorf("%s: list limit must be positive: %w", errPrefix, domain.ErrInvalidInput)
	}
	q := `SELECT ` + handleColumns + ` FROM handles
WHERE state = $1 AND quarantine_until IS NOT NULL AND quarantine_until <= $2
ORDER BY quarantine_until ASC, id ASC LIMIT $3`
	rows, err := r.e.QueryContext(ctx, q,
		string(domain.NameStateQuarantined), encTime(now), limit)
	if err != nil {
		return nil, mapError(err)
	}
	return collectHandles(rows)
}

// Release deletes an elapsed quarantined claim so the name returns to the pool.
//
// The state and deadline predicates are part of the DELETE rather than a read
// beforehand, so the decision to release and the release itself cannot be
// separated: a claim the owner reclaimed (state back to active) or an operator
// retired after the sweep listed it no longer matches, and survives untouched.
//
// UNSCOPED: system-maintenance sweep across all owners; see the port.
func (r *handleRepo) Release(ctx context.Context, id domain.HandleID, now time.Time) error {
	const q = `DELETE FROM handles
WHERE id = $1 AND state = $2 AND quarantine_until IS NOT NULL AND quarantine_until <= $3`
	res, err := r.e.ExecContext(ctx, q,
		string(id), string(domain.NameStateQuarantined), encTime(now))
	if err != nil {
		return mapError(err)
	}
	return requireAffected(res)
}

// collectHandles drains rows into a slice, mapping any iteration error through
// mapError and always closing the cursor.
func collectHandles(rows *sql.Rows) ([]domain.Handle, error) {
	defer func() { _ = rows.Close() }()

	var handles []domain.Handle
	for rows.Next() {
		h, err := scanHandle(rows)
		if err != nil {
			return nil, err
		}
		handles = append(handles, *h)
	}
	if err := rows.Err(); err != nil {
		return nil, mapError(err)
	}
	return handles, nil
}

// scanHandle decodes one handle row in handleColumns order. A sql.ErrNoRows
// from a *sql.Row read maps to domain.ErrNotFound via mapError.
func scanHandle(s rowScanner) (*domain.Handle, error) {
	var (
		h               domain.Handle
		state           string
		quarantineUntil sql.NullString
		createdAt       string
		updatedAt       string
	)
	// The two flags scan straight into bool: they are BOOLEAN columns, unlike
	// the SQLite adapter's 0/1 INTEGERs which need an int64 hop.
	if err := s.Scan(
		&h.ID, &h.OwnerID, &h.Name, &state, &quarantineUntil,
		&h.FlaggedForReview, &h.QuarantineOnRelease, &createdAt, &updatedAt,
	); err != nil {
		return nil, mapError(err)
	}
	h.State = domain.NameState(state)

	var err error
	if h.QuarantineUntil, err = decNullTime(quarantineUntil); err != nil {
		return nil, err
	}
	if h.CreatedAt, err = decTime(createdAt); err != nil {
		return nil, err
	}
	if h.UpdatedAt, err = decTime(updatedAt); err != nil {
		return nil, err
	}
	return &h, nil
}
