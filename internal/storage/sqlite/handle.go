package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/repository"
)

// handleColumns is the fixed column list shared by every handle SELECT so the
// scan order in scanHandle stays in lockstep with the queries.
const handleColumns = `id, owner_id, name, state, quarantine_until,
flagged_for_review, quarantine_on_release, created_at, updated_at`

// handleRepo is the SQLite HandleRepository. Every owner-scoped method carries
// owner_id in its WHERE clause so a row belonging to another owner is
// indistinguishable from a missing row.
type handleRepo struct {
	e execer
}

// Compile-time assertion that handleRepo satisfies the port.
var _ repository.HandleRepository = (*handleRepo)(nil)

// Register persists a new handle name-claim exactly as given. The global
// UNIQUE index on name maps a clash to domain.ErrConflict.
func (r *handleRepo) Register(ctx context.Context, h *domain.Handle) error {
	// A nil entity is a caller programming error, not a storage fault; reject it
	// as invalid input rather than dereferencing it into a panic.
	if h == nil {
		return fmt.Errorf("%s: nil handle: %w", errPrefix, domain.ErrInvalidInput)
	}
	const q = `INSERT INTO handles (id, owner_id, name, state, quarantine_until,
flagged_for_review, quarantine_on_release, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
	_, err := r.e.ExecContext(ctx, q,
		string(h.ID),
		string(h.OwnerID),
		h.Name,
		string(h.State),
		encNullTime(h.QuarantineUntil),
		encBool(h.FlaggedForReview),
		encBool(h.QuarantineOnRelease),
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
	q := `SELECT ` + handleColumns + ` FROM handles WHERE name = ?`
	return scanHandle(r.e.QueryRowContext(ctx, q, normalized))
}

// Get returns the owner's handle with the given ID, scoped by owner_id, or
// domain.ErrNotFound if it does not exist or belongs to another owner.
func (r *handleRepo) Get(ctx context.Context, ownerID domain.OwnerID, id domain.HandleID) (*domain.Handle, error) {
	q := `SELECT ` + handleColumns + ` FROM handles WHERE id = ? AND owner_id = ?`
	return scanHandle(r.e.QueryRowContext(ctx, q, string(id), string(ownerID)))
}

// GetActiveByOwner returns the owner's single active handle, or
// domain.ErrNotFound if the owner has none.
func (r *handleRepo) GetActiveByOwner(ctx context.Context, ownerID domain.OwnerID) (*domain.Handle, error) {
	q := `SELECT ` + handleColumns + ` FROM handles WHERE owner_id = ? AND state = ?`
	return scanHandle(r.e.QueryRowContext(ctx, q, string(ownerID), string(domain.NameStateActive)))
}

// ListByOwner returns all of the owner's handle rows in any state, ordered by
// creation time then id for a stable sequence.
func (r *handleRepo) ListByOwner(ctx context.Context, ownerID domain.OwnerID) ([]domain.Handle, error) {
	q := `SELECT ` + handleColumns + ` FROM handles WHERE owner_id = ?
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
	return withLocalTx(ctx, r.e, func(ex execer) error {
		const sel = `SELECT name FROM handles WHERE id = ? AND owner_id = ?`
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
SET state = ?, quarantine_until = ?, flagged_for_review = ?,
quarantine_on_release = ?, updated_at = ?
WHERE id = ? AND owner_id = ?`
		res, err := ex.ExecContext(ctx, upd,
			string(h.State),
			encNullTime(h.QuarantineUntil),
			encBool(h.FlaggedForReview),
			encBool(h.QuarantineOnRelease),
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
	if limit <= 0 {
		limit = defaultPageLimit
	}
	q := `SELECT ` + handleColumns + ` FROM handles
WHERE state = ? AND quarantine_until IS NOT NULL AND quarantine_until <= ?
ORDER BY quarantine_until ASC, id ASC LIMIT ?`
	rows, err := r.e.QueryContext(ctx, q,
		string(domain.NameStateQuarantined), encTime(now), limit)
	if err != nil {
		return nil, mapError(err)
	}
	return collectHandles(rows)
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
		h                   domain.Handle
		state               string
		quarantineUntil     sql.NullString
		flaggedForReview    int64
		quarantineOnRelease int64
		createdAt           string
		updatedAt           string
	)
	if err := s.Scan(
		&h.ID, &h.OwnerID, &h.Name, &state, &quarantineUntil,
		&flaggedForReview, &quarantineOnRelease, &createdAt, &updatedAt,
	); err != nil {
		return nil, mapError(err)
	}
	h.State = domain.NameState(state)
	h.FlaggedForReview = flaggedForReview != 0
	h.QuarantineOnRelease = quarantineOnRelease != 0

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

// encBool encodes a Go bool as the SQLite 0/1 INTEGER the schema's CHECK
// constraints require, keeping storage explicit rather than relying on driver
// bool coercion.
func encBool(b bool) int64 {
	if b {
		return 1
	}
	return 0
}
