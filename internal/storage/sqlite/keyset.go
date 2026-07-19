package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/repository"
)

// keySetColumns is the fixed column list shared by every key_sets SELECT so the
// scan order in scanKeySet stays in lockstep with the queries.
const keySetColumns = `id, owner_id, name, visibility, is_default, state,
quarantine_until, flagged_for_review, quarantine_on_release, created_at, updated_at`

// prefixedKeySetColumns is keySetColumns qualified with the ks alias for the
// membership joins, keeping the same column order as scanKeySet.
const prefixedKeySetColumns = `ks.id, ks.owner_id, ks.name, ks.visibility, ks.is_default, ks.state,
ks.quarantine_until, ks.flagged_for_review, ks.quarantine_on_release, ks.created_at, ks.updated_at`

// keySetRepo is the SQLite KeySetRepository. Every owner-scoped method carries
// owner_id in its WHERE clause so a row belonging to another owner is
// indistinguishable from a missing row.
//
// The membership table key_set_members has no owner_id column, so its two
// foreign keys can only guarantee that the referenced set and key exist — never
// that the two share an owner. This repository is therefore the sole
// enforcement point for membership owner-consistency; see AddMember.
type keySetRepo struct {
	e execer
}

// Compile-time assertion that keySetRepo satisfies the port.
var _ repository.KeySetRepository = (*keySetRepo)(nil)

// Create persists a fully populated KeySet exactly as given. The unique index
// on (owner_id, name) maps a duplicate to domain.ErrConflict in any state,
// including a quarantined tombstone, so a freed name stays reserved.
func (r *keySetRepo) Create(ctx context.Context, s *domain.KeySet) error {
	// A nil entity is a caller programming error, not a storage fault; reject it
	// as invalid input rather than dereferencing it into a panic.
	if s == nil {
		return fmt.Errorf("%s: nil key set: %w", errPrefix, domain.ErrInvalidInput)
	}
	const q = `INSERT INTO key_sets (id, owner_id, name, visibility, is_default, state,
quarantine_until, flagged_for_review, quarantine_on_release, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	_, err := r.e.ExecContext(ctx, q,
		string(s.ID),
		string(s.OwnerID),
		s.Name,
		string(s.Visibility),
		encBool(s.IsDefault),
		string(s.State),
		encNullTime(s.QuarantineUntil),
		encBool(s.FlaggedForReview),
		encBool(s.QuarantineOnRelease),
		encTime(s.CreatedAt),
		encTime(s.UpdatedAt),
	)
	return mapError(err)
}

// Get returns the owner's key set with the given ID, scoped by id AND owner_id,
// or domain.ErrNotFound if it does not exist or belongs to another owner.
func (r *keySetRepo) Get(ctx context.Context, ownerID domain.OwnerID, id domain.KeySetID) (*domain.KeySet, error) {
	q := `SELECT ` + keySetColumns + ` FROM key_sets WHERE id = ? AND owner_id = ?`
	return scanKeySet(r.e.QueryRowContext(ctx, q, string(id), string(ownerID)))
}

// GetByName returns the owner's key set with the given normalized name, scoped
// by owner_id, or domain.ErrNotFound if the owner has none.
func (r *keySetRepo) GetByName(ctx context.Context, ownerID domain.OwnerID, normalized string) (*domain.KeySet, error) {
	q := `SELECT ` + keySetColumns + ` FROM key_sets WHERE owner_id = ? AND name = ?`
	return scanKeySet(r.e.QueryRowContext(ctx, q, string(ownerID), normalized))
}

// GetDefault returns the owner's default key set, or domain.ErrNotFound if the
// owner has none. The partial unique index on (owner_id) WHERE is_default = 1
// guarantees at most one such row per owner.
func (r *keySetRepo) GetDefault(ctx context.Context, ownerID domain.OwnerID) (*domain.KeySet, error) {
	q := `SELECT ` + keySetColumns + ` FROM key_sets WHERE owner_id = ? AND is_default = 1`
	return scanKeySet(r.e.QueryRowContext(ctx, q, string(ownerID)))
}

// ListByOwner returns all of the owner's key sets ordered by id for a stable,
// deterministic sequence.
func (r *keySetRepo) ListByOwner(ctx context.Context, ownerID domain.OwnerID) ([]domain.KeySet, error) {
	q := `SELECT ` + keySetColumns + ` FROM key_sets WHERE owner_id = ? ORDER BY id ASC`
	rows, err := r.e.QueryContext(ctx, q, string(ownerID))
	if err != nil {
		return nil, mapError(err)
	}
	return collectKeySets(rows)
}

// CountByOwner returns the number of the owner's key sets, scoped by owner_id.
func (r *keySetRepo) CountByOwner(ctx context.Context, ownerID domain.OwnerID) (int, error) {
	const q = `SELECT COUNT(*) FROM key_sets WHERE owner_id = ?`
	var n int
	if err := r.e.QueryRowContext(ctx, q, string(ownerID)).Scan(&n); err != nil {
		return 0, mapError(err)
	}
	return n, nil
}

// Update persists changes to the mutable fields of a key set, scoped by
// s.OwnerID AND s.ID. Only visibility, state, quarantine_until,
// flagged_for_review, and quarantine_on_release are written (plus the
// updated_at bookkeeping stamp). name and is_default are deliberately absent
// from the SET clause: name is immutable per row (renaming is a service-layer
// WithTx composition) and is_default is owned exclusively by SetDefault, which
// alone can move it without tripping the partial unique index. Changes to
// either field in the passed struct are silently ignored rather than persisted.
func (r *keySetRepo) Update(ctx context.Context, s *domain.KeySet) error {
	// A nil entity is a caller programming error, not a storage fault; reject it
	// as invalid input rather than dereferencing it into a panic.
	if s == nil {
		return fmt.Errorf("%s: nil key set: %w", errPrefix, domain.ErrInvalidInput)
	}
	const q = `UPDATE key_sets
SET visibility = ?, state = ?, quarantine_until = ?, flagged_for_review = ?,
quarantine_on_release = ?, updated_at = ?
WHERE id = ? AND owner_id = ?`
	res, err := r.e.ExecContext(ctx, q,
		string(s.Visibility),
		string(s.State),
		encNullTime(s.QuarantineUntil),
		encBool(s.FlaggedForReview),
		encBool(s.QuarantineOnRelease),
		encTime(s.UpdatedAt),
		string(s.ID),
		string(s.OwnerID),
	)
	if err != nil {
		return mapError(err)
	}
	return requireAffected(res)
}

// SetDefault makes the given set the owner's default inside one transaction.
//
// The order is load-bearing: the schema carries a partial unique index
// ux_key_sets_owner_default on (owner_id) WHERE is_default = 1, so the owner's
// existing default MUST be cleared before the new one is set or the second
// statement trips the index. The clear is deliberately not checked for affected
// rows — an owner who holds no default yet legitimately clears nothing — while
// the owner-scoped set IS checked, so a set that does not exist or belongs to
// another owner reports domain.ErrNotFound and rolls the clear back with it,
// leaving the previous default intact.
func (r *keySetRepo) SetDefault(ctx context.Context, ownerID domain.OwnerID, id domain.KeySetID) error {
	return withLocalTx(ctx, r.e, func(ex execer) error {
		const clear = `UPDATE key_sets SET is_default = 0 WHERE owner_id = ? AND is_default = 1`
		if _, err := ex.ExecContext(ctx, clear, string(ownerID)); err != nil {
			return mapError(err)
		}

		const set = `UPDATE key_sets SET is_default = 1 WHERE id = ? AND owner_id = ?`
		res, err := ex.ExecContext(ctx, set, string(id), string(ownerID))
		if err != nil {
			return mapError(err)
		}
		return requireAffected(res)
	})
}

// Delete removes the owner's key set and its membership rows inside one
// transaction, never touching the referenced public_keys rows.
//
// A set whose is_default is true is refused with domain.ErrDefaultKeySet, a
// distinct recoverable signal telling the caller to designate another default
// first. The flag is read through an owner-scoped SELECT inside the same
// transaction, so the refusal can never be provoked for another owner's set:
// that read misses and reports domain.ErrNotFound instead, exactly as a missing
// row does. Membership rows are deleted before the set itself to respect the
// foreign key direction.
func (r *keySetRepo) Delete(ctx context.Context, ownerID domain.OwnerID, id domain.KeySetID) error {
	return withLocalTx(ctx, r.e, func(ex execer) error {
		const sel = `SELECT is_default FROM key_sets WHERE id = ? AND owner_id = ?`
		var isDefault int64
		if err := ex.QueryRowContext(ctx, sel, string(id), string(ownerID)).Scan(&isDefault); err != nil {
			return mapError(err)
		}
		if isDefault != 0 {
			return domain.ErrDefaultKeySet
		}

		const delMembers = `DELETE FROM key_set_members WHERE key_set_id = ?`
		if _, err := ex.ExecContext(ctx, delMembers, string(id)); err != nil {
			return mapError(err)
		}

		const delSet = `DELETE FROM key_sets WHERE id = ? AND owner_id = ?`
		res, err := ex.ExecContext(ctx, delSet, string(id), string(ownerID))
		if err != nil {
			return mapError(err)
		}
		return requireAffected(res)
	})
}

// AddMember adds the key to the set, stamping added_at with now.
//
// SECURITY: this method is the ONLY enforcement point for membership
// owner-consistency. key_set_members carries no owner_id column, and its two
// foreign keys constrain only that the referenced key_set and public_key rows
// EXIST — nothing in the schema prevents an INSERT that links one owner's set
// to another owner's key. The database therefore cannot stop that
// confused-deputy write; this repository must.
//
// Both existence checks are owner-scoped SELECTs run inside the same
// transaction as the INSERT, so the membership row is written only once BOTH
// the set and the key have been proven to belong to ownerID. A miss on either
// check maps identically to domain.ErrNotFound: "the set/key does not exist"
// and "it belongs to another owner" are never distinguished, so the error can
// leak no cross-owner existence information. An already-present member trips
// the composite primary key and maps to domain.ErrConflict.
func (r *keySetRepo) AddMember(ctx context.Context, ownerID domain.OwnerID, setID domain.KeySetID, keyID domain.PublicKeyID, now time.Time) error {
	return withLocalTx(ctx, r.e, func(ex execer) error {
		const selSet = `SELECT 1 FROM key_sets WHERE id = ? AND owner_id = ?`
		var found int64
		if err := ex.QueryRowContext(ctx, selSet, string(setID), string(ownerID)).Scan(&found); err != nil {
			return mapError(err)
		}

		const selKey = `SELECT 1 FROM public_keys WHERE id = ? AND owner_id = ?`
		if err := ex.QueryRowContext(ctx, selKey, string(keyID), string(ownerID)).Scan(&found); err != nil {
			return mapError(err)
		}

		const ins = `INSERT INTO key_set_members (key_set_id, public_key_id, added_at) VALUES (?, ?, ?)`
		_, err := ex.ExecContext(ctx, ins, string(setID), string(keyID), encTime(now))
		return mapError(err)
	})
}

// RemoveMember removes the key from the owner's set. key_set_members has no
// owner_id column, so both sides are scoped through subqueries against the
// owner's own key_sets and public_keys rows: a membership naming another
// owner's set or key matches nothing and, like an absent membership, reports
// domain.ErrNotFound.
func (r *keySetRepo) RemoveMember(ctx context.Context, ownerID domain.OwnerID, setID domain.KeySetID, keyID domain.PublicKeyID) error {
	const q = `DELETE FROM key_set_members
WHERE key_set_id IN (SELECT id FROM key_sets WHERE id = ? AND owner_id = ?)
AND public_key_id IN (SELECT id FROM public_keys WHERE id = ? AND owner_id = ?)`
	res, err := r.e.ExecContext(ctx, q,
		string(setID), string(ownerID), string(keyID), string(ownerID))
	if err != nil {
		return mapError(err)
	}
	return requireAffected(res)
}

// ListMembers returns the membership rows of the owner's set, ordered by
// public_key_id for a deterministic sequence. The join to key_sets carries the
// owner_id predicate, so another owner's set yields no rows rather than its
// membership.
func (r *keySetRepo) ListMembers(ctx context.Context, ownerID domain.OwnerID, setID domain.KeySetID) ([]domain.KeySetMembership, error) {
	const q = `SELECT m.key_set_id, m.public_key_id, m.added_at
FROM key_set_members m
JOIN key_sets ks ON ks.id = m.key_set_id
WHERE ks.owner_id = ? AND ks.id = ?
ORDER BY m.public_key_id ASC`
	rows, err := r.e.QueryContext(ctx, q, string(ownerID), string(setID))
	if err != nil {
		return nil, mapError(err)
	}
	defer func() { _ = rows.Close() }()

	var members []domain.KeySetMembership
	for rows.Next() {
		var (
			m       domain.KeySetMembership
			addedAt string
		)
		if err := rows.Scan(&m.KeySetID, &m.PublicKeyID, &addedAt); err != nil {
			return nil, mapError(err)
		}
		if m.AddedAt, err = decTime(addedAt); err != nil {
			return nil, err
		}
		members = append(members, m)
	}
	if err := rows.Err(); err != nil {
		return nil, mapError(err)
	}
	return members, nil
}

// ListSetsForKey returns the owner's key sets that contain the given key,
// ordered by id. Both sides of the membership are owner-scoped — the set
// through ks.owner_id and the key through pk.owner_id — so a membership row
// that links the owner's set to another owner's key (which the schema cannot
// prevent; see AddMember) is not surfaced here either.
func (r *keySetRepo) ListSetsForKey(ctx context.Context, ownerID domain.OwnerID, keyID domain.PublicKeyID) ([]domain.KeySet, error) {
	q := `SELECT ` + prefixedKeySetColumns + `
FROM key_sets ks
JOIN key_set_members m ON m.key_set_id = ks.id
JOIN public_keys pk ON pk.id = m.public_key_id AND pk.owner_id = ?
WHERE ks.owner_id = ? AND m.public_key_id = ?
ORDER BY ks.id ASC`
	rows, err := r.e.QueryContext(ctx, q, string(ownerID), string(ownerID), string(keyID))
	if err != nil {
		return nil, mapError(err)
	}
	return collectKeySets(rows)
}

// ListExpiredQuarantine returns up to limit quarantined key-set tombstones
// whose quarantine_until is at or before now, oldest first, for the release
// sweep. Because timestamps are fixed-width UTC text, the "<=" comparison is a
// lexical one that matches chronological order.
//
// UNSCOPED: a system-maintenance sweep across all owners; the quarantine-release
// job acts on behalf of no single owner.
func (r *keySetRepo) ListExpiredQuarantine(ctx context.Context, now time.Time, limit int) ([]domain.KeySet, error) {
	if limit <= 0 {
		limit = defaultPageLimit
	}
	q := `SELECT ` + keySetColumns + ` FROM key_sets
WHERE state = ? AND quarantine_until IS NOT NULL AND quarantine_until <= ?
ORDER BY quarantine_until ASC, id ASC LIMIT ?`
	rows, err := r.e.QueryContext(ctx, q,
		string(domain.NameStateQuarantined), encTime(now), limit)
	if err != nil {
		return nil, mapError(err)
	}
	return collectKeySets(rows)
}

// collectKeySets drains rows into a slice, mapping any iteration error through
// mapError and always closing the cursor.
func collectKeySets(rows *sql.Rows) ([]domain.KeySet, error) {
	defer func() { _ = rows.Close() }()

	var sets []domain.KeySet
	for rows.Next() {
		s, err := scanKeySet(rows)
		if err != nil {
			return nil, err
		}
		sets = append(sets, *s)
	}
	if err := rows.Err(); err != nil {
		return nil, mapError(err)
	}
	return sets, nil
}

// scanKeySet decodes one key_sets row in keySetColumns order. A sql.ErrNoRows
// from a *sql.Row read maps to domain.ErrNotFound via mapError.
func scanKeySet(s rowScanner) (*domain.KeySet, error) {
	var (
		ks                  domain.KeySet
		visibility          string
		isDefault           int64
		state               string
		quarantineUntil     sql.NullString
		flaggedForReview    int64
		quarantineOnRelease int64
		createdAt           string
		updatedAt           string
	)
	if err := s.Scan(
		&ks.ID, &ks.OwnerID, &ks.Name, &visibility, &isDefault, &state,
		&quarantineUntil, &flaggedForReview, &quarantineOnRelease,
		&createdAt, &updatedAt,
	); err != nil {
		return nil, mapError(err)
	}
	ks.Visibility = domain.Visibility(visibility)
	ks.IsDefault = isDefault != 0
	ks.State = domain.NameState(state)
	ks.FlaggedForReview = flaggedForReview != 0
	ks.QuarantineOnRelease = quarantineOnRelease != 0

	var err error
	if ks.QuarantineUntil, err = decNullTime(quarantineUntil); err != nil {
		return nil, err
	}
	if ks.CreatedAt, err = decTime(createdAt); err != nil {
		return nil, err
	}
	if ks.UpdatedAt, err = decTime(updatedAt); err != nil {
		return nil, err
	}
	return &ks, nil
}
