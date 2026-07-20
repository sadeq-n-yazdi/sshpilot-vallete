package postgres

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/repository"
)

// linkedIdentityRepo is the PostgreSQL LinkedIdentityRepository. It runs against
// an execer so the same code serves both the auto-commit (*sql.DB) and
// transaction (*sql.Tx) paths.
type linkedIdentityRepo struct {
	e execer
}

// Compile-time assertion that linkedIdentityRepo satisfies the port.
var _ repository.LinkedIdentityRepository = (*linkedIdentityRepo)(nil)

// linkedIdentityColumns is the shared SELECT list, kept in one place so the
// column order can never drift from scanLinkedIdentity's Scan order.
const linkedIdentityColumns = `id, owner_id, provider, subject, email, created_at, updated_at`

// Create persists a fully populated LinkedIdentity exactly as given. A second
// link of the same (provider, subject) pair violates the unique index and,
// through SQLSTATE 23505, maps to domain.ErrConflict — the same sentinel the
// SQLite adapter derives from its extended constraint codes.
//
// That conflict is the point of the constraint: it is what stops one external
// subject from being bound to a second owner, so the check is left to the
// database rather than a read-then-insert in this adapter, which two concurrent
// callers could both pass. Postgres does not serialize writers the way the
// SQLite adapter's single write lock does, so this is not a convenience here —
// it is the only thing standing between two simultaneous logins and a
// double-bound subject.
func (r *linkedIdentityRepo) Create(ctx context.Context, li *domain.LinkedIdentity) error {
	// A nil entity is a caller programming error, not a storage fault; reject it
	// as invalid input rather than dereferencing it into a panic.
	if li == nil {
		return fmt.Errorf("%s: nil linked identity: %w", errPrefix, domain.ErrInvalidInput)
	}
	const q = `INSERT INTO linked_identities (` + linkedIdentityColumns + `)
VALUES ($1, $2, $3, $4, $5, $6, $7)`
	_, err := r.e.ExecContext(ctx, q,
		string(li.ID),
		string(li.OwnerID),
		li.Provider,
		li.Subject,
		encNullText(li.Email),
		encTime(li.CreatedAt),
		encTime(li.UpdatedAt),
	)
	return mapError(err)
}

// GetByProviderSubject returns the linked identity for the given provider and
// subject, or domain.ErrNotFound if none exists.
//
// UNSCOPED: this is the login bootstrap that resolves an external subject to an
// owner; the owner is not yet known when this runs, so there is no owner to
// scope by. The lookup is by the exact (provider, subject) pair the provider
// asserted, which is unique, so it can return at most one row and cannot be
// used to enumerate identities.
func (r *linkedIdentityRepo) GetByProviderSubject(ctx context.Context, provider, subject string) (*domain.LinkedIdentity, error) {
	const q = `SELECT ` + linkedIdentityColumns + `
FROM linked_identities WHERE provider = $1 AND subject = $2`
	return scanLinkedIdentity(r.e.QueryRowContext(ctx, q, provider, subject))
}

// ListByOwner returns all of the owner's linked identities, oldest first. An
// owner with no linked identities yields a nil slice, not an empty one.
//
// created_at is fixed-width UTC text — see timefmt.go — so ordering by it
// lexically is chronological; id breaks ties so the order is total and stable.
func (r *linkedIdentityRepo) ListByOwner(ctx context.Context, ownerID domain.OwnerID) ([]domain.LinkedIdentity, error) {
	const q = `SELECT ` + linkedIdentityColumns + `
FROM linked_identities WHERE owner_id = $1 ORDER BY created_at ASC, id ASC`
	rows, err := r.e.QueryContext(ctx, q, string(ownerID))
	if err != nil {
		return nil, mapError(err)
	}
	return collectLinkedIdentities(rows)
}

// Delete removes the owner's linked identity with the given ID. A row that does
// not exist and a row belonging to another owner are both reported as
// domain.ErrNotFound; distinguishing them would leak the existence of another
// owner's identity to a caller who cannot read it.
func (r *linkedIdentityRepo) Delete(ctx context.Context, ownerID domain.OwnerID, id domain.LinkedIdentityID) error {
	const q = `DELETE FROM linked_identities WHERE id = $1 AND owner_id = $2`
	res, err := r.e.ExecContext(ctx, q, string(id), string(ownerID))
	if err != nil {
		return mapError(err)
	}
	return requireAffected(res)
}

// DeleteByOwner removes all of the owner's linked identities and returns the
// number deleted. This supports account deletion and crypto-erasure.
//
// Unlike Delete, a zero count is a success, not domain.ErrNotFound: an owner
// with nothing linked is already in the requested state, and an erasure sweep
// must not fail on an owner who has no rows to erase.
func (r *linkedIdentityRepo) DeleteByOwner(ctx context.Context, ownerID domain.OwnerID) (int64, error) {
	const q = `DELETE FROM linked_identities WHERE owner_id = $1`
	res, err := r.e.ExecContext(ctx, q, string(ownerID))
	if err != nil {
		return 0, mapError(err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, mapError(err)
	}
	return n, nil
}

// encNullText encodes an optional string for binding as a SQL argument. A nil
// pointer becomes an untyped nil (SQL NULL); a non-nil pointer becomes its
// value, so an empty string round-trips as an empty string rather than NULL.
func encNullText(s *string) any {
	if s == nil {
		return nil
	}
	return *s
}

// decNullText decodes an optional string read from a nullable text column. A
// NULL column yields a nil pointer.
func decNullText(ns sql.NullString) *string {
	if !ns.Valid {
		return nil
	}
	v := ns.String
	return &v
}

// collectLinkedIdentities drains rows into a slice, mapping any iteration error
// through mapError and always closing the cursor. An empty result yields a nil
// slice, never an empty one.
func collectLinkedIdentities(rows *sql.Rows) ([]domain.LinkedIdentity, error) {
	defer func() { _ = rows.Close() }()

	var out []domain.LinkedIdentity
	for rows.Next() {
		li, err := scanLinkedIdentity(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *li)
	}
	if err := rows.Err(); err != nil {
		return nil, mapError(err)
	}
	return out, nil
}

// scanLinkedIdentity decodes one linked_identities row in
// linkedIdentityColumns order. A sql.ErrNoRows from a *sql.Row read is mapped
// to domain.ErrNotFound by mapError.
func scanLinkedIdentity(s rowScanner) (*domain.LinkedIdentity, error) {
	var (
		li        domain.LinkedIdentity
		email     sql.NullString
		createdAt string
		updatedAt string
	)
	if err := s.Scan(&li.ID, &li.OwnerID, &li.Provider, &li.Subject, &email, &createdAt, &updatedAt); err != nil {
		return nil, mapError(err)
	}
	li.Email = decNullText(email)

	var err error
	if li.CreatedAt, err = decTime(createdAt); err != nil {
		return nil, err
	}
	if li.UpdatedAt, err = decTime(updatedAt); err != nil {
		return nil, err
	}
	return &li, nil
}
