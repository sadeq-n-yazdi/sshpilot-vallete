package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/repository"
)

// defaultPageLimit is applied by paginated list methods when the caller
// requests a non-positive Limit.
const defaultPageLimit = 50

// ownerRepo is the PostgreSQL OwnerRepository. It runs against an execer so the
// same code serves both the auto-commit (*sql.DB) and transaction (*sql.Tx)
// paths.
type ownerRepo struct {
	e execer
}

// Compile-time assertion that ownerRepo satisfies the port.
var _ repository.OwnerRepository = (*ownerRepo)(nil)

// Create persists a fully populated Owner exactly as given. A duplicate primary
// key maps to domain.ErrConflict.
func (r *ownerRepo) Create(ctx context.Context, o *domain.Owner) error {
	// A nil entity is a caller programming error, not a storage fault; reject it
	// as invalid input rather than dereferencing it into a panic.
	if o == nil {
		return fmt.Errorf("%s: nil owner: %w", errPrefix, domain.ErrInvalidInput)
	}
	const q = `INSERT INTO owners (id, status, created_at, updated_at, deleted_at)
VALUES ($1, $2, $3, $4, $5)`
	_, err := r.e.ExecContext(ctx, q,
		string(o.ID),
		string(o.Status),
		encTime(o.CreatedAt),
		encTime(o.UpdatedAt),
		encNullTime(o.DeletedAt),
	)
	return mapError(err)
}

// Get returns the owner with the given ID, or domain.ErrNotFound if none
// exists.
func (r *ownerRepo) Get(ctx context.Context, id domain.OwnerID) (*domain.Owner, error) {
	const q = `SELECT id, status, created_at, updated_at, deleted_at
FROM owners WHERE id = $1`
	return scanOwner(r.e.QueryRowContext(ctx, q, string(id)))
}

// UpdateStatus sets the owner's status and stamps updated_at with now. A
// missing owner maps to domain.ErrNotFound.
func (r *ownerRepo) UpdateStatus(ctx context.Context, id domain.OwnerID, status domain.OwnerStatus, now time.Time) error {
	const q = `UPDATE owners SET status = $1, updated_at = $2 WHERE id = $3`
	res, err := r.e.ExecContext(ctx, q, string(status), encTime(now), string(id))
	if err != nil {
		return mapError(err)
	}
	return requireAffected(res)
}

// SoftDelete stamps deleted_at and updated_at with now without removing the
// row. Per the port contract it sets only those two fields; owner status is
// owned by UpdateStatus and is deliberately left untouched here.
func (r *ownerRepo) SoftDelete(ctx context.Context, id domain.OwnerID, now time.Time) error {
	const q = `UPDATE owners SET deleted_at = $1, updated_at = $2 WHERE id = $3`
	res, err := r.e.ExecContext(ctx, q, encTime(now), encTime(now), string(id))
	if err != nil {
		return mapError(err)
	}
	return requireAffected(res)
}

// List returns a page of owners ordered by id together with the next-page
// cursor. The cursor is the last id returned; an empty cursor starts from the
// beginning and an empty returned cursor means there are no further pages.
//
// UNSCOPED: an administrative sweep across all owners; not owner-scoped.
func (r *ownerRepo) List(ctx context.Context, page repository.Page) ([]domain.Owner, string, error) {
	limit := page.Limit
	if limit <= 0 {
		limit = defaultPageLimit
	}

	// Fetch one extra row to detect whether a further page exists without a
	// second round trip. id is the stable, unique keyset cursor.
	//
	// The cursor comparison relies on the text collation of owners.id. Postgres
	// orders text by the database's collation, which for a non-C locale is not
	// byte order; the ">" predicate and the ORDER BY use the same collation, so
	// the keyset walk stays consistent with itself and no row is skipped or
	// repeated. Ordering may differ from the SQLite adapter's byte ordering,
	// which the port contract does not constrain.
	const q = `SELECT id, status, created_at, updated_at, deleted_at
FROM owners WHERE id > $1 ORDER BY id ASC LIMIT $2`
	rows, err := r.e.QueryContext(ctx, q, page.Cursor, limit+1)
	if err != nil {
		return nil, "", mapError(err)
	}
	defer func() { _ = rows.Close() }()

	var owners []domain.Owner
	for rows.Next() {
		o, serr := scanOwner(rows)
		if serr != nil {
			return nil, "", serr
		}
		owners = append(owners, *o)
	}
	if err := rows.Err(); err != nil {
		return nil, "", mapError(err)
	}

	next := ""
	if len(owners) > limit {
		next = string(owners[limit-1].ID)
		owners = owners[:limit]
	}
	return owners, next, nil
}

// rowScanner is the shared surface of *sql.Row and *sql.Rows used by the scan
// helpers, so a single-row read and a row inside an iteration share code.
type rowScanner interface {
	Scan(dest ...any) error
}

// scanOwner decodes one owner row. A sql.ErrNoRows from a *sql.Row read is
// mapped to domain.ErrNotFound by mapError.
func scanOwner(s rowScanner) (*domain.Owner, error) {
	var (
		o         domain.Owner
		status    string
		createdAt string
		updatedAt string
		deletedAt sql.NullString
	)
	if err := s.Scan(&o.ID, &status, &createdAt, &updatedAt, &deletedAt); err != nil {
		return nil, mapError(err)
	}
	o.Status = domain.OwnerStatus(status)

	var err error
	if o.CreatedAt, err = decTime(createdAt); err != nil {
		return nil, err
	}
	if o.UpdatedAt, err = decTime(updatedAt); err != nil {
		return nil, err
	}
	if o.DeletedAt, err = decNullTime(deletedAt); err != nil {
		return nil, err
	}
	return &o, nil
}

// requireAffected maps an UPDATE that touched no rows to domain.ErrNotFound.
// Because every mutator is owner- or id-scoped in its WHERE clause, "no rows
// affected" means the target does not exist or belongs to another owner, which
// the contract reports identically as ErrNotFound.
func requireAffected(res sql.Result) error {
	n, err := res.RowsAffected()
	if err != nil {
		return mapError(err)
	}
	if n == 0 {
		return domain.ErrNotFound
	}
	return nil
}
