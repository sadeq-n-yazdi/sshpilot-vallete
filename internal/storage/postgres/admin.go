package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/repository"
)

// adminRepo is the PostgreSQL adapter for administrators: the system-axis
// principals authorized to curate the reserved-identifier lists (ADR-0017).
//
// # Why nothing here is owner-scoped
//
// Every method is unscoped, and unlike the UNSCOPED exceptions elsewhere in
// this package that is not a concession — there is no owner axis to scope by.
// An administrator belongs to no owner: the blocklist and its allowlist are
// global, so the authority to edit them cannot be attached to one owner without
// becoming the wrong authority. The administrators table accordingly carries no
// owner_id and no foreign key to owners; see repository.AdministratorRepository
// and migration0009Administrators, which explains the choice at length.
//
// # Reads validate what they decode
//
// Get and List refuse a row whose status is not a known domain.AdminStatus
// rather than returning it. The status is an authorization input — the edit
// service asks "is this administrator active?" — and the one thing an
// authorization input must never do is arrive in a state nobody defined. The
// CHECK constraint already refuses such a row on write, so a decode failure
// here means the table was modified out from under the application, which is
// precisely the case where returning the row would be worst. Failing the read
// makes the caller fail closed; returning it would make the caller decide on
// data it cannot interpret.
type adminRepo struct {
	e execer
}

// Compile-time assertion that adminRepo satisfies the port.
var _ repository.AdministratorRepository = (*adminRepo)(nil)

// adminColumns is the SELECT list shared by Get and List, so the two cannot
// drift into scanning different shapes. It doubles as the INSERT column list,
// which is why it is also the order Create binds its arguments in.
const adminColumns = `id, label, status, created_at, updated_at`

// Create persists a fully populated Administrator.
//
// The status is validated before the insert as well as by the table's CHECK.
// The duplicate check is left to the primary key: a pre-read would be a
// time-of-check/time-of-use race under concurrency, whereas the unique
// violation is decided by the database and surfaces as SQLSTATE 23505, which
// mapError turns into domain.ErrConflict. That matters more here than on
// SQLite, whose adapter serializes writers behind one lock: Postgres runs two
// concurrent creates of the same id in parallel, and the primary key is what
// decides between them.
//
// UNSCOPED: administrators are system-axis principals, not owner-owned data.
func (r *adminRepo) Create(ctx context.Context, a *domain.Administrator) error {
	if a == nil {
		return fmt.Errorf("%s: nil administrator: %w", errPrefix, domain.ErrInvalidInput)
	}
	if a.ID == "" {
		return fmt.Errorf("%s: empty administrator id: %w", errPrefix, domain.ErrInvalidInput)
	}
	if !a.Status.IsValid() {
		return fmt.Errorf("%s: invalid administrator status: %w", errPrefix, domain.ErrInvalidInput)
	}

	const q = `INSERT INTO administrators (` + adminColumns + `)
VALUES ($1, $2, $3, $4, $5)`
	_, err := r.e.ExecContext(ctx, q,
		string(a.ID), a.Label, string(a.Status), encTime(a.CreatedAt), encTime(a.UpdatedAt))
	return mapError(err)
}

// Get returns the administrator with the given ID, or domain.ErrNotFound.
//
// UNSCOPED: administrators are system-axis principals, not owner-owned data.
func (r *adminRepo) Get(ctx context.Context, id domain.AdministratorID) (*domain.Administrator, error) {
	if id == "" {
		return nil, fmt.Errorf("%s: empty administrator id: %w", errPrefix, domain.ErrInvalidInput)
	}

	const q = `SELECT ` + adminColumns + ` FROM administrators WHERE id = $1`
	return scanAdmin(r.e.QueryRowContext(ctx, q, string(id)))
}

// List returns all administrators, ordered by ID so the result is stable across
// calls and engines. An unordered list would make a report of who holds the
// role differ run to run for no reason — and Postgres, unlike SQLite, is free
// to return rows in whatever order the plan produces, so the ORDER BY is doing
// real work here rather than merely pinning an incidental one. An empty table
// yields a nil slice, never an empty one.
//
// UNSCOPED: administrators are system-axis principals, not owner-owned data.
func (r *adminRepo) List(ctx context.Context) ([]domain.Administrator, error) {
	const q = `SELECT ` + adminColumns + ` FROM administrators ORDER BY id`
	rows, err := r.e.QueryContext(ctx, q)
	if err != nil {
		return nil, mapError(err)
	}
	defer func() { _ = rows.Close() }()

	var out []domain.Administrator
	for rows.Next() {
		a, serr := scanAdmin(rows)
		if serr != nil {
			return nil, serr
		}
		out = append(out, *a)
	}
	if err := rows.Err(); err != nil {
		return nil, mapError(err)
	}
	return out, nil
}

// SetLabel sets the display label and stamps UpdatedAt with now.
//
// UNSCOPED: administrators are system-axis principals, not owner-owned data.
func (r *adminRepo) SetLabel(
	ctx context.Context, id domain.AdministratorID, label string, now time.Time,
) error {
	const q = `UPDATE administrators SET label = $1, updated_at = $2 WHERE id = $3`
	return r.update(ctx, id, q, label, encTime(now), string(id))
}

// UpdateStatus sets the lifecycle status and stamps UpdatedAt with now.
//
// An unknown status is refused here rather than handed to the CHECK constraint,
// so the error is domain.ErrInvalidInput — a caller's mistake — instead of an
// opaque driver error. The CHECK remains as the backstop, and it is the reason
// a status that slipped past this guard would fail the write rather than be
// stored: an unrecognized status must never become readable as authorization.
//
// UNSCOPED: administrators are system-axis principals, not owner-owned data.
func (r *adminRepo) UpdateStatus(
	ctx context.Context, id domain.AdministratorID, status domain.AdminStatus, now time.Time,
) error {
	if !status.IsValid() {
		return fmt.Errorf("%s: invalid administrator status: %w", errPrefix, domain.ErrInvalidInput)
	}
	const q = `UPDATE administrators SET status = $1, updated_at = $2 WHERE id = $3`
	return r.update(ctx, id, q, string(status), encTime(now), string(id))
}

// update runs a single-row UPDATE and turns "no rows affected" into
// domain.ErrNotFound, so an update against a missing administrator is reported
// rather than silently succeeding. It wraps the sentinel with the id, which is
// safe to name because an administrator id is not owner-scoped data and the
// caller supplied it.
func (r *adminRepo) update(
	ctx context.Context, id domain.AdministratorID, query string, args ...any,
) error {
	if id == "" {
		return fmt.Errorf("%s: empty administrator id: %w", errPrefix, domain.ErrInvalidInput)
	}

	res, err := r.e.ExecContext(ctx, query, args...)
	if err != nil {
		return mapError(err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return mapError(err)
	}
	if n == 0 {
		return fmt.Errorf("%s: administrator %q: %w", errPrefix, string(id), domain.ErrNotFound)
	}
	return nil
}

// scanAdmin decodes one administrator row, validating the status and the
// timestamps. See adminRepo for why an unrecognized status is an error.
//
// Unlike the SQLite sibling it does not special-case sql.ErrNoRows: mapError is
// the choke point that already turns it into domain.ErrNotFound.
func scanAdmin(s rowScanner) (*domain.Administrator, error) {
	var (
		id, label, status string
		createdAt         string
		updatedAt         string
	)
	if err := s.Scan(&id, &label, &status, &createdAt, &updatedAt); err != nil {
		return nil, mapError(err)
	}

	st := domain.AdminStatus(status)
	if !st.IsValid() {
		return nil, fmt.Errorf("%s: administrator %q has unknown status: %w",
			errPrefix, id, domain.ErrInvalidInput)
	}

	created, err := decTime(createdAt)
	if err != nil {
		return nil, err
	}
	updated, err := decTime(updatedAt)
	if err != nil {
		return nil, err
	}

	return &domain.Administrator{
		ID:        domain.AdministratorID(id),
		Label:     label,
		Status:    st,
		CreatedAt: created,
		UpdatedAt: updated,
	}, nil
}
