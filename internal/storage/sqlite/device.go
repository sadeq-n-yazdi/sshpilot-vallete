package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/repository"
)

// deviceColumns is the fixed column list shared by every device SELECT so the
// scan order in scanDevice stays in lockstep with the queries.
const deviceColumns = `id, owner_id, name, status, created_at, updated_at, revoked_at`

// deviceRepo is the SQLite DeviceRepository. Every method is owner-scoped: the
// owner_id predicate is carried in the WHERE clause so a row belonging to
// another owner is indistinguishable from a missing row.
type deviceRepo struct {
	e execer
}

// Compile-time assertion that deviceRepo satisfies the port.
var _ repository.DeviceRepository = (*deviceRepo)(nil)

// Create persists a fully populated Device exactly as given. A duplicate
// primary key maps to domain.ErrConflict.
func (r *deviceRepo) Create(ctx context.Context, d *domain.Device) error {
	// A nil entity is a caller programming error, not a storage fault; reject it
	// as invalid input rather than dereferencing it into a panic.
	if d == nil {
		return fmt.Errorf("%s: nil device: %w", errPrefix, domain.ErrInvalidInput)
	}
	const q = `INSERT INTO devices (id, owner_id, name, status, created_at, updated_at, revoked_at)
VALUES (?, ?, ?, ?, ?, ?, ?)`
	_, err := r.e.ExecContext(ctx, q,
		string(d.ID),
		string(d.OwnerID),
		d.Name,
		string(d.Status),
		encTime(d.CreatedAt),
		encTime(d.UpdatedAt),
		encNullTime(d.RevokedAt),
	)
	return mapError(err)
}

// Get returns the owner's device with the given ID, scoped by owner_id, or
// domain.ErrNotFound if it does not exist or belongs to another owner.
func (r *deviceRepo) Get(ctx context.Context, ownerID domain.OwnerID, id domain.DeviceID) (*domain.Device, error) {
	q := `SELECT ` + deviceColumns + ` FROM devices WHERE id = ? AND owner_id = ?`
	return scanDevice(r.e.QueryRowContext(ctx, q, string(id), string(ownerID)))
}

// ListByOwner returns all of the owner's devices ordered by id for a stable,
// deterministic sequence.
func (r *deviceRepo) ListByOwner(ctx context.Context, ownerID domain.OwnerID) ([]domain.Device, error) {
	q := `SELECT ` + deviceColumns + ` FROM devices WHERE owner_id = ? ORDER BY id ASC`
	rows, err := r.e.QueryContext(ctx, q, string(ownerID))
	if err != nil {
		return nil, mapError(err)
	}
	return collectDevices(rows)
}

// Rename sets the device's display name and stamps updated_at with now, scoped
// by id AND owner_id. A row that does not exist or belongs to another owner
// affects no rows and maps to domain.ErrNotFound.
func (r *deviceRepo) Rename(ctx context.Context, ownerID domain.OwnerID, id domain.DeviceID, name string, now time.Time) error {
	const q = `UPDATE devices SET name = ?, updated_at = ? WHERE id = ? AND owner_id = ?`
	res, err := r.e.ExecContext(ctx, q, name, encTime(now), string(id), string(ownerID))
	if err != nil {
		return mapError(err)
	}
	return requireAffected(res)
}

// Revoke marks the device revoked, stamping status, revoked_at, and updated_at
// with now, scoped by id AND owner_id. A row that does not exist or belongs to
// another owner affects no rows and maps to domain.ErrNotFound.
func (r *deviceRepo) Revoke(ctx context.Context, ownerID domain.OwnerID, id domain.DeviceID, now time.Time) error {
	const q = `UPDATE devices SET status = ?, revoked_at = ?, updated_at = ?
WHERE id = ? AND owner_id = ?`
	res, err := r.e.ExecContext(ctx, q,
		string(domain.DeviceStatusRevoked),
		encTime(now),
		encTime(now),
		string(id),
		string(ownerID),
	)
	if err != nil {
		return mapError(err)
	}
	return requireAffected(res)
}

// collectDevices drains rows into a slice, mapping any iteration error through
// mapError and always closing the cursor.
func collectDevices(rows *sql.Rows) ([]domain.Device, error) {
	defer func() { _ = rows.Close() }()

	var devices []domain.Device
	for rows.Next() {
		d, err := scanDevice(rows)
		if err != nil {
			return nil, err
		}
		devices = append(devices, *d)
	}
	if err := rows.Err(); err != nil {
		return nil, mapError(err)
	}
	return devices, nil
}

// scanDevice decodes one device row in deviceColumns order. A sql.ErrNoRows
// from a *sql.Row read maps to domain.ErrNotFound via mapError.
func scanDevice(s rowScanner) (*domain.Device, error) {
	var (
		d         domain.Device
		status    string
		createdAt string
		updatedAt string
		revokedAt sql.NullString
	)
	if err := s.Scan(&d.ID, &d.OwnerID, &d.Name, &status, &createdAt, &updatedAt, &revokedAt); err != nil {
		return nil, mapError(err)
	}
	d.Status = domain.DeviceStatus(status)

	var err error
	if d.CreatedAt, err = decTime(createdAt); err != nil {
		return nil, err
	}
	if d.UpdatedAt, err = decTime(updatedAt); err != nil {
		return nil, err
	}
	if d.RevokedAt, err = decNullTime(revokedAt); err != nil {
		return nil, err
	}
	return &d, nil
}
