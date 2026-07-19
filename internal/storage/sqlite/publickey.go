package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/repository"
)

// publicKeyColumns is the fixed column list shared by every public_keys SELECT
// so the scan order in scanPublicKey stays in lockstep with the queries. The
// Signature field has no column in phase 1 and is neither written nor scanned.
const publicKeyColumns = `id, owner_id, device_id, algorithm, blob, comment, fingerprint, bit_len, status, created_at, updated_at, revoked_at`

// publicKeyRepo is the SQLite PublicKeyRepository. Every method is owner-scoped:
// the owner_id predicate is carried in the WHERE clause so a row belonging to
// another owner is indistinguishable from a missing row. Its ListActiveByKeySet
// method feeds the public authorized_keys endpoint, so its owner-scope and
// active-status filter are the tenant-isolation and correctness backstop for
// the publish path.
type publicKeyRepo struct {
	e execer
}

// Compile-time assertion that publicKeyRepo satisfies the port.
var _ repository.PublicKeyRepository = (*publicKeyRepo)(nil)

// Create persists a fully populated PublicKey exactly as given. A duplicate
// (owner_id, fingerprint) pair maps to domain.ErrConflict; a device_id that
// does not belong to the same owner fails the composite device foreign key and
// surfaces as a generic mapped error.
func (r *publicKeyRepo) Create(ctx context.Context, k *domain.PublicKey) error {
	// A nil entity is a caller programming error, not a storage fault; reject it
	// as invalid input rather than dereferencing it into a panic.
	if k == nil {
		return fmt.Errorf("%s: nil public key: %w", errPrefix, domain.ErrInvalidInput)
	}
	const q = `INSERT INTO public_keys (id, owner_id, device_id, algorithm, blob, comment, fingerprint, bit_len, status, created_at, updated_at, revoked_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	_, err := r.e.ExecContext(ctx, q,
		string(k.ID),
		string(k.OwnerID),
		string(k.DeviceID),
		string(k.Algorithm),
		k.Blob,
		k.Comment,
		k.Fingerprint,
		k.BitLen,
		string(k.Status),
		encTime(k.CreatedAt),
		encTime(k.UpdatedAt),
		encNullTime(k.RevokedAt),
	)
	return mapError(err)
}

// Get returns the owner's public key with the given ID, scoped by id AND
// owner_id, or domain.ErrNotFound if it does not exist or belongs to another
// owner.
func (r *publicKeyRepo) Get(ctx context.Context, ownerID domain.OwnerID, id domain.PublicKeyID) (*domain.PublicKey, error) {
	q := `SELECT ` + publicKeyColumns + ` FROM public_keys WHERE id = ? AND owner_id = ?`
	return scanPublicKey(r.e.QueryRowContext(ctx, q, string(id), string(ownerID)))
}

// ListByOwner returns all of the owner's public keys ordered by id for a
// stable, deterministic sequence.
func (r *publicKeyRepo) ListByOwner(ctx context.Context, ownerID domain.OwnerID) ([]domain.PublicKey, error) {
	q := `SELECT ` + publicKeyColumns + ` FROM public_keys WHERE owner_id = ? ORDER BY id ASC`
	rows, err := r.e.QueryContext(ctx, q, string(ownerID))
	if err != nil {
		return nil, mapError(err)
	}
	return collectPublicKeys(rows)
}

// ListByDevice returns the owner's public keys on the given device ordered by
// id, scoped by owner_id AND device_id.
func (r *publicKeyRepo) ListByDevice(ctx context.Context, ownerID domain.OwnerID, deviceID domain.DeviceID) ([]domain.PublicKey, error) {
	q := `SELECT ` + publicKeyColumns + ` FROM public_keys WHERE owner_id = ? AND device_id = ? ORDER BY id ASC`
	rows, err := r.e.QueryContext(ctx, q, string(ownerID), string(deviceID))
	if err != nil {
		return nil, mapError(err)
	}
	return collectPublicKeys(rows)
}

// GetByFingerprint returns the owner's public key with the given fingerprint,
// scoped by owner_id AND fingerprint, or domain.ErrNotFound if none exists for
// that owner.
func (r *publicKeyRepo) GetByFingerprint(ctx context.Context, ownerID domain.OwnerID, fingerprint string) (*domain.PublicKey, error) {
	q := `SELECT ` + publicKeyColumns + ` FROM public_keys WHERE owner_id = ? AND fingerprint = ?`
	return scanPublicKey(r.e.QueryRowContext(ctx, q, string(ownerID), fingerprint))
}

// Revoke marks the key revoked, stamping status, revoked_at, and updated_at
// with now, scoped by id AND owner_id. A row that does not exist or belongs to
// another owner affects no rows and maps to domain.ErrNotFound.
func (r *publicKeyRepo) Revoke(ctx context.Context, ownerID domain.OwnerID, id domain.PublicKeyID, now time.Time) error {
	const q = `UPDATE public_keys SET status = ?, revoked_at = ?, updated_at = ?
WHERE id = ? AND owner_id = ?`
	res, err := r.e.ExecContext(ctx, q,
		string(domain.KeyStatusRevoked),
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

// RevokeByDevice revokes all of the owner's ACTIVE keys on the given device,
// stamping status, revoked_at, and updated_at with now, and returns the number
// of keys revoked. It is scoped by owner_id AND device_id AND status='active';
// touching no rows is not an error and returns (0, nil).
func (r *publicKeyRepo) RevokeByDevice(ctx context.Context, ownerID domain.OwnerID, deviceID domain.DeviceID, now time.Time) (int64, error) {
	const q = `UPDATE public_keys SET status = ?, revoked_at = ?, updated_at = ?
WHERE owner_id = ? AND device_id = ? AND status = ?`
	res, err := r.e.ExecContext(ctx, q,
		string(domain.KeyStatusRevoked),
		encTime(now),
		encTime(now),
		string(ownerID),
		string(deviceID),
		string(domain.KeyStatusActive),
	)
	if err != nil {
		return 0, mapError(err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, mapError(err)
	}
	return n, nil
}

// ListActiveByKeySet returns the owner's ACTIVE public keys that are members of
// the given key set — active keys intersected with membership — ordered by id
// for a deterministic sequence. This is the publisher-facing resolution query
// behind the public authorized_keys endpoint: the join is owner-scoped on
// pk.owner_id and filtered to status='active' so neither another owner's rows
// nor revoked keys can ever be published.
func (r *publicKeyRepo) ListActiveByKeySet(ctx context.Context, ownerID domain.OwnerID, setID domain.KeySetID) ([]domain.PublicKey, error) {
	q := `SELECT ` + prefixedPublicKeyColumns + `
FROM public_keys pk
JOIN key_set_members m ON m.public_key_id = pk.id
WHERE pk.owner_id = ? AND m.key_set_id = ? AND pk.status = ?
ORDER BY pk.id ASC`
	rows, err := r.e.QueryContext(ctx, q, string(ownerID), string(setID), string(domain.KeyStatusActive))
	if err != nil {
		return nil, mapError(err)
	}
	return collectPublicKeys(rows)
}

// prefixedPublicKeyColumns is publicKeyColumns qualified with the pk alias for
// the ListActiveByKeySet join, keeping the same column order as scanPublicKey.
const prefixedPublicKeyColumns = `pk.id, pk.owner_id, pk.device_id, pk.algorithm, pk.blob, pk.comment, pk.fingerprint, pk.bit_len, pk.status, pk.created_at, pk.updated_at, pk.revoked_at`

// collectPublicKeys drains rows into a slice, mapping any iteration error
// through mapError and always closing the cursor.
func collectPublicKeys(rows *sql.Rows) ([]domain.PublicKey, error) {
	defer func() { _ = rows.Close() }()

	var keys []domain.PublicKey
	for rows.Next() {
		k, err := scanPublicKey(rows)
		if err != nil {
			return nil, err
		}
		keys = append(keys, *k)
	}
	if err := rows.Err(); err != nil {
		return nil, mapError(err)
	}
	return keys, nil
}

// scanPublicKey decodes one public_keys row in publicKeyColumns order. A
// sql.ErrNoRows from a *sql.Row read maps to domain.ErrNotFound via mapError.
// The BLOB and INTEGER columns scan directly into the []byte and int fields;
// the Signature field has no column and is left nil.
func scanPublicKey(s rowScanner) (*domain.PublicKey, error) {
	var (
		k         domain.PublicKey
		algorithm string
		status    string
		createdAt string
		updatedAt string
		revokedAt sql.NullString
	)
	if err := s.Scan(
		&k.ID,
		&k.OwnerID,
		&k.DeviceID,
		&algorithm,
		&k.Blob,
		&k.Comment,
		&k.Fingerprint,
		&k.BitLen,
		&status,
		&createdAt,
		&updatedAt,
		&revokedAt,
	); err != nil {
		return nil, mapError(err)
	}
	k.Algorithm = domain.Algorithm(algorithm)
	k.Status = domain.KeyStatus(status)

	var err error
	if k.CreatedAt, err = decTime(createdAt); err != nil {
		return nil, err
	}
	if k.UpdatedAt, err = decTime(updatedAt); err != nil {
		return nil, err
	}
	if k.RevokedAt, err = decNullTime(revokedAt); err != nil {
		return nil, err
	}
	return &k, nil
}
