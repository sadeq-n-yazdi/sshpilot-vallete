package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/repository"
)

// accessKeyColumns is the fixed column list shared by every access key SELECT,
// kept in one place so the scan order in scanAccessKey can never drift from the
// queries.
const accessKeyColumns = `id, owner_id, key_set_id, name, secret_hash, status,
created_at, revoked_at, grace_until, replaced_by_id`

// accessKeyRepo is the PostgreSQL AccessKeyRepository.
//
// Every method is owner-scoped except ListExpiredGrace, which carries an
// UNSCOPED note explaining why it cannot be. The owner-scoped methods carry
// owner_id in the WHERE clause, so a row belonging to another owner is
// indistinguishable from a missing one: both affect no rows or return no row,
// and both surface as domain.ErrNotFound. That equivalence is deliberate — an
// error that distinguished the two would confirm to one owner that an access
// key id they cannot read nonetheless exists.
//
// The repository stores the credential's digest and never the plaintext access
// key. It also never compares one: the plaintext is shown once at creation and
// is not persisted, logged, or returned by any method here. Bearer verification
// resolves the owner first, loads the key under that owner, and does a
// constant-time comparison against the SecretHash this type returns. Comparing
// digests in SQL would put "is this the right secret" behind an equality test
// that is neither constant-time nor in the one place allowed to decide it.
type accessKeyRepo struct {
	e execer
}

// Compile-time assertion that accessKeyRepo satisfies the port.
var _ repository.AccessKeyRepository = (*accessKeyRepo)(nil)

// Create persists a fully populated AccessKey exactly as given, including its
// SecretHash. Per the repository convention it mints no ID, no timestamp and no
// digest — the caller supplies all three, because the caller is also the only
// party that ever holds the plaintext. A duplicate primary key raises SQLSTATE
// 23505 and maps to domain.ErrConflict.
func (r *accessKeyRepo) Create(ctx context.Context, k *domain.AccessKey) error {
	// A nil entity is a caller programming error, not a storage fault; reject it
	// as invalid input rather than dereferencing it into a panic.
	if k == nil {
		return fmt.Errorf("%s: nil access key: %w", errPrefix, domain.ErrInvalidInput)
	}

	const q = `INSERT INTO access_keys (id, owner_id, key_set_id, name, secret_hash,
status, created_at, revoked_at, grace_until, replaced_by_id)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`
	// secret_hash is a BYTEA column here where SQLite declares BLOB; the driver
	// binds the []byte digest directly either way.
	_, err := r.e.ExecContext(ctx, q,
		string(k.ID),
		string(k.OwnerID),
		string(k.KeySetID),
		k.Name,
		k.SecretHash,
		string(k.Status),
		encTime(k.CreatedAt),
		encNullTime(k.RevokedAt),
		encNullTime(k.GraceUntil),
		encReplacedBy(k.ReplacedByID),
	)
	return mapError(err)
}

// Get returns the owner's access key with the given ID, scoped by owner_id, or
// domain.ErrNotFound if it does not exist or belongs to another owner.
//
// This is also the read behind Bearer verification: the caller resolves the
// handle to an owner, loads the key under that owner, and compares SecretHash
// itself. Both predicates are supplied values matched for equality, so there is
// only one error path out of here — no row — and a caller cannot tell which of
// the two predicates failed.
func (r *accessKeyRepo) Get(ctx context.Context, ownerID domain.OwnerID, id domain.AccessKeyID) (*domain.AccessKey, error) {
	const q = `SELECT ` + accessKeyColumns + `
FROM access_keys WHERE id = $1 AND owner_id = $2`
	return scanAccessKey(r.e.QueryRowContext(ctx, q, string(id), string(ownerID)))
}

// ListByKeySet returns the owner's access keys for the given key set, ordered by
// id for a stable sequence. An owner with none gets a nil slice.
//
// It is owner-scoped as well as set-scoped. A key set id is not a secret, and
// without the owner predicate one owner could enumerate another's credentials
// for a set by guessing or replaying that set's id. The schema also does not
// enforce that a key set and a key referencing it share an owner — see
// migration0010AccessKeys — so this predicate is the only thing that keeps a
// mismatched row out of an owner's own reads.
func (r *accessKeyRepo) ListByKeySet(ctx context.Context, ownerID domain.OwnerID, setID domain.KeySetID) ([]domain.AccessKey, error) {
	const q = `SELECT ` + accessKeyColumns + `
FROM access_keys WHERE owner_id = $1 AND key_set_id = $2 ORDER BY id ASC`
	rows, err := r.e.QueryContext(ctx, q, string(ownerID), string(setID))
	if err != nil {
		return nil, mapError(err)
	}
	return collectAccessKeys(rows)
}

// ListByOwner returns all of the owner's access keys ordered by id for a stable,
// deterministic sequence. An owner with none gets a nil slice, never an empty
// one.
func (r *accessKeyRepo) ListByOwner(ctx context.Context, ownerID domain.OwnerID) ([]domain.AccessKey, error) {
	const q = `SELECT ` + accessKeyColumns + `
FROM access_keys WHERE owner_id = $1 ORDER BY id ASC`
	rows, err := r.e.QueryContext(ctx, q, string(ownerID))
	if err != nil {
		return nil, mapError(err)
	}
	return collectAccessKeys(rows)
}

// MarkRotated moves the owner's key into the grace state, recording the
// replacement in replaced_by_id and the deadline in grace_until.
//
// The WHERE clause excludes revoked rows, and that exclusion is a security
// property rather than tidiness. Without it this statement would move a revoked
// key back to 'grace' — reviving a credential an operator had already shut
// down, and doing so through an ordinary rotation call rather than anything
// that looks like an un-revoke. Revocation has to be terminal for it to mean
// anything, so a revoked row is left untouched.
//
// A revoked row consequently affects nothing and reports domain.ErrNotFound,
// the same answer a missing row and another owner's row give. That is the whole
// error surface the port declares, and collapsing the three cases into one is
// also what keeps a revoked key from being distinguishable from a nonexistent
// one by a caller who should not be able to tell.
//
// Note the contrast with refreshCredRepo.MarkRotated, which classifies its
// zero-rows outcome into domain.ErrConflict. That method implements a
// single-use interlock whose port declares a conflict; this one does not. Here
// a follow-up probe that reported "the row exists but is revoked" would hand
// back exactly the distinction the paragraph above exists to remove, so the
// zero-rows case goes straight to requireAffected and stops there.
func (r *accessKeyRepo) MarkRotated(ctx context.Context, ownerID domain.OwnerID, id domain.AccessKeyID, replacedBy domain.AccessKeyID, graceUntil time.Time) error {
	const q = `UPDATE access_keys SET status = $1, replaced_by_id = $2, grace_until = $3
WHERE id = $4 AND owner_id = $5 AND status <> $6`
	res, err := r.e.ExecContext(ctx, q,
		string(domain.AccessKeyStatusGrace),
		string(replacedBy),
		encTime(graceUntil),
		string(id),
		string(ownerID),
		string(domain.AccessKeyStatusRevoked),
	)
	if err != nil {
		return mapError(err)
	}
	return requireAffected(res)
}

// Revoke marks the owner's key revoked, scoped by id AND owner_id.
//
// The transition is unconditional across the non-revoked states and idempotent
// over the revoked one: an active key and a key in its grace window are both
// taken out of service by the same statement. Revocation must converge rather
// than object, because refusing it would make the incident-response path fail
// at exactly the moment an operator is trying to shut a credential down.
//
// It also clears grace_until and replaced_by_id, so a revoked key carries no
// live deadline that a later grace sweep could act on. Revocation takes effect
// on the next read: every read here is a fresh query against the row this
// statement wrote, so there is no cached decision to outlive it.
//
// A row that does not exist or belongs to another owner affects no rows and
// maps to domain.ErrNotFound — the same answer, so revocation of somebody
// else's key is not distinguishable from revocation of a key that was never
// there.
func (r *accessKeyRepo) Revoke(ctx context.Context, ownerID domain.OwnerID, id domain.AccessKeyID, now time.Time) error {
	// revoked_at is written with COALESCE so it records the FIRST revocation,
	// not the most recent call. A plain assignment would let a repeated revoke
	// walk the timestamp forward, which is the wrong direction for a forensic
	// field: the question it answers is "from when was this credential dead",
	// and anyone holding the token can call revoke again. Overwriting would
	// hand them a way to move the recorded time away from the compromise
	// without ever failing a request. Converging on the first value makes that
	// unavailable rather than merely discouraged.
	const q = `UPDATE access_keys SET status = $1, revoked_at = COALESCE(revoked_at, $2),
grace_until = NULL, replaced_by_id = NULL WHERE id = $3 AND owner_id = $4`
	res, err := r.e.ExecContext(ctx, q,
		string(domain.AccessKeyStatusRevoked),
		encTime(now),
		string(id),
		string(ownerID),
	)
	if err != nil {
		return mapError(err)
	}
	return requireAffected(res)
}

// ListExpiredGrace returns up to limit access keys still in the grace state
// whose grace_until is at or before now, oldest deadline first, for the
// grace-expiry sweep.
//
// UNSCOPED: this is a system-maintenance sweep across all owners; the
// grace-expiry job acts on behalf of no single owner, so there is no owner id
// to scope by. It is reachable only from that job and never from a
// request-scoped path, and it selects strictly by expiry state, so it cannot be
// steered at a chosen owner's rows.
//
// grace_until is fixed-width RFC3339 UTC text, so ordering by it lexically is
// chronological; id breaks ties so the batch boundary is deterministic and the
// sweep makes progress rather than re-reading one ambiguous page. See
// timefmt.go for why that text ordering holds.
func (r *accessKeyRepo) ListExpiredGrace(ctx context.Context, now time.Time, limit int) ([]domain.AccessKey, error) {
	// A non-positive limit has no safe interpretation. Reading it as "unbounded"
	// would turn a caller's zero value into a full-table scan, which is the
	// accident this API's batching exists to prevent, so it is rejected as
	// invalid input instead.
	if limit <= 0 {
		return nil, fmt.Errorf("%s: list limit must be positive: %w", errPrefix, domain.ErrInvalidInput)
	}

	const q = `SELECT ` + accessKeyColumns + `
FROM access_keys WHERE status = $1 AND grace_until IS NOT NULL AND grace_until <= $2
ORDER BY grace_until ASC, id ASC LIMIT $3`
	rows, err := r.e.QueryContext(ctx, q, string(domain.AccessKeyStatusGrace), encTime(now), limit)
	if err != nil {
		return nil, mapError(err)
	}
	return collectAccessKeys(rows)
}

// encReplacedBy binds an optional successor id, mapping a nil pointer to SQL
// NULL so a key that has not been rotated stores no replacement.
func encReplacedBy(id *domain.AccessKeyID) any {
	if id == nil {
		return nil
	}
	return string(*id)
}

// collectAccessKeys drains rows into a slice, mapping any iteration error
// through mapError and always closing the cursor. An empty result yields a nil
// slice, never an empty one.
func collectAccessKeys(rows *sql.Rows) ([]domain.AccessKey, error) {
	defer func() { _ = rows.Close() }()

	var keys []domain.AccessKey
	for rows.Next() {
		k, err := scanAccessKey(rows)
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

// scanAccessKey decodes one row in accessKeyColumns order. A sql.ErrNoRows from
// a *sql.Row read maps to domain.ErrNotFound via mapError.
func scanAccessKey(s rowScanner) (*domain.AccessKey, error) {
	var (
		k            domain.AccessKey
		status       string
		createdAt    string
		revokedAt    sql.NullString
		graceUntil   sql.NullString
		replacedByID sql.NullString
	)
	if err := s.Scan(
		&k.ID, &k.OwnerID, &k.KeySetID, &k.Name, &k.SecretHash, &status,
		&createdAt, &revokedAt, &graceUntil, &replacedByID,
	); err != nil {
		return nil, mapError(err)
	}
	k.Status = domain.AccessKeyStatus(status)

	var err error
	if k.CreatedAt, err = decTime(createdAt); err != nil {
		return nil, err
	}
	if k.RevokedAt, err = decNullTime(revokedAt); err != nil {
		return nil, err
	}
	if k.GraceUntil, err = decNullTime(graceUntil); err != nil {
		return nil, err
	}
	if replacedByID.Valid {
		next := domain.AccessKeyID(replacedByID.String)
		k.ReplacedByID = &next
	}
	return &k, nil
}
