package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/repository"
)

// refreshCredColumns is the fixed column list shared by every refresh
// credential SELECT so the scan order in scanRefreshCred stays in lockstep with
// the queries. rotated_at exists in the table but is deliberately absent here:
// it is write-only, stamped by MarkRotated and never read back, exactly as on
// the SQLite side.
const refreshCredColumns = `id, owner_id, lineage_id, secret_hash, scopes, client_label,
rotated_from_id, issued_at, expires_at, status, revoked_at`

// refreshCredRepo is the PostgreSQL RefreshCredentialRepository.
//
// Every method is owner-scoped except GetByID and DeleteExpired, each of which
// carries an UNSCOPED note explaining why it cannot be. The owner-scoped
// methods carry owner_id in the WHERE clause, so another owner's row is
// indistinguishable from a missing one.
//
// The repository stores the credential's secret digest and never the secret.
// It also never compares one: verification is a constant-time comparison in
// internal/auth against the SecretHash this type returns. A repository that
// compared digests itself would put the decision "is this the right secret"
// behind a SQL equality test, which is neither constant-time nor in the one
// place that is allowed to make it.
type refreshCredRepo struct {
	e execer
}

// Compile-time assertion that refreshCredRepo satisfies the port.
var _ repository.RefreshCredentialRepository = (*refreshCredRepo)(nil)

// Create persists a fully populated RefreshCredential exactly as given,
// including its SecretHash. Per the repository convention it mints no ID, no
// timestamp and no digest. A duplicate primary key raises SQLSTATE 23505 and
// maps to domain.ErrConflict.
func (r *refreshCredRepo) Create(ctx context.Context, c *domain.RefreshCredential) error {
	// A nil entity is a caller programming error, not a storage fault; reject it
	// as invalid input rather than dereferencing it into a panic.
	if c == nil {
		return fmt.Errorf("%s: nil refresh credential: %w", errPrefix, domain.ErrInvalidInput)
	}

	scopes, err := encScopes(c.Scopes)
	if err != nil {
		return err
	}

	const q = `INSERT INTO refresh_credentials (id, owner_id, lineage_id, secret_hash, scopes,
client_label, rotated_from_id, issued_at, expires_at, status, revoked_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`
	// secret_hash is a BYTEA column here where SQLite declares BLOB; the driver
	// binds the []byte digest directly either way.
	_, err = r.e.ExecContext(ctx, q,
		string(c.ID),
		string(c.OwnerID),
		string(c.LineageID),
		c.SecretHash,
		scopes,
		c.ClientLabel,
		encRotatedFrom(c.RotatedFromID),
		encTime(c.IssuedAt),
		encTime(c.ExpiresAt),
		string(c.Status),
		encNullTime(c.RevokedAt),
	)
	return mapError(err)
}

// GetByID returns the refresh credential with the given ID.
//
// UNSCOPED: the refresh exchange IS the authentication step, so no owner is
// established when this runs — there is no owner id to scope by, because
// resolving one is what this lookup is for. The returned OwnerID is not
// trustworthy until the caller has verified SecretHash and status, which the
// port contract requires of it.
func (r *refreshCredRepo) GetByID(ctx context.Context, id domain.RefreshCredentialID) (*domain.RefreshCredential, error) {
	q := `SELECT ` + refreshCredColumns + ` FROM refresh_credentials WHERE id = $1`
	return scanRefreshCred(r.e.QueryRowContext(ctx, q, string(id)))
}

// Get returns the owner's refresh credential with the given ID, scoped by
// owner_id, or domain.ErrNotFound if it does not exist or belongs to another
// owner.
func (r *refreshCredRepo) Get(ctx context.Context, ownerID domain.OwnerID, id domain.RefreshCredentialID) (*domain.RefreshCredential, error) {
	q := `SELECT ` + refreshCredColumns + ` FROM refresh_credentials WHERE id = $1 AND owner_id = $2`
	return scanRefreshCred(r.e.QueryRowContext(ctx, q, string(id), string(ownerID)))
}

// ListByOwner returns all of the owner's refresh credentials ordered by id for
// a stable, deterministic sequence. An owner with none gets a nil slice.
func (r *refreshCredRepo) ListByOwner(ctx context.Context, ownerID domain.OwnerID) ([]domain.RefreshCredential, error) {
	q := `SELECT ` + refreshCredColumns + ` FROM refresh_credentials WHERE owner_id = $1 ORDER BY id ASC`
	rows, err := r.e.QueryContext(ctx, q, string(ownerID))
	if err != nil {
		return nil, mapError(err)
	}
	return collectRefreshCreds(rows)
}

// ListByLineage returns the owner's refresh credentials in the given lineage,
// ordered by id. It is owner-scoped as well as lineage-scoped: a lineage id is
// not a secret, so without the owner predicate one owner could enumerate
// another's rotation chain by guessing or replaying a lineage id.
func (r *refreshCredRepo) ListByLineage(ctx context.Context, ownerID domain.OwnerID, lineageID domain.LineageID) ([]domain.RefreshCredential, error) {
	q := `SELECT ` + refreshCredColumns + ` FROM refresh_credentials
WHERE owner_id = $1 AND lineage_id = $2 ORDER BY id ASC`
	rows, err := r.e.QueryContext(ctx, q, string(ownerID), string(lineageID))
	if err != nil {
		return nil, mapError(err)
	}
	return collectRefreshCreds(rows)
}

// MarkRotated moves an active credential to rotated in ONE conditional
// statement. This is the single-use interlock, and the shape of it is the
// security property.
//
// The status predicate lives in the WHERE clause, so the database decides
// whether the transition applies while holding the row's write lock. Of two
// concurrent redemptions of the same credential, exactly one UPDATE can find a
// row still active and affect it; the other affects nothing and is reported as
// domain.ErrConflict, which the service reads as evidence the token was
// captured.
//
// It must NOT be written as a read of the status followed by a write. Under
// read-committed both redemptions would read 'active', both would then write
// 'rotated', and both would succeed — the token would have been spent twice
// with two successors minted and no signal that anything was wrong. That is a
// silent replay hole, and the only thing preventing it is that the condition
// and the write are the same statement. This matters more here than on SQLite,
// whose adapter serializes every write transaction behind one lock: Postgres
// runs the two redemptions concurrently at READ COMMITTED, which is exactly the
// isolation level the read-then-write form fails at.
//
// The zero-rows case is then classified, because it has two meanings the
// contract keeps apart: no such row for this owner is domain.ErrNotFound, while
// a row that exists but is no longer active is domain.ErrConflict.
func (r *refreshCredRepo) MarkRotated(ctx context.Context, ownerID domain.OwnerID, id domain.RefreshCredentialID, now time.Time) error {
	const q = `UPDATE refresh_credentials SET status = $1, rotated_at = $2
WHERE id = $3 AND owner_id = $4 AND status = $5`
	res, err := r.e.ExecContext(ctx, q,
		string(domain.CredentialStatusRotated),
		encTime(now),
		string(id),
		string(ownerID),
		string(domain.CredentialStatusActive),
	)
	if err != nil {
		return mapError(err)
	}
	return r.classifyConditional(ctx, res, ownerID, id)
}

// Revoke marks the owner's credential revoked, scoped by id AND owner_id.
//
// Unlike MarkRotated this transition is unconditional: the contract declares
// only domain.ErrNotFound, and revocation must converge rather than object.
// Refusing to revoke an already-rotated or already-revoked credential would
// make the incident-response path fail exactly when an operator is trying to
// shut a credential down, so any existing row of this owner is moved to
// revoked. A row that does not exist or belongs to another owner affects no
// rows and maps to domain.ErrNotFound.
func (r *refreshCredRepo) Revoke(ctx context.Context, ownerID domain.OwnerID, id domain.RefreshCredentialID, now time.Time) error {
	const q = `UPDATE refresh_credentials SET status = $1, revoked_at = $2
WHERE id = $3 AND owner_id = $4`
	res, err := r.e.ExecContext(ctx, q,
		string(domain.CredentialStatusRevoked),
		encTime(now),
		string(id),
		string(ownerID),
	)
	if err != nil {
		return mapError(err)
	}
	return requireAffected(res)
}

// RevokeLineage revokes every one of the owner's credentials in the lineage and
// returns how many it changed. This is the reuse-detection response: when a
// rotated credential is presented a second time, the whole chain is burned in
// one statement rather than row by row, so there is no window in which an
// attacker's freshly minted successor survives the response that was triggered
// by their own replay.
//
// Already-revoked rows are excluded from the count so the number returned is
// the number of credentials this call actually took out of service.
func (r *refreshCredRepo) RevokeLineage(ctx context.Context, ownerID domain.OwnerID, lineageID domain.LineageID, now time.Time) (int64, error) {
	const q = `UPDATE refresh_credentials SET status = $1, revoked_at = $2
WHERE owner_id = $3 AND lineage_id = $4 AND status <> $5`
	res, err := r.e.ExecContext(ctx, q,
		string(domain.CredentialStatusRevoked),
		encTime(now),
		string(ownerID),
		string(lineageID),
		string(domain.CredentialStatusRevoked),
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

// DeleteExpired removes up to limit credentials whose expires_at is at or
// before cutoff, oldest first, and returns how many it deleted.
//
// UNSCOPED: this is a system-maintenance sweep across all owners; the
// expiry-cleanup job acts on behalf of no single owner.
func (r *refreshCredRepo) DeleteExpired(ctx context.Context, cutoff time.Time, limit int) (int64, error) {
	// A non-positive limit has no safe interpretation. Treating it as
	// "unbounded" would turn a caller's zero value into a full-table delete,
	// which is precisely the accident this API's batching exists to prevent, so
	// it is rejected as invalid input instead.
	if limit <= 0 {
		return 0, fmt.Errorf("%s: delete limit must be positive: %w", errPrefix, domain.ErrInvalidInput)
	}

	// PostgreSQL has no DELETE ... LIMIT at all, so the bound is expressed the
	// same portable way the SQLite adapter uses: delete the rows named by a
	// bounded subquery, which also makes the oldest-first ordering explicit.
	// The comparison is a text comparison, which is chronological because every
	// encoded timestamp is fixed-width UTC — see timefmt.go.
	const q = `DELETE FROM refresh_credentials WHERE id IN (
	SELECT id FROM refresh_credentials WHERE expires_at <= $1 ORDER BY expires_at, id LIMIT $2
)`
	res, err := r.e.ExecContext(ctx, q, encTime(cutoff), limit)
	if err != nil {
		return 0, mapError(err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, mapError(err)
	}
	return n, nil
}

// classifyConditional turns the zero-rows outcome of a conditional, owner-scoped
// UPDATE into the right sentinel. A non-zero row count is a success.
//
// The follow-up SELECT is deliberately owner-scoped. An unscoped "does this id
// exist" probe would answer ErrConflict for a row belonging to somebody else,
// which tells the caller that an id they cannot access is nonetheless in use —
// exactly the cross-owner existence leak the port forbids. Scoped, a missing row
// and another owner's row produce the identical ErrNotFound.
//
// Reading after the write does not reintroduce the race the conditional UPDATE
// exists to close. The transition has already happened, atomically, in the one
// statement above; this read only decides which error to name for a caller that
// changed nothing, and no write is derived from what it sees. It is also safe
// inside a caller's transaction: the UPDATE returned no error, so the
// transaction is not in the aborted state that would reject this SELECT.
func (r *refreshCredRepo) classifyConditional(ctx context.Context, res sql.Result, ownerID domain.OwnerID, id domain.RefreshCredentialID) error {
	n, err := res.RowsAffected()
	if err != nil {
		return mapError(err)
	}
	if n > 0 {
		return nil
	}

	const q = `SELECT status FROM refresh_credentials WHERE id = $1 AND owner_id = $2`
	var status string
	if serr := r.e.QueryRowContext(ctx, q, string(id), string(ownerID)).Scan(&status); serr != nil {
		return mapError(serr)
	}
	// The row is this owner's and it is present, so the only reason the
	// conditional update matched nothing is that it is no longer in the state
	// the transition requires.
	return domain.ErrConflict
}

// encScopes serializes a scope set as JSON for the scopes TEXT column, matching
// the JSON-in-TEXT convention audit_records.metadata already uses. A nil or
// empty set encodes as "[]" rather than SQL NULL, so the column is always a
// valid JSON document.
func encScopes(scopes []domain.Scope) (string, error) {
	if len(scopes) == 0 {
		return "[]", nil
	}
	b, err := json.Marshal(scopes)
	if err != nil {
		return "", fmt.Errorf("%s: encode scopes: %w", errPrefix, err)
	}
	return string(b), nil
}

// decScopes parses the scopes column back into a slice. An empty JSON array
// yields a nil slice, matching the convention that an empty list is nil.
func decScopes(s string) ([]domain.Scope, error) {
	var scopes []domain.Scope
	if err := json.Unmarshal([]byte(s), &scopes); err != nil {
		return nil, fmt.Errorf("%s: decode scopes: %w", errPrefix, err)
	}
	if len(scopes) == 0 {
		return nil, nil
	}
	return scopes, nil
}

// encRotatedFrom binds an optional predecessor id, mapping a nil pointer to SQL
// NULL so the first credential in a lineage stores no predecessor.
func encRotatedFrom(id *domain.RefreshCredentialID) any {
	if id == nil {
		return nil
	}
	return string(*id)
}

// collectRefreshCreds drains rows into a slice, mapping any iteration error
// through mapError and always closing the cursor. An empty result yields a nil
// slice, never an empty one.
func collectRefreshCreds(rows *sql.Rows) ([]domain.RefreshCredential, error) {
	defer func() { _ = rows.Close() }()

	var creds []domain.RefreshCredential
	for rows.Next() {
		c, err := scanRefreshCred(rows)
		if err != nil {
			return nil, err
		}
		creds = append(creds, *c)
	}
	if err := rows.Err(); err != nil {
		return nil, mapError(err)
	}
	return creds, nil
}

// scanRefreshCred decodes one row in refreshCredColumns order. A sql.ErrNoRows
// from a *sql.Row read maps to domain.ErrNotFound via mapError.
func scanRefreshCred(s rowScanner) (*domain.RefreshCredential, error) {
	var (
		c             domain.RefreshCredential
		scopes        string
		status        string
		rotatedFromID sql.NullString
		issuedAt      string
		expiresAt     string
		revokedAt     sql.NullString
	)
	if err := s.Scan(
		&c.ID, &c.OwnerID, &c.LineageID, &c.SecretHash, &scopes, &c.ClientLabel,
		&rotatedFromID, &issuedAt, &expiresAt, &status, &revokedAt,
	); err != nil {
		return nil, mapError(err)
	}
	c.Status = domain.CredentialStatus(status)

	var err error
	if c.Scopes, err = decScopes(scopes); err != nil {
		return nil, err
	}
	if rotatedFromID.Valid {
		prev := domain.RefreshCredentialID(rotatedFromID.String)
		c.RotatedFromID = &prev
	}
	if c.IssuedAt, err = decTime(issuedAt); err != nil {
		return nil, err
	}
	if c.ExpiresAt, err = decTime(expiresAt); err != nil {
		return nil, err
	}
	if c.RevokedAt, err = decNullTime(revokedAt); err != nil {
		return nil, err
	}
	return &c, nil
}
