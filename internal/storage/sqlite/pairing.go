package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/repository"
)

// pairingRepo is the SQLite DevicePairingRepository. It runs against an execer
// so the same code serves both the auto-commit (*sql.DB) and transaction
// (*sql.Tx) paths.
type pairingRepo struct {
	e execer
}

// Compile-time assertion that pairingRepo satisfies the port.
var _ repository.DevicePairingRepository = (*pairingRepo)(nil)

// pairingColumns is the shared SELECT list, kept in one place so the column
// order can never drift from scanPairing's Scan order.
const pairingColumns = `id, owner_id, device_code_hash, user_code_hash, client_label, scopes,
status, lineage_id, next_poll_at, created_at, expires_at, approved_at, redeemed_at, revoked_at`

// Create persists a fully populated DevicePairing, digests included. A
// duplicate primary key maps to domain.ErrConflict.
func (r *pairingRepo) Create(ctx context.Context, p *domain.DevicePairing) error {
	// A nil entity is a caller programming error, not a storage fault; reject it
	// as invalid input rather than dereferencing it into a panic.
	if p == nil {
		return fmt.Errorf("%s: nil device pairing: %w", errPrefix, domain.ErrInvalidInput)
	}
	scopes, err := encPairingScopes(p.Scopes)
	if err != nil {
		return err
	}
	const q = `INSERT INTO device_pairings (` + pairingColumns + `)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	_, err = r.e.ExecContext(ctx, q,
		string(p.ID),
		encPairingOwner(p.OwnerID),
		p.DeviceCodeHash,
		encPairingHash(p.UserCodeHash),
		p.ClientLabel,
		scopes,
		string(p.Status),
		string(p.LineageID),
		encTime(p.NextPollAt),
		encTime(p.CreatedAt),
		encTime(p.ExpiresAt),
		encNullTime(p.ApprovedAt),
		encNullTime(p.RedeemedAt),
		encNullTime(p.RevokedAt),
	)
	return mapError(err)
}

// GetByID returns the pairing with the given ID, or domain.ErrNotFound if none
// exists.
//
// UNSCOPED: redeeming a device code IS the authentication step, so no owner is
// established when this runs. Per the port contract the caller must verify
// DeviceCodeHash, Status and ExpiresAt before trusting the returned OwnerID;
// this method deliberately performs none of those checks, because the digest
// comparison belongs in internal/auth where it can be done in constant time.
func (r *pairingRepo) GetByID(ctx context.Context, id domain.PairingID) (*domain.DevicePairing, error) {
	const q = `SELECT ` + pairingColumns + ` FROM device_pairings WHERE id = ?`
	return scanPairing(r.e.QueryRowContext(ctx, q, string(id)))
}

// GetByUserCodeHash returns the pairing whose UserCodeHash equals hash, or
// domain.ErrNotFound if none does.
//
// UNSCOPED: an approving owner holds a transcribed user code and nothing else,
// and a pending pairing has no owner to scope by — the owner boundary is
// established by the approval that follows this lookup. Callers must rate-limit
// this path; a user code is short enough to guess.
//
// An empty or nil hash short-circuits to domain.ErrNotFound rather than being
// issued as a query. user_code_hash is NULL for manually minted pairings, and a
// caller presenting no code at all must never reach one of those rows. SQL
// already refuses this — NULL = NULL is not true, so a nil bind matches
// nothing — but that makes an authentication boundary rest on a subtlety of
// three-valued logic that a later change to the NULL representation would
// silently remove. The guard states it directly. ErrNotFound, not
// ErrInvalidInput, because the contract defines this method's miss as
// ErrNotFound and callers branch on it.
func (r *pairingRepo) GetByUserCodeHash(ctx context.Context, hash []byte) (*domain.DevicePairing, error) {
	if len(hash) == 0 {
		return nil, domain.ErrNotFound
	}
	const q = `SELECT ` + pairingColumns + ` FROM device_pairings WHERE user_code_hash = ?`
	return scanPairing(r.e.QueryRowContext(ctx, q, hash))
}

// Get returns the owner's pairing with the given ID. A pairing that does not
// exist and one belonging to another owner are both domain.ErrNotFound, so the
// caller cannot learn that an inaccessible id exists.
func (r *pairingRepo) Get(ctx context.Context, ownerID domain.OwnerID, id domain.PairingID) (*domain.DevicePairing, error) {
	const q = `SELECT ` + pairingColumns + ` FROM device_pairings WHERE id = ? AND owner_id = ?`
	return scanPairing(r.e.QueryRowContext(ctx, q, string(id), string(ownerID)))
}

// ListByOwner returns all of the owner's pairings, oldest first. An owner with
// none gets a nil slice, not an empty one.
func (r *pairingRepo) ListByOwner(ctx context.Context, ownerID domain.OwnerID) ([]domain.DevicePairing, error) {
	const q = `SELECT ` + pairingColumns + `
FROM device_pairings WHERE owner_id = ? ORDER BY created_at ASC, id ASC`
	rows, err := r.e.QueryContext(ctx, q, string(ownerID))
	if err != nil {
		return nil, mapError(err)
	}
	return collectPairings(rows)
}

// Approve binds the pairing to ownerID and stamps approved_at with now.
//
// The owner binding is the WHERE condition, applied in a single statement: the
// row moves from pending to approved only if it is still pending. A
// read-then-write would let two approvals both observe a pending row, and the
// second would rewrite owner_id — so an attacker who guessed a user code could
// re-point a pairing another owner had already approved, and the device would
// hand its credentials to whichever account won the race. Because the status
// predicate and the owner write happen in one statement, the loser of that race
// changes nothing and is told ErrConflict.
//
// UNSCOPED: there is deliberately no owner predicate. This method establishes
// the owner; requiring one would make approval impossible.
func (r *pairingRepo) Approve(ctx context.Context, id domain.PairingID, ownerID domain.OwnerID, now time.Time) error {
	const q = `UPDATE device_pairings SET status = ?, owner_id = ?, approved_at = ?
WHERE id = ? AND status = ?`
	res, err := r.e.ExecContext(ctx, q,
		string(domain.PairingStatusApproved),
		string(ownerID),
		encTime(now),
		string(id),
		string(domain.PairingStatusPending),
	)
	if err != nil {
		return mapError(err)
	}
	return r.classifyByID(ctx, res, id)
}

// MarkRedeemed consumes the pairing: it moves an approved row to redeemed,
// stamps redeemed_at with now and records lineageID.
//
// This is what makes a device code single-use under concurrency. The status
// predicate is evaluated in the same statement as the write, so of two
// simultaneous redemptions exactly one updates a row and the other is told
// ErrConflict. A read-then-write would let both read the same approved row and
// install two independent credentials, only one of which the owner would ever
// see in a listing.
func (r *pairingRepo) MarkRedeemed(ctx context.Context, ownerID domain.OwnerID, id domain.PairingID, lineageID domain.LineageID, now time.Time) error {
	const q = `UPDATE device_pairings SET status = ?, lineage_id = ?, redeemed_at = ?
WHERE id = ? AND owner_id = ? AND status = ?`
	res, err := r.e.ExecContext(ctx, q,
		string(domain.PairingStatusRedeemed),
		string(lineageID),
		encTime(now),
		string(id),
		string(ownerID),
		string(domain.PairingStatusApproved),
	)
	if err != nil {
		return mapError(err)
	}
	return r.classifyByOwner(ctx, res, ownerID, id)
}

// Revoke marks the owner's pairing revoked and sets revoked_at to now.
//
// Unlike a plain owner-scoped mutator this transition is conditional: the
// contract distinguishes a pairing that cannot be reached (ErrNotFound) from
// one that is already terminal (ErrConflict), so re-revoking a redeemed pairing
// must not silently overwrite the terminal state and lose the record of how the
// pairing ended.
func (r *pairingRepo) Revoke(ctx context.Context, ownerID domain.OwnerID, id domain.PairingID, now time.Time) error {
	const q = `UPDATE device_pairings SET status = ?, revoked_at = ?
WHERE id = ? AND owner_id = ? AND status IN (?, ?)`
	res, err := r.e.ExecContext(ctx, q,
		string(domain.PairingStatusRevoked),
		encTime(now),
		string(id),
		string(ownerID),
		string(domain.PairingStatusPending),
		string(domain.PairingStatusApproved),
	)
	if err != nil {
		return mapError(err)
	}
	return r.classifyByOwner(ctx, res, ownerID, id)
}

// Touch sets next_poll_at, throttling a polling client. A missing pairing is
// domain.ErrNotFound.
//
// This transition is unconditional by design: it must throttle a client in any
// state, including one polling a pairing that has already become terminal, so
// there is no status predicate and no conflict case.
//
// UNSCOPED: polling happens before redemption, so the poller is not yet an
// owner. Per the port contract the caller must already have verified the
// presented device code against DeviceCodeHash, so only the holder of the
// pairing's own secret reaches this.
func (r *pairingRepo) Touch(ctx context.Context, id domain.PairingID, nextPollAt time.Time) error {
	const q = `UPDATE device_pairings SET next_poll_at = ? WHERE id = ?`
	res, err := r.e.ExecContext(ctx, q, encTime(nextPollAt), string(id))
	if err != nil {
		return mapError(err)
	}
	return requireAffected(res)
}

// DeleteExpired removes up to limit pairings whose expires_at is at or before
// cutoff, oldest first, and returns the number deleted.
//
// UNSCOPED: a system-maintenance sweep across all owners.
func (r *pairingRepo) DeleteExpired(ctx context.Context, cutoff time.Time, limit int) (int64, error) {
	// A non-positive limit has no safe interpretation. Treating it as
	// "unbounded" would turn a caller's zero value into a full-table delete,
	// which is the accident this API's batching exists to prevent.
	if limit <= 0 {
		return 0, fmt.Errorf("%s: delete limit must be positive: %w", errPrefix, domain.ErrInvalidInput)
	}

	// DELETE ... LIMIT needs a SQLite build flag this driver does not set and
	// has no PostgreSQL equivalent; the portable form deletes the rows named by
	// a bounded subquery, which also makes the oldest-first order explicit.
	const q = `DELETE FROM device_pairings WHERE id IN (
	SELECT id FROM device_pairings WHERE expires_at <= ? ORDER BY expires_at, id LIMIT ?
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

// classifyByID resolves a conditional update that touched no rows for a
// transition with no owner predicate (Approve). Zero rows means either that no
// such pairing exists or that it was not in the required state, and the
// contract reports those differently.
//
// The SELECT runs strictly AFTER the atomic write and feeds no decision the
// write depended on, so it cannot reintroduce the race the single-statement
// update exists to close: by the time it runs, the update has already either
// won or lost.
func (r *pairingRepo) classifyByID(ctx context.Context, res sql.Result, id domain.PairingID) error {
	n, err := res.RowsAffected()
	if err != nil {
		return mapError(err)
	}
	if n > 0 {
		return nil
	}
	const q = `SELECT status FROM device_pairings WHERE id = ?`
	var status string
	if serr := r.e.QueryRowContext(ctx, q, string(id)).Scan(&status); serr != nil {
		return mapError(serr)
	}
	return domain.ErrConflict
}

// classifyByOwner is classifyByID for the owner-scoped transitions
// (MarkRedeemed, Revoke). The disambiguating SELECT carries the same owner
// predicate as the update, so a pairing belonging to another owner is reported
// as ErrNotFound exactly like a missing one and the caller cannot use the
// conflict signal to discover that an inaccessible id exists.
func (r *pairingRepo) classifyByOwner(ctx context.Context, res sql.Result, ownerID domain.OwnerID, id domain.PairingID) error {
	n, err := res.RowsAffected()
	if err != nil {
		return mapError(err)
	}
	if n > 0 {
		return nil
	}
	const q = `SELECT status FROM device_pairings WHERE id = ? AND owner_id = ?`
	var status string
	if serr := r.e.QueryRowContext(ctx, q, string(id), string(ownerID)).Scan(&status); serr != nil {
		return mapError(serr)
	}
	return domain.ErrConflict
}

// encPairingOwner encodes the owner id of a pairing. A pending pairing has no
// owner, and the empty string is stored as SQL NULL so "unowned" is a distinct
// value rather than an owner whose id happens to be empty.
func encPairingOwner(id domain.OwnerID) any {
	if id == "" {
		return nil
	}
	return string(id)
}

// encPairingHash encodes an optional digest. A nil or empty slice becomes SQL
// NULL, which is the manually-minted-pairing case for user_code_hash. Storing
// an empty blob instead would make every such row match a lookup for the empty
// digest.
func encPairingHash(h []byte) any {
	if len(h) == 0 {
		return nil
	}
	return h
}

// encPairingScopes encodes scopes as a JSON array in a TEXT column. A nil or
// empty slice becomes "[]" so the column is never NULL.
//
// TODO: this duplicates encScopes/decScopes from the refresh-credential
// adapter, which is developed on a sibling branch. Fold both onto one shared
// helper once that branch has merged.
func encPairingScopes(scopes []domain.Scope) (string, error) {
	if len(scopes) == 0 {
		return "[]", nil
	}
	b, err := json.Marshal(scopes)
	if err != nil {
		return "", fmt.Errorf("%s: encode scopes: %w", errPrefix, err)
	}
	return string(b), nil
}

// decPairingScopes decodes the JSON scope array. An empty array decodes to a
// nil slice, matching the package's empty-list convention.
func decPairingScopes(s string) ([]domain.Scope, error) {
	var scopes []domain.Scope
	if err := json.Unmarshal([]byte(s), &scopes); err != nil {
		return nil, fmt.Errorf("%s: decode scopes: %w", errPrefix, err)
	}
	if len(scopes) == 0 {
		return nil, nil
	}
	return scopes, nil
}

// collectPairings drains rows into a slice, mapping any iteration error through
// mapError and always closing the cursor. An empty result yields a nil slice,
// never an empty one.
//
// The cursor is closed here rather than at the call site so the helper is safe
// by construction: a future caller cannot leak a connection by forgetting the
// defer. This matches collectDevices, collectPublicKeys and every other
// collector in this package.
func collectPairings(rows *sql.Rows) ([]domain.DevicePairing, error) {
	defer func() { _ = rows.Close() }()

	var out []domain.DevicePairing
	for rows.Next() {
		p, err := scanPairing(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *p)
	}
	if err := rows.Err(); err != nil {
		return nil, mapError(err)
	}
	return out, nil
}

// scanPairing decodes one device_pairings row. A sql.ErrNoRows from a *sql.Row
// read is mapped to domain.ErrNotFound by mapError.
func scanPairing(s rowScanner) (*domain.DevicePairing, error) {
	var (
		p          domain.DevicePairing
		ownerID    sql.NullString
		userCode   []byte
		scopes     string
		status     string
		lineageID  string
		nextPollAt string
		createdAt  string
		expiresAt  string
		approvedAt sql.NullString
		redeemedAt sql.NullString
		revokedAt  sql.NullString
	)
	if err := s.Scan(
		&p.ID, &ownerID, &p.DeviceCodeHash, &userCode, &p.ClientLabel, &scopes,
		&status, &lineageID, &nextPollAt, &createdAt, &expiresAt,
		&approvedAt, &redeemedAt, &revokedAt,
	); err != nil {
		return nil, mapError(err)
	}
	p.OwnerID = domain.OwnerID(ownerID.String)
	p.UserCodeHash = userCode
	p.Status = domain.PairingStatus(status)
	p.LineageID = domain.LineageID(lineageID)

	var err error
	if p.Scopes, err = decPairingScopes(scopes); err != nil {
		return nil, err
	}
	if p.NextPollAt, err = decTime(nextPollAt); err != nil {
		return nil, err
	}
	if p.CreatedAt, err = decTime(createdAt); err != nil {
		return nil, err
	}
	if p.ExpiresAt, err = decTime(expiresAt); err != nil {
		return nil, err
	}
	if p.ApprovedAt, err = decNullTime(approvedAt); err != nil {
		return nil, err
	}
	if p.RedeemedAt, err = decNullTime(redeemedAt); err != nil {
		return nil, err
	}
	if p.RevokedAt, err = decNullTime(revokedAt); err != nil {
		return nil, err
	}
	return &p, nil
}
