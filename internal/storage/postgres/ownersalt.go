package postgres

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/repository"
)

// saltLen is the length in bytes of a per-owner erasure salt. It matches the
// output width of the HMAC-SHA256 it keys: a shorter key would be the weakest
// part of the construction, and a longer one buys nothing, because HMAC folds
// keys longer than the block size back through the hash anyway.
const saltLen = 32

// ownerSaltRepo is the PostgreSQL adapter for per-owner erasure salts.
//
// The salt row is the entire secret behind audit crypto-erasure: while it
// exists an owner's tombstones are verifiable, and once it is gone they are
// irreversible. See migration0005OwnerErasureSalts for the model in full.
//
// The only dialect difference from the SQLite adapter is the bind placeholder
// ($1 rather than ?); the salt column is BYTEA rather than BLOB, but the driver
// binds and scans the []byte identically either way.
type ownerSaltRepo struct {
	e execer
}

// Compile-time assertion that ownerSaltRepo satisfies the port.
var _ repository.OwnerSaltRepository = (*ownerSaltRepo)(nil)

// Ensure returns the owner's salt, minting one if the owner has none.
//
// It is idempotent under concurrency as well as repetition. The insert is a
// plain INSERT rather than an upsert, so two callers racing to create the same
// owner's salt cannot both win: one commits, the other takes a primary-key
// conflict and re-reads the winner's value. An upsert would let the loser
// overwrite the salt that the winner had already begun minting tombstones
// under, silently orphaning them — the tombstones would remain, but nothing
// could ever verify them again.
//
// The race is a live one on this engine in a way it is not on SQLite, whose
// writers are serialized behind a single BEGIN IMMEDIATE lock. Postgres runs
// the two transactions concurrently, so the loser's INSERT genuinely fails with
// SQLSTATE 23505 and takes the adopt-the-winner path below. That path is
// therefore load-bearing here, not defensive.
func (r *ownerSaltRepo) Ensure(ctx context.Context, ownerID string) ([]byte, error) {
	if ownerID == "" {
		return nil, fmt.Errorf("%s: empty owner id: %w", errPrefix, domain.ErrInvalidInput)
	}

	var salt []byte
	err := withLocalTx(ctx, r.e, func(e execer) error {
		var ferr error
		salt, ferr = ensureOwnerSalt(ctx, e, ownerID)
		return ferr
	})
	if err != nil {
		return nil, err
	}
	return salt, nil
}

// ensureOwnerSalt is the read-or-mint body of Ensure, factored out so it can be
// driven directly against an execer whose INSERT races — the concurrent path
// that a serialized in-process test cannot reliably provoke.
//
// # Why this diverges from the SQLite adapter
//
// This is the one place where a faithful transliteration of the SQLite adapter
// is not merely stylistically different but WRONG on this engine, so the shape
// deliberately differs and the difference is load-bearing.
//
// The SQLite version issues a plain INSERT, lets a racing caller's INSERT fail
// with a uniqueness violation, and then re-reads the winner's salt to adopt it.
// That recovery is impossible inside a PostgreSQL transaction: any statement
// error aborts the entire transaction, and every subsequent command in it —
// including the re-read — fails with SQLSTATE 25P02 "current transaction is
// aborted" until a rollback. Ensure runs its body inside withLocalTx, so the
// transliterated version does not merely fail to adopt the winner's salt, it
// fails outright under exactly the concurrency it exists to survive. Recovering
// would need a SAVEPOINT around the INSERT purely to make the failure
// survivable.
//
// ON CONFLICT DO NOTHING expresses the same intent without provoking an error
// at all: the row is written if absent and left strictly untouched if present.
// It is NOT an upsert and must never become one. The security property the
// SQLite comment protects is that a loser can never overwrite the winner's
// salt, because tombstones already minted under it would be orphaned — they
// would remain in the log with no key able to verify them, permanently. DO
// NOTHING preserves that property exactly; DO UPDATE would destroy it.
//
// Note the contrast with keySetRepo.AddMember, which deliberately does NOT use
// ON CONFLICT DO NOTHING: there a duplicate must surface as domain.ErrConflict,
// and swallowing it would downgrade the error. Here a duplicate is the expected
// benign outcome of a race and must be absorbed. The two are opposite
// requirements, so they get opposite statements.
func ensureOwnerSalt(ctx context.Context, e execer, ownerID string) ([]byte, error) {
	existing, err := getOwnerSalt(ctx, e, ownerID)
	switch {
	case err == nil:
		return existing, nil
	case !errors.Is(err, domain.ErrNotFound):
		return nil, err
	}

	fresh := newSalt()
	const q = `INSERT INTO owner_erasure_salts (owner_id, salt, created_at)
VALUES ($1, $2, $3)
ON CONFLICT (owner_id) DO NOTHING`
	res, ierr := e.ExecContext(ctx, q, ownerID, fresh, encTime(time.Now()))
	if ierr != nil {
		return nil, mapError(ierr)
	}

	// Zero rows affected means the conflict target already held a row: a
	// concurrent caller won the race between the read above and this write.
	// Adopt its salt rather than returning this caller's unwritten one, which
	// was never stored and would mint tombstones no reader could verify.
	n, aerr := res.RowsAffected()
	if aerr != nil {
		return nil, mapError(aerr)
	}
	if n == 0 {
		return getOwnerSalt(ctx, e, ownerID)
	}
	return fresh, nil
}

// newSalt returns saltLen cryptographically random bytes.
//
// A failure of the system entropy source panics rather than returning a zeroed
// or partial buffer, matching the convention in internal/auth. A predictable
// salt would make every tombstone minted under it reversible by anyone who
// guessed it, which is a silent, total failure of the erasure guarantee; a
// panic is the safe direction.
func newSalt() []byte {
	b := make([]byte, saltLen)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("%s: crypto/rand.Read failed: %v", errPrefix, err))
	}
	return b
}

// Get returns the owner's salt, or domain.ErrNotFound when there is none.
//
// A destroyed salt and a salt that never existed are the same answer, on
// purpose: distinguishing them would confirm that the owner once existed, which
// is exactly the fact erasure is meant to remove.
func (r *ownerSaltRepo) Get(ctx context.Context, ownerID string) ([]byte, error) {
	return getOwnerSalt(ctx, r.e, ownerID)
}

// getOwnerSalt reads one salt through the given execer so both the auto-commit
// path and the in-transaction path in Ensure share a single query.
func getOwnerSalt(ctx context.Context, e execer, ownerID string) ([]byte, error) {
	const q = `SELECT salt FROM owner_erasure_salts WHERE owner_id = $1`
	var salt []byte
	if err := e.QueryRowContext(ctx, q, ownerID).Scan(&salt); err != nil {
		return nil, mapError(err)
	}
	return salt, nil
}

// Destroy removes the owner's salt. This is the irreversible step: every
// tombstone minted under this salt becomes permanently unverifiable the moment
// it commits.
//
// The statement is a real DELETE, not an UPDATE that flags the row. That
// distinction is the whole erasure guarantee and not a matter of taste: a
// soft-deleted salt is a salt that still exists, so every tombstone minted
// under it stays reversible by anyone who can read the table — the erasure
// would be a label rather than a fact, and nothing above this layer could tell
// the difference. There is no soft-delete column on owner_erasure_salts and no
// other write path to this table in the package.
//
// Destroying a salt that is not there is not an error. Erasure must converge on
// retry — a flow that failed after destroying the salt but before recording
// that it had done so must be safe to run again — so requireAffected is
// deliberately not used here. Reporting ErrNotFound would also distinguish
// "already erased" from "never existed", which Get is careful not to do.
func (r *ownerSaltRepo) Destroy(ctx context.Context, ownerID string) error {
	const q = `DELETE FROM owner_erasure_salts WHERE owner_id = $1`
	if _, err := r.e.ExecContext(ctx, q, ownerID); err != nil {
		return mapError(err)
	}
	return nil
}
