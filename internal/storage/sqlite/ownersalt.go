package sqlite

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

// ownerSaltRepo is the SQLite adapter for per-owner erasure salts.
//
// The salt row is the entire secret behind audit crypto-erasure: while it
// exists an owner's tombstones are verifiable, and once it is gone they are
// irreversible. See migration0005OwnerErasureSalts for the model in full.
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
func (r *ownerSaltRepo) Ensure(ctx context.Context, ownerID string) ([]byte, error) {
	if ownerID == "" {
		return nil, fmt.Errorf("%s: empty owner id: %w", errPrefix, domain.ErrInvalidInput)
	}

	var salt []byte
	err := withLocalTx(ctx, r.e, func(e execer) error {
		existing, err := getOwnerSalt(ctx, e, ownerID)
		switch {
		case err == nil:
			salt = existing
			return nil
		case !errors.Is(err, domain.ErrNotFound):
			return err
		}

		fresh := make([]byte, saltLen)
		// crypto/rand.Read is documented never to return a short read without
		// an error. A failure here means the system entropy source is broken;
		// continuing would mint a predictable salt and hand out tombstones that
		// are reversible by anyone who guesses it, so the operation fails
		// instead.
		if _, rerr := rand.Read(fresh); rerr != nil {
			return fmt.Errorf("%s: generate erasure salt: %w", errPrefix, rerr)
		}

		const q = `INSERT INTO owner_erasure_salts (owner_id, salt, created_at) VALUES (?, ?, ?)`
		if _, ierr := e.ExecContext(ctx, q, ownerID, fresh, encTime(time.Now())); ierr != nil {
			// A conflict means a concurrent caller won the race; adopt its salt
			// rather than failing, so Ensure stays idempotent.
			if mapped := mapError(ierr); errors.Is(mapped, domain.ErrConflict) {
				won, gerr := getOwnerSalt(ctx, e, ownerID)
				if gerr != nil {
					return gerr
				}
				salt = won
				return nil
			}
			return mapError(ierr)
		}
		salt = fresh
		return nil
	})
	if err != nil {
		return nil, err
	}
	return salt, nil
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
	const q = `SELECT salt FROM owner_erasure_salts WHERE owner_id = ?`
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
// Destroying a salt that is not there is not an error. Erasure must converge on
// retry — a flow that failed after destroying the salt but before recording
// that it had done so must be safe to run again — so requireAffected is
// deliberately not used here. Reporting ErrNotFound would also distinguish
// "already erased" from "never existed", which Get is careful not to do.
func (r *ownerSaltRepo) Destroy(ctx context.Context, ownerID string) error {
	const q = `DELETE FROM owner_erasure_salts WHERE owner_id = ?`
	if _, err := r.e.ExecContext(ctx, q, ownerID); err != nil {
		return mapError(err)
	}
	return nil
}
