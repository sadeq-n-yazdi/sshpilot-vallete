package repository

import (
	"context"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
)

// DevicePairingRepository persists DevicePairing rows: the short-lived
// enrollment records that a device code and a user code are verified against.
//
// Methods are owner-scoped except the two lookups that run before an owner is
// established and DeleteExpired (a system-maintenance sweep); each is tagged
// UNSCOPED at the method with the reason it has to be.
//
// Implementations MUST NOT generate identifiers, timestamps or hashes. Every
// such value is computed by the caller and passed in, so that the one place
// which decides what a credential digest is stays in internal/auth rather than
// being reimplemented per storage engine.
type DevicePairingRepository interface {
	// Create persists a fully populated DevicePairing, including its code
	// digests. It returns domain.ErrConflict if the ID is already taken.
	Create(ctx context.Context, p *domain.DevicePairing) error

	// GetByID returns the pairing with the given ID, or domain.ErrNotFound if
	// none exists.
	//
	// UNSCOPED: redeeming a device code IS the authentication step, so no owner
	// is established when this runs. The caller MUST verify DeviceCodeHash,
	// Status and ExpiresAt before trusting the returned OwnerID.
	GetByID(ctx context.Context, id domain.PairingID) (*domain.DevicePairing, error)

	// GetByUserCodeHash returns the pairing whose UserCodeHash equals hash, or
	// domain.ErrNotFound if none does.
	//
	// UNSCOPED: an approving owner holds a transcribed user code and nothing
	// else -- not the pairing id, and not an owner id, because a pending pairing
	// has no owner yet. The owner boundary is established BY the approval that
	// follows this lookup, so it cannot constrain the lookup itself. Callers
	// MUST rate-limit this path: a user code is short enough to guess, and this
	// is the only method in the repository layer that can be asked "does this
	// short secret exist".
	//
	// The lookup is on the digest, never on the code, so the caller hashes
	// first and a store dump reveals no code.
	GetByUserCodeHash(ctx context.Context, hash []byte) (*domain.DevicePairing, error)

	// Get returns the owner's pairing with the given ID, or domain.ErrNotFound
	// if it does not exist or belongs to another owner.
	Get(ctx context.Context, ownerID domain.OwnerID, id domain.PairingID) (*domain.DevicePairing, error)

	// ListByOwner returns all of the owner's pairings. An owner with none gets a
	// nil slice, not an empty one.
	ListByOwner(ctx context.Context, ownerID domain.OwnerID) ([]domain.DevicePairing, error)

	// Approve binds the pairing to ownerID and stamps ApprovedAt with now.
	//
	// The transition is CONDITIONAL and MUST be a single statement: it applies
	// only when the pairing is currently pending, and returns
	// domain.ErrConflict when it is not. Implementations MUST NOT read the
	// status and then write it.
	//
	// The condition is the owner binding. Without it, a second approval of an
	// already-approved pairing would rewrite OwnerID, so an attacker who
	// guessed a user code could re-point a pairing another owner had already
	// approved -- and the device, which sees an ordinary success, would hand its
	// credentials to whichever account won the race.
	Approve(ctx context.Context, id domain.PairingID, ownerID domain.OwnerID, now time.Time) error

	// MarkRedeemed consumes the pairing: it moves the row to redeemed, stamps
	// RedeemedAt with now, and records lineageID as the refresh credential
	// lineage the redemption issued.
	//
	// The transition is CONDITIONAL and MUST be a single statement: it applies
	// only when the pairing is currently approved, and returns
	// domain.ErrConflict when it is not. Implementations MUST NOT read the
	// status and then write it, because between those two steps a second
	// presentation of the same device code reads the same approved row.
	//
	// This is what makes a device code single-use under concurrency. Without the
	// condition, two simultaneous redemptions both succeed and the pairing
	// installs two independent credentials, only one of which the owner ever
	// sees in a listing.
	MarkRedeemed(ctx context.Context, ownerID domain.OwnerID, id domain.PairingID, lineageID domain.LineageID, now time.Time) error

	// Revoke marks the owner's pairing revoked, setting RevokedAt to now. It
	// returns domain.ErrNotFound if the pairing does not exist or belongs to
	// another owner, and domain.ErrConflict if it is already terminal.
	Revoke(ctx context.Context, ownerID domain.OwnerID, id domain.PairingID, now time.Time) error

	// Touch sets NextPollAt, throttling a polling client. It returns
	// domain.ErrNotFound if the pairing does not exist.
	//
	// UNSCOPED: polling happens before redemption, so the poller is not yet an
	// owner. The caller MUST have verified the presented device code against
	// DeviceCodeHash first, so only the holder of the pairing's own secret can
	// reach it.
	Touch(ctx context.Context, id domain.PairingID, nextPollAt time.Time) error

	// DeleteExpired removes up to limit pairings whose ExpiresAt is at or before
	// cutoff, and returns the number deleted.
	//
	// UNSCOPED: this is a system-maintenance sweep across all owners; the
	// expiry-cleanup job is not acting on behalf of any single owner.
	DeleteExpired(ctx context.Context, cutoff time.Time, limit int) (int64, error)
}
