package auth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/repository"
)

// APITokenProviderID is the registered id of the API-token / device-pairing
// provider. It is the provider half of every identity key this provider mints,
// so principals it issues live in a namespace no other provider can reach.
const APITokenProviderID ProviderID = "api-token"

// APITokenProvider authenticates a device code against a DevicePairing row.
//
// It is the first concrete AuthProvider (ADR-0009, ADR-0018), and it fits the
// port exactly: it verifies presented material and reports a principal, and it
// never learns or asserts an owner. The principal it reports is the pairing's
// own identifier, which the approval step linked to an owner through a
// LinkedIdentity row. Authenticator turns that link into an owner; this type
// cannot, and could not be made to by a caller in a hurry.
//
// # Verification is single-use because the row is
//
// This provider verifies; it does not consume. A pairing is redeemable only in
// the approved state, so once EnrollmentService has moved it to redeemed, every
// later presentation of the same device code fails the status check here.
// Verification is therefore replayable only inside the window between a
// successful check and the conditional transition that closes it, and that
// window is closed by the transition itself: exactly one redemption commits and
// any other is compensated. Consuming the row here instead would put the
// destructive write before the caller had done anything with the result, so a
// crash between the two would burn a pairing and issue nothing.
//
// # The clock
//
// AuthProvider.Authenticate takes no time argument, and the expiry check needs
// one. Rather than read the wall clock inline -- which would make behavior at
// the expiry boundary untestable without sleeping -- the clock is a constructor
// argument, as counter.MemoryStore's is.
//
// An APITokenProvider is immutable after construction and safe for concurrent
// use.
type APITokenProvider struct {
	pairings repository.DevicePairingRepository
	now      func() time.Time
}

// Compile-time proof that the provider satisfies the port it is registered
// under. A mismatch here is a wiring failure that would otherwise surface as a
// runtime type assertion.
var _ AuthProvider = (*APITokenProvider)(nil)

// NewAPITokenProvider builds an APITokenProvider.
//
// Both dependencies are required. Tolerating a nil one would produce a provider
// that cannot check something -- the pairing row, or the expiry -- while still
// answering "authenticated", which is the failure mode this whole package
// refuses to allow at wiring time.
func NewAPITokenProvider(pairings repository.DevicePairingRepository, now func() time.Time) (*APITokenProvider, error) {
	if pairings == nil {
		return nil, fmt.Errorf("auth: nil device pairing repository: %w", domain.ErrInvalidInput)
	}
	if now == nil {
		return nil, fmt.Errorf("auth: nil clock: %w", domain.ErrInvalidInput)
	}
	return &APITokenProvider{pairings: pairings, now: now}, nil
}

// ID returns APITokenProviderID. It is constant for the life of the instance,
// as the port requires, so Authenticator's check that a provider spoke only for
// its own namespace is meaningful.
func (p *APITokenProvider) ID() ProviderID { return APITokenProviderID }

// Authenticate verifies a presented device code and returns the pairing it
// belongs to as a principal.
//
// Every denial returns bare ErrAuthFailed. A malformed code, an unknown pairing
// id, a wrong secret, a pending pairing, an already-redeemed one, a revoked one
// and an expired one are all one answer, so a caller cannot use this method to
// learn which device codes exist or what state a pairing is in. That is the
// same information-content guarantee the package documentation describes, and
// as there, it is not a timing guarantee: an unknown id costs one storage round
// trip and a known one costs a round trip plus a digest.
//
// A storage fault is returned as a distinct wrapped error rather than as
// ErrAuthFailed, so an operator can tell an outage from a rejected code in the
// logs. Authenticator collapses it before any caller sees it.
func (p *APITokenProvider) Authenticate(ctx context.Context, cred Credential) (Identity, error) {
	id, secret, err := parseDeviceCode(cred.Secret)
	if err != nil {
		return Identity{}, ErrAuthFailed
	}

	pairing, err := p.pairings.GetByID(ctx, id)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return Identity{}, ErrAuthFailed
		}
		return Identity{}, fmt.Errorf("auth: reading device pairing: %w", err)
	}
	if pairing == nil {
		// A nil row with a nil error violates the port contract. The safe
		// reading of a contract violation on an authentication path is "denied",
		// not "dereference and panic".
		return Identity{}, ErrAuthFailed
	}
	// Defense in depth: confirm the row returned is the row asked for. This
	// lookup is UNSCOPED -- redemption is the authentication step, so no owner
	// is established yet -- which makes it one of the few queries the owner
	// boundary cannot constrain, and therefore one where a case-insensitive
	// collation or a loosely keyed cache would hand back a neighbor.
	if pairing.ID != id {
		return Identity{}, ErrAuthFailed
	}

	// The secret is verified before any other property of the row is acted on.
	// Possession of the device code is what earns the right to have the pairing's
	// state consulted at all; checking status or expiry first would answer
	// questions about a pairing to a caller that had only guessed its id.
	if !deviceSecretMatches(pairing.DeviceCodeHash, secret) {
		return Identity{}, ErrAuthFailed
	}

	// Only an approved pairing is redeemable. Pending means no owner has
	// authorized this device yet; redeemed means the code has already been
	// spent, which is where single-use is enforced on every presentation after
	// the first; revoked means the owner withdrew it.
	if pairing.Status != domain.PairingStatusApproved {
		return Identity{}, ErrAuthFailed
	}
	// An approved pairing with no owner is a malformed row -- Approve sets both
	// in one statement -- so deny before the empty value can be used as a
	// lookup or comparison key anywhere downstream.
	if pairing.OwnerID == "" {
		return Identity{}, ErrAuthFailed
	}
	// Expiry is checked against the injected clock, and the comparison is
	// exclusive: a pairing is dead at its expiry instant, not one tick later.
	if !p.now().Before(pairing.ExpiresAt) {
		return Identity{}, ErrAuthFailed
	}

	return Identity{Provider: APITokenProviderID, Principal: Principal(pairing.ID)}, nil
}
