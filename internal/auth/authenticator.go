package auth

import (
	"context"
	"fmt"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/repository"
)

// Authenticator runs a registered provider and resolves the principal it
// returns to an owner. It is the only place in the codebase that turns a
// credential into a domain.OwnerID, and the only legitimate caller of
// LinkedIdentityRepository.GetByProviderSubject.
//
// That last point is deliberate. GetByProviderSubject is marked UNSCOPED in the
// repository port: it is the login bootstrap, so it necessarily runs before any
// owner is established and therefore cannot filter by owner the way every other
// owner-touching query does. Concentrating its use here keeps the number of
// places that cross the owner boundary at one, where it can be read and audited
// as a whole, rather than scattering an unscoped lookup through the service
// layer.
//
// An Authenticator is immutable after construction and safe for concurrent use.
type Authenticator struct {
	registry *Registry
	links    repository.LinkedIdentityRepository
	owners   repository.OwnerRepository
}

// NewAuthenticator builds an Authenticator. All three dependencies are
// required: a missing one is a wiring bug, and the alternative — tolerating nil
// and skipping the corresponding check — would turn a wiring bug into a silently
// weakened authentication path. Failing at startup is the only safe response.
func NewAuthenticator(reg *Registry, links repository.LinkedIdentityRepository, owners repository.OwnerRepository) (*Authenticator, error) {
	if reg == nil {
		return nil, fmt.Errorf("auth: nil registry: %w", domain.ErrInvalidInput)
	}
	if links == nil {
		return nil, fmt.Errorf("auth: nil linked identity repository: %w", domain.ErrInvalidInput)
	}
	if owners == nil {
		return nil, fmt.Errorf("auth: nil owner repository: %w", domain.ErrInvalidInput)
	}
	return &Authenticator{registry: reg, links: links, owners: owners}, nil
}

// Authenticate verifies cred with the provider registered under providerID and
// returns the owner the resulting principal is linked to.
//
// Every failure returns exactly ErrAuthFailed, bare and without a cause; see
// the package documentation for why the causes are not distinguished.
//
// providerID selects which provider handles the credential. It may come from
// the request (a route or an auth scheme), and it is treated as untrusted
// input: it selects a provider but never becomes part of the identity key. The
// key's provider half always comes from the provider's own ID, checked below.
func (a *Authenticator) Authenticate(ctx context.Context, providerID ProviderID, cred Credential) (domain.OwnerID, error) {
	provider, err := a.registry.Lookup(providerID)
	if err != nil {
		return "", ErrAuthFailed
	}

	identity, err := provider.Authenticate(ctx, cred)
	if err != nil {
		// The provider's error is discarded rather than wrapped. A provider may
		// legitimately distinguish "credential rejected" from "store
		// unreachable" for its own logging; propagating that distinction to the
		// caller would let an unauthenticated client learn whether a credential
		// was recognized.
		return "", ErrAuthFailed
	}

	// The provider must speak only for its own namespace. A provider that
	// returns some other provider's id — through a bug, a copy-paste, or
	// compromise — would otherwise mint principals that resolve to owners linked
	// under that other provider, which is a full account takeover. The id is
	// taken from the instance that was actually invoked and compared, so a
	// provider's claim about which namespace it is in is verified rather than
	// trusted.
	if identity.Provider != provider.ID() {
		return "", ErrAuthFailed
	}
	if err := identity.Validate(); err != nil {
		return "", ErrAuthFailed
	}

	return a.resolve(ctx, identity)
}

// Resolve maps an already-authenticated identity to its owner without running a
// provider. It exists for callers that obtained an Identity from a prior
// authentication — a session or token exchange, in later tracks — and must
// re-establish the owner.
//
// It performs the identical link and owner checks as Authenticate and returns
// the identical ErrAuthFailed. The caller is responsible for the identity being
// genuinely authenticated; this method verifies the mapping, not the
// credential.
func (a *Authenticator) Resolve(ctx context.Context, identity Identity) (domain.OwnerID, error) {
	if err := identity.Validate(); err != nil {
		return "", ErrAuthFailed
	}
	return a.resolve(ctx, identity)
}

// resolve is the single mapping path: (provider, principal) -> OwnerID, with
// every check that gates it. Both entry points funnel through here so the
// checks cannot drift apart between them.
func (a *Authenticator) resolve(ctx context.Context, identity Identity) (domain.OwnerID, error) {
	// Both halves of the key are passed, always together. Looking up by
	// principal alone would let a principal issued by one provider resolve to an
	// owner linked under another. The two values stay separate arguments and are
	// never joined into one string: "a" + "b:c" and "a:b" + "c" would collide
	// under any delimiter, which is the same cross-provider confusion in a
	// different costume.
	li, err := a.links.GetByProviderSubject(ctx, identity.Provider.String(), string(identity.Principal))
	if err != nil {
		// Covers domain.ErrNotFound (no such link) and any storage fault alike.
		// An unlinked principal must be indistinguishable from a rejected one.
		return "", ErrAuthFailed
	}
	if li == nil {
		// A nil row with a nil error violates the port contract, but the safe
		// reading of a contract violation on an authentication path is "denied",
		// not "dereference and panic".
		return "", ErrAuthFailed
	}

	// Defense in depth: re-check that the row returned is the row asked for.
	// The port promises an exact match, but this is the single query in the
	// codebase that crosses the owner boundary, so it is the last place to
	// accept a row on trust. A case-insensitive collation, a LIKE that reached
	// production, or a caching layer keyed too loosely would each hand back a
	// neighboring row; comparing the bytes here turns any of those from an
	// account takeover into a denial.
	if li.Provider != identity.Provider.String() || li.Subject != string(identity.Principal) {
		return "", ErrAuthFailed
	}

	// B3 (revocation denylist) adds link revocation state. This is its single
	// insertion point: the check belongs here, between matching the link and
	// accepting its owner, so that both Authenticate and Resolve get it at once.
	// No placeholder field is declared until the check that reads it ships.

	// An authenticated, correctly linked principal still must not become a
	// session for a suspended or deleted account. The link outlives the owner's
	// good standing, so the owner's own status is authoritative and is checked
	// on every authentication rather than assumed from the link's existence.
	owner, err := a.owners.Get(ctx, li.OwnerID)
	if err != nil {
		return "", ErrAuthFailed
	}
	if owner == nil {
		return "", ErrAuthFailed
	}
	// An owner row whose id differs from the one requested means the repository
	// ignored the id; deny rather than accept an owner nobody asked for.
	if owner.ID != li.OwnerID {
		return "", ErrAuthFailed
	}
	if owner.Status != domain.OwnerStatusActive || owner.DeletedAt != nil {
		return "", ErrAuthFailed
	}

	return li.OwnerID, nil
}
