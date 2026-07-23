// Package onboarding provisions a new owner on an administrator's authority and
// hands the owner a one-time enrollment credential to bootstrap their own tokens
// (Phase-1 decision #14, ADR-0033, ADR-0012).
//
// # What it composes, and what it deliberately does not
//
// This package ties two existing operations together and invents nothing new:
//
//   - It seeds an owner, its handle name-claim, and its default key set in ONE
//     transaction, mirroring bootstrap.Seed's invariants (a partial seed — an
//     owner with a claimed handle but no default set — would make /{handle}
//     answer 404 forever while the name looks taken to everyone else). Unlike
//     bootstrap it creates NO device and NO key: an admin-provisioned owner adds
//     their own keys later through the authenticated management surface.
//   - It mints a one-time enrollment credential for the new owner through the
//     existing enrollment path (auth.EnrollmentService.Mint). The returned code
//     is redeemed by the owner at the existing POST /api/v1/enroll/redeem to mint
//     their OWN refresh and access tokens. The operator never holds the owner's
//     long-lived credential — they hold only the short-lived, single-use code.
//
// # Why the administrator check lives here
//
// The transport gate authenticates the bearer's signature, but a signature is
// not authority: a disabled administrator's still-valid token would otherwise
// provision owners. So this package re-authorizes the identified administrator
// against the store (active status required, ADR-0031), exactly as listadmin
// does for blocklist edits. Placing the check in the service makes it a property
// of the operation rather than of one transport, so any future caller inherits
// it by construction.
//
// # Fail closed
//
// A nil dependency is refused at construction. A nil name guard refuses every
// name rather than skipping the blocklist. An administrator that cannot be
// established — empty, unknown, unreadable, or not active — refuses the
// provision. The owner-creating writes and the audit record are one transaction:
// either the owner exists and is audited, or nothing was written.
package onboarding

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/audit"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/auth"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/nameguard"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/repository"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/secrets"
)

// DefaultSetName is the name given to the new owner's default key set when the
// administrator requests none. It matches bootstrap.DefaultSetName so a
// provisioned owner and a seeded owner resolve /{handle} to the same set name.
const DefaultSetName = "default"

// DefaultClientLabel labels the enrollment credential minted for a newly
// provisioned owner when the administrator supplies no label. It is a
// non-secret, human-readable string recorded on the pairing and the audit
// record.
const DefaultClientLabel = "owner-enrollment"

// Minter mints a one-time enrollment credential for an owner through a
// caller-supplied, transaction-bound repos handle. It is the seam onto
// auth.EnrollmentService.MintInto, declared here at the point of use so this
// package depends on the capability rather than on the enrollment service's
// concrete type.
//
// The transaction-bound variant (not standalone Mint) is deliberate: it lets the
// mint join the owner-create transaction so the owner and its enrollment
// credential either both commit or both roll back. A mint that ran after the
// owner-create commit could strand an owner with a claimed handle and no way to
// enroll, and there is no API path to re-issue a credential for an existing owner.
type Minter interface {
	MintInto(ctx context.Context, r repository.Repos, ownerID domain.OwnerID, clientLabel string, scopes []domain.Scope) (*auth.Grant, error)
}

// Auditor appends an audit record to a transaction-bound sink. It is the seam
// onto audit.Emitter.EmitTo, so the owner-created record is written inside the
// same transaction as the owner it describes.
type Auditor interface {
	EmitTo(ctx context.Context, sink repository.AuditAppender, ev audit.Event) error
}

// Params are the dependencies a Service needs. They are named rather than
// positional because every one is required and several share a shape.
type Params struct {
	// Store is the unit-of-work root the owner, handle, key set, and audit
	// record are written through.
	Store repository.Store
	// Guard enforces the reserved-identifier blocklist (ADR-0017) on the handle
	// and, when one is supplied, the set name. It MUST be the composed policy
	// guard, not nameguard.Default(): an operator's seed and runtime overrides
	// only take effect on names routed through the composed guard.
	Guard *nameguard.Guard
	// Minter issues the one-time enrollment credential for the new owner.
	Minter Minter
	// Auditor writes the owner-created record inside the provisioning
	// transaction.
	Auditor Auditor
	// Now stamps every seeded row and the audit record. Optional; time.Now is
	// used when nil, since a missing clock has a single obviously-correct
	// default and is not a security decision the way a missing dependency is.
	Now func() time.Time
}

// Service provisions owners on an administrator's authority.
type Service struct {
	store   repository.Store
	guard   *nameguard.Guard
	minter  Minter
	auditor Auditor
	now     func() time.Time
}

// New returns a Service, or an error if a required dependency is missing.
//
// Every dependency but the clock is required and a nil one is refused rather
// than tolerated: a Service with no store could not write, no guard could not
// enforce the blocklist, no minter could not hand the owner a credential, and no
// auditor could not account for the owner it created. Refusing at construction
// makes that a startup failure instead of a latent one that surfaces on the
// first provision.
func New(p Params) (*Service, error) {
	if p.Store == nil {
		return nil, fmt.Errorf("onboarding: nil store: %w", domain.ErrInvalidInput)
	}
	if p.Guard == nil {
		return nil, fmt.Errorf("onboarding: nil guard: %w", domain.ErrInvalidInput)
	}
	if p.Minter == nil {
		return nil, fmt.Errorf("onboarding: nil minter: %w", domain.ErrInvalidInput)
	}
	if p.Auditor == nil {
		return nil, fmt.Errorf("onboarding: nil auditor: %w", domain.ErrInvalidInput)
	}
	now := p.Now
	if now == nil {
		now = time.Now
	}
	return &Service{
		store:   p.Store,
		guard:   p.Guard,
		minter:  p.Minter,
		auditor: p.Auditor,
		now:     now,
	}, nil
}

// Request describes the owner an administrator wants provisioned.
type Request struct {
	// Handle is the public name to claim for the new owner. Required.
	Handle string
	// SetName is the default key set's name; empty means DefaultSetName.
	SetName string
	// ClientLabel labels the enrollment credential minted for the owner; empty
	// means DefaultClientLabel.
	ClientLabel string
}

// Result reports what was provisioned and the one-time enrollment credential.
type Result struct {
	// OwnerID is the identifier of the created owner.
	OwnerID domain.OwnerID
	// Handle is the name actually claimed.
	Handle string
	// SetName is the name the default key set was actually created with —
	// Request.SetName, or DefaultSetName when none was supplied.
	SetName string
	// EnrollmentCode is the one-time device code the owner redeems at
	// POST /api/v1/enroll/redeem to mint their own tokens. It is a
	// secrets.Redacted so it never lands in a log or an error by accident; the
	// transport reveals it at exactly one disclosure point in the response.
	EnrollmentCode secrets.Redacted
	// ExpiresAt is when the enrollment code dies if unredeemed.
	ExpiresAt time.Time
	// PairingID identifies the pairing the code belongs to. It is not a secret.
	PairingID domain.PairingID
}

// ProvisionOwner authorizes the administrator, seeds a new owner with a handle
// and an empty default key set, records the creation, and mints a one-time
// enrollment credential for the owner.
//
// The administrator is re-authorized against the store here, not merely trusted
// from the transport: authentication proves a bearer, authorization proves an
// active administrator (ADR-0031). Every path that cannot establish one refuses.
//
// The owner-creating writes and the audit record are ONE transaction. The
// enrollment credential is minted AFTER that transaction commits, through the
// enrollment service's own transaction — the same deliberately-separate posture
// the redeem path takes. A mint that fails leaves a real owner with no issued
// code; the administrator sees the error and can re-issue a code for the owner
// rather than the provision silently half-succeeding with a forged owner.
func (s *Service) ProvisionOwner(ctx context.Context, actor domain.AdministratorID, req Request) (Result, error) {
	if err := s.authorize(ctx, actor); err != nil {
		return Result{}, err
	}

	// The guard subsumes the syntax validators: it runs the handle/set-name
	// syntax check itself and then consults the blocklist, so calling it here
	// replaces validation rather than adding a second, guard-free path.
	if err := s.guard.Check(nameguard.KindHandle, nameguard.OpCreate, req.Handle); err != nil {
		return Result{}, fmt.Errorf("onboarding: handle: %w", err)
	}

	setName := req.SetName
	if setName == "" {
		// The system, not the administrator, chose this name. ADR-0017 scopes
		// the blocklist to USER-CHOSEN identifiers, and DefaultSetName is itself
		// a routing term on the curated list — checking our own constant against
		// our own list would make every default provision fail on a name no one
		// picked. An explicitly supplied set name IS a choice, and is checked.
		setName = DefaultSetName
	} else if err := s.guard.Check(nameguard.KindKeySetName, nameguard.OpCreate, setName); err != nil {
		return Result{}, fmt.Errorf("onboarding: set name: %w", err)
	}

	now := s.now()
	res := Result{
		OwnerID: domain.OwnerID(newID()),
		Handle:  req.Handle,
		SetName: setName,
	}
	handleID := domain.HandleID(newID())
	keySetID := domain.KeySetID(newID())
	clientLabel := req.ClientLabel
	if clientLabel == "" {
		clientLabel = DefaultClientLabel
	}

	// grant is filled inside the transaction and read after it commits. It is
	// captured here so the mint can join the same unit of work as the owner it is
	// for -- see the mint step at the end of the closure.
	var grant *auth.Grant

	err := s.store.WithTx(ctx, func(ctx context.Context, r repository.Repos) error {
		if err := r.Owners.Create(ctx, &domain.Owner{
			ID:        res.OwnerID,
			Status:    domain.OwnerStatusActive,
			CreatedAt: now,
			UpdatedAt: now,
		}); err != nil {
			return fmt.Errorf("create owner: %w", err)
		}

		if err := r.Handles.Register(ctx, &domain.Handle{
			ID:        handleID,
			OwnerID:   res.OwnerID,
			Name:      req.Handle,
			State:     domain.NameStateActive,
			CreatedAt: now,
			UpdatedAt: now,
		}); err != nil {
			return fmt.Errorf("register handle: %w", err)
		}

		// Public and default: this is the set /{handle} resolves to. It is
		// created empty — the owner attaches keys after they enroll.
		if err := r.KeySets.Create(ctx, &domain.KeySet{
			ID:         keySetID,
			OwnerID:    res.OwnerID,
			Name:       setName,
			Visibility: domain.VisibilityPublic,
			IsDefault:  true,
			State:      domain.NameStateActive,
			CreatedAt:  now,
			UpdatedAt:  now,
		}); err != nil {
			return fmt.Errorf("create key set: %w", err)
		}

		// Audit inside the transaction: the owner-created record commits with
		// the owner or not at all. The details carry only the handle and set
		// name — non-secret display names on the allowlist. The enrollment code
		// is NEVER recorded; it is a credential.
		details := audit.Details{}.
			Set(audit.DetailHandle, req.Handle).
			Set(audit.DetailKeySetName, setName)
		if err := s.auditor.EmitTo(ctx, r.Audit, audit.Event{
			ActorType:  domain.ActorTypeAdministrator,
			ActorID:    string(actor),
			Action:     domain.AuditActionOwnerCreated,
			TargetType: domain.TargetTypeOwner,
			TargetID:   string(res.OwnerID),
			Details:    details,
		}); err != nil {
			return fmt.Errorf("audit owner created: %w", err)
		}

		// Mint the one-time enrollment credential INSIDE this transaction, through
		// the same repos handle. Full-owner scope: the redeemed tokens must let the
		// owner manage their own resources. Because the mint joins the owner-create
		// unit of work, a mint failure rolls the owner, handle, key set and audit
		// record back with it -- no owner can be left with a claimed handle and no
		// way to enroll. The link is written after the owner row exists in-tx, so
		// the LinkedIdentity's owner reference resolves.
		g, err := s.minter.MintInto(ctx, r, res.OwnerID, clientLabel, []domain.Scope{{Kind: domain.ScopeFullOwner}})
		if err != nil {
			return fmt.Errorf("mint enrollment credential: %w", err)
		}
		if g == nil {
			// A nil grant with no error would be a minter contract violation.
			// Refuse -- and roll the whole provision back -- rather than commit an
			// owner with an empty code it could never redeem.
			return fmt.Errorf("minter returned no grant: %w", domain.ErrInvalidInput)
		}
		grant = g
		return nil
	})
	if err != nil {
		return Result{}, fmt.Errorf("onboarding: %w", err)
	}

	res.EnrollmentCode = grant.DeviceCode
	res.ExpiresAt = grant.ExpiresAt
	res.PairingID = grant.PairingID
	return res, nil
}

// authorize refuses unless the actor names an ACTIVE administrator. It mirrors
// listadmin.authorize: an unavailable store is not permission, so a lookup that
// could not be performed fails closed rather than allowing the provision.
func (s *Service) authorize(ctx context.Context, actor domain.AdministratorID) error {
	if actor == "" {
		return fmt.Errorf("onboarding: no administrator named: %w", domain.ErrUnauthorized)
	}
	admin, err := s.store.Repos().Admins.Get(ctx, actor)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return fmt.Errorf("onboarding: not an administrator: %w", domain.ErrUnauthorized)
		}
		// Fail closed. A database outage must not become a window in which
		// anyone may provision owners.
		return fmt.Errorf("onboarding: administrator lookup failed, refusing: %w", err)
	}
	if admin == nil {
		return fmt.Errorf("onboarding: administrator lookup returned nothing: %w", domain.ErrUnauthorized)
	}
	if admin.Status != domain.AdminStatusActive {
		return fmt.Errorf("onboarding: administrator is not active: %w", domain.ErrForbidden)
	}
	return nil
}

// newID returns a fresh unguessable identifier. crypto/rand.Text yields
// URL-safe base32 with enough entropy that identifiers never collide in
// practice, and repositories are forbidden from generating IDs, so the service
// mints them here.
func newID() string { return rand.Text() }
