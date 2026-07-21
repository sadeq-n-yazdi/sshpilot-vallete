package accesskey

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/audit"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/repository"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/secrets"
)

// Rotate replaces one of the owner's access keys with a freshly minted one and
// leaves the outgoing credential usable until its grace window closes. It
// returns the new record and the new plaintext token, which — exactly as in
// Mint — is the only copy that will ever exist.
//
// This is the operation the grace machinery was built for. domain.AccessKeyStatusGrace,
// the GraceUntil deadline, the refusal in usable, and the expiry sweep were all
// in place before anything called MarkRotated, so nothing in the running product
// ever put a credential into grace. Rotate is what makes that state reachable.
//
// # The pair is atomic, because a half-applied rotation fails OPEN
//
// The mint and the grace transition run inside one store transaction. The
// ordering of the two failure modes is what forces it:
//
//   - If the mint committed and the transition did not, the owner would hold
//     TWO live credentials and the old one would carry no deadline at all —
//     status still active, GraceUntil still nil. That is not a degraded
//     rotation, it is a silent duplication of access with nothing scheduled to
//     end it, and neither the sweep nor Verify would ever notice: both read the
//     row, and the row says the credential is simply active.
//   - If the transition committed and the mint did not, the owner would hold a
//     credential counting down to nothing.
//
// The second is survivable and the first is not, but neither is acceptable, and
// a transaction removes the choice. WithTx commits when the closure returns nil
// and rolls back on any error, so a MarkRotated failure takes the new row with
// it and the outgoing credential remains the owner's only live one.
//
// The read that authorizes the whole operation is inside that transaction too,
// on the transaction-bound repositories. That is not decoration: a Get outside
// it would let a concurrent Revoke land between the status check and
// MarkRotated, and the repository's MarkRotated refuses only revoked rows —
// it would happily move a row this call had checked while it was still active.
//
// # Only an ACTIVE credential may be rotated
//
// One guard, two separate resurrection problems.
//
// A REVOKED credential must never rotate. Revocation is the control an operator
// reaches for during an incident, and a rotation that accepted a revoked key
// would bring it back to `grace` — a credential an operator had deliberately
// shut down becoming live again through an ordinary management call that does
// not look anything like an un-revoke. The storage adapter also refuses this
// (its UPDATE excludes revoked rows), and that belt-and-braces arrangement is
// deliberate: the guard here gives the refusal a service-level meaning and a
// test that does not depend on which adapter is mounted.
//
// A credential already IN GRACE must not rotate either, and this refusal is the
// service's alone — MarkRotated will happily move a grace row to grace again
// with a fresh deadline. Allowed, it would be an indefinite-life primitive: an
// owner (or anyone holding the token, since rotation is reachable with the
// credential's own authority in any surface that mounts it) could rotate every
// few hours and walk the deadline forward forever, so the credential the owner
// believed they had retired outlives the retirement by as long as anyone keeps
// calling. A grace window that can be extended is not a window. The owner's
// remedies are unchanged and both are explicit: Revoke ends the window early,
// and Mint issues another credential for the same set.
//
// Both refusals — and an unknown id, and another owner's id — are ErrNotFound,
// the single negative verdict this package returns for everything. See the
// package doc: a caller that could tell "revoked" from "never existed" from
// "already rotating" could read a credential's lifecycle off the error.
//
// # The label is inherited, not re-supplied
//
// The new credential keeps the old one's name. A rotation replaces the
// credential behind a label, and the label is how an owner recognizes it across
// rotations; letting this call rename it would make "the prod deploy key"
// discontinuous at the one moment its identity matters most. The inherited
// value was already validated by cleanName when the original was minted, so
// nothing here re-derives trust from stored text — it is re-screened by
// keyDetails before any write, and a refusal aborts the transaction.
//
// # The actor is the OWNER
//
// Unlike the expiry sweep, which emits under domain.ActorTypeSystem with an
// empty actor id because no principal asked for it, a rotation is something an
// owner requested. It is attributed to them, exactly as Mint and Revoke are.
//
// requestID correlates the audit records with the request log; it may be empty.
func (s *Service) Rotate(ctx context.Context, ownerID domain.OwnerID, id domain.AccessKeyID, requestID string) (*domain.AccessKey, secrets.Redacted, error) {
	if ownerID == "" {
		// As in Mint: an empty owner would act on nobody's credential, and the
		// owner-scoped predicates below would be scoped to nothing.
		return nil, "", fmt.Errorf("accesskey: missing owner: %w", domain.ErrInvalidInput)
	}
	if id == "" {
		// An empty id names no key, and collapses into the verdict a wrong one
		// gets so a caller cannot learn which shapes are well formed.
		return nil, "", ErrNotFound
	}
	// Defense in depth. New already refuses a non-positive window, so this is
	// unreachable through the constructor — but the value decides a deadline,
	// and the failure it guards against is a rotated credential that never
	// expires. A check that costs nothing is worth having on that path.
	if s.graceWindow <= 0 {
		return nil, "", fmt.Errorf("accesskey: grace window is not configured: %w", domain.ErrInvalidInput)
	}

	var (
		created        *domain.AccessKey
		token          secrets.Redacted
		rotateDetails  audit.Details
		createdDetails audit.Details
	)
	now := s.now().UTC()
	graceUntil := now.Add(s.graceWindow)

	if err := s.store.WithTx(ctx, func(ctx context.Context, r repository.Repos) error {
		old, err := r.AccessKeys.Get(ctx, ownerID, id)
		if err != nil {
			return err
		}
		// A nil row with a nil error is a port contract violation, and on an
		// owner-scoped path the safe reading of one is "denied", not
		// "dereference and panic". The status check is the ACTIVE-only guard
		// argued above; every other state, known or not yet invented, is
		// refused rather than allowed by omission.
		if old == nil || old.Status != domain.AccessKeyStatusActive {
			return ErrNotFound
		}

		// The set is resolved for the same reason Mint resolves it: this call
		// is about to write a NEW credential, and a set that has been
		// quarantined or retired must not gain one. Rotation is not a way
		// around Mint's refusal.
		set, err := s.keySetIn(ctx, r, ownerID, old.KeySetID)
		if err != nil {
			return err
		}

		// Both audit records are built BEFORE either write, inside the
		// transaction. A detail the audit screen refuses must abort the
		// rotation rather than leave a committed credential change unrecorded —
		// building them after the commit is exactly how that gap opens. The
		// stored name is not caller-supplied, so a refusal is a server fault
		// and the rejected text is not quoted back into an error bound for a
		// log.
		plaintext, newKey, err := s.newRotatedKey(old, set, now)
		if err != nil {
			return err
		}
		if createdDetails, err = keyDetails(old.Name, set.Name, requestID); err != nil {
			return errors.New("accesskey: stored key cannot be recorded")
		}
		if rotateDetails, err = rotationDetails(old, newKey.ID, set.Name, requestID); err != nil {
			return errors.New("accesskey: stored key cannot be recorded")
		}

		if err := r.AccessKeys.Create(ctx, newKey); err != nil {
			return err
		}
		// The transition the whole feature turns on. If this fails, the Create
		// above is rolled back with it and the outgoing credential is still the
		// owner's only live one.
		if err := r.AccessKeys.MarkRotated(ctx, ownerID, id, newKey.ID, graceUntil); err != nil {
			return err
		}

		// Published to the enclosing scope only after every write in this
		// transaction has succeeded, so a rollback cannot leave the caller
		// holding a token for a credential that does not exist.
		created, token = newKey, plaintext
		return nil
	}); err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return nil, "", ErrNotFound
		}
		return nil, "", err
	}

	// Emitted after the commit, matching keyset.SetDefault and the rest of this
	// tree: the auditor is not transaction-bound, so a record written inside the
	// closure would survive a rollback and describe a rotation that did not
	// happen.
	//
	// The creation is recorded first so the new credential is never live with no
	// record of where it came from. A failure of either emit is returned and the
	// token is NOT handed back — a caller that never receives it cannot use it,
	// so the committed rotation leaves the owner with an outgoing credential in
	// grace and an inert replacement. The recovery path is the ordinary one and
	// needs nothing special: Mint another credential for the set and Revoke the
	// one in grace.
	if err := s.emit(ctx, domain.AuditActionAccessKeyCreated, ownerID, created.ID, createdDetails); err != nil {
		return nil, "", err
	}
	if err := s.emit(ctx, domain.AuditActionAccessKeyRotated, ownerID, id, rotateDetails); err != nil {
		return nil, "", err
	}
	return created, token, nil
}

// newRotatedKey builds the replacement credential.
//
// It mints a fresh id and secret exactly as Mint does — nothing about the
// outgoing credential's secret is reused or derived from, because a replacement
// that shared any material with the credential it replaces would not be a
// replacement. The label and the key set are carried over; everything else is
// new.
func (s *Service) newRotatedKey(old *domain.AccessKey, set *domain.KeySet, now time.Time) (secrets.Redacted, *domain.AccessKey, error) {
	token, id, secret, err := newToken()
	if err != nil {
		return "", nil, err
	}
	return token, &domain.AccessKey{
		ID:         id,
		OwnerID:    old.OwnerID,
		KeySetID:   set.ID,
		Name:       old.Name,
		SecretHash: s.hasher.hash(id, secret),
		Status:     domain.AccessKeyStatusActive,
		CreatedAt:  now,
	}, nil
}

// keySetIn is keySet against a caller-supplied repository set, so the resolution
// can run on the transaction-bound repositories inside Rotate rather than on the
// auto-commit ones. The verdict is identical: every failure is ErrNotFound.
func (s *Service) keySetIn(ctx context.Context, r repository.Repos, ownerID domain.OwnerID, setID domain.KeySetID) (*domain.KeySet, error) {
	if setID == "" {
		return nil, ErrNotFound
	}
	set, err := r.KeySets.Get(ctx, ownerID, setID)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if set == nil || set.State != domain.NameStateActive {
		return nil, ErrNotFound
	}
	return set, nil
}

// rotationDetails builds the audit details for the rotation itself.
//
// It records which credential replaced which, using the from/to vocabulary the
// rename and default-change records already use. The ids are recorded rather
// than the labels because the label is inherited and therefore identical on both
// sides — it would say nothing — while the ids are what an incident review
// follows from one credential to the next.
//
// As everywhere in this package, neither a plaintext token nor a digest is
// recorded.
func rotationDetails(old *domain.AccessKey, replacement domain.AccessKeyID, setName, requestID string) (audit.Details, error) {
	d := audit.Details{}.
		Set(audit.DetailClientLabel, old.Name).
		Set(audit.DetailFrom, string(old.ID)).
		Set(audit.DetailTo, string(replacement))
	if setName != "" {
		d = d.Set(audit.DetailKeySetName, setName)
	}
	if requestID != "" {
		d = d.Set(audit.DetailRequestID, requestID)
	}
	if err := d.Err(); err != nil {
		return audit.Details{}, fmt.Errorf("accesskey: rotation cannot be recorded: %w", domain.ErrInvalidInput)
	}
	return d, nil
}
