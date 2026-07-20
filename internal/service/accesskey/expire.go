package accesskey

import (
	"context"
	"errors"
	"fmt"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/audit"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
)

// ExpireGrace retires the access keys whose rotation grace window has closed,
// up to limit of them, and returns how many it retired.
//
// # This sweep is hygiene, not the enforcement boundary
//
// It is worth being exact about what this does and does not protect, because
// the obvious reading is wrong. A credential past its grace deadline is ALREADY
// refused without this sweep ever running: Verify calls usable, which for a
// grace row compares the deadline against the clock on every single request and
// answers ErrNotFound once it has passed. The enforcement is at time of use, so
// it cannot be behind — there is no window in which a lapsed credential
// authenticates because a background job had not got to it yet.
//
// That makes this sweep fail CLOSED in the only sense that matters. If it never
// runs, nothing becomes usable that was not usable before; what remains is a
// row still labeled `grace` that no longer opens anything. So this job may be
// disabled by an operator, and its cadence is a housekeeping choice rather than
// a security control. Turning the deadline check in usable into something this
// sweep alone enforced would be the actual fail-open design, and is exactly
// what must not be done.
//
// What it is for is to keep the stored state honest: a credential that is dead
// should say so. An owner listing their keys sees `revoked` rather than a grace
// window that expired months ago, the audit trail carries the moment the
// rotation actually completed, and any later code that reads status without
// re-deriving the deadline reads the truth.
//
// # Retire means REVOKE, not delete
//
// The row is moved to domain.AccessKeyStatusRevoked, which is the vocabulary
// this package already uses for a credential that is permanently out of
// service, and is checked as an explicit deny in usable. Deleting the row was
// the alternative and is rejected on two counts.
//
// The first is accountability. An access key id appears in the audit trail as
// the target of its own creation, rotation, and revocation. Deleting the row
// leaves those records pointing at an id that resolves to nothing, so the one
// question an incident review asks — what was this credential, whose was it,
// when did it die — becomes unanswerable at exactly the moment it is asked.
// ADR-0007 wants the credential lifecycle recorded, and a lifecycle whose final
// state is an absent row is not recorded.
//
// The second is that deletion is not this sweep's decision to make. Erasure of
// an owner's data is its own obligation, with its own scope, ordering, and
// audit consequences, and it is handled by the erasure path — not by a
// maintenance job that happened to be looking at the row. A retention sweep
// that quietly destroyed records would put deletion on a schedule nobody
// reviewed as a deletion policy.
//
// Revoking is also self-limiting in a way deleting is not: the repository's
// ListExpiredGrace selects only rows still in the grace state, so a row this
// sweep has retired drops out of its own query and is never revisited.
//
// # The actor is the system
//
// The audit record is domain.AuditActionAccessKeyRevoked — the existing action,
// not a new one, because what happened to the credential is exactly what Revoke
// does to it — but it is emitted with domain.ActorTypeSystem and an empty actor
// id. No owner asked for this. Attributing it to the key's owner, as an
// owner-scoped Revoke would, would put a credential change in the trail under a
// principal who did not make it, which is the one thing an accountability
// record must never say. audit.Event permits an empty actor id for the system
// actor precisely so a job with no principal behind it can still be recorded.
//
// # Concurrency, honestly
//
// Two servers sweeping one datastore is safe but not perfectly clean, and the
// difference is worth stating rather than glossing. The repository's Revoke is
// keyed on id and owner alone and does not re-check the grace state, so if both
// instances list the same row before either writes, both writes succeed and TWO
// revocation records are emitted for one credential. The credential's fate is
// identical either way — revoked_at is written with COALESCE and keeps the
// first instant — so this costs a duplicate audit line, not a wrong outcome.
//
// The narrow race in the other direction is a key rotated again between the
// list and the write: MarkRotated only refuses a revoked row, so it could
// install a fresh grace deadline that this sweep then revokes. The result is a
// live credential being retired early, which is the safe direction of that
// mistake, and the owner's remedy is the rotation they were already performing.
//
// # limit
//
// limit must be positive and is rejected here rather than passed through. The
// repository's ListExpiredGrace rejects a non-positive limit too, so nothing
// unbounded could reach the database in any case — but the sweep primitives in
// this tree do not agree on that (the quarantine lists coerce a non-positive
// limit to a page default instead), so the caller's bound is validated at the
// service boundary where the error can name this operation.
func (s *Service) ExpireGrace(ctx context.Context, limit int) (int, error) {
	if limit < 1 {
		return 0, fmt.Errorf("accesskey: expire grace batch must be >= 1, got %d: %w", limit, domain.ErrInvalidInput)
	}

	now := s.now().UTC()

	expired, err := s.keys.ListExpiredGrace(ctx, now, limit)
	if err != nil {
		return 0, fmt.Errorf("accesskey: list expired grace: %w", err)
	}

	retired := 0
	for i := range expired {
		k := expired[i]

		// The details are built before the write, as in Mint and Revoke: a
		// value the audit screen refuses must stop this retirement rather than
		// leave a credential shut down with no record that it was. The stored
		// name is not caller-supplied here, so a refusal is a server fault and
		// the rejected text is not quoted back into an error bound for a log.
		details, err := keyDetails(k.Name, "", "")
		if err != nil {
			return retired, errors.New("accesskey: stored key cannot be recorded")
		}

		if err := s.keys.Revoke(ctx, k.OwnerID, k.ID, now); err != nil {
			if errors.Is(err, domain.ErrNotFound) {
				// Revoked by its owner, or swept by another instance, between
				// the list and here. Not an error: the row is already in the
				// state this pass wanted to put it in.
				continue
			}
			return retired, fmt.Errorf("accesskey: retire %s: %w", k.ID, err)
		}
		if err := s.emitSystem(ctx, domain.AuditActionAccessKeyRevoked, k.ID, details); err != nil {
			return retired, err
		}
		retired++
	}
	return retired, nil
}

// emitSystem records a credential change no principal requested.
//
// It is separate from emit rather than a parameter on it so that no
// owner-facing call site can reach for the system actor by passing an argument.
// The actor id is empty because there is nobody to name: inventing one — the
// owner, the job's name — would put a principal in the trail that did not act.
func (s *Service) emitSystem(ctx context.Context, action domain.AuditAction, id domain.AccessKeyID, details audit.Details) error {
	return s.auditor.Emit(ctx, audit.Event{
		ActorType:  domain.ActorTypeSystem,
		Action:     action,
		TargetType: domain.TargetTypeAccessKey,
		TargetID:   string(id),
		Details:    details,
	})
}
