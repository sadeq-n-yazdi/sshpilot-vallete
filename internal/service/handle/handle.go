// Package handle implements the lifecycle of an owner's public name: rename,
// quarantine, reclaim, and release (ADR-0026).
//
// # Why a released name is dangerous
//
// A handle is the first path segment of GET /{handle}/{set}, which is the URL
// an AuthorizedKeysCommand polls to decide who may log in. Whoever holds a
// handle serves keys to every server still pointed at it. So a handle that
// changes hands is not a renamed profile — it is a change in who is trusted by
// every consumer that has not been told, and those consumers are scripts on
// other people's machines that nobody will think to update.
//
// That is the whole reason quarantine exists. On rename the old name is held,
// claimable by nobody but its previous owner, for a cooling-off window (default
// 30 days) during which GET /{old-handle} returns 404. Pollers stop updating
// rather than silently start trusting a stranger's keys, and an operator has a
// month to notice.
//
// # Why 404 and not 410
//
// ADR-0026 permits either. This package produces neither directly — the publish
// path already funnels a non-active handle into its uniform ErrNotFound, and
// that is left alone deliberately. 410 would be more informative to a
// well-behaved client and would also confirm to anyone asking that a name once
// existed and is now in its cooling-off window, which is a schedule an attacker
// would use to time a claim. A uniform 404 makes "never existed", "quarantined",
// and "suspended owner" one answer.
//
// The handle namespace is public by construction, so this leak would be a small
// one: it is enumerable by trying names. It is refused anyway because the cost
// of refusing is nothing — no client behaves differently — and "small leak, no
// benefit" is not a trade worth making on the path that decides who logs in.
//
// # Audit is not optional
//
// Rename, reclaim, and release each change who may serve keys at a public
// address. A record that a name moved is what an incident review has to work
// with, so a failure to record fails the operation.
package handle

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/audit"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/nameguard"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/repository"
)

// DefaultQuarantineWindow is how long a freed handle stays reserved when no
// option overrides it. It matches config.Retention.HandleQuarantine's default
// and ADR-0026's resolved 30 days: long enough for cached consumers and
// AuthorizedKeysCommand pollers to stop trusting the old URL before anyone else
// can claim the name.
const DefaultQuarantineWindow = 30 * 24 * time.Hour

// DefaultMaxHeldNames caps how many name-claims one owner may hold at once —
// the active one plus its quarantined tombstones.
//
// Without a cap, rename is a squatting primitive. Each rename parks the name
// just vacated in a 30-day hold that nobody else can claim, so an owner could
// rename in a loop and accumulate an unbounded set of reserved names at no
// cost, holding them against everyone else while only ever publishing under
// one. The cap makes the loop terminate: past the limit a further rename is
// refused until an earlier hold elapses.
const DefaultMaxHeldNames = 5

// ErrNotFound is the uniform negative verdict. It covers an owner with no
// active handle and, deliberately, nothing else: any distinction between
// "missing" and "not yours" is what leaks the existence of another owner's row.
var ErrNotFound = fmt.Errorf("handle: not found: %w", domain.ErrNotFound)

// ErrNameTaken is returned when the requested name is claimed. It does not say
// by whom, nor whether the claim is active or a quarantined hold: the caller
// gets the same refusal for a live handle, another owner's cooling-off name,
// and a name an operator has retired.
var ErrNameTaken = fmt.Errorf("handle: name is not available: %w", domain.ErrConflict)

// ErrTooManyNames is returned when an owner already holds DefaultMaxHeldNames
// claims. See that constant for the squatting case it closes.
var ErrTooManyNames = fmt.Errorf("handle: too many held names: %w", domain.ErrLimitExceeded)

// ErrMissingDependency is returned by New when a required collaborator is
// absent. It is a construction-time programming error: the service fails to
// build rather than nil-panicking on the first request.
var ErrMissingDependency = errors.New("handle: missing dependency")

// Auditor is the audit dependency, declared at the point of use so this package
// depends on a method set rather than a concrete type. *audit.Emitter satisfies
// it.
type Auditor interface {
	Emit(ctx context.Context, ev audit.Event) error
}

// Service implements handle lifecycle management. It is immutable after
// construction and safe for concurrent use if its collaborators are.
type Service struct {
	store      repository.Store
	guard      *nameguard.Guard
	auditor    Auditor
	maxNames   int
	quarantine time.Duration
	now        func() time.Time
	newID      func() string
}

// Option customizes a Service.
type Option func(*Service)

// WithClock overrides the clock used to stamp timestamps and compute quarantine
// deadlines. A clock is behavior a test needs to control, not a security
// control.
func WithClock(now func() time.Time) Option {
	return func(s *Service) {
		if now != nil {
			s.now = now
		}
	}
}

// WithQuarantineWindow overrides how long a freed handle stays reserved. A
// non-positive value is ignored: a zero window would return the name to the
// pool the instant it was vacated, which is exactly the immediate-reclaim
// hijack the quarantine exists to prevent.
func WithQuarantineWindow(d time.Duration) Option {
	return func(s *Service) {
		if d > 0 {
			s.quarantine = d
		}
	}
}

// WithMaxHeldNames overrides the per-owner claim cap. A non-positive value is
// ignored rather than applied: zero would refuse every rename, and a negative
// value would compare as "always under the limit", which is the direction that
// silently removes the control.
func WithMaxHeldNames(n int) Option {
	return func(s *Service) {
		if n > 0 {
			s.maxNames = n
		}
	}
}

// There is deliberately no option overriding the handle ID generator. A handle
// ID is not a secret in the way a token is, but making IDs predictable is the
// kind of seam that only ever helps an attacker, and no test needs it.

// New builds a Service.
//
// All three collaborators are required. The store especially: a rename is a
// quarantine and a claim that must both happen or neither, and a Service
// holding a bare repository could not enforce that. The guard likewise — a
// Service without one would let a renamed handle land on a reserved or
// impersonating name that create would have refused — and the auditor, because
// a Service that looked wired up and moved public names leaving no trace is
// worse than one that will not start.
func New(store repository.Store, guard *nameguard.Guard, auditor Auditor, opts ...Option) (*Service, error) {
	if store == nil {
		return nil, fmt.Errorf("%w: store", ErrMissingDependency)
	}
	if guard == nil {
		return nil, fmt.Errorf("%w: name guard", ErrMissingDependency)
	}
	if auditor == nil {
		return nil, fmt.Errorf("%w: auditor", ErrMissingDependency)
	}
	// A non-nil store is not the same as a usable one. Every method here reaches
	// the handle rows through store.Repos().Handles, so a store assembled with
	// that repository left nil produces a Service that satisfies every check
	// above, starts, and panics on the first rename — a nil dereference in the
	// middle of a quarantine-and-claim, which is precisely the state this
	// package exists to make atomic. Reading it once here turns that into a
	// refusal at construction, which is the promise the doc above already makes.
	if store.Repos().Handles == nil {
		return nil, fmt.Errorf("%w: handle repository", ErrMissingDependency)
	}
	s := &Service{
		store:      store,
		guard:      guard,
		auditor:    auditor,
		maxNames:   DefaultMaxHeldNames,
		quarantine: DefaultQuarantineWindow,
		now:        time.Now,
		newID:      newHandleID,
	}
	for i, opt := range opts {
		// A nil option is rejected rather than skipped: skipping it would leave
		// a Service that looks configured and is not.
		if opt == nil {
			return nil, fmt.Errorf("%w: nil option at index %d", ErrMissingDependency, i)
		}
		opt(s)
	}
	return s, nil
}

// newHandleID returns a fresh, unguessable handle ID. crypto/rand.Text yields
// 26 base32 characters (~130 bits), matching the identifier convention used for
// key sets, devices, keys, and audit records.
func newHandleID() string {
	return rand.Text()
}

// Rename moves the owner's public name to name.
//
// The old name is NOT returned to the pool. It becomes a quarantined
// name-claim, held for the configured window, during which no other owner may
// take it and GET /{old-name} 404s. Only when that hold elapses does the name
// become claimable again.
//
// If name is one of the caller's OWN quarantined holds the call reclaims it —
// the same owner taking back a name they vacated hands nothing to anyone, so
// there is nobody for the quarantine to protect. A hold belonging to any other
// owner is refused with the same ErrNameTaken as a live handle, so a caller
// cannot learn whether a name is free later or never.
//
// The whole thing runs in ONE transaction. Quarantining the old claim and
// establishing the new one are not independently valid states: between them the
// owner has no active handle, or two, and the second is refused outright by
// ux_handles_owner_active. Committing either half alone would leave an owner
// unreachable or ambiguous.
func (s *Service) Rename(ctx context.Context, ownerID domain.OwnerID, name, requestID string) (*domain.Handle, error) {
	if ownerID == "" {
		return nil, fmt.Errorf("handle: missing owner: %w", domain.ErrInvalidInput)
	}
	// OpRename, not OpCreate. The verdict is identical by design — a name
	// blocked at create must be blocked at rename, or registering a permitted
	// name and renaming afterwards would be a bypass — but stating the op is
	// what makes a rename path that skipped the guard visible by its absence.
	if err := s.guard.Check(nameguard.KindHandle, nameguard.OpRename, name); err != nil {
		return nil, err
	}

	var (
		details   audit.Details
		action    = domain.AuditActionHandleRenamed
		result    *domain.Handle
		now       = s.now().UTC()
		untilTime = s.now().UTC().Add(s.quarantine)
	)
	if err := s.store.WithTx(ctx, func(ctx context.Context, r repository.Repos) error {
		// The owner-scoped read establishes that this caller has a handle to
		// rename at all. Everything below is reached only after it matched a row
		// of the caller's own.
		old, err := r.Handles.GetActiveByOwner(ctx, ownerID)
		if err != nil {
			return err
		}
		if old == nil {
			// The port says a nil error carries a row, and no adapter here
			// breaks that. If one ever did, the two readings of the violation
			// are dereference-and-panic and refuse; only the second is safe.
			// ErrNotFound is the same verdict a genuinely absent active handle
			// gets, so the caller cannot tell the two apart.
			return ErrNotFound
		}
		if old.Name == name {
			// Renaming to the name already held is refused rather than treated
			// as a no-op. Succeeding would emit an audit record for a move that
			// did not happen, and quarantining a name onto itself is not a
			// state this model has.
			return ErrNameTaken
		}

		held, err := r.Handles.ListByOwner(ctx, ownerID)
		if err != nil {
			return err
		}
		// The cap counts claims, so it may only refuse a rename that ADDS one.
		// Taking back one of the owner's own quarantined holds does not: that
		// row is already in held, already counted, and claim below reactivates
		// it in place rather than registering a second one. Applying the cap to
		// it would strand an owner at the limit, unable to return to a name they
		// demonstrably still hold and unable to free a slot either, since only
		// the elapsed-quarantine sweep releases a hold. The squatting loop the
		// cap exists to stop is untouched: cycling through NEW names still adds
		// a claim every time and still hits the limit.
		//
		// This decides whether the cap APPLIES. It is not the reclaim
		// authorization — that stays in claim, which re-reads the row by name
		// and refuses anything that is not the caller's own quarantined hold.
		// held is owner-scoped by ListByOwner's contract, so another owner's
		// quarantined name cannot reach this branch; if one ever did, all it
		// would buy is a cap exemption for a rename claim then refuses anyway.
		if !reclaims(held, name) && len(held) >= s.maxNames {
			return ErrTooManyNames
		}

		// Details are built after the read that supplies the old name and
		// before the first write, so a value the audit screen refuses aborts
		// the transaction rather than leaving a committed rename unrecorded.
		if details, err = renameDetails(old.Name, name, requestID); err != nil {
			return err
		}

		// The old claim becomes the tombstone FIRST. ux_handles_owner_active
		// permits one active claim per owner, so the new one cannot be
		// established until this one steps aside; doing it in this order means
		// the index is a backstop rather than an obstacle.
		old.State = domain.NameStateQuarantined
		old.QuarantineUntil = &untilTime
		old.UpdatedAt = now
		if err := r.Handles.Update(ctx, old); err != nil {
			return err
		}

		claimed, reclaim, err := s.claim(ctx, r, ownerID, name, now)
		if err != nil {
			return err
		}
		if reclaim {
			action = domain.AuditActionHandleReclaimed
		}
		result = claimed
		return nil
	}); err != nil {
		return nil, mapErr(err)
	}

	if err := s.emit(ctx, action, ownerID, result.ID, details); err != nil {
		return nil, err
	}
	return result, nil
}

// reclaims reports whether name is one of the owner's own quarantined holds, so
// a rename onto it reactivates a claim that is already counted rather than
// adding one.
//
// held MUST be owner-scoped; every caller passes ListByOwner's result, whose
// contract is exactly that. Passing an unscoped list would let one owner's hold
// excuse another owner's rename from the cap.
//
// Retired rows deliberately do not match. A retired name is one an operator
// withdrew, and reclaiming it is refused outright a few lines further on; the
// cap has no business being the thing that reports it.
func reclaims(held []domain.Handle, name string) bool {
	for i := range held {
		if held[i].Name == name && held[i].State == domain.NameStateQuarantined {
			return true
		}
	}
	return false
}

// claim establishes name as the owner's active handle, either by reactivating
// one of their own quarantined holds or by registering a fresh claim. It
// reports which of the two happened so the caller can record the right action.
//
// The distinction is not cosmetic. Reclaiming is the one case where a name
// leaves quarantine early, and an incident review reading "renamed" where the
// truth was "took back a name that was still in its hold" would be missing the
// fact it most needs.
func (s *Service) claim(
	ctx context.Context,
	r repository.Repos,
	ownerID domain.OwnerID,
	name string,
	now time.Time,
) (*domain.Handle, bool, error) {
	existing, err := r.Handles.GetByName(ctx, name)
	switch {
	case err == nil:
		// A claim exists. The ONLY one the caller may take over is their own,
		// still-quarantined hold. A live handle, another owner's hold, and a
		// retired name all refuse with the same error, so the caller learns
		// only "not available" and never whose it is or when it frees up.
		//
		// The nil test leads because this is the reclaim gate: it is the check
		// that decides who may take a quarantined name. A row that arrived
		// with a nil error against the port's contract must refuse here, not
		// panic — and refusing is also the conservative reading, since a claim
		// the service cannot inspect is one it cannot establish belongs to the
		// caller.
		if existing == nil || existing.OwnerID != ownerID || existing.State != domain.NameStateQuarantined {
			return nil, false, ErrNameTaken
		}
		existing.State = domain.NameStateActive
		existing.QuarantineUntil = nil
		existing.UpdatedAt = now
		if err := r.Handles.Update(ctx, existing); err != nil {
			return nil, false, err
		}
		return existing, true, nil

	case errors.Is(err, domain.ErrNotFound):
		// Unclaimed: register a fresh name-claim. Register is the only writer of
		// the fold, and the unique indexes behind it are what make this safe
		// against a concurrent claimant rather than the read above, which is
		// only an early and friendlier refusal.
		fresh := &domain.Handle{
			ID:        domain.HandleID(s.newID()),
			OwnerID:   ownerID,
			Name:      name,
			State:     domain.NameStateActive,
			CreatedAt: now,
			UpdatedAt: now,
		}
		if err := r.Handles.Register(ctx, fresh); err != nil {
			return nil, false, err
		}
		return fresh, false, nil

	default:
		return nil, false, err
	}
}

// ReleaseExpired ends the quarantines that have elapsed, returning those names
// to the pool, and reports how many it released.
//
// Each release is a separate call rather than one bulk delete because each one
// is separately audited: the moment a name becomes claimable by a stranger is
// the moment an incident review needs to be able to place in time.
//
// The record is written after the delete, not with it, so an emitter failure
// leaves a name already released and no audit line saying so. That ordering is
// deliberate and matches the rest of the services here: emitting first would
// risk the opposite failure, a record asserting a release that never happened,
// and a missing record is the safer of the two to reconcile against the row
// that is demonstrably gone. The sweep stops on that failure rather than
// continuing, so the gap is bounded to a single name.
//
// The repository re-checks the state and the deadline inside the DELETE, so a
// hold the owner reclaimed between this sweep's read and its write is not
// deleted out from under them; that row simply reports ErrNotFound and the
// sweep moves on.
func (s *Service) ReleaseExpired(ctx context.Context, limit int) (int, error) {
	now := s.now().UTC()

	expired, err := s.store.Repos().Handles.ListExpiredQuarantine(ctx, now, limit)
	if err != nil {
		return 0, fmt.Errorf("handle: list expired quarantine: %w", err)
	}

	released := 0
	for i := range expired {
		h := expired[i]

		// Details are built before the delete so a value the audit screen
		// refuses stops this release rather than freeing a name with no record
		// that it was freed.
		details, err := handleDetails(h.Name, "")
		if err != nil {
			return released, err
		}

		if err := s.store.Repos().Handles.Release(ctx, h.ID, now); err != nil {
			if errors.Is(err, domain.ErrNotFound) {
				// Reclaimed, retired, or already swept between the list and
				// here. Not an error: the row is exactly where it should be.
				continue
			}
			return released, fmt.Errorf("handle: release %s: %w", h.ID, err)
		}
		if err := s.emit(ctx, domain.AuditActionHandleReleased, h.OwnerID, h.ID, details); err != nil {
			return released, err
		}
		released++
	}
	return released, nil
}

// mapErr collapses the storage layer's verdicts into this package's.
//
// domain.ErrConflict from any of the three unique indexes becomes ErrNameTaken:
// which index refused is a fact about who else holds what, and the caller has
// no business learning it. domain.ErrNotFound becomes the package's uniform
// ErrNotFound.
func mapErr(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, domain.ErrConflict):
		return ErrNameTaken
	case errors.Is(err, domain.ErrNotFound):
		return ErrNotFound
	default:
		return err
	}
}

// emit records an audited handle transition.
func (s *Service) emit(
	ctx context.Context,
	action domain.AuditAction,
	ownerID domain.OwnerID,
	id domain.HandleID,
	details audit.Details,
) error {
	return s.auditor.Emit(ctx, audit.Event{
		ActorType:  domain.ActorTypeOwner,
		ActorID:    string(ownerID),
		Action:     action,
		TargetType: domain.TargetTypeHandle,
		TargetID:   string(id),
		Details:    details,
	})
}

// handleDetails builds the audit details for a handle change.
//
// The name is the one fact that makes the record readable in an incident
// review — it is the public address whose keys moved — and it is not a secret:
// it is the first path segment of every request that resolves the handle.
func handleDetails(name, requestID string) (audit.Details, error) {
	d := audit.Details{}.Set(audit.DetailHandle, name)
	if requestID != "" {
		d = d.Set(audit.DetailRequestID, requestID)
	}
	if err := d.Err(); err != nil {
		// The rejected value is not quoted back. This error is destined for a
		// log and has no reason to carry content it does not need.
		return audit.Details{}, fmt.Errorf("handle: name cannot be recorded: %w", domain.ErrInvalidInput)
	}
	return d, nil
}

// renameDetails builds the audit details for a rename, recording the
// before/after pair. Both are public names, so neither is a secret, and a
// record naming only the destination would leave an incident review unable to
// tell which address stopped resolving — which is the address whose consumers
// are now failing closed and need to be told.
func renameDetails(from, to, requestID string) (audit.Details, error) {
	d, err := handleDetails(to, requestID)
	if err != nil {
		return audit.Details{}, err
	}
	d = d.Set(audit.DetailFrom, from).Set(audit.DetailTo, to)
	if err := d.Err(); err != nil {
		return audit.Details{}, fmt.Errorf("handle: name cannot be recorded: %w", domain.ErrInvalidInput)
	}
	return d, nil
}
