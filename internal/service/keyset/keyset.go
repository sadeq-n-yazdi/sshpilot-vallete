// Package keyset is the owner-facing key set management service: create, list,
// rename, and delete named key sets, designate which one is the default, and
// move a set between public and protected (ADR-0016).
//
// # The owner is a parameter, never a lookup
//
// Every exported method takes a domain.OwnerID as its first meaningful argument
// and passes it straight through to the owner-scoped repository ports. The
// service never derives an owner from anything it was given about the request.
// The transport obtains the owner from the verified token
// (auth.Authorization.Owner) and hands it in, so the boundary is established
// before this package's first line runs (ADR-0004).
//
// # One negative verdict
//
// Every reason a set cannot be addressed collapses into ErrNotFound: the id is
// unknown, it belongs to another owner, or it names a quarantined tombstone
// rather than a live set. A caller holding a valid token for owner B must not
// be able to tell owner A's set id apart from a string it invented, so a rename
// or a delete aimed at a stranger's set is byte-identical to one aimed at an id
// that never existed.
//
// The three conflict verdicts below are deliberately NOT collapsed, and the
// difference is safe: each reports only on the caller's OWN account, whose
// contents the caller can already enumerate with List. None of them can be
// provoked for another owner's data — every one is reached only after an
// owner-scoped read or write has already matched a row of the caller's own.
//
// # Names are validated by the guard, not here
//
// Every user-chosen set name goes through nameguard, which runs
// domain.ValidateSetName and then the reserved-identifier blocklist (ADR-0017).
// There is deliberately no second syntax check next to it: a second place that
// decides a name is valid is a second place that can be made to disagree with
// the first. A nil Guard refuses every name, so a Service built without one
// creates nothing rather than creating unchecked names.
//
// # Audit is not optional
//
// Every exported mutation changes what a published set resolves to, or who may
// resolve it, so each emits an audit record (ADR-0007). A failure to record is
// returned to the caller rather than swallowed.
//
// SetVisibility records BOTH directions. protected→public exposes the
// handle→keys association the owner had chosen to restrict, and public→protected
// breaks consumers still polling the URL; neither is the harmless one, so there
// is no direction this package records more quietly than the other.
package keyset

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

// DefaultMaxSets is the per-owner cap applied when no option overrides it. It
// matches config.Retention.MaxSetsPerOwner's default (ADR-0016: configurable,
// default 100); production wiring passes the configured value through
// WithMaxSets rather than relying on this constant.
const DefaultMaxSets = 100

// DefaultQuarantineWindow is how long a freed set name stays reserved when no
// option overrides it. It matches config.Retention.HandleQuarantine's default,
// because ADR-0016 aligns set-name quarantine with the handle lifecycle
// (ADR-0026).
const DefaultQuarantineWindow = 30 * 24 * time.Hour

// ErrNotFound is the single negative verdict for addressing a key set: unknown
// id, another owner's id, or a quarantined tombstone. See the package doc.
//
// It wraps domain.ErrNotFound so callers that already branch on the domain
// sentinel keep working, and so the transport can map one error to one status.
var ErrNotFound = fmt.Errorf("keyset: not found: %w", domain.ErrNotFound)

// ErrDuplicate is returned when the owner already holds a set with the same
// name, INCLUDING a quarantined tombstone left behind by a rename or a delete.
// A freed name stays reserved for the quarantine window so re-creating it
// cannot silently serve different keys to consumers still polling the old
// /{handle}/{set} URL (ADR-0016).
var ErrDuplicate = fmt.Errorf("keyset: name already in use: %w", domain.ErrConflict)

// ErrLimitExceeded is returned when the owner is at the per-owner cap.
//
// The count includes quarantined tombstones, per the KeySetRepository contract:
// a reserved name still occupies the owner's namespace, and excluding
// tombstones would let an owner hold unboundedly many reserved names by
// renaming in a loop.
var ErrLimitExceeded = fmt.Errorf("keyset: key set limit reached: %w", domain.ErrLimitExceeded)

// ErrDefaultSet is returned when a delete targets the owner's designated
// default set. The default cannot be deleted by any path, so that bare
// GET /{handle} never dangles; the owner must designate another default first.
var ErrDefaultSet = fmt.Errorf("keyset: the default key set cannot be deleted: %w", domain.ErrDefaultKeySet)

// ErrConfirmationRequired is returned when a delete targets a NON-EMPTY set
// without explicit confirmation (ADR-0016). It fails closed: confirmation is a
// value the caller must positively supply, and anything short of that — absent,
// false, or a body that will not decode — refuses.
var ErrConfirmationRequired = fmt.Errorf("keyset: deleting a non-empty key set requires confirmation: %w", domain.ErrConflict)

// ErrMissingDependency is returned by New when a required collaborator is
// absent. It is a construction-time programming error: the service fails to
// build rather than nil-panicking on the first request.
var ErrMissingDependency = errors.New("keyset: missing dependency")

// Auditor is the audit dependency, declared at the point of use so this package
// depends on a method set rather than a concrete type. *audit.Emitter satisfies
// it.
type Auditor interface {
	Emit(ctx context.Context, ev audit.Event) error
}

// Service implements key set management. It is immutable after construction and
// safe for concurrent use if its collaborators are.
type Service struct {
	store      repository.Store
	guard      *nameguard.Guard
	auditor    Auditor
	maxSets    int
	quarantine time.Duration
	now        func() time.Time
	newID      func() string
}

// Option customizes a Service.
type Option func(*Service)

// WithClock overrides the clock used to stamp timestamps. A clock is behavior a
// test needs to control, not a security control.
func WithClock(now func() time.Time) Option {
	return func(s *Service) {
		if now != nil {
			s.now = now
		}
	}
}

// WithMaxSets overrides the per-owner cap. A non-positive value is ignored
// rather than applied: a cap of zero would refuse every create, and a negative
// one would be compared as "always under the limit", which is the direction
// that silently removes the control.
func WithMaxSets(n int) Option {
	return func(s *Service) {
		if n > 0 {
			s.maxSets = n
		}
	}
}

// WithQuarantineWindow overrides how long a freed set name stays reserved. A
// non-positive value is ignored: a zero window would free the name immediately,
// which is precisely the re-registration race the quarantine exists to close.
func WithQuarantineWindow(d time.Duration) Option {
	return func(s *Service) {
		if d > 0 {
			s.quarantine = d
		}
	}
}

// There is deliberately no option overriding the key set ID generator, matching
// the device and public key services. A set ID is how a rename or delete names
// its target, so a seam that let any caller make IDs predictable would make the
// cross-owner 404 pointless — an attacker would not need to guess.

// New builds a Service.
//
// All three collaborators are required. The store especially: the cap check and
// the rename composition are multi-statement invariants that are only sound
// inside one transaction, so a Service holding a bare repository could not
// enforce them at all. The guard likewise — a Service without one would create
// names no blocklist ever saw — and the auditor, because a Service that looked
// wired up and renamed sets leaving no trace is worse than one that will not
// start.
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
	// A non-nil Store can still hand out a Repos with the one field this
	// service uses left nil, and every method here dereferences it. Checking at
	// construction turns that wiring bug into a startup failure instead of a
	// panic on the first request that names a key set. The auto-commit Repos is
	// checked as a proxy for the transaction-bound one WithTx passes, which is
	// where most of this service's dereferences happen: both stores build the
	// two by calling one reposFor(execer) over the db handle and the tx handle
	// respectively, so a field non-nil in one is non-nil in the other.
	if store.Repos().KeySets == nil {
		return nil, fmt.Errorf("%w: key set repository", ErrMissingDependency)
	}
	s := &Service{
		store:      store,
		guard:      guard,
		auditor:    auditor,
		maxSets:    DefaultMaxSets,
		quarantine: DefaultQuarantineWindow,
		now:        time.Now,
		newID:      newSetID,
	}
	for i, opt := range opts {
		// A nil option is rejected rather than skipped, matching the device and
		// public key services: skipping it would leave a Service that looks
		// configured and is not.
		if opt == nil {
			return nil, fmt.Errorf("%w: nil option at index %d", ErrMissingDependency, i)
		}
		opt(s)
	}
	return s, nil
}

// newSetID returns a fresh, unguessable key set ID. crypto/rand.Text yields 26
// base32 characters (~130 bits), matching the identifier convention used for
// devices, keys, audit records, and request IDs.
func newSetID() string {
	return rand.Text()
}

// Create makes a new, empty key set for the owner.
//
// The new set is never the default and is always created protected: a set that
// arrived public by default would publish the moment its first key was added,
// which is a visibility decision the owner has not made. Designating a default
// and changing visibility are separate operations (C4) and deliberately cannot
// be smuggled in through this call — there is no request field for either.
//
// The cap check and the insert run inside ONE transaction. A check-then-insert
// split across two auto-committing calls is raceable by construction: two
// concurrent creates can both read 99 and both insert, landing the owner at
// 101. Inside a single WithTx the pair is serialized against other writers
// (SQLite takes a BEGIN IMMEDIATE write lock; see the Store contract), so no
// interleaving observes a stale count.
func (s *Service) Create(ctx context.Context, ownerID domain.OwnerID, name, requestID string) (*domain.KeySet, error) {
	if ownerID == "" {
		// An empty owner would produce a set belonging to nobody, reachable by
		// any other request that also failed to carry an owner. Refusing here
		// means the write is never attempted.
		return nil, fmt.Errorf("keyset: missing owner: %w", domain.ErrInvalidInput)
	}
	// The guard subsumes domain.ValidateSetName and then consults the
	// reserved-identifier blocklist. It runs before the transaction opens, so a
	// refused name costs no write lock and never reaches storage.
	if err := s.guard.Check(nameguard.KindKeySetName, nameguard.OpCreate, name); err != nil {
		return nil, err
	}

	details, err := setDetails(name, requestID)
	if err != nil {
		return nil, err
	}

	now := s.now().UTC()
	set := &domain.KeySet{
		ID:         domain.KeySetID(s.newID()),
		OwnerID:    ownerID,
		Name:       name,
		Visibility: domain.VisibilityProtected,
		IsDefault:  false,
		State:      domain.NameStateActive,
		CreatedAt:  now,
		UpdatedAt:  now,
	}
	if err := s.store.WithTx(ctx, func(ctx context.Context, r repository.Repos) error {
		return s.createLocked(ctx, r, ownerID, set)
	}); err != nil {
		return nil, err
	}

	if err := s.emit(ctx, domain.AuditActionKeySetCreated, ownerID, set.ID, details); err != nil {
		return nil, err
	}
	return set, nil
}

// createLocked enforces the cap and inserts, inside a caller-supplied
// transaction. It is shared by Create and Rename so the cap cannot be enforced
// on one path and forgotten on the other.
func (s *Service) createLocked(ctx context.Context, r repository.Repos, ownerID domain.OwnerID, set *domain.KeySet) error {
	n, err := r.KeySets.CountByOwner(ctx, ownerID)
	if err != nil {
		return err
	}
	if n >= s.maxSets {
		return ErrLimitExceeded
	}
	if err := r.KeySets.Create(ctx, set); err != nil {
		if errors.Is(err, domain.ErrConflict) {
			return ErrDuplicate
		}
		return err
	}
	return nil
}

// List returns the owner's live key sets.
//
// Quarantined tombstones are filtered out: they are freed names being held in
// reserve, not sets an owner can publish, add keys to, or address. This is not
// an owner-scoping filter — owner scoping is done in-query by the repository,
// and no other owner's row can appear here at all.
//
// An owner with no live sets gets a nil slice, per the repository's
// nil-collection convention. The transport, not this package, decides what nil
// looks like on the wire.
func (s *Service) List(ctx context.Context, ownerID domain.OwnerID) ([]domain.KeySet, error) {
	if ownerID == "" {
		return nil, fmt.Errorf("keyset: missing owner: %w", domain.ErrInvalidInput)
	}
	all, err := s.store.Repos().KeySets.ListByOwner(ctx, ownerID)
	if err != nil {
		return nil, err
	}
	var live []domain.KeySet
	for _, set := range all {
		if set.State == domain.NameStateActive {
			live = append(live, set)
		}
	}
	return live, nil
}

// Rename moves one of the owner's sets onto a different name.
//
// # Why the identifier changes
//
// The KeySetRepository has no Rename method and its Update deliberately does
// not touch Name: a key_sets row's name is immutable, and renaming is a
// service-layer composition. So a rename is a new row under the new name, with
// the old row kept as a quarantined tombstone that holds the freed name in
// reserve (ADR-0016, aligned with the handle lifecycle in ADR-0026). The set's
// membership moves to the new row; the returned set therefore carries a NEW id,
// and a client holding the old one must re-read it.
//
// The whole composition runs in ONE transaction. A partial rename is the state
// that must not be reachable: a new row with no members, or an old row freed
// with no successor, would each be a published set silently serving the wrong
// keys.
//
// # The default is carried, never orphaned
//
// If the renamed set was the owner's default, the new row is made the default
// in the same transaction. Quarantining the old default without transferring
// the designation would leave bare GET /{handle} resolving to a non-active set
// — the dangle ADR-0016's deletion rule exists to prevent, reached through
// rename instead of delete.
func (s *Service) Rename(ctx context.Context, ownerID domain.OwnerID, id domain.KeySetID, name, requestID string) (*domain.KeySet, error) {
	if ownerID == "" {
		return nil, fmt.Errorf("keyset: missing owner: %w", domain.ErrInvalidInput)
	}
	if id == "" {
		// An empty id names no set. It collapses into the same verdict as a
		// wrong one so a caller cannot learn which shapes are well formed.
		return nil, ErrNotFound
	}
	// OpRename, not OpCreate. The verdict is identical by design — a name
	// blocked at create must be blocked at rename, or creating a permitted name
	// and renaming afterwards would be a bypass — but stating the op is what
	// makes a rename path that skipped the guard visible by its absence.
	if err := s.guard.Check(nameguard.KindKeySetName, nameguard.OpRename, name); err != nil {
		return nil, err
	}

	var details audit.Details
	now := s.now().UTC()
	renamed := &domain.KeySet{
		ID:        domain.KeySetID(s.newID()),
		OwnerID:   ownerID,
		Name:      name,
		State:     domain.NameStateActive,
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := s.store.WithTx(ctx, func(ctx context.Context, r repository.Repos) error {
		// The owner-scoped read is what establishes that this caller may act on
		// this set at all. Everything below is reached only after it matched a
		// row of the caller's own, so no verdict past this point can report on
		// another owner's data.
		old, err := live(r.KeySets.Get(ctx, ownerID, id))
		if err != nil {
			return err
		}

		// The details are built here: after the read that supplies the old name,
		// and before the first write. A detail the audit screen refuses then
		// aborts the transaction rather than leaving a committed rename with no
		// record of what it moved.
		if details, err = renameDetails(old.Name, name, requestID); err != nil {
			return err
		}

		// Visibility carries over. A rename must not quietly widen or narrow who
		// can resolve the set; that is C4's decision, made through its own
		// endpoint. IsDefault is NOT carried in the struct — the partial unique
		// index allows one default per owner and the old row still holds it, so
		// the designation is moved below with SetDefault, which clears and sets
		// atomically.
		renamed.Visibility = old.Visibility
		if err := s.createLocked(ctx, r, ownerID, renamed); err != nil {
			return err
		}

		members, err := r.KeySets.ListMembers(ctx, ownerID, id)
		if err != nil {
			return err
		}
		for _, m := range members {
			if err := r.KeySets.AddMember(ctx, ownerID, renamed.ID, m.PublicKeyID, now); err != nil {
				return err
			}
		}

		// The old row becomes the tombstone. Its name stays claimed until the
		// quarantine expires, so re-creating it in the meantime returns
		// ErrDuplicate rather than serving a different key list at a URL
		// consumers are still polling.
		until := now.Add(s.quarantine)
		old.State = domain.NameStateQuarantined
		old.QuarantineUntil = &until
		old.UpdatedAt = now
		if err := r.KeySets.Update(ctx, old); err != nil {
			return err
		}

		if old.IsDefault {
			if err := r.KeySets.SetDefault(ctx, ownerID, renamed.ID); err != nil {
				return err
			}
			// The struct is corrected to match what was persisted, so the value
			// returned to the caller is the row that now exists rather than the
			// one that was inserted a few statements ago.
			renamed.IsDefault = true
		}
		return nil
	}); err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}

	if err := s.emit(ctx, domain.AuditActionKeySetRenamed, ownerID, renamed.ID, details); err != nil {
		return nil, err
	}
	return renamed, nil
}

// Delete removes one of the owner's key sets and its membership rows, never the
// underlying public keys (they may belong to other sets and to their device).
//
// confirm must be true to delete a set that still has members (ADR-0016). It
// fails closed: the caller must positively supply the confirmation, and the
// transport refuses a body it cannot decode rather than defaulting the flag.
//
// The two refusals below are both reached only AFTER an owner-scoped read has
// matched a row of the caller's own, which is what keeps them from becoming an
// existence oracle: a stranger's set id never reaches either, because the read
// that precedes them returns ErrNotFound first.
//
// The default-set guard is the repository's, not a pre-read here. Its Delete
// checks is_default through an owner-scoped SELECT inside its own transaction,
// so another owner's default reports ErrNotFound exactly as a missing row does.
// Reading the set here and branching on IsDefault in Go would reintroduce the
// distinction the collapse exists to remove.
func (s *Service) Delete(ctx context.Context, ownerID domain.OwnerID, id domain.KeySetID, confirm bool, requestID string) error {
	if ownerID == "" {
		return fmt.Errorf("keyset: missing owner: %w", domain.ErrInvalidInput)
	}
	if id == "" {
		return ErrNotFound
	}

	var name string
	if err := s.store.WithTx(ctx, func(ctx context.Context, r repository.Repos) error {
		set, err := live(r.KeySets.Get(ctx, ownerID, id))
		if err != nil {
			return err
		}
		name = set.Name

		// ListMembers is owner-scoped through its join, so a stranger's set
		// would have produced ErrNotFound above and never reach this count.
		members, err := r.KeySets.ListMembers(ctx, ownerID, id)
		if err != nil {
			return err
		}
		if len(members) > 0 && !confirm {
			return ErrConfirmationRequired
		}

		if err := r.KeySets.Delete(ctx, ownerID, id); err != nil {
			if errors.Is(err, domain.ErrDefaultKeySet) {
				return ErrDefaultSet
			}
			return err
		}
		return nil
	}); err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return ErrNotFound
		}
		return err
	}

	details, err := setDetails(name, requestID)
	if err != nil {
		// The name was stored earlier rather than supplied by this caller, so a
		// refusal here is not the caller's fault and is not reported as invalid
		// input: it is a server fault the caller cannot fix.
		return errors.New("keyset: deleted set cannot be recorded")
	}
	return s.emit(ctx, domain.AuditActionKeySetDeleted, ownerID, id, details)
}

// SetDefault designates one of the owner's sets as the default — the set bare
// GET /{handle} resolves to (ADR-0016).
//
// # Exactly one default, enforced by the schema
//
// The service does NOT clear the previous default itself. The repository's
// SetDefault clears and sets inside one transaction, in that order, because the
// schema carries a partial unique index on (owner_id) WHERE is_default = 1: a
// set-before-clear would trip the index, and a clear that committed without its
// set would leave the owner with no default at all. Two defaults make bare
// GET /{handle} non-deterministic and zero make it dangle, so both failures are
// removed at the storage layer rather than re-implemented here — a second place
// that moves the designation is a second place that can be made to disagree
// with the index.
//
// # Why the live read still has to happen here
//
// The repository's SetDefault is scoped by id AND owner_id but carries no state
// predicate, so on its own it would happily designate a quarantined tombstone.
// A tombstone is a reserved name, not an addressable set; making one the
// default would point bare GET /{handle} at a row that no longer publishes
// anything. The live() read below is the only thing that refuses it, and it
// runs inside the same transaction as the write so a rename cannot quarantine
// the row in between.
//
// Designating a new default is also what frees the previous one for deletion:
// Delete refuses the default set, and the refusal follows the designation.
func (s *Service) SetDefault(ctx context.Context, ownerID domain.OwnerID, id domain.KeySetID, requestID string) (*domain.KeySet, error) {
	if ownerID == "" {
		return nil, fmt.Errorf("keyset: missing owner: %w", domain.ErrInvalidInput)
	}
	if id == "" {
		// An empty id names no set, and collapses into the verdict a wrong one
		// gets so a caller cannot learn which shapes are well formed.
		return nil, ErrNotFound
	}

	var (
		set     *domain.KeySet
		details audit.Details
	)
	now := s.now().UTC()
	if err := s.store.WithTx(ctx, func(ctx context.Context, r repository.Repos) error {
		// The owner-scoped read establishes that this caller may act on this set
		// at all. Everything below is reached only after it matched a row of the
		// caller's own.
		target, err := live(r.KeySets.Get(ctx, ownerID, id))
		if err != nil {
			return err
		}

		// The outgoing default is read for the audit record, not for a decision:
		// nothing below branches on it, and an owner with no default yet is not
		// an error. It is read inside the transaction so the recorded "from" is
		// the designation this call actually replaced.
		previous, err := r.KeySets.GetDefault(ctx, ownerID)
		if err != nil && !errors.Is(err, domain.ErrNotFound) {
			return err
		}
		from := ""
		if previous != nil {
			from = previous.Name
		}
		// The details are built before the write, so a value the audit screen
		// refuses aborts the transaction rather than leaving a committed
		// designation with no record of what it moved.
		if details, err = defaultDetails(from, target.Name, requestID); err != nil {
			return err
		}

		if err := r.KeySets.SetDefault(ctx, ownerID, id); err != nil {
			return err
		}
		// The struct is corrected to match what was persisted, so the value
		// returned is the row that now exists rather than the one just read.
		target.IsDefault = true
		target.UpdatedAt = now
		set = target
		return nil
	}); err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}

	if err := s.emit(ctx, domain.AuditActionKeySetDefaultChanged, ownerID, id, details); err != nil {
		return nil, err
	}
	return set, nil
}

// SetVisibility moves one of the owner's sets between public and protected
// (ADR-0010, refined per key set by ADR-0016; publish semantics in ADR-0019).
//
// Both directions are access-affecting and both are audited. protected→public
// exposes the handle→keys association the owner had chosen to restrict;
// public→protected breaks consumers still polling the URL. Neither is the
// harmless direction, so neither is recorded more quietly than the other.
//
// An unknown visibility is refused rather than persisted. The check fails
// closed in the same shape Delete's confirmation does: the caller must
// positively supply one of the two known values, and the zero value — what an
// absent or malformed field decodes to — is not one of them, so a request that
// failed to say what it wanted changes nothing.
//
// As in SetDefault, the live() read is what keeps a quarantined tombstone
// unaddressable: the repository's Update is owner-scoped but has no state
// predicate, so it would rewrite a tombstone's visibility. A reserved name has
// no visibility worth changing — nothing resolves through it.
func (s *Service) SetVisibility(ctx context.Context, ownerID domain.OwnerID, id domain.KeySetID, v domain.Visibility, requestID string) (*domain.KeySet, error) {
	if ownerID == "" {
		return nil, fmt.Errorf("keyset: missing owner: %w", domain.ErrInvalidInput)
	}
	if id == "" {
		return nil, ErrNotFound
	}
	// Validated before the transaction opens, so a refused value costs no write
	// lock and never reaches storage.
	if !v.IsValid() {
		// The rejected value is not quoted back; this error is destined for a
		// log and carries no content it does not need.
		return nil, fmt.Errorf("keyset: unknown visibility: %w", domain.ErrInvalidInput)
	}

	var (
		set     *domain.KeySet
		details audit.Details
	)
	now := s.now().UTC()
	if err := s.store.WithTx(ctx, func(ctx context.Context, r repository.Repos) error {
		target, err := live(r.KeySets.Get(ctx, ownerID, id))
		if err != nil {
			return err
		}
		if details, err = visibilityDetails(target.Visibility, v, target.Name, requestID); err != nil {
			return err
		}

		// A no-op change is written and recorded like any other. Refusing it
		// would answer "you already had that value", which is a fact about the
		// set's state reported through a path whose only other answer is the
		// collapsed 404 — and an owner re-asserting a visibility is entitled to
		// see it recorded as asserted.
		target.Visibility = v
		target.UpdatedAt = now
		if err := r.KeySets.Update(ctx, target); err != nil {
			return err
		}
		set = target
		return nil
	}); err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}

	if err := s.emit(ctx, domain.AuditActionKeySetVisibilityChanged, ownerID, id, details); err != nil {
		return nil, err
	}
	return set, nil
}

// live folds a quarantined tombstone into the same ErrNotFound a missing row
// gets. A tombstone is a reserved name, not an addressable set: answering
// distinctly would make an owner's rename history observable as a third answer,
// and would let a rename or delete act on a row that is no longer a set.
func live(set *domain.KeySet, err error) (*domain.KeySet, error) {
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if set == nil {
		// A nil row with a nil error violates the port contract, so this is
		// unreachable through any adapter in the tree. It is kept because the
		// alternative reading of a contract violation on an owner-scoped path
		// is "dereference and panic", and the safe one is "denied" -- the same
		// choice Authenticator.resolve makes for a nil linked identity.
		//
		// Every caller of live() is deciding whether an owner may act on a set,
		// so a panic here is reachable from a request and would take the
		// process down rather than refuse one call.
		return nil, ErrNotFound
	}
	if set.State != domain.NameStateActive {
		return nil, ErrNotFound
	}
	return set, nil
}

// setDetails builds the audit details for a key set change.
//
// The set name is the one fact that makes a record readable in an incident
// review — it is the published address of the set — and it is not a secret: it
// appears in the URL of every request that resolves the set.
func setDetails(name, requestID string) (audit.Details, error) {
	d := audit.Details{}.Set(audit.DetailKeySetName, name)
	if requestID != "" {
		d = d.Set(audit.DetailRequestID, requestID)
	}
	if err := d.Err(); err != nil {
		// The rejected value is not quoted back. This error is destined for a
		// log and there is no reason for it to carry content it does not need.
		return audit.Details{}, fmt.Errorf("keyset: name cannot be recorded: %w", domain.ErrInvalidInput)
	}
	return d, nil
}

// renameDetails builds the audit details for a rename, recording the
// before/after pair. Both names are set names — the public second segment of a
// /{handle}/{set} URL — so neither is a secret, and a record that named only
// the destination would leave an incident review unable to tell which address
// stopped resolving.
func renameDetails(from, to, requestID string) (audit.Details, error) {
	d, err := setDetails(to, requestID)
	if err != nil {
		return audit.Details{}, err
	}
	d = d.Set(audit.DetailFrom, from).Set(audit.DetailTo, to)
	if err := d.Err(); err != nil {
		return audit.Details{}, fmt.Errorf("keyset: name cannot be recorded: %w", domain.ErrInvalidInput)
	}
	return d, nil
}

// defaultDetails builds the audit details for a change of designated default,
// recording which set took the designation and, when there was one, which set
// gave it up. Both are set names — the public second segment of a /{handle}/{set}
// URL — so neither is a secret, and a record naming only the new default would
// leave an incident review unable to tell what bare GET /{handle} used to serve.
//
// An owner designating a first default has no predecessor to name, and the
// audit screen refuses an empty value, so the from key is omitted rather than
// set to a placeholder that a reader could mistake for a set called "".
func defaultDetails(from, to, requestID string) (audit.Details, error) {
	d, err := setDetails(to, requestID)
	if err != nil {
		return audit.Details{}, err
	}
	if from != "" {
		d = d.Set(audit.DetailFrom, from)
	}
	d = d.Set(audit.DetailTo, to)
	if err := d.Err(); err != nil {
		return audit.Details{}, fmt.Errorf("keyset: name cannot be recorded: %w", domain.ErrInvalidInput)
	}
	return d, nil
}

// visibilityDetails builds the audit details for a visibility change, recording
// the before/after pair alongside the set it applied to. The pair is what makes
// the record answer the question an incident review actually asks — which
// direction the set moved — rather than only its resting state.
//
// Both values come from the closed Visibility set, never from caller text.
func visibilityDetails(from, to domain.Visibility, name, requestID string) (audit.Details, error) {
	d, err := setDetails(name, requestID)
	if err != nil {
		return audit.Details{}, err
	}
	d = d.Set(audit.DetailVisibility, string(to)).
		Set(audit.DetailFrom, string(from)).
		Set(audit.DetailTo, string(to))
	if err := d.Err(); err != nil {
		return audit.Details{}, fmt.Errorf("keyset: visibility cannot be recorded: %w", domain.ErrInvalidInput)
	}
	return d, nil
}

// emit records an access-affecting key set change. The details are built by the
// caller before its write, so that a value the audit screen refuses cannot leave
// a committed change unrecorded.
func (s *Service) emit(ctx context.Context, action domain.AuditAction, ownerID domain.OwnerID, id domain.KeySetID, details audit.Details) error {
	return s.auditor.Emit(ctx, audit.Event{
		ActorType:  domain.ActorTypeOwner,
		ActorID:    string(ownerID),
		Action:     action,
		TargetType: domain.TargetTypeKeySet,
		TargetID:   string(id),
		Details:    details,
	})
}
