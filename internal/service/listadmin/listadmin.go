// Package listadmin is the authorization and audit boundary for runtime edits
// to the reserved-identifier lists (ADR-0017, Fb3).
//
// # Why the administrator check lives here and not in a handler
//
// An allowlist entry is a deliberate hole punched in a security control:
// whoever can allowlist "admin" can then register "admin". A check that lived
// only in an HTTP handler would protect exactly one caller, and every internal
// path added later -- a CLI, a migration, a background reconciler, another
// service -- would reach the matcher with no check at all. Placing it here
// means the authorization is a property of the operation rather than of one
// transport, so a new caller inherits it by construction instead of by the
// author remembering.
//
// The transport layer is still expected to authenticate. This package does not
// authenticate anybody; it authorizes an already-identified administrator, and
// it refuses when it cannot.
//
// # Fail closed
//
// Every path that cannot establish an active administrator refuses the edit.
// That includes the case where the administrator store returns an error: a
// lookup that could not be performed is not evidence of authority, and treating
// an unavailable store as permission would make a database outage into a window
// in which anyone may edit the blocklist.
package listadmin

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/audit"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/blocklist"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/repository"
)

// maxEntryLen bounds an entry an administrator may submit. It matches the
// matcher's own input bound, so an entry that could never be compared against
// an identifier cannot be stored as though it might be.
const maxEntryLen = blocklist.MaxInputBytes

// Service performs audited, authorized edits to the runtime lists.
//
// It is safe for concurrent use. Edits are serialized by a mutex because each
// one is a read-modify-write of a whole list: two concurrent adds that both
// read the same starting set would otherwise each write a set missing the
// other's entry, and the loser's change would vanish while its audit record
// claimed it had been applied.
type Service struct {
	admins    repository.AdministratorRepository
	overrides repository.ListOverrideRepository
	emitter   *audit.Emitter
	matcher   *blocklist.Matcher
	now       audit.Clock

	mu sync.Mutex
}

// Params are the dependencies a Service needs. They are named rather than
// positional because every one of them is required and several share a shape:
// two repositories side by side in a positional signature are a transposition
// away from a Service that authorizes against the wrong table.
type Params struct {
	// Admins is the authority the edit is checked against.
	Admins repository.AdministratorRepository
	// Overrides is where an edit is durably recorded before it takes effect.
	Overrides repository.ListOverrideRepository
	// Emitter writes the audit record.
	Emitter *audit.Emitter
	// Matcher is the live policy the edit is applied to.
	Matcher *blocklist.Matcher
	// Now stamps the persisted override. Optional; time.Now is used when nil,
	// since a missing clock has a single obviously-correct default and is not a
	// security decision the way a missing repository is.
	Now audit.Clock
}

// New returns a Service, or an error if a dependency is missing.
//
// Every dependency is required and a nil one is refused rather than tolerated.
// A Service with no administrator repository could not authorize, one with no
// emitter could not audit, and one with no override repository could not make
// an edit survive a restart -- each would be an unaccountable or a
// silently-reverting edit path, which is precisely what this package exists to
// prevent. Refusing at construction makes that a startup failure instead of a
// silent runtime hole.
func New(p Params) (*Service, error) {
	switch {
	case p.Admins == nil:
		return nil, fmt.Errorf("listadmin: administrator repository is required")
	case p.Overrides == nil:
		return nil, fmt.Errorf("listadmin: list override repository is required")
	case p.Emitter == nil:
		return nil, fmt.Errorf("listadmin: audit emitter is required")
	case p.Matcher == nil:
		return nil, fmt.Errorf("listadmin: matcher is required")
	}
	now := p.Now
	if now == nil {
		now = time.Now
	}
	return &Service{
		admins:    p.Admins,
		overrides: p.Overrides,
		emitter:   p.Emitter,
		matcher:   p.Matcher,
		now:       now,
	}, nil
}

// AddAllowlistEntry exempts entry from the blocklist, on the acting
// administrator's authority.
func (s *Service) AddAllowlistEntry(
	ctx context.Context, actor domain.AdministratorID, entry string,
) error {
	return s.edit(ctx, actor, entry, listOp{
		target:  domain.TargetTypeAllowlistEntry,
		action:  domain.AuditActionAllowlistEntryAdded,
		kind:    domain.ListKindAllowlist,
		current: s.matcher.Allowlist,
		apply:   s.matcher.SetAllowlist,
		add:     true,
		// An exemption lets an otherwise-blocked identifier through.
		weakens: true,
	})
}

// RemoveAllowlistEntry withdraws an exemption.
//
// Identifiers already registered under the entry are NOT affected, and that is
// ADR-0017's rule rather than a choice made here: the blocklist is enforced at
// creation and rename only, so nothing re-checks a name once it is claimed.
// Removing an entry therefore prevents new registrations without breaking live
// URLs. ADR-0017 prescribes what happens to the existing ones -- they keep
// working, are flagged for administrator review, and are marked
// quarantine-on-release so the name cannot be re-claimed once freed. That
// flagging machinery belongs to the handle lifecycle (ADR-0026) and is not
// implemented here.
func (s *Service) RemoveAllowlistEntry(
	ctx context.Context, actor domain.AdministratorID, entry string,
) error {
	return s.edit(ctx, actor, entry, listOp{
		target:  domain.TargetTypeAllowlistEntry,
		action:  domain.AuditActionAllowlistEntryRemoved,
		kind:    domain.ListKindAllowlist,
		current: s.matcher.Allowlist,
		apply:   s.matcher.SetAllowlist,
		// Withdrawing an exemption re-blocks the term.
		weakens: false,
	})
}

// AddBlocklistTerm adds a term an administrator wants refused.
func (s *Service) AddBlocklistTerm(
	ctx context.Context, actor domain.AdministratorID, entry string,
) error {
	return s.edit(ctx, actor, entry, listOp{
		target:  domain.TargetTypeBlocklistEntry,
		action:  domain.AuditActionBlocklistEntryAdded,
		kind:    domain.ListKindBlocklistTerm,
		current: s.matcher.ExtraTerms,
		apply:   s.matcher.SetExtraTerms,
		add:     true,
		// A new term refuses names that were previously accepted.
		weakens: false,
	})
}

// RemoveBlocklistTerm withdraws an administrator-added term. Curated terms from
// the built-in lists are not reachable: they are reviewed data, and a runtime
// operation that could silently disable a shipped impersonation term would be a
// larger hole than the allowlist it is meant to complement.
func (s *Service) RemoveBlocklistTerm(
	ctx context.Context, actor domain.AdministratorID, entry string,
) error {
	return s.edit(ctx, actor, entry, listOp{
		target:  domain.TargetTypeBlocklistEntry,
		action:  domain.AuditActionBlocklistEntryRemoved,
		kind:    domain.ListKindBlocklistTerm,
		current: s.matcher.ExtraTerms,
		apply:   s.matcher.SetExtraTerms,
		// Dropping a term stops refusing names it used to catch.
		weakens: true,
	})
}

// Allowlist returns the entries currently in force.
func (s *Service) Allowlist() []string { return s.matcher.Allowlist() }

// BlocklistTerms returns the administrator-added terms currently in force.
func (s *Service) BlocklistTerms() []string { return s.matcher.ExtraTerms() }

// listOp is the per-list wiring one edit needs: which audit target and action
// name it, how to read the current set, how to write a new one, whether this is
// an addition or a removal, and which way it moves the security control.
type listOp struct {
	target  domain.TargetType
	action  domain.AuditAction
	kind    domain.ListKind
	current func() []string
	apply   func([]string) error
	add     bool
	// weakens is true when the edit lets MORE identifiers through than before:
	// adding an allowlist exemption, or removing a blocklist term. It is false
	// when the edit refuses more than before. It decides the write order in
	// edit, so it is stated explicitly at each call site rather than derived
	// from add and kind -- the derivation is a correct-looking one-liner whose
	// two branches invert, and getting it backwards would silently choose the
	// fail-open order for exactly the operation that must not have it.
	weakens bool
}

// edit is the single body every list change goes through. Having exactly one
// means the authorization check, the audit and the ordering between them cannot
// drift between the four operations.
//
// # The order is authorize, then two durable writes, then apply
//
// The audit write and the override write are separate auto-commits rather than
// one transaction, so a crash can land between them. Which of the two goes
// first is therefore a security decision, and it is NOT the same decision for
// every operation -- there is no single static order that fails safe for all
// four, which is why the order here depends on op.weakens.
//
// Take the two crash outcomes. Audit-then-persist leaves a record of an edit
// that no override backs, so the edit is absent from the composed policy after
// the restart: an over-record. Persist-then-audit leaves the edit durable and
// in force after the restart with nobody named as having made it: an
// unattributed policy change.
//
// Neither is universally safer, because what the edit DOES differs:
//
//   - A weakening edit (allowlist add, blocklist term removal) lets more
//     identifiers through. Its dangerous outcome is being in force unrecorded,
//     so it audits first. The crash outcome is an over-record: the hole was
//     never punched, and the log names an attempt an investigator reconciles
//     against the live policy.
//   - A strengthening edit (allowlist removal, blocklist term addition) refuses
//     more. Its dangerous outcome is silently NOT being in force -- an
//     allowlist removal that fails to persist leaves the seed's exemption
//     standing, re-permitting an identifier an administrator refused, while the
//     audit log says it was removed. That is the fail-open case this whole
//     mechanism exists to close, so it persists first. The crash outcome is an
//     unattributed tightening: the term is refused and the log is missing the
//     name of who refused it. Conservative rather than dangerous, and visible,
//     because the override row carries its own actor_id and updated_at.
//
// So the ordering rule is: whichever write failing would leave the permissive
// state goes first. Every crash window closes toward refusing more, never
// toward allowing more.
//
// Either write failing aborts the edit outright. An edit that cannot be
// recorded, in the log or durably, is an edit that did not happen.
//
// Collapsing both writes into one transaction would remove the window entirely
// and is the better end state, but it is not available here: the audit sink is
// deliberately the narrow, self-committing repository.AuditAppender (see
// sqlite.Store's AuditAppender). Enlisting it in this service's transaction
// would mean holding the full repository.AuditRepository, which also exposes
// the ADR-0024 purge and pseudonymize operations -- buying atomicity would hand
// list-editing code the ability to rewrite the log recording its own actions.
// Until the audit port grows a transaction-bound append-only form, the
// direction-aware order above is the strongest available, and unlike a single
// fixed order it has no fail-open window at all.
//
// The apply step is last because it is the only one that cannot be undone: the
// matcher swap is an atomic.Value store with no rollback.
func (s *Service) edit(
	ctx context.Context, actor domain.AdministratorID, entry string, op listOp,
) error {
	if err := validateEntry(entry); err != nil {
		return err
	}

	// Authorization precedes everything with an effect, including the audit
	// write: an unauthorized caller must not be able to append to the audit log
	// by submitting edits it was never allowed to make.
	if err := s.authorize(ctx, actor); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	next, err := nextSet(op.current(), entry, op.add)
	if err != nil {
		return err
	}

	if op.weakens {
		// The edit lets more through, so the record must be durable before the
		// permission can be.
		if err := s.audit(ctx, actor, entry, op); err != nil {
			return err
		}
		if err := s.persist(ctx, actor, entry, op); err != nil {
			return err
		}
	} else {
		// The edit refuses more, so the refusal must be durable before it can
		// be reported as done.
		if err := s.persist(ctx, actor, entry, op); err != nil {
			return err
		}
		if err := s.audit(ctx, actor, entry, op); err != nil {
			return err
		}
	}

	if err := op.apply(next); err != nil {
		return fmt.Errorf("listadmin: apply the edit: %w", err)
	}
	return nil
}

// audit writes the record for one edit. It fails the edit rather than
// proceeding unrecorded.
func (s *Service) audit(
	ctx context.Context, actor domain.AdministratorID, entry string, op listOp,
) error {
	if err := s.emitter.Emit(ctx, audit.Event{
		ActorType:  domain.ActorTypeAdministrator,
		ActorID:    string(actor),
		Action:     op.action,
		TargetType: op.target,
		// The entry as the administrator typed it. A skeleton must never be
		// stored or displayed, and the raw spelling is what a reviewer needs to
		// see to judge whether the change was reasonable.
		TargetID: entry,
	}); err != nil {
		return fmt.Errorf("listadmin: audit the edit before applying it: %w", err)
	}
	return nil
}

// persist records the edit durably so it survives a restart. It fails the edit
// rather than applying a change that would silently revert.
func (s *Service) persist(
	ctx context.Context, actor domain.AdministratorID, entry string, op listOp,
) error {
	if err := s.overrides.Put(ctx, &domain.ListOverride{
		List:     op.kind,
		Skeleton: blocklist.Skeleton(entry),
		Entry:    entry,
		State:    op.state(),
		ActorID:  actor,
		// The service supplies the timestamp; repositories hold no clock.
		UpdatedAt: s.now().UTC(),
	}); err != nil {
		return fmt.Errorf("listadmin: persist the edit before applying it: %w", err)
	}
	return nil
}

// state is the durable state this operation records: an addition puts the entry
// in force, a removal lays a tombstone that outranks the seed at replay.
func (o listOp) state() domain.ListOverrideState {
	if o.add {
		return domain.ListOverridePresent
	}
	return domain.ListOverrideRemoved
}

// nextSet computes the list contents after adding or removing entry, or reports
// why the edit is a no-op.
//
// Membership is decided on the SKELETON, not the raw string, so the set the
// service reasons about is the set the matcher enforces. Removing "adm1n" must
// withdraw an entry added as "admin", because those are one entry to the
// engine; deciding membership on the raw spelling would leave an administrator
// unable to remove a hole they could plainly see in the listing.
//
// A no-op is an error rather than a silent success. Adding an entry that is
// already present, or removing one that is not, means the administrator's
// belief about the list disagrees with its contents -- and auditing a change
// that changed nothing would put a false event in the record.
//
// Both edit paths clone current before mutating it, and that clone is
// DELIBERATE -- not redundant with what the caller hands in. Today op.current()
// returns a make()-allocated copy (Matcher.Allowlist / Matcher.ExtraTerms build
// a fresh slice), so the clone is provably unnecessary for correctness against
// the current callers. It is kept so nextSet stays safe irrespective of what
// its caller passes: if op.current() were ever changed to return the matcher's
// live slice -- the natural way to "avoid a copy" -- in-place mutation here
// would rewrite the in-force allowlist under atomic.Value, outside the audit
// path every legitimate edit takes, silently punching a hole in a security
// control from a refactor two levels away. The cost is one allocation on a
// cold, rarely-taken, audited path; the defensive property is worth it.
func nextSet(current []string, entry string, add bool) ([]string, error) {
	sk := blocklist.Skeleton(entry)
	idx := slices.IndexFunc(current, func(e string) bool {
		return blocklist.Skeleton(e) == sk
	})

	if add {
		if idx >= 0 {
			return nil, fmt.Errorf("listadmin: entry is already present: %w", domain.ErrConflict)
		}
		return append(slices.Clone(current), entry), nil
	}
	if idx < 0 {
		return nil, fmt.Errorf("listadmin: entry is not present: %w", domain.ErrNotFound)
	}
	return slices.Delete(slices.Clone(current), idx, idx+1), nil
}

// authorize refuses unless actor names an active administrator.
//
// Every non-success path returns an error, and the store error is deliberately
// not folded into "unauthorized": the two are different operational facts and a
// reviewer needs to tell "somebody without authority tried this" from "the
// authorization could not be evaluated". Both refuse the edit.
//
// BOUNDARY OBLIGATION: a transport layer MUST render every refusal from this
// function identically. Distinguishing "no such administrator" from "disabled
// administrator" at the API would let an unauthenticated caller enumerate which
// administrator IDs exist.
func (s *Service) authorize(ctx context.Context, actor domain.AdministratorID) error {
	if actor == "" {
		return fmt.Errorf("listadmin: no administrator named: %w", domain.ErrUnauthorized)
	}

	admin, err := s.admins.Get(ctx, actor)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return fmt.Errorf("listadmin: not an administrator: %w", domain.ErrUnauthorized)
		}
		// Fail closed. An unavailable store is not permission; treating it as
		// such would turn a database outage into an interval during which the
		// blocklist is editable by anyone.
		return fmt.Errorf("listadmin: administrator lookup failed, refusing the edit: %w", err)
	}

	// A nil administrator with no error would be a repository contract
	// violation, and dereferencing it would panic. Refuse instead: an
	// authorization decision must never depend on a value nobody promised.
	if admin == nil {
		return fmt.Errorf("listadmin: administrator lookup returned nothing: %w", domain.ErrUnauthorized)
	}

	if admin.Status != domain.AdminStatusActive {
		return fmt.Errorf("listadmin: administrator is not active: %w", domain.ErrForbidden)
	}
	return nil
}

// validateEntry rejects an entry that could not be a meaningful list member.
//
// The bounds matter beyond tidiness: the entry is written to an audit record as
// the target ID, so an unbounded one would let an administrator park arbitrary
// content in the append-only log.
func validateEntry(entry string) error {
	if entry == "" {
		return fmt.Errorf("listadmin: empty entry: %w", domain.ErrInvalidInput)
	}
	if len(entry) > maxEntryLen {
		return fmt.Errorf("listadmin: entry is too long: %w", domain.ErrInvalidInput)
	}
	// An entry with no skeleton can never match any identifier, so accepting it
	// would record an approval or a prohibition that does nothing at all.
	if blocklist.Skeleton(entry) == "" {
		return fmt.Errorf("listadmin: entry has no comparable content: %w", domain.ErrInvalidInput)
	}
	return nil
}
