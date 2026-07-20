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
	admins  repository.AdministratorRepository
	emitter *audit.Emitter
	matcher *blocklist.Matcher

	mu sync.Mutex
}

// New returns a Service, or an error if a dependency is missing.
//
// Every dependency is required and a nil one is refused rather than tolerated.
// A Service with no administrator repository could not authorize, and one with
// no emitter could not audit; either would be an unaccountable edit path, which
// is precisely what this package exists to prevent. Refusing at construction
// makes that a startup failure instead of a silent runtime hole.
func New(
	admins repository.AdministratorRepository,
	emitter *audit.Emitter,
	matcher *blocklist.Matcher,
) (*Service, error) {
	switch {
	case admins == nil:
		return nil, fmt.Errorf("listadmin: administrator repository is required")
	case emitter == nil:
		return nil, fmt.Errorf("listadmin: audit emitter is required")
	case matcher == nil:
		return nil, fmt.Errorf("listadmin: matcher is required")
	}
	return &Service{admins: admins, emitter: emitter, matcher: matcher}, nil
}

// AddAllowlistEntry exempts entry from the blocklist, on the acting
// administrator's authority.
func (s *Service) AddAllowlistEntry(
	ctx context.Context, actor domain.AdministratorID, entry string,
) error {
	return s.edit(ctx, actor, entry, listOp{
		target:  domain.TargetTypeAllowlistEntry,
		action:  domain.AuditActionAllowlistEntryAdded,
		current: s.matcher.Allowlist,
		apply:   s.matcher.SetAllowlist,
		add:     true,
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
		current: s.matcher.Allowlist,
		apply:   s.matcher.SetAllowlist,
	})
}

// AddBlocklistTerm adds a term an administrator wants refused.
func (s *Service) AddBlocklistTerm(
	ctx context.Context, actor domain.AdministratorID, entry string,
) error {
	return s.edit(ctx, actor, entry, listOp{
		target:  domain.TargetTypeBlocklistEntry,
		action:  domain.AuditActionBlocklistEntryAdded,
		current: s.matcher.ExtraTerms,
		apply:   s.matcher.SetExtraTerms,
		add:     true,
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
		current: s.matcher.ExtraTerms,
		apply:   s.matcher.SetExtraTerms,
	})
}

// Allowlist returns the entries currently in force.
func (s *Service) Allowlist() []string { return s.matcher.Allowlist() }

// BlocklistTerms returns the administrator-added terms currently in force.
func (s *Service) BlocklistTerms() []string { return s.matcher.ExtraTerms() }

// listOp is the per-list wiring one edit needs: which audit target and action
// name it, how to read the current set, how to write a new one, and whether
// this is an addition or a removal.
type listOp struct {
	target  domain.TargetType
	action  domain.AuditAction
	current func() []string
	apply   func([]string) error
	add     bool
}

// edit is the single body every list change goes through. Having exactly one
// means the authorization check, the audit and the ordering between them cannot
// drift between the four operations.
//
// # The order is authorize, then audit, then apply
//
// The audit record is written BEFORE the change takes effect, never after. The
// two failure modes are not symmetric. A record written for a change that then
// fails to apply is an over-record: it says an edit was attempted, an
// investigator can reconcile it against the list's actual contents, and nothing
// is unaccounted for. A change applied with no record is a hole in a security
// control that nobody can attribute to anybody -- there is no later evidence
// that it happened, so no review can find it. A crash between the two steps
// must therefore leave the recorded-but-not-applied state, which is what this
// order guarantees.
//
// An audit failure aborts the edit outright rather than proceeding unrecorded.
//
// This is the weaker of the two orderings ADR-0007 permits. Writing both in one
// transaction would be stronger, and it is what the storage-backed version of
// this should do; the runtime lists live in memory in this slice, so there is
// no shared transaction to enlist the swap in, and "audit first, abort on
// failure" is the strongest available ordering that never produces the
// unrecorded direction.
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

	if err := op.apply(next); err != nil {
		return fmt.Errorf("listadmin: apply the edit: %w", err)
	}
	return nil
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
