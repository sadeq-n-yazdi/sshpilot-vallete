package repository

import (
	"context"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
)

// ListOverrideRepository persists the durable runtime decisions about the
// reserved-identifier lists (ADR-0017, Fb3).
//
// Rows here are the record of what an administrator decided at runtime, and
// they are ranked ABOVE the startup seed when the lists are composed. See
// domain.ListOverride for why a removal is a stored tombstone rather than an
// absent row; the short version is that an absent row cannot outrank a seed,
// so a removal recorded that way silently comes back on restart.
//
// Every method is unscoped. The reserved-identifier lists are global service
// policy on the system axis, not owner-owned data, so there is no owner to
// filter by -- the same reason AdministratorRepository is unscoped.
type ListOverrideRepository interface {
	// Put records an override, replacing any previous decision for the same
	// list and skeleton.
	//
	// It is an upsert rather than an insert because the identity of an override
	// is the entry it governs, not the event that produced it: an entry that is
	// added, removed, and added again is one rule with a current state, and
	// keeping one row per (list, skeleton) means a reader of this table cannot
	// see a stale decision at all. The history of who changed what and when
	// lives in the append-only audit log, which is the surface built to answer
	// that question; duplicating it here would create a second, weaker history
	// that could disagree with the authoritative one.
	//
	// UNSCOPED: the reserved-identifier lists are global service policy on the
	// system axis, not owner-owned data.
	Put(ctx context.Context, o *domain.ListOverride) error

	// List returns every override across all lists, ordered by list and then
	// skeleton so replay is deterministic across calls, processes, and engines.
	//
	// A nondeterministic order would be a correctness problem and not merely an
	// untidy one: replay applies these over a seed, so an unstable order could
	// make the composed policy depend on how the database happened to return
	// rows. It returns a nil slice when there are no overrides.
	//
	// UNSCOPED: the reserved-identifier lists are global service policy on the
	// system axis, not owner-owned data.
	List(ctx context.Context) ([]domain.ListOverride, error)
}
