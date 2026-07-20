package domain

import "time"

// ListKind names which reserved-identifier list an override applies to
// (ADR-0017). The two lists pull in opposite directions -- the allowlist
// exempts, the extra terms refuse -- so an override that landed on the wrong one
// would invert its own meaning. Keeping the kind an explicit, CHECK-constrained
// column rather than inferring it from context means a row can never be read
// back as an override of a list nobody wrote it for.
type ListKind string

// The reserved-identifier lists an administrator may override at runtime.
const (
	// ListKindAllowlist is the exemption list: an entry here stops the
	// blocklist refusing that identifier.
	ListKindAllowlist ListKind = "allowlist"
	// ListKindBlocklistTerm is the administrator-added term list: an entry here
	// refuses an identifier the curated lists would have permitted.
	ListKindBlocklistTerm ListKind = "blocklist_term"
)

// IsValid reports whether k is a known ListKind.
func (k ListKind) IsValid() bool {
	switch k {
	case ListKindAllowlist, ListKindBlocklistTerm:
		return true
	default:
		return false
	}
}

// ListOverrideState is what a runtime edit decided about an entry.
//
// # Why removal is a state and not an absent row
//
// This is the whole point of the type. A removal recorded as the ABSENCE of a
// row cannot outrank anything: replaying such a record over a seed leaves the
// seed's copy of the entry standing, so an entry an administrator deliberately
// removed comes back on the next restart. For the allowlist that direction is
// fail-OPEN -- removing an allowlist entry means re-blocking a term, so a lost
// removal silently re-permits a name somebody decided to refuse -- and the audit
// log still shows the removal, so the record describes a policy that is not in
// force.
//
// Recording removal as an explicit state makes the tombstone a fact that
// replay can rank ABOVE the seed. A seed file that later re-adds a removed
// entry therefore does not resurrect it: the tombstone still wins, and the
// resurrection is not merely detected but inexpressible. Undoing a removal
// requires an audited runtime addition, which is the only path that leaves a
// record of who decided it.
type ListOverrideState string

// Runtime override states.
const (
	// ListOverridePresent means the entry is in force regardless of the seed.
	ListOverridePresent ListOverrideState = "present"
	// ListOverrideRemoved is a tombstone: the entry is NOT in force, and it
	// outranks any seed or default that supplies it.
	ListOverrideRemoved ListOverrideState = "removed"
)

// IsValid reports whether s is a known ListOverrideState.
func (s ListOverrideState) IsValid() bool {
	switch s {
	case ListOverridePresent, ListOverrideRemoved:
		return true
	default:
		return false
	}
}

// ListOverride is one durable runtime decision about one list entry.
//
// Identity is (List, Skeleton), not (List, Entry). The skeleton is the form the
// matcher compares on, so two spellings that fold together are one entry to the
// engine and must be one row here: keying on the raw spelling would let
// "adm1n" sit alongside "admin" as separate overrides while the matcher treats
// them as the same rule, and which of the two won would depend on replay order.
//
// Entry keeps the raw spelling anyway, for the audit and listing surfaces. A
// skeleton is comparison-only and must never be displayed or presented as the
// thing an administrator approved; a reviewer needs to see the word that was
// actually typed to judge whether the decision was reasonable. The spelling is
// retained on a tombstone too, so a review of a removal can show what was
// removed rather than an opaque folded string.
type ListOverride struct {
	// List is which list this override applies to.
	List ListKind
	// Skeleton is the matcher's comparison form of Entry, and the identity of
	// this override within its list. The service computes it; per the
	// repository conventions a repository never derives it.
	Skeleton string
	// Entry is the raw spelling as the administrator typed it.
	Entry string
	// State is whether the entry is in force or tombstoned.
	State ListOverrideState
	// ActorID is the administrator whose authority the edit was made under. It
	// is retained so the durable policy and the audit record name the same
	// person, and a reviewer can reconcile the two without joining on time.
	ActorID AdministratorID
	// UpdatedAt is when the decision was recorded, supplied by the caller.
	UpdatedAt time.Time
}
