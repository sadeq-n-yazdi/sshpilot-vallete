package blocklist

import (
	"fmt"
	"sort"
)

// AllowlistName is the value reported in Result.List when an identifier was
// permitted by the allowlist rather than by matching no term. It is a fixed
// string so an audit reader can filter on it.
const AllowlistName = "allowlist"

// allowSet is one compiled, immutable revision of the allowlist.
//
// It maps an entry's skeleton to the entry as the administrator typed it. The
// skeleton is the key because that is the form the blocklist compares on: an
// allowlist keyed on anything else would exempt a different set of identifiers
// than the blocklist blocks, and the gap between the two sets would be
// reachable by exactly the confusable spellings the folding exists to catch.
//
// The raw spelling is the value because an audit record and an administrator's
// listing must show the word that was approved, never a skeleton — skeletons
// are comparison-only and must not be stored or displayed.
type allowSet struct {
	bySkeleton map[string]string
}

// SetAllowlist replaces the matcher's allowlist with entries, or reports why it
// cannot and leaves the previous allowlist in place.
//
// # All-or-nothing
//
// The new set is compiled and validated in full before anything is swapped, so
// a malformed entry cannot leave the matcher holding a partially applied
// allowlist. A partial allowlist is the dangerous outcome and not merely an
// untidy one: it is a set of holes nobody approved as a set, and whether a
// given hole is open would depend on where in the input the parse failed.
//
// # The swap is atomic
//
// The matcher's lists are fixed at construction, but the allowlist is not: it
// is edited at runtime by an administrator. The swap is a single atomic pointer
// store, so a concurrent Check sees either the whole old set or the whole new
// one and never a half-built map.
//
// Storing through the pointer rather than rebuilding the Matcher is what lets a
// runtime edit reach an enforcement choke point that captured a *Matcher at its
// own construction: the pointer the choke point holds stays valid and its
// contents change underneath. Rebuilding the Matcher would produce a new
// pointer that every already-constructed caller would never see, so the edit
// would appear to succeed while changing nothing at the only place it matters.
//
// # Validation
//
// An entry whose skeleton is empty is refused: it carries no comparable content
// and so could never exempt any identifier, which means accepting it would
// record an approval that does nothing. Two entries sharing a skeleton are
// refused because they are the same entry to this engine, and the duplicate
// should be resolved where a reviewer can see it rather than one spelling
// silently shadowing the other. An empty entries slice is valid and clears the
// allowlist.
func (m *Matcher) SetAllowlist(entries []string) error {
	if m == nil || !m.ready {
		return fmt.Errorf("blocklist: allowlist set on an unbuilt matcher")
	}

	compiled := make(map[string]string, len(entries))
	for _, raw := range entries {
		sk := Skeleton(raw)
		if sk == "" {
			return fmt.Errorf("blocklist: allowlist entry %q has an empty skeleton", raw)
		}
		if prev, dup := compiled[sk]; dup {
			return fmt.Errorf("blocklist: allowlist entries %q and %q share a skeleton", prev, raw)
		}
		compiled[sk] = raw
	}

	m.allow.Store(&allowSet{bySkeleton: compiled})
	return nil
}

// Allowlist returns the current entries in their original spelling, sorted so
// the listing is stable across calls and processes. The returned slice is a
// copy; mutating it cannot reach the matcher.
//
// A matcher whose allowlist was never set, or whose load failed, reports an
// empty allowlist rather than an error. That is the safe direction and it is
// the same value Check acts on, so an operator reading this listing is reading
// the set that is actually in force.
func (m *Matcher) Allowlist() []string {
	if m == nil || !m.ready {
		return nil
	}
	set := m.allow.Load()
	if set == nil {
		return nil
	}
	out := make([]string, 0, len(set.bySkeleton))
	for _, raw := range set.bySkeleton {
		out = append(out, raw)
	}
	sort.Strings(out)
	return out
}

// ExtraListName is the value reported in Result.List when an identifier was
// blocked by an administrator-added term rather than by a curated default.
// Keeping it distinct from the built-in list names is what lets a reviewer tell
// a policy decision somebody made at runtime from one that shipped with the
// service.
const ExtraListName = "administrator"

// SetExtraTerms replaces the administrator-added blocklist terms.
//
// These are whole-skeleton terms, matching the mode ADR-0017 assigns to routing
// and impersonation words. Substring mode is deliberately not offered at
// runtime: a substring term blocks every identifier containing it, so a single
// mistyped entry could refuse a large share of the namespace, and the curated
// substring list in lists.go is reviewed precisely because that power needs
// review. An administrator who needs a substring term changes the curated data.
//
// The same all-or-nothing and atomic-swap properties as SetAllowlist apply, and
// for the same reasons; see SetAllowlist. The failure direction differs though,
// and is worth stating: an extra-terms set that fails to load leaves the
// matcher blocking only the curated defaults, which is LESS blocking than
// intended. That is the opposite of the allowlist's failure direction and it is
// not a contradiction -- in both cases the safe answer is the one that keeps
// the deliberate exemptions closed and falls back to reviewed policy.
func (m *Matcher) SetExtraTerms(terms []string) error {
	if m == nil || !m.ready {
		return fmt.Errorf("blocklist: extra terms set on an unbuilt matcher")
	}

	cl := compiledList{
		name:  ExtraListName,
		mode:  MatchWholeSkeleton,
		whole: make(map[string]compiledTerm, len(terms)),
	}
	seen := make(map[string]string, len(terms))
	for _, raw := range terms {
		sk := Skeleton(raw)
		if sk == "" {
			return fmt.Errorf("blocklist: extra term %q has an empty skeleton", raw)
		}
		if prev, dup := seen[sk]; dup {
			return fmt.Errorf("blocklist: extra terms %q and %q share a skeleton", prev, raw)
		}
		seen[sk] = raw
		cl.whole[sk] = compiledTerm{skeleton: sk, raw: raw}
	}

	m.extra.Store(&cl)
	return nil
}

// ExtraTerms returns the administrator-added terms in their original spelling,
// sorted for a stable listing. The slice is a copy.
func (m *Matcher) ExtraTerms() []string {
	if m == nil || !m.ready {
		return nil
	}
	cl := m.extra.Load()
	if cl == nil {
		return nil
	}
	out := make([]string, 0, len(cl.whole))
	for _, term := range cl.whole {
		out = append(out, term.raw)
	}
	sort.Strings(out)
	return out
}

// allowlisted reports whether skeleton is exempt, and under which entry.
//
// # Exact skeleton equality, never substring
//
// An allowlist entry is a deliberate hole in a security control, so it is made
// as narrow as it can be while still solving the problem it exists for. Exact
// equality exempts precisely the identifier that was approved. A substring rule
// would exempt every identifier containing the entry, so approving one
// false positive would silently approve an unbounded family of names nobody
// looked at — including names that are blocked for a completely different
// reason than the one the entry was added to fix.
//
// # The skeleton, not the candidate expansion
//
// Only the identifier's own skeleton is consulted, deliberately not the
// alternative readings from candidateSkeletons. The expansion exists to widen
// what is REFUSED — an identifier is blocked if any reading of it is a
// reserved word — and running it through the allowlist would invert that
// logic into widening what is permitted, exempting an identifier because some
// alternative reading of it happened to be approved. Candidates make the
// blocklist stricter and would make the allowlist looser, so the allowlist
// does not see them.
//
// A nil set means no allowlist is loaded, and nothing is exempt. See Check.
func (m *Matcher) allowlisted(skeleton string) (string, bool) {
	set := m.allow.Load()
	if set == nil {
		return "", false
	}
	raw, ok := set.bySkeleton[skeleton]
	return raw, ok
}
