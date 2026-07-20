package blocklist

import (
	"strings"
	"sync"
	"testing"
)

// blockedMatcher builds a matcher with one whole-skeleton term and one
// substring term, so both match modes can be exercised against the allowlist.
func blockedMatcher(t *testing.T) *Matcher {
	t.Helper()
	m, err := NewMatcher(
		List{Name: "impersonation", Mode: MatchWholeSkeleton, Terms: []string{"admin"}},
		List{Name: "offensive", Mode: MatchSubstring, Terms: []string{"cunt"}},
	)
	if err != nil {
		t.Fatalf("NewMatcher: %v", err)
	}
	return m
}

// TestAllowlistExemptsExactIdentifier is the central behavior: an entry turns a
// blocked identifier into an allowed one, and the verdict says it was an
// exemption rather than an ordinary pass.
func TestAllowlistExemptsExactIdentifier(t *testing.T) {
	t.Parallel()
	m := blockedMatcher(t)

	if res := m.Check("scunthorpe"); !res.Blocked() {
		t.Fatal("precondition failed: \"scunthorpe\" was not blocked before the allowlist")
	}

	if err := m.SetAllowlist([]string{"scunthorpe"}); err != nil {
		t.Fatalf("SetAllowlist: %v", err)
	}

	res := m.Check("scunthorpe")
	if res.Blocked() {
		t.Fatal("allowlisted identifier is still blocked")
	}
	if res.Reason != ReasonAllowlisted {
		t.Errorf("Reason = %v, want ReasonAllowlisted", res.Reason)
	}
	if res.List != AllowlistName {
		t.Errorf("List = %q, want %q", res.List, AllowlistName)
	}
	// The entry is reported as the administrator typed it, so an audit reader
	// sees the approved word rather than a skeleton.
	if res.Term != "scunthorpe" {
		t.Errorf("Term = %q, want the entry as typed", res.Term)
	}
}

// TestAllowlistDoesNotExemptOtherIdentifiers is the hole-width test. An entry is
// a deliberate hole in a security control, so it must exempt the identifier it
// names and nothing else -- in particular nothing that merely CONTAINS it.
func TestAllowlistDoesNotExemptOtherIdentifiers(t *testing.T) {
	t.Parallel()
	m := blockedMatcher(t)
	if err := m.SetAllowlist([]string{"scunthorpe"}); err != nil {
		t.Fatalf("SetAllowlist: %v", err)
	}

	// Each of these is still blocked by the substring term, and each would be
	// wrongly exempted by a substring or prefix allowlist rule.
	for _, name := range []string{
		"scunthorpe-town",
		"xscunthorpe",
		"scunthorpex",
		"scunthorp",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if res := m.Check(name); !res.Blocked() {
				t.Errorf("%q was exempted by an entry for \"scunthorpe\"", name)
			}
		})
	}
}

// TestAllowlistExemptsConfusableSpellingOfTheEntry pins that the allowlist is
// consulted on the SKELETON. "adm1n" folds to the same skeleton as "admin", so
// an entry for "admin" must exempt it: the exempted set and the blocked set are
// the same set, which is the property that stops a confusable spelling from
// falling into the gap between them.
func TestAllowlistExemptsConfusableSpellingOfTheEntry(t *testing.T) {
	t.Parallel()
	m := blockedMatcher(t)
	if err := m.SetAllowlist([]string{"admin"}); err != nil {
		t.Fatalf("SetAllowlist: %v", err)
	}

	for _, spelling := range []string{"admin", "adm1n", "ad-min", "AdMiN"} {
		t.Run(spelling, func(t *testing.T) {
			t.Parallel()
			res := m.Check(spelling)
			if res.Blocked() {
				t.Errorf("%q blocked despite an entry for its skeleton", spelling)
			}
			if res.Reason != ReasonAllowlisted {
				t.Errorf("Reason = %v, want ReasonAllowlisted", res.Reason)
			}
		})
	}
}

// TestAllowlistDoesNotBypassTheInputBounds is the ordering test that matters
// most. The length and empty-skeleton refusals are fail-closed guards about the
// input being unexaminable, not policy judgments about a word, so no allowlist
// entry may exempt an input from them. If the allowlist were consulted before
// these guards, an entry would become a way to bypass the engine itself.
func TestAllowlistDoesNotBypassTheInputBounds(t *testing.T) {
	t.Parallel()
	m := blockedMatcher(t)

	// An over-length input. Its skeleton is allowlisted, and it must STILL be
	// refused as too long.
	long := strings.Repeat("a", MaxInputBytes+1)
	if err := m.SetAllowlist([]string{long}); err != nil {
		t.Fatalf("SetAllowlist(long): %v", err)
	}
	res := m.Check(long)
	if !res.Blocked() {
		t.Error("an allowlist entry exempted an over-length input from the length bound")
	}
	if res.Reason != ReasonTooLong {
		t.Errorf("Reason = %v, want ReasonTooLong", res.Reason)
	}

	// An input whose skeleton is empty. It cannot be allowlisted at all --
	// SetAllowlist refuses the entry -- and the input stays refused.
	if err := m.SetAllowlist([]string{"---"}); err == nil {
		t.Error("SetAllowlist accepted an entry with an empty skeleton")
	}
	if res := m.Check("---"); !res.Blocked() || res.Reason != ReasonEmptySkeleton {
		t.Errorf("empty-skeleton input: allowed=%v reason=%v, want blocked/empty-skeleton",
			!res.Blocked(), res.Reason)
	}
}

// TestNoAllowlistExemptsNothing is the fail-closed default: a matcher whose
// allowlist was never set exempts nothing. This is the state a matcher is left
// in when an allowlist fails to load, and the safe direction is to block more.
func TestNoAllowlistExemptsNothing(t *testing.T) {
	t.Parallel()
	m := blockedMatcher(t)

	if res := m.Check("admin"); !res.Blocked() {
		t.Error("a matcher with no allowlist exempted an identifier")
	}
	if got := m.Allowlist(); len(got) != 0 {
		t.Errorf("Allowlist() = %v, want empty", got)
	}
}

// TestClearingAllowlistRestoresTheBlock is the removal direction: once an entry
// is gone, the identifier is refused again. New registrations are prevented;
// identifiers already registered are unaffected because nothing re-checks them.
func TestClearingAllowlistRestoresTheBlock(t *testing.T) {
	t.Parallel()
	m := blockedMatcher(t)

	if err := m.SetAllowlist([]string{"admin"}); err != nil {
		t.Fatalf("SetAllowlist: %v", err)
	}
	if res := m.Check("admin"); res.Blocked() {
		t.Fatal("precondition failed: entry did not take effect")
	}

	if err := m.SetAllowlist(nil); err != nil {
		t.Fatalf("SetAllowlist(nil): %v", err)
	}
	res := m.Check("admin")
	if !res.Blocked() {
		t.Error("identifier still exempt after its entry was removed")
	}
	if res.Reason != ReasonBlockedTerm {
		t.Errorf("Reason = %v, want ReasonBlockedTerm", res.Reason)
	}
}

// TestSetAllowlistIsAllOrNothing pins that a rejected set leaves the previous
// one intact. A partially applied allowlist is a set of holes nobody approved
// as a set.
func TestSetAllowlistIsAllOrNothing(t *testing.T) {
	t.Parallel()
	m := blockedMatcher(t)

	if err := m.SetAllowlist([]string{"admin"}); err != nil {
		t.Fatalf("SetAllowlist: %v", err)
	}

	// The good entry precedes the malformed one, so a partial application would
	// be visible as "scunthorpe" becoming exempt.
	err := m.SetAllowlist([]string{"scunthorpe", "\u200b"})
	if err == nil {
		t.Fatal("SetAllowlist accepted a set containing an empty-skeleton entry")
	}
	if res := m.Check("scunthorpe"); !res.Blocked() {
		t.Error("a rejected SetAllowlist partially applied its entries")
	}
	if res := m.Check("admin"); res.Blocked() {
		t.Error("a rejected SetAllowlist discarded the previous allowlist")
	}
	if got := m.Allowlist(); len(got) != 1 || got[0] != "admin" {
		t.Errorf("Allowlist() = %v, want the previous set [admin]", got)
	}
}

func TestSetAllowlistRejectsDuplicateSkeletons(t *testing.T) {
	t.Parallel()
	m := blockedMatcher(t)

	// "admin" and "adm1n" are the same entry to this engine; accepting both
	// would let one spelling silently shadow the other in a listing.
	err := m.SetAllowlist([]string{"admin", "adm1n"})
	if err == nil {
		t.Fatal("SetAllowlist accepted two entries sharing a skeleton")
	}
	if !strings.Contains(err.Error(), "share a skeleton") {
		t.Errorf("error = %v, want it to name the shared skeleton", err)
	}
}

func TestSetAllowlistOnUnbuiltMatcher(t *testing.T) {
	t.Parallel()

	// A zero Matcher is not usable, and an allowlist set on one must not read
	// as success: a caller that believed the edit landed would think a hole was
	// open or closed when neither is true.
	var zero Matcher
	if err := zero.SetAllowlist([]string{"admin"}); err == nil {
		t.Error("SetAllowlist on a zero Matcher returned no error")
	}
	if got := zero.Allowlist(); got != nil {
		t.Errorf("Allowlist() on a zero Matcher = %v, want nil", got)
	}

	var nilM *Matcher
	if err := nilM.SetAllowlist([]string{"admin"}); err == nil {
		t.Error("SetAllowlist on a nil Matcher returned no error")
	}
	if got := nilM.Allowlist(); got != nil {
		t.Errorf("Allowlist() on a nil Matcher = %v, want nil", got)
	}
}

// TestAllowlistListingIsSortedAndCopied pins that a listing is stable and that
// the caller cannot reach into the matcher through it.
func TestAllowlistListingIsSortedAndCopied(t *testing.T) {
	t.Parallel()
	m := blockedMatcher(t)

	if err := m.SetAllowlist([]string{"charlie", "alpha", "bravo"}); err != nil {
		t.Fatalf("SetAllowlist: %v", err)
	}
	got := m.Allowlist()
	want := []string{"alpha", "bravo", "charlie"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Allowlist() = %v, want %v", got, want)
		}
	}

	got[0] = "mutated"
	if again := m.Allowlist(); again[0] != "alpha" {
		t.Error("mutating the returned slice changed the matcher's allowlist")
	}
}

// TestAllowlistConcurrentEditAndCheck exercises the atomic swap under -race: a
// Check must see either the whole old set or the whole new one, never a
// half-built map.
func TestAllowlistConcurrentEditAndCheck(t *testing.T) {
	t.Parallel()
	m := blockedMatcher(t)

	var wg sync.WaitGroup
	for i := range 4 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for range 100 {
				entries := []string{"admin"}
				if i%2 == 0 {
					entries = nil
				}
				if err := m.SetAllowlist(entries); err != nil {
					t.Errorf("SetAllowlist: %v", err)
					return
				}
			}
		}(i)
	}
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 100 {
				// The verdict may legitimately be either, but it must always be
				// a decided one -- never the unavailable-engine zero value.
				if res := m.Check("admin"); res.Reason == ReasonEngineUnavailable {
					t.Error("Check saw an unavailable engine during a concurrent edit")
					return
				}
			}
		}()
	}
	wg.Wait()
}

// TestAllowlistedIdentifierPassesTheRealMatcherFromDefaultLists exercises the
// allowlist against the real curated lists rather than a test fixture, so the
// exemption is shown to work on the engine the system actually runs.
func TestAllowlistedIdentifierPassesTheRealMatcherFromDefaultLists(t *testing.T) {
	t.Parallel()
	// Built from DefaultLists rather than taken from DefaultMatcher, which is a
	// process-wide singleton: SetAllowlist mutates the matcher it is called on,
	// so allowlisting through the shared instance would change the engine every
	// other test in the package is asserting against.
	m, err := NewMatcher(DefaultLists()...)
	if err != nil {
		t.Fatalf("NewMatcher(DefaultLists): %v", err)
	}

	if res := m.Check("admin"); !res.Blocked() {
		t.Fatal("precondition failed: \"admin\" is not blocked by the default lists")
	}
	if err := m.SetAllowlist([]string{"admin"}); err != nil {
		t.Fatalf("SetAllowlist: %v", err)
	}
	if res := m.Check("admin"); res.Blocked() {
		t.Error("allowlisted identifier blocked by the default matcher")
	}
	// A different blocked identifier must remain blocked: the entry is not a
	// switch that disables the list.
	if res := m.Check("root"); !res.Blocked() {
		t.Error("an entry for \"admin\" also exempted \"root\"")
	}
}

// TestAllowlistPointerIdentityIsStable is the property an enforcement choke
// point depends on. A caller that captured this *Matcher must observe a runtime
// edit; that is only true if the edit mutates through the pointer rather than
// producing a new Matcher.
func TestAllowlistPointerIdentityIsStable(t *testing.T) {
	t.Parallel()
	m := blockedMatcher(t)

	// Stand in for a downstream component that captured the matcher at its own
	// construction and never re-reads it.
	captured := m

	if res := captured.Check("admin"); !res.Blocked() {
		t.Fatal("precondition failed: \"admin\" was not blocked")
	}
	if err := m.SetAllowlist([]string{"admin"}); err != nil {
		t.Fatalf("SetAllowlist: %v", err)
	}
	if res := captured.Check("admin"); res.Blocked() {
		t.Error("a runtime allowlist edit did not reach a previously captured matcher")
	}
}
