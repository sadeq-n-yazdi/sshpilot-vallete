package nameguard_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/blocklist"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/nameguard"
)

func mustDefault(t *testing.T) *nameguard.Guard {
	t.Helper()
	g, err := nameguard.Default()
	if err != nil {
		t.Fatalf("nameguard.Default(): %v", err)
	}
	return g
}

// TestOrdinaryNamesPass pins names that must keep working. Over-blocking is a
// product-breaking regression, and a blocklist nobody can register around is
// as bad as no blocklist: these are the canary for a folding table that grew
// too aggressive.
func TestOrdinaryNamesPass(t *testing.T) {
	t.Parallel()
	g := mustDefault(t)
	for _, name := range []string{
		"alice", "bob-smith", "acme-corp", "laptops", "personal",
		"work-servers", "team-blue", "j0hn-doe-7", "raspberry-pi", "ci-runners",
	} {
		for _, op := range []nameguard.Op{nameguard.OpCreate, nameguard.OpRename} {
			if err := g.Check(nameguard.KindHandle, op, name); err != nil {
				t.Errorf("Check(handle, %v, %q) = %v, want nil", op, name, err)
			}
			if err := g.Check(nameguard.KindKeySetName, op, name); err != nil {
				t.Errorf("Check(set, %v, %q) = %v, want nil", op, name, err)
			}
		}
	}
}

// TestBlockedTermsRefused covers the reachable evasions. Handles and set names
// are ASCII slugs, so leetspeak and separator padding -- not homoglyphs -- are
// the forms an attacker can actually submit here; see TestHomoglyphRefused for
// the Unicode case.
func TestBlockedTermsRefused(t *testing.T) {
	t.Parallel()
	g := mustDefault(t)
	for _, name := range []string{
		"admin", "adm1n", "ad-min", "4dm1n", "root", "r00t",
		"support", "security", "official", "staff", "api", "healthz",
	} {
		for _, op := range []nameguard.Op{nameguard.OpCreate, nameguard.OpRename} {
			err := g.Check(nameguard.KindHandle, op, name)
			if !errors.Is(err, domain.ErrBlockedName) {
				t.Errorf("Check(handle, %v, %q) = %v, want ErrBlockedName", op, name, err)
			}
			err = g.Check(nameguard.KindKeySetName, op, name)
			if !errors.Is(err, domain.ErrBlockedName) {
				t.Errorf("Check(set, %v, %q) = %v, want ErrBlockedName", op, name, err)
			}
		}
	}
}

// TestRenameIsEnforced states the rename invariant on its own rather than
// leaving it implied by a table. Rename is the enforcement point most likely
// to be dropped, and it is the one that lets an actor land on a blocked name
// after the fact by claiming a permitted one first.
func TestRenameIsEnforced(t *testing.T) {
	t.Parallel()
	g := mustDefault(t)
	for _, k := range []nameguard.Kind{nameguard.KindHandle, nameguard.KindKeySetName, nameguard.KindDeviceName} {
		if err := g.Check(k, nameguard.OpRename, "admin"); !errors.Is(err, domain.ErrBlockedName) {
			t.Errorf("Check(%v, rename, \"admin\") = %v, want ErrBlockedName", k, err)
		}
		// Same verdict either way: a rule that differed by Op would be the
		// bypass rename exists to close.
		if err := g.Check(k, nameguard.OpCreate, "admin"); !errors.Is(err, domain.ErrBlockedName) {
			t.Errorf("Check(%v, create, \"admin\") = %v, want ErrBlockedName", k, err)
		}
	}
}

// TestHomoglyphRefused feeds a confusable through the real Fb1 normalization.
// It runs on KindDeviceName because that is the Kind whose charset rule
// permits non-ASCII, so it is where a homoglyph reaches the blocklist rather
// than being stopped earlier -- and it is the Kind C1 will wire.
func TestHomoglyphRefused(t *testing.T) {
	t.Parallel()
	g := mustDefault(t)
	// Cyrillic а (U+0430), Cyrillic о (U+043E), Cyrillic ѕ (U+0455) and Greek
	// capital lunate sigma Ϲ (U+03F9) -- none of these are the ASCII letters
	// they render as, and each folds to one under the Fb1 tables.
	for _, name := range []string{"аdmin", "rооt", "ѕupport", "Ϲonsole"} {
		if blocklist.Skeleton(name) == name {
			t.Fatalf("Skeleton(%q) did not fold; the test input is not confusable", name)
		}
		if err := g.Check(nameguard.KindDeviceName, nameguard.OpCreate, name); !errors.Is(err, domain.ErrBlockedName) {
			t.Errorf("Check(device, create, %q) = %v, want ErrBlockedName", name, err)
		}
	}
	// The same homoglyph as a handle is refused too -- by the ASCII charset
	// rule, which is a different error but still a refusal. Asserting the
	// refusal (not the reason) is the point: there is no spelling of "admin"
	// that lands a handle.
	if err := g.Check(nameguard.KindHandle, nameguard.OpCreate, "аdmin"); err == nil {
		t.Error("Check(handle, create, cyrillic-admin) = nil, want refusal")
	}
}

// TestConsultationFailureRefuses is the fail-closed invariant. A guard that
// cannot consult the blocklist must refuse, because a name allowed through
// during a fault is claimed permanently.
func TestConsultationFailureRefuses(t *testing.T) {
	t.Parallel()
	// Each of these is a way the guard can end up unable to reach a verdict:
	// never constructed, constructed without a matcher, or holding a matcher
	// that was never compiled by NewMatcher.
	cases := map[string]*nameguard.Guard{
		"nil guard":    nil,
		"nil matcher":  nameguard.New(nil),
		"zero matcher": nameguard.New(&blocklist.Matcher{}),
	}
	for name, g := range cases {
		// "alice" is an ordinary name the working guard allows, so a refusal
		// here can only come from the consultation failing.
		if err := g.Check(nameguard.KindHandle, nameguard.OpCreate, "alice"); err == nil {
			t.Errorf("%s: Check(handle, create, \"alice\") = nil, want refusal", name)
		} else if !errors.Is(err, domain.ErrBlockedName) {
			t.Errorf("%s: Check = %v, want ErrBlockedName", name, err)
		}
	}
}

// mustMatcher builds a matcher over a single tiny list, used to prove the
// guard consults whatever matcher it was given rather than a global.
func mustMatcher(t *testing.T) *blocklist.Matcher {
	t.Helper()
	m, err := blocklist.NewMatcher(blocklist.List{
		Name:  "test",
		Mode:  blocklist.MatchWholeSkeleton,
		Terms: []string{"forbidden"},
	})
	if err != nil {
		t.Fatalf("blocklist.NewMatcher(): %v", err)
	}
	return m
}

// TestGuardUsesInjectedMatcher proves Check consults the Guard's own matcher.
// Without this, a guard that ignored its matcher and consulted a package
// global would pass every other test here.
func TestGuardUsesInjectedMatcher(t *testing.T) {
	t.Parallel()
	g := nameguard.New(mustMatcher(t))
	if err := g.Check(nameguard.KindHandle, nameguard.OpCreate, "forbidden"); !errors.Is(err, domain.ErrBlockedName) {
		t.Errorf("Check(handle, create, \"forbidden\") = %v, want ErrBlockedName", err)
	}
	// "admin" is in the DEFAULT lists but not in this matcher's list, so a
	// guard honoring its injected matcher must allow it.
	if err := g.Check(nameguard.KindHandle, nameguard.OpCreate, "admin"); err != nil {
		t.Errorf("Check(handle, create, \"admin\") with custom list = %v, want nil", err)
	}
}

// TestRefusalDoesNotNameTheRule is the no-oracle invariant. The refusal must
// not disclose the matched term, the list it came from, or the match mode:
// each disclosure turns one rejected registration into one bit of the curated
// blocklist.
func TestRefusalDoesNotNameTheRule(t *testing.T) {
	t.Parallel()
	g := mustDefault(t)
	err := g.Check(nameguard.KindHandle, nameguard.OpCreate, "adm1n")
	if !errors.Is(err, domain.ErrBlockedName) {
		t.Fatalf("Check = %v, want ErrBlockedName", err)
	}
	msg := err.Error()
	// The matched term, the list names, and the mode names must all be absent.
	forbidden := []string{"admin", "adm1n", "routing", "impersonation", "offensive", "whole", "substring", "system"}
	for _, s := range forbidden {
		if strings.Contains(strings.ToLower(msg), s) {
			t.Errorf("refusal %q leaks %q", msg, s)
		}
	}
	// Two different blocked terms from two different lists must be
	// indistinguishable by their message.
	other := g.Check(nameguard.KindHandle, nameguard.OpCreate, "healthz")
	if other == nil {
		t.Fatal(`Check("healthz") = nil, want refusal`)
	}
	if other.Error() != msg {
		t.Errorf("refusals differ by term: %q vs %q", msg, other.Error())
	}
}

// TestSyntaxFailuresAreDistinctFromBlocks keeps the two refusal classes apart:
// a malformed name must get the actionable syntax error, not the vague one.
func TestSyntaxFailuresAreDistinctFromBlocks(t *testing.T) {
	t.Parallel()
	g := mustDefault(t)
	for _, tc := range []struct {
		kind nameguard.Kind
		name string
	}{
		{nameguard.KindHandle, ""},
		{nameguard.KindHandle, "Upper"},
		{nameguard.KindHandle, "-lead"},
		{nameguard.KindHandle, strings.Repeat("a", 65)},
		{nameguard.KindKeySetName, "has space"},
		{nameguard.KindDeviceName, ""},
		{nameguard.KindDeviceName, " lead"},
	} {
		err := g.Check(tc.kind, nameguard.OpCreate, tc.name)
		if !errors.Is(err, domain.ErrInvalidInput) {
			t.Errorf("Check(%v, create, %q) = %v, want ErrInvalidInput", tc.kind, tc.name, err)
		}
	}
}

// TestUnknownKindAndOpRefused covers the zero values. A caller that left Kind
// or Op unset must be refused rather than defaulting to some rule.
func TestUnknownKindAndOpRefused(t *testing.T) {
	t.Parallel()
	g := mustDefault(t)
	for _, k := range []nameguard.Kind{nameguard.KindInvalid, nameguard.Kind(200)} {
		if err := g.Check(k, nameguard.OpCreate, "alice"); !errors.Is(err, domain.ErrInvalidInput) {
			t.Errorf("Check(%v, create, \"alice\") = %v, want ErrInvalidInput", k, err)
		}
	}
	for _, op := range []nameguard.Op{nameguard.OpInvalid, nameguard.Op(200)} {
		if err := g.Check(nameguard.KindHandle, op, "alice"); !errors.Is(err, domain.ErrInvalidInput) {
			t.Errorf("Check(handle, %v, \"alice\") = %v, want ErrInvalidInput", op, err)
		}
	}
}

// TestDeviceKindWorks pins the C1 seam: KindDeviceName is implemented and
// enforced here even though Fb4 wires no device call site. If this fails, C1
// cannot adopt the seam by calling Check alone.
func TestDeviceKindWorks(t *testing.T) {
	t.Parallel()
	g := mustDefault(t)
	if err := g.Check(nameguard.KindDeviceName, nameguard.OpCreate, "Sadeq's Laptop"); err != nil {
		t.Errorf("Check(device, create, ordinary name) = %v, want nil", err)
	}
	if err := g.Check(nameguard.KindDeviceName, nameguard.OpCreate, "root"); !errors.Is(err, domain.ErrBlockedName) {
		t.Errorf("Check(device, create, \"root\") = %v, want ErrBlockedName", err)
	}
}

// TestEmptySkeletonRefused covers an input that is syntactically a valid
// device name but reduces to nothing. It must be refused: no blocklist entry
// can ever speak to it, so permitting it would create a name no future list
// can reach.
func TestEmptySkeletonRefused(t *testing.T) {
	t.Parallel()
	g := mustDefault(t)
	if err := g.Check(nameguard.KindDeviceName, nameguard.OpCreate, "..."); !errors.Is(err, domain.ErrBlockedName) {
		t.Errorf("Check(device, create, \"...\") = %v, want ErrBlockedName", err)
	}
}

// TestKindAndOpStrings pins the log spellings. They must never carry user
// input, so they are fixed strings and are asserted as such.
func TestKindAndOpStrings(t *testing.T) {
	t.Parallel()
	kinds := map[nameguard.Kind]string{
		nameguard.KindHandle: "handle", nameguard.KindKeySetName: "set name",
		nameguard.KindDeviceName: "device name", nameguard.KindInvalid: "invalid",
		nameguard.Kind(200): "unknown",
	}
	for k, want := range kinds {
		if got := k.String(); got != want {
			t.Errorf("Kind(%d).String() = %q, want %q", k, got, want)
		}
	}
	ops := map[nameguard.Op]string{
		nameguard.OpCreate: "create", nameguard.OpRename: "rename",
		nameguard.OpInvalid: "invalid", nameguard.Op(200): "unknown",
	}
	for o, want := range ops {
		if got := o.String(); got != want {
			t.Errorf("Op(%d).String() = %q, want %q", o, got, want)
		}
	}
}

// TestDefaultBuilds pins that Default returns a usable guard over the real
// curated lists.
func TestDefaultBuilds(t *testing.T) {
	t.Parallel()
	g, err := nameguard.Default()
	if err != nil {
		t.Fatalf("Default() = %v, want nil", err)
	}
	if g == nil {
		t.Fatal("Default() returned a nil guard with no error")
	}
}
