package blocklist

import (
	"strings"
	"sync"
	"testing"
)

// TestDefaultListsCompile is the first thing to break if a curated term is
// mis-typed. Every validation NewMatcher performs -- empty skeletons, duplicate
// skeletons, bad modes -- runs over the shipped data here.
func TestDefaultListsCompile(t *testing.T) {
	if _, err := DefaultMatcher(); err != nil {
		t.Fatalf("the shipped lists do not compile: %v", err)
	}
}

// TestDefaultListsAreFreshCopies pins the promise on DefaultLists: a caller may
// append to or edit what it gets back without affecting anyone else's copy.
// Fb3 composes lists this way, so a shared backing array would be a bug that
// only appeared once two callers existed.
func TestDefaultListsAreFreshCopies(t *testing.T) {
	first := DefaultLists()
	second := DefaultLists()

	if len(first) != len(second) {
		t.Fatalf("DefaultLists() returned %d lists then %d", len(first), len(second))
	}
	first[0].Name = "clobbered"
	first[0].Terms[0] = "clobbered"

	if second[0].Name == "clobbered" || second[0].Terms[0] == "clobbered" {
		t.Fatal("DefaultLists() shares state between calls")
	}
	if _, err := DefaultMatcher(); err != nil {
		t.Fatalf("DefaultMatcher broke after a caller edited its own copy: %v", err)
	}
}

// TestEveryDefaultTermHasANonEmptySkeleton is the invariant that would do the
// most damage if it were violated in a substring list: the empty string is a
// substring of every string, so a single such term would block every identifier
// the service can ever issue. NewMatcher refuses it, and this checks the
// shipped data never asks it to.
func TestEveryDefaultTermHasANonEmptySkeleton(t *testing.T) {
	for _, l := range DefaultLists() {
		for _, term := range l.Terms {
			if Skeleton(term) == "" {
				t.Errorf("list %q term %q has an empty skeleton", l.Name, term)
			}
		}
	}
}

// TestDefaultTermsAreSkeletonStable checks that each curated term is written in
// a form that survives folding. A term whose skeleton differs from itself still
// works -- the term is skeletonized before use -- but it means the word a
// reviewer reads is not the word being matched, and ".well-known" folding to
// "wellknown" is exactly the case where a second entry would look like extra
// coverage and be a duplicate.
//
// Terms containing separators are exempt and listed explicitly, so that adding
// one is a deliberate act rather than something that slips through.
func TestDefaultTermsAreSkeletonStable(t *testing.T) {
	// The curated terms that intentionally contain characters the fold removes.
	separatorBearing := map[string]bool{
		".well-known":      true,
		"robots.txt":       true,
		"favicon.ico":      true,
		"sitemap.xml":      true,
		"sshpilot-vallet":  true,
		"customer-service": true,
		"customer-support": true,
		"contact-us":       true,
		"verify-account":   true,
		"security-team":    true,
	}

	seenExempt := make(map[string]bool, len(separatorBearing))
	for _, l := range DefaultLists() {
		for _, term := range l.Terms {
			sk := Skeleton(term)
			if sk == term {
				continue
			}
			if !separatorBearing[term] {
				t.Errorf("list %q term %q folds to %q; write the term in its "+
					"folded form or add it to separatorBearing", l.Name, term, sk)
				continue
			}
			seenExempt[term] = true
		}
	}
	for term := range separatorBearing {
		if !seenExempt[term] {
			t.Errorf("separatorBearing lists %q, which is no longer a term "+
				"that folds; remove it", term)
		}
	}
}

// TestNoDefaultTermAppearsInTwoLists keeps the reported List unambiguous. Two
// lists can legitimately hold different terms with the same meaning, but the
// same term in two places means the Result depends on list precedence rather
// than on the data, and an administrator reading an audit record cannot tell
// which entry they need to edit.
func TestNoDefaultTermAppearsInTwoLists(t *testing.T) {
	owner := make(map[string]string)
	for _, l := range DefaultLists() {
		for _, term := range l.Terms {
			sk := Skeleton(term)
			if prev, ok := owner[sk]; ok {
				t.Errorf("term %q appears in both %q and %q", term, prev, l.Name)
				continue
			}
			owner[sk] = l.Name
		}
	}
}

// TestNoOffensiveTermIsRedundant enforces the rule recorded on offensiveTerms:
// in a substring list, a term that contains another term can never be the one
// reported, because the shorter one always matches first. Such an entry reads
// to a reviewer as coverage that does not exist.
func TestNoOffensiveTermIsRedundant(t *testing.T) {
	terms := offensiveTerms()
	for _, a := range terms {
		for _, b := range terms {
			if a == b {
				continue
			}
			if strings.Contains(Skeleton(a), Skeleton(b)) {
				t.Errorf("offensive term %q contains %q and is therefore "+
					"unreachable; drop it", a, b)
			}
		}
	}
}

// TestOffensiveTermsAvoidCommonWords is the Scunthorpe guard. Substring
// matching cannot distinguish a word from a fragment, so any term that appears
// inside an ordinary word blocks that word for every user, permanently, with no
// allowlist yet in place to relieve it.
//
// The corpus is small and deliberately weighted toward vocabulary this product
// attracts -- shell, ssh, assets, password, analytics -- plus the classic
// English traps. It is a regression net for the curation decisions recorded on
// offensiveTerms, not a proof of safety.
func TestOffensiveTermsAvoidCommonWords(t *testing.T) {
	corpus := []string{
		// Words the excluded terms would have broken; see offensiveTerms.
		"class", "classic", "assist", "assets", "password", "assign",
		"embassy", "brass", "compass", "assessment", "passive",
		"analysis", "analytics", "canal", "analog",
		"document", "documentation", "circumstance", "accumulate", "cucumber",
		"title", "constitution", "competitor", "institute", "entities",
		"shell", "shelling", "hello", "michelle", "seashell", "powershell",
		"grape", "drape", "scrape", "therapy", "therapist",
		"torpedo", "pedometer", "pedestrian",
		"raccoon", "cocoon", "tycoon",
		"spice", "suspicious", "conspicuous",
		"chink", "night", "nightly", "insignia", "designer",
		// Ordinary infrastructure and product vocabulary.
		"kubernetes", "openssh", "keypair", "fingerprint", "bastion",
		"penistone", "lightwater", "sussex", "essex",
		"shiitake", "cockpit", "cocktail", "scunner",
	}

	m := testMatcher(t, List{
		Name:  "offensive",
		Mode:  MatchSubstring,
		Terms: offensiveTerms(),
	})

	for _, word := range corpus {
		t.Run(word, func(t *testing.T) {
			if got := m.Check(word); got.Blocked() {
				t.Fatalf("the ordinary word %q is blocked by offensive term %q; "+
					"either the term is too short to be safe as a substring or "+
					"it belongs in a whole-skeleton list", word, got.Term)
			}
		})
	}
}

// TestKnownFalsePositives records the over-blocking this policy knowingly
// accepts. These are NOT bugs to fix by shortening the term list -- each term
// involved is one that must stay -- and they are not bugs to fix by weakening
// substring mode either, since embedding is the whole point of that mode.
//
// They are written down as passing assertions rather than left undiscovered so
// that the cost of the substring lists is visible in the test output, and so
// that whoever builds the Fb3 allowlist has a ready-made list of the first
// entries it needs. If one of these starts being allowed, the term that caught
// it has gone missing and this test says so.
func TestKnownFalsePositives(t *testing.T) {
	m := defaultMatcher(t)

	cases := []struct {
		input string
		why   string
	}{
		{"scunthorpe", "the eponymous case; contains the slur at position 1"},
		{"penistone-united", "not caught today, but the class is the same"},
		{"mishit", "an ordinary verb that spans s-h-i-t across the join"},
		{"clbuttic", "shows why naive replacement is not the alternative"},
	}

	var blocked, allowed []string
	for _, tc := range cases {
		if m.Check(tc.input).Blocked() {
			blocked = append(blocked, tc.input)
		} else {
			allowed = append(allowed, tc.input)
		}
	}
	// The set is asserted as a whole rather than per-case: what matters is that
	// the split is the documented one, so a change in either direction shows up.
	if len(blocked) != 2 || blocked[0] != "scunthorpe" || blocked[1] != "mishit" {
		t.Errorf("known false positives = %v; want [scunthorpe mishit]. "+
			"A change here is a real policy change: %v are allowed.", blocked, allowed)
	}
}

// TestOffensiveTermsActuallyBlock is the other direction: each curated term must
// be refused both on its own and embedded in a longer name, since embedding is
// the case the substring mode exists for.
func TestOffensiveTermsActuallyBlock(t *testing.T) {
	m := defaultMatcher(t)
	for _, term := range offensiveTerms() {
		t.Run(term, func(t *testing.T) {
			if got := m.Check(term); !got.Blocked() {
				t.Errorf("Check(%q) allowed the term itself", term)
			}
			embedded := "my" + term + "site"
			got := m.Check(embedded)
			if !got.Blocked() {
				t.Fatalf("Check(%q) allowed an embedded offensive term", embedded)
			}
			if got.Mode != MatchSubstring {
				t.Errorf("Check(%q).Mode = %v; want %v", embedded, got.Mode, MatchSubstring)
			}
		})
	}
}

// TestWholeSkeletonTermsActuallyBlock walks every routing and impersonation
// term and asserts each is refused exactly, and that appending a letter is not.
// It is the exhaustive version of the two hand-written match tests: a term
// added to lists.go but shadowed by an earlier list, or one written in a form
// that cannot be reached, fails here.
func TestWholeSkeletonTermsActuallyBlock(t *testing.T) {
	m := defaultMatcher(t)
	for _, l := range DefaultLists() {
		if l.Mode != MatchWholeSkeleton {
			continue
		}
		for _, term := range l.Terms {
			t.Run(l.Name+"/"+term, func(t *testing.T) {
				got := m.Check(term)
				if !got.Blocked() {
					t.Fatalf("Check(%q) allowed a reserved term", term)
				}
				if got.List != l.Name {
					t.Errorf("Check(%q).List = %q; want %q -- the term is "+
						"shadowed by another list", term, got.List, l.Name)
				}
				if got.Term != term {
					t.Errorf("Check(%q).Term = %q; want %q", term, got.Term, term)
				}
			})
		}
	}
}

// TestListVersionIsSet guards the audit trail. ListVersion is what lets a later
// reader tell which policy produced a stored decision, so it must be a real
// positive revision and must not be confused with TableVersion.
func TestListVersionIsSet(t *testing.T) {
	if ListVersion < 1 {
		t.Errorf("ListVersion = %d; want a positive revision", ListVersion)
	}
}

// TestDefaultMatcherIsSharedAndStable pins the two properties that make
// computing the default matcher once acceptable.
//
// Callers get the same instance, which is the point -- compiling the defaults
// skeletonizes every term, and enforcement runs on every create and rename.
// Sharing is only safe while a Matcher stays immutable, so this also checks
// that a verdict is unchanged after concurrent use: if a mutating method were
// ever added and something wrote through the shared pointer, the second read
// would disagree with the first.
func TestDefaultMatcherIsSharedAndStable(t *testing.T) {
	t.Parallel()

	first, err := DefaultMatcher()
	if err != nil {
		t.Fatalf("DefaultMatcher() error = %v", err)
	}
	second, err := DefaultMatcher()
	if err != nil {
		t.Fatalf("DefaultMatcher() error = %v", err)
	}
	if first != second {
		t.Errorf("DefaultMatcher returned distinct instances (%p, %p); the compiled lists should be shared", first, second)
	}

	before := first.Check("admin")

	var wg sync.WaitGroup
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m, err := DefaultMatcher()
			if err != nil || m != first {
				t.Errorf("concurrent DefaultMatcher() = %p, %v; want %p, nil", m, err, first)
				return
			}
			_ = m.Check("admin")
			_ = m.Check("some-unremarkable-handle")
		}()
	}
	wg.Wait()

	if after := first.Check("admin"); after != before {
		t.Errorf("verdict changed after concurrent use: %+v -> %+v; a Matcher must stay immutable", before, after)
	}
}
