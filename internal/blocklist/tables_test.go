package blocklist

import (
	"testing"
	"unicode"
	"unicode/utf8"
)

// TestEveryEntryFoldsLikeItsTarget enforces the invariant the tables are
// designed around: a source codepoint must end up wherever its target ends up.
// Targets are ASCII letters or digits, and a digit target is deliberately
// carried on into the leetspeak stage ("¹" -> "1" -> "i"), so the assertion is
// agreement after the full pipeline rather than a literal match. A new entry
// whose target is unreachable or mis-spelled fails here.
//
// The second assertion is the one idempotence rests on: whatever the pipeline
// finally emits for a target must itself be stable.
func TestEveryEntryFoldsLikeItsTarget(t *testing.T) {
	check := func(source, target string) {
		t.Helper()
		want := Skeleton(target)
		if got := Skeleton(source); got != want {
			t.Errorf("source %q folds to %q but its target %q folds to %q", source, got, target, want)
		}
		if got := Skeleton(want); got != want {
			t.Errorf("target %q settles on %q, which is not a fixed point (%q)", target, want, got)
		}
		if want == "" {
			t.Errorf("target %q of source %q folds away to nothing", target, source)
		}
	}
	for src, target := range confusables {
		if !utf8.ValidString(target) {
			t.Errorf("confusables[%q] = %q is not valid UTF-8", src, target)
		}
		check(string(src), target)
	}
	for src, target := range leetspeak {
		check(string(src), string(target))
	}
}

// TestTableKeysAreLowercase pins the ordering assumption that lets the tables
// carry lowercase keys only: Skeleton case-folds before consulting them, so an
// uppercase key would be dead weight that never matches.
func TestTableKeysAreLowercase(t *testing.T) {
	for src := range confusables {
		if unicode.ToLower(src) != src {
			t.Errorf("confusables key %q is not lowercase and can never be reached", src)
		}
	}
}

// TestNoTableKeyIsAsciiLetter guards against an entry that would fold one
// ordinary ASCII letter into another, which would collide real identifiers.
func TestNoTableKeyIsAsciiLetter(t *testing.T) {
	for r := 'a'; r <= 'z'; r++ {
		if _, ok := confusables[r]; ok {
			t.Errorf("confusables maps ASCII letter %q; that would over-fold", r)
		}
		if _, ok := leetspeak[r]; ok {
			t.Errorf("leetspeak maps ASCII letter %q; that would over-fold", r)
		}
		if isSeparator(r) {
			t.Errorf("ASCII letter %q is treated as a separator", r)
		}
	}
}

// TestMathAlphanumericBlockIsFullyReduced walks every codepoint of the
// Mathematical Alphanumeric Symbols block, U+1D400..U+1D7FF, and asserts that
// no assigned rune in it survives Skeleton.
//
// This is deliberately an exhaustive walk and not a list of interesting cases.
// The bug it exists to prevent is a RANGE GAP: a gap by definition
// means some rune in it maps to itself.
//
// "Reduced" means the skeleton contains no codepoint from the block. It does
// not mean ASCII: a styled Greek letter folds to the plain Greek letter, and
// the plain letters without a Latin look-alike (beta, gamma, theta, ...)
// legitimately stop there. What matters for impersonation is that the styled
// and unstyled spellings agree, which is exactly what this asserts.
func TestMathAlphanumericBlockIsFullyReduced(t *testing.T) {
	const lo, hi = 0x1D400, 0x1D7FF

	assigned := 0
	for r := rune(lo); r <= hi; r++ {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && !unicode.IsSymbol(r) {
			continue // unassigned holes are not reachable input
		}
		assigned++

		got := Skeleton(string(r))
		if got == "" {
			t.Errorf("%U folded away to nothing; it should reduce, not vanish", r)
			continue
		}
		// For the styled LATIN letters and the styled digits, the assertion is
		// ASCII rather than merely "left the block". Escaping the block is not
		// enough: U+1D6A5 MATHEMATICAL ITALIC SMALL DOTLESS J decomposes to ȷ
		// (U+0237), which is outside lo..hi and so passed a block-only check
		// while leaving "blow𝚥ob" and "𝚥s" spellable past the list. A styled
		// Latin letter that lands anywhere other than plain ASCII has not been
		// reduced, it has just moved, and the plain spelling it is supposed to
		// collide with is ASCII.
		//
		// The styled GREEK letters in between are held only to the weaker
		// assertion, deliberately. Their plain spellings are plain Greek, and
		// confusables covers only the Greek letters that draw a Latin one --
		// β, γ, δ and the rest reduce to themselves and must, because folding
		// them to ASCII would be an invention, not a fold. Agreement between
		// the styled and plain spellings is the whole property there.
		latin := r <= 0x1D6A5 || r >= 0x1D7CE
		for _, o := range got {
			if latin && o > unicode.MaxASCII {
				t.Errorf("%U reduces to %U in skeleton %q, not to ASCII: it moved rather than folded", r, o, got)
			}
			if o >= lo && o <= hi {
				t.Errorf("%U survives as %U in skeleton %q: styled and plain spellings disagree", r, o, got)
			}
		}
		if again := Skeleton(got); again != got {
			t.Errorf("%U folds to %q which is not a fixed point (%q)", r, got, again)
		}
	}

	// A miscount here means the walk silently stopped covering the block, or
	// that a Go release brought a newer Unicode version that assigns codepoints
	// this block did not have. Both warrant a look rather than a number bump:
	// newly assigned runes in this block are exactly the case that reopens the
	// gap. Treat a failure here as "re-audit the block", not as flakiness.
	if want := 996; assigned != want {
		t.Errorf("walked %d assigned runes in the block, want %d", assigned, want)
	}
}

// TestEveryConfusablePreimageReachesItsTarget is the guard for the whole class
// of defect that version 6 repaired. It is the test that stops the next
// recurrence, and it is deliberately not the test the obvious reading suggests.
//
// # What went wrong
//
// Version 4 put NFKD at the front of the pipeline. NFKD folds by compatibility;
// confusables folds by drawn shape. Where the two disagree, whichever runs
// first wins, and NFKD running first rewrites a source into a base form the
// table is not keyed on -- so the entry stops firing and a codepoint that used
// to fold survives unfolded. That is a silent weakening: nothing errors, a
// reserved word simply becomes spellable again.
//
// # Why this sweeps preimages rather than the table's keys
//
// The tempting guard is "for each key k in confusables, assert Skeleton(k)
// folds to its value". That guard is USELESS here: it is green on the broken
// code. U+03F2 ϲ folded correctly even while the defect was live, because NFKD
// happens to decompose it to ς, which has its own entry. The bypass was only
// ever visible one step up, through the uppercase preimage U+03F9 Ϲ, which
// lowercases to ϲ but decomposes to Σ and lowercases to σ -- nothing.
//
// So the sweep is over the codepoint space, not over the table. Every rune that
// case-folds onto a confusables key is a way of writing that key, and every one
// of them must reach the same skeleton the key does. "Ϲonsole" == "console" is
// the property; the table entry is only the mechanism.
//
// # Why it is phrased as an outcome and not as a rule about entries
//
// It would be possible to assert instead that no confusables key is a
// compatibility form NFKD folds elsewhere -- a rule about what entries are
// allowed to look like. That would be wrong twice over. It would reject
// perfectly safe future entries, because stage 0 now consults the table before
// NFKD can touch the source, so such a key is no longer vulnerable. And it
// would not have caught this defect anyway, for the reason above: the key was
// fine, its preimage was not. Asserting the outcome fails if and only if the
// fold is actually broken, which is the only condition worth failing on.
func TestEveryConfusablePreimageReachesItsTarget(t *testing.T) {
	checked := 0
	for r := rune(0); r <= unicode.MaxRune; r++ {
		if !utf8.ValidRune(r) {
			continue
		}
		target, ok := confusables[unicode.ToLower(r)]
		if !ok {
			continue
		}
		checked++
		want := Skeleton(target)
		if got := Skeleton(string(r)); got != want {
			t.Errorf("%U case-folds onto confusable %q (target %q, skeleton %q) but folds to %q",
				r, unicode.ToLower(r), target, want, got)
		}
	}
	// Every key is its own preimage, so the sweep can never find fewer runes
	// than the table has entries. Finding exactly that many would mean the
	// walk stopped covering the uppercase forms, which is the half that
	// carries the defect this test exists for.
	if checked <= len(confusables) {
		t.Errorf("swept %d preimages for %d entries; the uppercase forms are not being reached",
			checked, len(confusables))
	}
}

// TestTableVersionIsSet documents that the ruleset revision is exported and
// must be bumped whenever a table above changes.
func TestTableVersionIsSet(t *testing.T) {
	if TableVersion < 1 {
		t.Errorf("TableVersion = %d, want a positive revision", TableVersion)
	}
}

// TestAmbiguousReadingsAreASCII enforces the invariant candidateSkeletons
// relies on to scan a skeleton byte by byte.
//
// Every key and every reading must be a single ASCII byte. If one were not,
// two things would break at once: a multi-byte rune's continuation bytes could
// be mistaken for a key, and substituting a reading of a different width would
// shift every byte offset after it, so the candidates built from the remaining
// positions would be garbage. Both failures are silent -- they produce wrong
// candidates, not a panic -- which is why this is a test and not a comment.
func TestAmbiguousReadingsAreASCII(t *testing.T) {
	for key, readings := range ambiguousReadings {
		if key >= 0x80 {
			t.Errorf("ambiguousReadings key %#x is not ASCII", key)
		}
		if len(readings) == 0 {
			t.Errorf("ambiguousReadings[%q] has no readings; the entry does nothing", key)
		}
		for _, r := range readings {
			if r >= 0x80 {
				t.Errorf("ambiguousReadings[%q] reading %#x is not ASCII", key, r)
			}
			if r == key {
				t.Errorf("ambiguousReadings[%q] lists its own key as an alternative; "+
					"candidates[0] already covers that reading", key)
			}
		}
	}
}

// TestAmbiguousKeysAreSkeletonFixedPoints checks that every key is something a
// skeleton can actually contain.
//
// ambiguousReadings is keyed on the pipeline's OUTPUT, so a key that the
// pipeline never emits would be an entry that can never fire -- it would read
// to a reviewer as coverage that does not exist. A key must therefore survive
// Skeleton unchanged.
func TestAmbiguousKeysAreSkeletonFixedPoints(t *testing.T) {
	for key := range ambiguousReadings {
		s := string(rune(key))
		if got := Skeleton(s); got != s {
			t.Errorf("ambiguousReadings key %q folds to %q; a key the pipeline "+
				"never emits can never fire", s, got)
		}
	}
}

// TestAmbiguousReadingsAreNotThemselvesAmbiguous closes the loop on the
// expansion being one-way and therefore terminating.
//
// If a reading were itself a key, expanding it would produce a further reading,
// and the "candidates differ from the skeleton only at ambiguous positions"
// property that bounds the set at 2^k would no longer hold. The one-way
// direction is a deliberate false-positive decision (see ambiguousReadings);
// this makes an accidental reversal a test failure.
func TestAmbiguousReadingsAreNotThemselvesAmbiguous(t *testing.T) {
	for key, readings := range ambiguousReadings {
		for _, r := range readings {
			if _, isKey := ambiguousReadings[r]; isKey {
				t.Errorf("ambiguousReadings[%q] reads as %q, which is itself a key; "+
					"the expansion must be one-way", key, r)
			}
		}
	}
}

// TestMaxCandidateSkeletonsMatchesTheRuneBound keeps the two constants from
// drifting apart. maxCandidateSkeletons is only meaningful as the exact ceiling
// implied by maxAmbiguousRunes, and a bound that overstated the real one would
// make the fail-closed test pass while the engine did more work than intended.
func TestMaxCandidateSkeletonsMatchesTheRuneBound(t *testing.T) {
	if maxCandidateSkeletons != 1<<maxAmbiguousRunes {
		t.Errorf("maxCandidateSkeletons = %d; want 1<<%d = %d",
			maxCandidateSkeletons, maxAmbiguousRunes, 1<<maxAmbiguousRunes)
	}
	if maxAmbiguousRunes < 1 {
		t.Errorf("maxAmbiguousRunes = %d; expansion would be disabled entirely",
			maxAmbiguousRunes)
	}
}

// TestAmbiguousReadingsCannotOvershootTheCandidateCeiling ties the two bounds
// together.
//
// maxAmbiguousRunes bounds POSITIONS and maxCandidateSkeletons bounds
// CANDIDATES, and the second only follows from the first while every entry has
// exactly one alternative reading. A two-reading entry would expand 3^k and
// overshoot the ceiling. candidateSkeletons checks the real product and fails
// closed, so this cannot become a bypass, but an entry that made every
// identifier containing it too-ambiguous-to-check would be a severe and
// silent over-block. This test makes that a review-time failure instead.
func TestAmbiguousReadingsCannotOvershootTheCandidateCeiling(t *testing.T) {
	worst := 1
	for _, readings := range ambiguousReadings {
		if branch := 1 + len(readings); branch > worst {
			worst = branch
		}
	}
	total := 1
	for range maxAmbiguousRunes {
		total *= worst
		if total > maxCandidateSkeletons {
			t.Fatalf("a skeleton with %d ambiguous positions can expand to %d "+
				"candidates, past the ceiling of %d; maxAmbiguousRunes and "+
				"maxCandidateSkeletons no longer agree",
				maxAmbiguousRunes, total, maxCandidateSkeletons)
		}
	}
}
