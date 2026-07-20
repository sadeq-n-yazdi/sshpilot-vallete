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
		for _, o := range got {
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

// TestTableVersionIsSet documents that the ruleset revision is exported and
// must be bumped whenever a table above changes.
func TestTableVersionIsSet(t *testing.T) {
	if TableVersion < 1 {
		t.Errorf("TableVersion = %d, want a positive revision", TableVersion)
	}
}
