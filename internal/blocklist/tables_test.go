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

// TestFoldRangeBoundaries exercises each arithmetic range at its edges and
// just outside them, where an off-by-one would silently mis-map a codepoint.
func TestFoldRangeBoundaries(t *testing.T) {
	cases := []struct {
		name string
		in   rune
		want rune
		ok   bool
	}{
		{"below fullwidth", 0xFF00, 0, false},
		{"fullwidth first", 0xFF01, '!', true},
		{"fullwidth last", 0xFF5E, '~', true},
		{"above fullwidth", 0xFF5F, 0, false},
		{"math first", 0x1D400, 'a', true},
		{"math last", 0x1D6A3, 'z', true},
		{"math dotless i", 0x1D6A4, 'i', true},
		{"math dotless j", 0x1D6A5, 'j', true},
		{"unassigned after dotless j", 0x1D6A6, 0, false},
		{"unassigned before math greek", 0x1D6A7, 0, false},
		{"math greek first is capital alpha", 0x1D6A8, 'α', true},
		{"math greek capital theta symbol", 0x1D6B9, 'θ', true},
		{"math greek small alpha", 0x1D6C2, 'α', true},
		{"math greek small omicron", 0x1D6D0, 'ο', true},
		{"math greek nabla is not folded", 0x1D6C1, 0, false},
		{"math greek partial differential is not folded", 0x1D6DB, 0, false},
		{"math greek last unit first rune", 0x1D790, 'α', true},
		{"math greek last", 0x1D7C9, 'π', true},
		{"math capital digamma", 0x1D7CA, 0x03DD, true},
		{"math small digamma", 0x1D7CB, 0x03DD, true},
		{"unassigned after digamma", 0x1D7CC, 0, false},
		{"unassigned before math digits", 0x1D7CD, 0, false},
		{"math digits first", 0x1D7CE, '0', true},
		{"math digits last", 0x1D7FF, '9', true},
		{"above math digits", 0x1D800, 0, false},
		{"circled capital first", 0x24B6, 'a', true},
		{"circled capital last", 0x24CF, 'z', true},
		{"circled small first", 0x24D0, 'a', true},
		{"circled small last", 0x24E9, 'z', true},
		{"circled one", 0x2460, '1', true},
		{"circled nine", 0x2468, '9', true},
		{"circled ten is not folded", 0x2469, 0, false},
		{"circled zero", 0x24EA, '0', true},
		{"plain ascii is not a range", 'a', 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := foldRange(tc.in)
			if ok != tc.ok || (ok && got != tc.want) {
				t.Errorf("foldRange(%U) = (%q, %v), want (%q, %v)", tc.in, got, ok, tc.want, tc.ok)
			}
		})
	}
}

// TestMathAlphanumericBlockIsFullyReduced walks every codepoint of the
// Mathematical Alphanumeric Symbols block, U+1D400..U+1D7FF, and asserts that
// no assigned rune in it survives Skeleton.
//
// This is deliberately an exhaustive walk and not a list of interesting cases.
// The bug it exists to prevent is a RANGE GAP: foldRange once covered
// U+1D400..U+1D6A3 and U+1D7CE..U+1D7FF and nothing between, which left the
// entire Mathematical Greek block unfolded and every styled Greek letter usable
// as an impersonation vector. Hand-picked cases did not catch that and would
// not catch the next one; walking the block does, because a gap by definition
// means some rune in it maps to itself.
//
// "Reduced" means the skeleton contains no codepoint from the block. It does
// not mean ASCII: a styled Greek letter folds to the plain Greek letter, and
// the plain letters without a Latin look-alike (beta, gamma, theta, ...)
// legitimately stop there. What matters for impersonation is that the styled
// and unstyled spellings agree, which is exactly what this asserts.
func TestMathAlphanumericBlockIsFullyReduced(t *testing.T) {
	const lo, hi = 0x1D400, 0x1D7FF

	// The only assigned runes in the block with no letter or digit to fold to.
	// Both are mathematical operators rather than letterforms. Each appears
	// once per styled Greek alphabet, five times over.
	unreduced := map[rune]string{}
	for _, base := range []rune{0x1D6A8, 0x1D6E2, 0x1D71C, 0x1D756, 0x1D790} {
		unreduced[base+25] = "NABLA"
		unreduced[base+51] = "PARTIAL DIFFERENTIAL"
	}

	assigned := 0
	for r := rune(lo); r <= hi; r++ {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && !unicode.IsSymbol(r) {
			continue // unassigned holes are not reachable input
		}
		assigned++

		got := Skeleton(string(r))
		if name, ok := unreduced[r]; ok {
			if got != string(r) {
				t.Errorf("%U (%s) is a documented exception but folded to %q", r, name, got)
			}
			continue
		}
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

// TestMathGreekUnitLayout pins the internal layout of the repeating 58-rune
// styled-Greek alphabet, including the two positions where a plain arithmetic
// rule would be wrong, and asserts all five alphabets share it.
func TestMathGreekUnitLayout(t *testing.T) {
	if got := len(mathGreekUnit); got != 58 {
		t.Fatalf("mathGreekUnit has %d entries, want 58", got)
	}
	for _, base := range []rune{0x1D6A8, 0x1D6E2, 0x1D71C, 0x1D756, 0x1D790} {
		for off, want := range mathGreekUnit {
			r := base + rune(off)
			got, ok := foldRange(r)
			if want == 0 {
				if ok {
					t.Errorf("%U (offset %d) folded to %q, want no fold", r, off, got)
				}
				continue
			}
			if !ok || got != want {
				t.Errorf("foldRange(%U) (offset %d) = (%q, %v), want (%q, true)", r, off, got, ok, want)
			}
		}
	}
	// Position 17 is CAPITAL THETA SYMBOL filling the U+03A2 reserved hole, and
	// position 43 is FINAL SIGMA. Arithmetic from U+0391 gets the first wrong.
	if mathGreekUnit[17] != 'θ' {
		t.Errorf("offset 17 = %q, want theta; U+03A2 is a reserved hole", mathGreekUnit[17])
	}
	if mathGreekUnit[43] != 'ς' {
		t.Errorf("offset 43 = %q, want final sigma", mathGreekUnit[43])
	}
	// Every fold target must be lowercase: foldRange runs after the case fold,
	// so a capital target could never reach the lowercase-keyed confusables.
	for off, r := range mathGreekUnit {
		if r != 0 && unicode.ToLower(r) != r {
			t.Errorf("offset %d target %q is not lowercase and cannot reach confusables", off, r)
		}
	}
}

// TestTableVersionIsSet documents that the ruleset revision is exported and
// must be bumped whenever a table above changes.
func TestTableVersionIsSet(t *testing.T) {
	if TableVersion < 1 {
		t.Errorf("TableVersion = %d, want a positive revision", TableVersion)
	}
}
