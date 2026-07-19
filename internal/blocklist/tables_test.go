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
		{"above math letters", 0x1D6A4, 0, false},
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

// TestTableVersionIsSet documents that the ruleset revision is exported and
// must be bumped whenever a table above changes.
func TestTableVersionIsSet(t *testing.T) {
	if TableVersion < 1 {
		t.Errorf("TableVersion = %d, want a positive revision", TableVersion)
	}
}
