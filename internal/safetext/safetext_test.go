package safetext

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// TestBoundDoesNotSplitAMultiByteRune is the test this package exists for.
//
// The PRECONDITION assertion is load-bearing and is not decoration. An earlier
// fix for this same defect elsewhere in the repository shipped with a test that
// passed against the UNFIXED code, because the author computed the byte offset
// by hand and got it wrong: the cut happened to land on a character boundary,
// so the naive slice was already valid and the test never exercised the case.
// Asserting that the naive slice IS broken first is what proves the fixture
// actually straddles a rune before anything is claimed about the fix.
func TestBoundDoesNotSplitAMultiByteRune(t *testing.T) {
	for _, tc := range []struct {
		name string
		char string
	}{
		{name: "two-byte rune", char: "é"},   // 2 bytes
		{name: "three-byte rune", char: "世"}, // 3 bytes
		{name: "four-byte rune", char: "𝄞"},  // 4 bytes
	} {
		t.Run(tc.name, func(t *testing.T) {
			const maxBytes = 200
			// One byte of the multi-byte character sits before the cut and the
			// rest after it, so the naive slice must end mid-rune.
			s := strings.Repeat("a", maxBytes-1) + tc.char + strings.Repeat("b", 50)

			naive := s[:maxBytes]
			if utf8.ValidString(naive) {
				t.Fatalf("fixture does not straddle a rune: s[:%d] is already valid UTF-8, "+
					"so this test would pass against unfixed code", maxBytes)
			}

			got := Bound(s, maxBytes)
			if !utf8.ValidString(got) {
				t.Errorf("Bound produced invalid UTF-8: %q", got)
			}
			if len(got) > maxBytes {
				t.Errorf("Bound returned %d bytes, want at most %d", len(got), maxBytes)
			}
			if want := strings.Repeat("a", maxBytes-1); got != want {
				t.Errorf("Bound = %q, want the whole characters that fit", got)
			}
		})
	}
}

// TestTrimPartialRunePreservesAGenuineReplacementChar is the discriminating
// case for the size check.
//
// U+FFFD decodes as utf8.RuneError, exactly like a one-byte fragment does, so a
// implementation that tests only the RUNE cannot tell a real character the
// sender wrote from a stub the cut created -- and silently eats the real one.
// The size is what separates them: a genuine U+FFFD decodes at size 3.
func TestTrimPartialRunePreservesAGenuineReplacementChar(t *testing.T) {
	const genuine = "�"
	if len(genuine) != 3 {
		t.Fatalf("fixture: U+FFFD is %d bytes, want 3", len(genuine))
	}

	for _, tc := range []struct{ name, in string }{
		{name: "ends with U+FFFD", in: "ab" + genuine},
		{name: "only a U+FFFD", in: genuine},
		{name: "two U+FFFD", in: genuine + genuine},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := TrimPartialRune(tc.in); got != tc.in {
				t.Errorf("TrimPartialRune(%q) = %q, want it unchanged: a genuine "+
					"U+FFFD is a real character, not a fragment left by a cut", tc.in, got)
			}
		})
	}
}

// TestBoundPreservesAGenuineReplacementCharAtTheCut drives the same
// discrimination through Bound, with the cut landing exactly after a real
// U+FFFD so the character is the last thing in the retained prefix.
func TestBoundPreservesAGenuineReplacementCharAtTheCut(t *testing.T) {
	s := "aa�bbbb"
	const maxBytes = 5 // "aa" plus the three bytes of U+FFFD

	naive := s[:maxBytes]
	if !utf8.ValidString(naive) {
		t.Fatalf("fixture: s[:%d] should end on a boundary, got %q", maxBytes, naive)
	}

	got := Bound(s, maxBytes)
	if got != naive {
		t.Errorf("Bound = %q, want %q: the cut landed after a whole U+FFFD, "+
			"so nothing should be trimmed", got, naive)
	}
}

// TestTrimPartialRuneBoundaryCases is the boundary table this repair turns on.
// It moved here with the helper from the Cloudflare Origin CA client, which was
// the first place the defect was fixed.
func TestTrimPartialRuneBoundaryCases(t *testing.T) {
	for _, tc := range []struct{ name, in, want string }{
		{name: "ascii is untouched", in: "plain", want: "plain"},
		{name: "empty is untouched", in: "", want: ""},
		{name: "whole rune is kept", in: "ok…", want: "ok…"},
		{name: "one leading byte is dropped", in: "ok\xe2", want: "ok"},
		{name: "two of three bytes are dropped", in: "ok\xe2\x80", want: "ok"},
		{name: "three of four bytes are dropped", in: "ok\xf0\x9f\x92", want: "ok"},
		// A genuine U+FFFD decodes as RuneError at size 3. Dropping it would
		// mean the repair eats real characters out of the sender's message.
		{name: "a real replacement char is kept", in: "ok�", want: "ok�"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := TrimPartialRune(tc.in); got != tc.want {
				t.Errorf("TrimPartialRune(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestBoundLeavesShortStringsAlone(t *testing.T) {
	for _, tc := range []struct {
		in       string
		maxBytes int
		want     string
	}{
		{in: "", maxBytes: 10, want: ""},
		{in: "short", maxBytes: 10, want: "short"},
		{in: "exact", maxBytes: 5, want: "exact"},
		{in: "世界", maxBytes: 6, want: "世界"},
		// A non-positive bound yields nothing rather than panicking on a slice.
		{in: "anything", maxBytes: 0, want: ""},
		{in: "anything", maxBytes: -1, want: ""},
		// A bound smaller than the first rune cannot keep any whole character.
		{in: "世界", maxBytes: 2, want: ""},
	} {
		if got := Bound(tc.in, tc.maxBytes); got != tc.want {
			t.Errorf("Bound(%q, %d) = %q, want %q", tc.in, tc.maxBytes, got, tc.want)
		}
	}
}

// TestTrimPartialRuneLeavesPreexistingInvalidBytesAlone pins the documented
// boundary of this package: it repairs what a CUT introduced, and does not
// promise to sanitize input that was already malformed.
func TestTrimPartialRuneLeavesPreexistingInvalidBytesAlone(t *testing.T) {
	// Four continuation bytes: more than a cut can leave, so the capped loop
	// stops and the remainder is returned as-is rather than looping the string
	// away.
	in := "ok\x80\x80\x80\x80"
	got := TrimPartialRune(in)
	if !strings.HasPrefix(got, "ok") {
		t.Errorf("TrimPartialRune(%q) = %q, want the valid prefix kept", in, got)
	}
	if len(got) < len("ok") {
		t.Errorf("TrimPartialRune(%q) = %q, trimmed past the fragment", in, got)
	}
}
