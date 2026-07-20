package blocklist

import (
	"strings"
	"testing"
)

// FuzzCheck asserts the Matcher's contract on arbitrary input. Skeleton's own
// fuzz test covers the fold; this covers the decision built on it.
//
// The properties are chosen to be ones a plausible refactor breaks:
//
//   - Check never panics, including on invalid UTF-8 and over-length input.
//   - The verdict is a total function: every Result has a Reason, and the
//     Reason and the Allowed flag always agree. A path that sets one without
//     the other is the shape a fail-open bug takes.
//   - Blocking is stable under re-checking, which is the matcher-level
//     consequence of Skeleton's idempotence.
//   - Anything that survives is reported with a term, so no Result can say
//     "blocked" without naming the entry an administrator would have to edit.
func FuzzCheck(f *testing.F) {
	seeds := []string{
		"", " ", "-_.", "admin", "ADMIN", "аdmin", "ａｄｍｉｎ", "a-d-m-i-n",
		"4dm1n", "@dm1n", "admiη", "\U0001d41a\U0001d41d\U0001d426\U0001d422\U0001d427",
		"roots", "badminton", "administrivia", "apiary", "root2689",
		"sadeq", "my-key-set", "prod", "staging",
		"\xff\xfe", "ad\xc3min", "漢字", "a\u200bd\u0301min",
		strings.Repeat("a", MaxInputBytes), strings.Repeat("a", MaxInputBytes+1),
	}
	for _, s := range seeds {
		f.Add(s)
	}

	m, err := DefaultMatcher()
	if err != nil {
		f.Fatalf("DefaultMatcher: %v", err)
	}

	f.Fuzz(func(t *testing.T, in string) {
		got := m.Check(in)

		// Allowed and Reason must never disagree.
		switch got.Reason {
		case ReasonAllowed:
			if !got.Allowed {
				t.Fatalf("Check(%q) = %+v: reason allowed but Allowed is false", in, got)
			}
		case ReasonEngineUnavailable, ReasonEmptySkeleton, ReasonTooLong, ReasonBlockedTerm:
			if got.Allowed {
				t.Fatalf("Check(%q) = %+v: blocking reason but Allowed is true", in, got)
			}
		default:
			t.Fatalf("Check(%q) = %+v: unrecognized reason", in, got)
		}

		// A ready matcher over valid-length input can never report the two
		// reasons that mean the engine declined to look.
		if len(in) <= MaxInputBytes && got.Reason == ReasonTooLong {
			t.Fatalf("Check(%q) = %+v: in-range input reported too long", in, got)
		}
		if got.Reason == ReasonEngineUnavailable {
			t.Fatalf("Check(%q) = %+v: a built matcher reported itself unavailable", in, got)
		}

		// A refusal on a term must name it; a refusal on any other ground must
		// not invent one.
		if got.Reason == ReasonBlockedTerm {
			if got.List == "" || got.Term == "" {
				t.Fatalf("Check(%q) = %+v: blocked on a term but did not name it", in, got)
			}
			if got.Mode != MatchWholeSkeleton && got.Mode != MatchSubstring {
				t.Fatalf("Check(%q) = %+v: blocked under no valid mode", in, got)
			}
		} else if got.List != "" || got.Term != "" || got.Mode != MatchModeInvalid {
			t.Fatalf("Check(%q) = %+v: named a term without matching one", in, got)
		}

		// Determinism within the process: the same input, the same verdict.
		if again := m.Check(in); again != got {
			t.Fatalf("Check(%q) is not deterministic: %+v then %+v", in, got, again)
		}

		// The public message never carries the detail.
		if got.Term != "" && strings.Contains(got.PublicMessage(), got.Term) {
			t.Fatalf("Check(%q).PublicMessage() leaks term %q", in, got.Term)
		}

		// Blocking survives re-normalization. Skeleton is idempotent, so an
		// input that matched must still match once folded -- unless it was
		// refused for length, which folding can shorten past the limit.
		if got.Reason == ReasonBlockedTerm {
			if refolded := m.Check(Skeleton(in)); !refolded.Blocked() {
				t.Fatalf("Check(%q) blocked but its skeleton %q is allowed",
					in, Skeleton(in))
			}
		}
	})
}

// FuzzNewMatcher asserts that NewMatcher either returns a usable Matcher or an
// error, and never a Matcher that would misbehave. The interesting direction is
// that a successfully built Matcher must actually block its own terms: a
// validation that accepted a term it then could not match would be a silent
// hole in any list an administrator adds at runtime in Fb3.
func FuzzNewMatcher(f *testing.F) {
	f.Add("admin", "bad", uint8(1))
	f.Add("", "", uint8(2))
	f.Add("---", "a-d-m-i-n", uint8(1))
	f.Add("root", "root", uint8(2))

	f.Fuzz(func(t *testing.T, wholeTerm, subTerm string, mode uint8) {
		lists := []List{
			{Name: "whole", Mode: MatchWholeSkeleton, Terms: []string{wholeTerm}},
			{Name: "sub", Mode: MatchMode(mode%3 + 1), Terms: []string{subTerm}},
		}
		m, err := NewMatcher(lists...)
		if err != nil {
			if m != nil {
				t.Fatalf("NewMatcher returned a Matcher alongside error %v", err)
			}
			return
		}
		if m == nil {
			t.Fatal("NewMatcher returned neither a Matcher nor an error")
		}

		// Whatever it accepted, it must enforce.
		if got := m.Check(wholeTerm); !got.Blocked() {
			t.Fatalf("Check(%q) allowed a term the matcher accepted", wholeTerm)
		}
		if got := m.Check(subTerm); !got.Blocked() {
			t.Fatalf("Check(%q) allowed a term the matcher accepted", subTerm)
		}
	})
}
