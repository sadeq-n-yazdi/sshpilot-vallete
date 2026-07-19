package blocklist

import (
	"slices"
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

		// Ambiguous-reading expansion. The bypasses TableVersion 4 closes,
		// legitimate neighbors that must stay allowed, and inputs at and past
		// the expansion bound so the fail-closed path is reachable from here.
		"he1p", "1ogin", "bi11ing", "officia1", "nu11", "b1ll1ng", "heIp",
		"heıp", "heιp", "he１p", "he¹p",
		"lima", "mall", "kelly", "indivisibility", "helpful",
		strings.Repeat("i", maxAmbiguousRunes),
		strings.Repeat("i", maxAmbiguousRunes+1),
		strings.Repeat("1", MaxInputBytes),
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
		case ReasonEngineUnavailable, ReasonEmptySkeleton, ReasonTooLong,
			ReasonBlockedTerm, ReasonTooAmbiguous:
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

// FuzzCandidateSkeletons asserts the expansion's contract on arbitrary input.
//
// The properties are the ones Check's correctness rests on and that a plausible
// refactor breaks silently -- wrong candidates produce wrong verdicts, never a
// panic:
//
//   - The first candidate is the input untouched, which is what makes an exact
//     match take precedence over an alternative reading.
//   - Refusal is total: either the bound holds and the set is complete, or
//     nothing is returned. A partially-expanded set would be walked, would find
//     no match, and would allow the input on an expansion that never finished.
//   - Candidates differ from the input only by substituting a declared reading
//     at an ambiguous position, so expansion can never invent a match out of
//     bytes the user did not type.
//   - The set is exactly 2^k and free of duplicates, which is what the bound
//     actually bounds.
func FuzzCandidateSkeletons(f *testing.F) {
	for _, s := range []string{
		"", "admin", "heip", "biiiing", "hello", "αi", "漢字i",
		strings.Repeat("i", maxAmbiguousRunes),
		strings.Repeat("i", maxAmbiguousRunes+1),
	} {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, in string) {
		// Only skeletons are ever expanded, so hold the fuzzer to that.
		sk := Skeleton(in)

		ambiguous := 0
		for i := 0; i < len(sk); i++ {
			if _, ok := ambiguousReadings[sk[i]]; ok {
				ambiguous++
			}
		}

		got, ok := candidateSkeletons(sk)
		if !ok {
			if ambiguous <= maxAmbiguousRunes {
				t.Fatalf("candidateSkeletons(%q) refused %d ambiguous runes; the bound is %d",
					sk, ambiguous, maxAmbiguousRunes)
			}
			if got != nil {
				t.Fatalf("candidateSkeletons(%q) returned %d candidates alongside a refusal",
					sk, len(got))
			}
			return
		}

		if ambiguous > maxAmbiguousRunes {
			t.Fatalf("candidateSkeletons(%q) accepted %d ambiguous runes; the bound is %d",
				sk, ambiguous, maxAmbiguousRunes)
		}
		if got[0] != sk {
			t.Fatalf("candidateSkeletons(%q)[0] = %q; want the input itself", sk, got[0])
		}
		if want := 1 << ambiguous; len(got) != want {
			t.Fatalf("candidateSkeletons(%q) returned %d candidates; want %d", sk, len(got), want)
		}
		if len(got) > maxCandidateSkeletons {
			t.Fatalf("candidateSkeletons(%q) returned %d candidates; the ceiling is %d",
				sk, len(got), maxCandidateSkeletons)
		}

		seen := make(map[string]struct{}, len(got))
		for _, c := range got {
			if _, dup := seen[c]; dup {
				t.Fatalf("candidateSkeletons(%q) repeated candidate %q", sk, c)
			}
			seen[c] = struct{}{}

			if len(c) != len(sk) {
				t.Fatalf("candidate %q has a different length to %q", c, sk)
			}
			for i := 0; i < len(c); i++ {
				if c[i] == sk[i] {
					continue
				}
				readings, isKey := ambiguousReadings[sk[i]]
				if !isKey {
					t.Fatalf("candidate %q changed byte %d of %q, which is not ambiguous",
						c, i, sk)
				}
				if !slices.Contains(readings, c[i]) {
					t.Fatalf("candidate %q substituted %q at byte %d of %q, which is "+
						"not a declared reading", c, c[i], i, sk)
				}
			}
		}

		// Determinism: the same skeleton, the same slice, in the same order.
		again, ok := candidateSkeletons(sk)
		if !ok || !slices.Equal(got, again) {
			t.Fatalf("candidateSkeletons(%q) is not deterministic", sk)
		}
	})
}
