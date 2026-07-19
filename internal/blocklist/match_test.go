package blocklist

import (
	"slices"
	"strings"
	"testing"
)

// testMatcher builds a Matcher from lists or fails the test. Construction
// errors are never the thing under test in the match cases below.
func testMatcher(t *testing.T, lists ...List) *Matcher {
	t.Helper()
	m, err := NewMatcher(lists...)
	if err != nil {
		t.Fatalf("NewMatcher: %v", err)
	}
	return m
}

// defaultMatcher builds the shipped lists or fails the test.
func defaultMatcher(t *testing.T) *Matcher {
	t.Helper()
	m, err := DefaultMatcher()
	if err != nil {
		t.Fatalf("DefaultMatcher: %v", err)
	}
	return m
}

// TestWholeSkeletonCatchesEveryFoldedEvasion is the end-to-end assertion that
// Fb1's folding and Fb2's matching actually meet. Each input below is a
// spelling of a reserved word that a naive string compare permits; every one
// must reduce to the term and be refused.
//
// This is deliberately duplicated effort with the skeleton tests. Those prove
// the fold; this proves the fold is wired to a decision. A refactor that
// skeletonized the input but compared the original would pass every test in
// skeleton_test.go and fail here.
func TestWholeSkeletonCatchesEveryFoldedEvasion(t *testing.T) {
	m := defaultMatcher(t)

	cases := []struct {
		name  string
		input string
		term  string
	}{
		{"plain", "admin", "admin"},
		{"upper", "ADMIN", "admin"},
		{"mixed case", "AdMiN", "admin"},
		{"leetspeak", "4dm1n", "admin"},
		{"leet with symbol", "@dm1n", "admin"},
		{"separators", "a-d-m-i-n", "admin"},
		{"dot separators", "a.d.m.i.n", "admin"},
		{"underscore separators", "a_d_m_i_n", "admin"},
		{"space separators", "a d m i n", "admin"},
		{"cyrillic a", "аdmin", "admin"},
		{"greek eta", "admiη", "admin"},
		{"mathematical bold", "\U0001D41A\U0001D41D\U0001D426\U0001D422\U0001D427", "admin"},
		{"fullwidth", "ａｄｍｉｎ", "admin"},
		{"circled", "ⓐⓓⓜⓘⓝ", "admin"},
		{"zero-width joiner", "a\u200bd\u200bmin", "admin"},
		{"accents", "ádmín", "admin"},
		{"combined evasions", "а-DＭ1n", "admin"},
		{"root leet", "r00t", "root"},
		{"root separators", "r-o-o-t", "root"},
		{"www fullwidth", "ｗｗｗ", "www"},
		{"api leet", "@p1", "api"},
		{"support cyrillic o", "suppоrt", "support"},
		{"security upper", "SECURITY", "security"},
		{"billing leet", "b1ll1ng", "billing"},
		{"official leet", "0ff1c1al", "official"},
		{"staff leet", "st@ff", "staff"},
		{"help separators", "h-e-l-p", "help"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := m.Check(tc.input)
			if !got.Blocked() {
				t.Fatalf("Check(%q) allowed; want blocked", tc.input)
			}
			if got.Reason != ReasonBlockedTerm {
				t.Errorf("Check(%q).Reason = %v; want %v", tc.input, got.Reason, ReasonBlockedTerm)
			}
			if got.Term != tc.term {
				t.Errorf("Check(%q).Term = %q; want %q", tc.input, got.Term, tc.term)
			}
			if got.Mode != MatchWholeSkeleton {
				t.Errorf("Check(%q).Mode = %v; want %v", tc.input, got.Mode, MatchWholeSkeleton)
			}
		})
	}
}

// TestWholeSkeletonTermsDoNotMatchAsSubstrings is the false-positive direction,
// and it is the test this package would be dangerous without.
//
// Every identifier below is one a real person could plausibly want, and every
// one contains a reserved word's letters. If whole-skeleton matching were ever
// weakened to a substring scan -- the single most tempting "fix" to make an
// evasion test pass -- all of them would be refused and the product would be
// broken for ordinary users. ADR-0017 states the requirement directly: "root"
// blocks "root" but not "roots".
func TestWholeSkeletonTermsDoNotMatchAsSubstrings(t *testing.T) {
	m := defaultMatcher(t)

	// Each entry names the reserved word whose letters it contains, so a
	// failure says immediately which term over-reached.
	cases := []struct {
		input    string
		contains string
	}{
		{"roots", "root"},
		{"rooted", "root"},
		{"rootkit", "root"},
		{"root-cause", "root"},
		{"grassroots", "root"},
		{"badminton", "admin"},
		{"administrivia", "admin"},
		{"apiary", "api"},
		{"api-docs", "api"},
		{"therapist", "api"},
		{"helpful", "help"},
		{"helping-hands", "help"},
		{"supporters", "support"},
		{"staffordshire", "staff"},
		{"security-blog", "security"},
		{"insecurity", "security"},
		{"moderately", "moderator"},
		{"billings", "billing"},
		{"testament", "test"},
		{"contactless", "contact"},
		{"newsletter", "news"},
		{"statusquo", "status"},
		{"nodejs", "node"},
		{"hostel", "host"},
		{"tokenizer", "token"},
		{"systemic", "system"},
		{"teamwork", "team"},
		{"ownership", "owner"},
		{"informal", "info"},
		{"servicer", "service"},
		{"wwwx", "www"},
		{"demonstration", "demo"},
		{"examples", "example"},
		{"guestbook", "guest"},
		{"defaults", "default"},
		{"publication", "public"},
		{"mailbox", "mail"},
		{"pinguin", "ping"},
		{"verifying", "verify"},
		{"sessions-log", "session"},
	}

	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			got := m.Check(tc.input)
			if got.Blocked() {
				t.Fatalf("Check(%q) blocked by list %q term %q (mode %v); "+
					"a whole-skeleton term must not match as a substring of %q",
					tc.input, got.List, got.Term, got.Mode, tc.contains)
			}
			if got.Reason != ReasonAllowed {
				t.Errorf("Check(%q).Reason = %v; want %v", tc.input, got.Reason, ReasonAllowed)
			}
		})
	}
}

// TestSubstringTermsMatchAnywhere covers the other match mode: an offensive
// term is refused wherever it sits, including when separators were what made it
// look innocent before folding.
func TestSubstringTermsMatchAnywhere(t *testing.T) {
	m := testMatcher(t, List{
		Name:  "offensive",
		Mode:  MatchSubstring,
		Terms: []string{"badword", "otherword"},
	})

	blocked := []struct {
		name  string
		input string
	}{
		{"exactly the term", "badword"},
		{"prefix", "badwordly"},
		{"suffix", "verybadword"},
		{"infix", "mybadwordhere"},
		{"separated", "b-a-d-w-o-r-d"},
		{"separated infix", "my.bad.word.here"},
		{"leetspeak", "b4dw0rd"},
		{"cased", "BadWord"},
		{"across a join", "grab-adwordly"},
		{"second term", "seeotherwordnow"},
	}
	for _, tc := range blocked {
		t.Run(tc.name, func(t *testing.T) {
			got := m.Check(tc.input)
			if !got.Blocked() {
				t.Fatalf("Check(%q) allowed; want blocked", tc.input)
			}
			if got.Mode != MatchSubstring {
				t.Errorf("Check(%q).Mode = %v; want %v", tc.input, got.Mode, MatchSubstring)
			}
		})
	}

	allowed := []string{"badwor", "adword", "goodword", "badward"}
	for _, in := range allowed {
		t.Run("allowed/"+in, func(t *testing.T) {
			if got := m.Check(in); got.Blocked() {
				t.Fatalf("Check(%q) blocked by term %q; want allowed", in, got.Term)
			}
		})
	}
}

// TestCheckFailsClosed pins every path that is not a positive decision to allow.
// Each of these is a place where an "allowed" default would be a bypass rather
// than a bug.
func TestCheckFailsClosed(t *testing.T) {
	ready := testMatcher(t, List{Name: "l", Mode: MatchWholeSkeleton, Terms: []string{"admin"}})

	t.Run("nil matcher", func(t *testing.T) {
		var m *Matcher
		got := m.Check("anything")
		if !got.Blocked() {
			t.Fatal("nil Matcher allowed an identifier")
		}
		if got.Reason != ReasonEngineUnavailable {
			t.Errorf("Reason = %v; want %v", got.Reason, ReasonEngineUnavailable)
		}
	})

	t.Run("zero matcher", func(t *testing.T) {
		got := new(Matcher).Check("anything")
		if !got.Blocked() {
			t.Fatal("zero Matcher allowed an identifier")
		}
		if got.Reason != ReasonEngineUnavailable {
			t.Errorf("Reason = %v; want %v", got.Reason, ReasonEngineUnavailable)
		}
	})

	t.Run("zero Result is blocked", func(t *testing.T) {
		// The field is Allowed rather than Blocked precisely so this holds.
		var r Result
		if !r.Blocked() {
			t.Fatal("the zero Result is not blocked; the engine cannot fail closed")
		}
	})

	t.Run("over length", func(t *testing.T) {
		got := ready.Check(strings.Repeat("a", MaxInputBytes+1))
		if !got.Blocked() {
			t.Fatal("over-length input allowed")
		}
		if got.Reason != ReasonTooLong {
			t.Errorf("Reason = %v; want %v", got.Reason, ReasonTooLong)
		}
	})

	t.Run("at the length limit", func(t *testing.T) {
		// The boundary is inclusive: exactly MaxInputBytes is examined, so an
		// off-by-one that refused it would be caught here rather than showing
		// up as an unexplained rejection in production.
		if got := ready.Check(strings.Repeat("a", MaxInputBytes)); got.Blocked() {
			t.Fatalf("input of exactly MaxInputBytes was blocked: %v", got.Reason)
		}
	})

	emptySkeletons := []struct {
		name  string
		input string
	}{
		{"empty", ""},
		{"spaces", "   "},
		{"separators only", "-_.-"},
		{"combining marks only", "́̂"},
		{"zero width only", "\u200b\u200c"},
		{"invalid utf8 only", "\xff\xfe"},
	}
	for _, tc := range emptySkeletons {
		t.Run("empty skeleton/"+tc.name, func(t *testing.T) {
			got := ready.Check(tc.input)
			if !got.Blocked() {
				t.Fatalf("Check(%q) allowed an identifier with no comparable content", tc.input)
			}
			if got.Reason != ReasonEmptySkeleton {
				t.Errorf("Reason = %v; want %v", got.Reason, ReasonEmptySkeleton)
			}
		})
	}
}

// TestCheckIsDeterministic asserts the property Go's randomized map iteration
// threatens: not just a stable verdict, but a stable reported term.
//
// The input matches three offensive terms at once, so an implementation that
// ranged over a map to find one would return a different Term on different
// runs while the boolean stayed correct -- corrupting the audit record and
// nothing else, which is exactly the kind of bug that survives review.
func TestCheckIsDeterministic(t *testing.T) {
	lists := []List{{
		Name:  "offensive",
		Mode:  MatchSubstring,
		Terms: []string{"alpha", "beta", "gamma"},
	}}
	const input = "xxgammaxxbetaxxalphaxx"

	first := testMatcher(t, lists...).Check(input)
	if first.Term != "alpha" {
		t.Fatalf("Term = %q; want %q (the first term in declared order, "+
			"not the first by position in the input)", first.Term, "alpha")
	}

	// Rebuild the matcher each round so that any map built during construction
	// is a fresh one with a fresh iteration seed.
	for i := range 500 {
		got := testMatcher(t, lists...).Check(input)
		if got != first {
			t.Fatalf("round %d: Check(%q) = %+v; want %+v", i, input, got, first)
		}
	}

	// The same, over the shipped lists and a whole-skeleton hit.
	firstDefault := defaultMatcher(t).Check("4dm1n")
	for i := range 500 {
		if got := defaultMatcher(t).Check("4dm1n"); got != firstDefault {
			t.Fatalf("round %d: default Check = %+v; want %+v", i, got, firstDefault)
		}
	}
}

// TestWholeSkeletonListsTakePrecedence pins the documented ordering: an
// identifier that is exactly a reserved word is reported as that, even when it
// also contains a substring term and even when the caller supplied the
// substring list first.
func TestWholeSkeletonListsTakePrecedence(t *testing.T) {
	m := testMatcher(t,
		List{Name: "offensive", Mode: MatchSubstring, Terms: []string{"min"}},
		List{Name: "routing", Mode: MatchWholeSkeleton, Terms: []string{"admin"}},
	)

	got := m.Check("admin")
	if got.List != "routing" || got.Mode != MatchWholeSkeleton {
		t.Fatalf("Check(\"admin\") reported list %q mode %v; want routing/%v",
			got.List, got.Mode, MatchWholeSkeleton)
	}

	// The substring list still fires when the whole-skeleton list does not.
	if got := m.Check("mining"); got.List != "offensive" {
		t.Fatalf("Check(\"mining\") reported list %q; want offensive", got.List)
	}
}

// TestListOrderIsPreservedWithinAMode checks the other half of the ordering
// rule: the caller's relative order survives the partition, so ties inside one
// mode are still the caller's to decide.
func TestListOrderIsPreservedWithinAMode(t *testing.T) {
	m := testMatcher(t,
		List{Name: "first", Mode: MatchWholeSkeleton, Terms: []string{"aaa"}},
		List{Name: "second", Mode: MatchSubstring, Terms: []string{"bbb"}},
		List{Name: "third", Mode: MatchWholeSkeleton, Terms: []string{"ccc"}},
		List{Name: "fourth", Mode: MatchSubstring, Terms: []string{"bb"}},
	)

	if got := m.Check("aaa"); got.List != "first" {
		t.Errorf("Check(\"aaa\").List = %q; want first", got.List)
	}
	if got := m.Check("ccc"); got.List != "third" {
		t.Errorf("Check(\"ccc\").List = %q; want third", got.List)
	}
	// "bbb" is in both substring lists; the earlier one wins.
	if got := m.Check("xbbbx"); got.List != "second" {
		t.Errorf("Check(\"xbbbx\").List = %q; want second", got.List)
	}
}

// TestNewMatcherRejectsUnusableLists covers each validation NewMatcher performs.
// The empty-skeleton case is the security-relevant one: an empty term in a
// substring list is a substring of everything and would block the entire
// namespace.
func TestNewMatcherRejectsUnusableLists(t *testing.T) {
	cases := []struct {
		name  string
		lists []List
		want  string
	}{
		{
			name:  "no name",
			lists: []List{{Mode: MatchWholeSkeleton, Terms: []string{"a"}}},
			want:  "has no name",
		},
		{
			name: "duplicate name",
			lists: []List{
				{Name: "dup", Mode: MatchWholeSkeleton, Terms: []string{"a"}},
				{Name: "dup", Mode: MatchSubstring, Terms: []string{"b"}},
			},
			want: "duplicate list name",
		},
		{
			name:  "zero mode",
			lists: []List{{Name: "l", Terms: []string{"a"}}},
			want:  "invalid match mode",
		},
		{
			name:  "out of range mode",
			lists: []List{{Name: "l", Mode: MatchMode(9), Terms: []string{"a"}}},
			want:  "invalid match mode",
		},
		{
			name:  "term with empty skeleton",
			lists: []List{{Name: "l", Mode: MatchSubstring, Terms: []string{"---"}}},
			want:  "empty skeleton",
		},
		{
			name:  "term that is the empty string",
			lists: []List{{Name: "l", Mode: MatchSubstring, Terms: []string{""}}},
			want:  "empty skeleton",
		},
		{
			name:  "duplicate skeleton in a whole list",
			lists: []List{{Name: "l", Mode: MatchWholeSkeleton, Terms: []string{"admin", "4dm1n"}}},
			want:  "share a skeleton",
		},
		{
			name:  "duplicate skeleton in a substring list",
			lists: []List{{Name: "l", Mode: MatchSubstring, Terms: []string{"bad", "b-a-d"}}},
			want:  "share a skeleton",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m, err := NewMatcher(tc.lists...)
			if err == nil {
				t.Fatalf("NewMatcher accepted %+v; want an error", tc.lists)
			}
			if m != nil {
				t.Errorf("NewMatcher returned a non-nil Matcher alongside an error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q; want it to mention %q", err, tc.want)
			}
		})
	}
}

// TestNewMatcherAcceptsEmptyInput records that no lists, and a list with no
// terms, are legitimate. Fb3 needs an empty allowlist to be constructible.
func TestNewMatcherAcceptsEmptyInput(t *testing.T) {
	t.Run("no lists", func(t *testing.T) {
		m := testMatcher(t)
		if got := m.Check("admin"); got.Blocked() {
			t.Fatalf("a matcher with no lists blocked %q", "admin")
		}
		// Fail-closed paths still apply with no lists at all.
		if got := m.Check(""); !got.Blocked() {
			t.Fatal("a matcher with no lists allowed an empty skeleton")
		}
	})

	t.Run("empty list", func(t *testing.T) {
		m := testMatcher(t,
			List{Name: "whole", Mode: MatchWholeSkeleton},
			List{Name: "sub", Mode: MatchSubstring},
		)
		if got := m.Check("admin"); got.Blocked() {
			t.Fatalf("empty lists blocked %q", "admin")
		}
	})
}

// TestMatcherDoesNotAliasCallerLists checks that mutating a caller's slice
// after construction cannot change the compiled policy. A Matcher is documented
// as immutable and concurrency-safe, and that claim has to survive a caller who
// reuses the slice it passed in.
func TestMatcherDoesNotAliasCallerLists(t *testing.T) {
	terms := []string{"admin"}
	m := testMatcher(t, List{Name: "l", Mode: MatchWholeSkeleton, Terms: terms})

	terms[0] = "harmless"
	if got := m.Check("admin"); !got.Blocked() {
		t.Fatal("mutating the caller's term slice disabled a compiled term")
	}
	if got := m.Check("harmless"); got.Blocked() {
		t.Fatal("mutating the caller's term slice added a term")
	}
}

// TestResultDoesNotLeakTheList asserts the reporting boundary. The structured
// fields carry the detail an audit log needs; the user-facing text must not,
// and must be identical for every refusal so that it cannot be used to probe
// the list one registration at a time.
func TestResultDoesNotLeakTheList(t *testing.T) {
	m := defaultMatcher(t)

	blocked := []string{"admin", "root", "www", "4dm1n", "", strings.Repeat("a", 300)}
	var messages []string
	for _, in := range blocked {
		got := m.Check(in)
		if !got.Blocked() {
			t.Fatalf("Check(%q) allowed; want blocked", in)
		}
		if got.Term != "" && strings.Contains(got.PublicMessage(), got.Term) {
			t.Errorf("PublicMessage() for %q leaks the matched term %q", in, got.Term)
		}
		if got.List != "" && strings.Contains(got.PublicMessage(), got.List) {
			t.Errorf("PublicMessage() for %q leaks the list name %q", in, got.List)
		}
		messages = append(messages, got.PublicMessage())
	}
	for i, msg := range messages {
		if msg != messages[0] {
			t.Errorf("refusal %d has message %q; every refusal must read %q",
				i, msg, messages[0])
		}
	}

	allowed := m.Check("sadeq")
	if allowed.Blocked() {
		t.Fatalf("Check(%q) blocked unexpectedly", "sadeq")
	}
	if allowed.PublicMessage() == messages[0] {
		t.Error("an allowed Result and a blocked Result share a public message")
	}
}

// TestResultCarriesNoSkeleton is a structural assertion, not a behavioral one.
// Skeletons are comparison-only and must never be stored or displayed; the way
// to guarantee a Result never carries one into a log is for it to have no field
// that could hold one. A future field added carelessly fails here.
func TestResultCarriesNoSkeleton(t *testing.T) {
	m := defaultMatcher(t)
	got := m.Check("а-DＭ1n")
	if !got.Blocked() {
		t.Fatal("evasive spelling of admin was allowed")
	}
	// Term is the curated spelling, never the folded input.
	if got.Term != "admin" {
		t.Fatalf("Term = %q; want the curated term %q", got.Term, "admin")
	}
	for _, field := range []string{got.List, got.Term} {
		if field == Skeleton("а-DＭ1n") && field != "admin" {
			t.Errorf("Result field %q is the input's skeleton", field)
		}
	}
}

// TestMatchModeString and TestReasonString cover the log renderings, including
// the values no correct code produces. Those default arms exist so that a
// corrupt value logs as "unknown" instead of as a plausible-looking mode.
func TestMatchModeString(t *testing.T) {
	cases := map[MatchMode]string{
		MatchWholeSkeleton: "whole-skeleton",
		MatchSubstring:     "substring",
		MatchModeInvalid:   "invalid",
		MatchMode(200):     "unknown",
	}
	for mode, want := range cases {
		if got := mode.String(); got != want {
			t.Errorf("MatchMode(%d).String() = %q; want %q", mode, got, want)
		}
	}
}

func TestReasonString(t *testing.T) {
	cases := map[Reason]string{
		ReasonAllowed:           "allowed",
		ReasonEmptySkeleton:     "empty-skeleton",
		ReasonTooLong:           "too-long",
		ReasonBlockedTerm:       "blocked-term",
		ReasonEngineUnavailable: "engine-unavailable",
		ReasonTooAmbiguous:      "too-ambiguous",
		Reason(200):             "unknown",
	}
	for reason, want := range cases {
		if got := reason.String(); got != want {
			t.Errorf("Reason(%d).String() = %q; want %q", reason, got, want)
		}
	}
}

// --- Ambiguous-reading expansion (TableVersion 4) ---------------------------

// TestCandidateSkeletonsContract pins the three properties Check depends on:
// the first candidate is the input untouched, the set is exactly the subsets of
// the ambiguous positions, and the order is fixed.
func TestCandidateSkeletonsContract(t *testing.T) {
	for _, tc := range []struct{ name, in string }{
		{"no ambiguous rune", "admin"},
		{"empty", ""},
		{"l does not expand", "hello"},
		{"one position", "heip"},
		{"two positions", "biiing"},
		{"non-ascii is not a key", "αi"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := candidateSkeletons(tc.in)
			if !ok {
				t.Fatalf("candidateSkeletons(%q) refused an in-bounds input", tc.in)
			}
			if got[0] != tc.in {
				t.Errorf("candidateSkeletons(%q)[0] = %q; want the input itself",
					tc.in, got[0])
			}
			if len(got) != 1<<strings.Count(tc.in, "i") {
				t.Errorf("candidateSkeletons(%q) returned %d candidates; want 2^%d",
					tc.in, len(got), strings.Count(tc.in, "i"))
			}
			// Every candidate must differ from the input only by i->l.
			for _, c := range got {
				if len(c) != len(tc.in) {
					t.Errorf("candidate %q has a different length to %q", c, tc.in)
					continue
				}
				for i := 0; i < len(c); i++ {
					if c[i] == tc.in[i] {
						continue
					}
					if tc.in[i] != 'i' || c[i] != 'l' {
						t.Errorf("candidate %q changed byte %d of %q from %q to %q; "+
							"only i->l is permitted", c, i, tc.in, tc.in[i], c[i])
					}
				}
			}
		})
	}
}

// TestCandidateSkeletonsAreDeterministic runs the expansion repeatedly and
// requires an identical slice each time. Go randomizes map iteration, so a
// refactor that ranged ambiguousReadings instead of indexing it would reorder
// the candidates, and with them the term a Result reports.
func TestCandidateSkeletonsAreDeterministic(t *testing.T) {
	const in = "biiiing"
	first, ok := candidateSkeletons(in)
	if !ok {
		t.Fatalf("candidateSkeletons(%q) refused an in-bounds input", in)
	}
	for range 200 {
		again, ok := candidateSkeletons(in)
		if !ok {
			t.Fatal("candidateSkeletons became unavailable between calls")
		}
		if !slices.Equal(first, again) {
			t.Fatalf("candidateSkeletons(%q) is not deterministic:\n%q\n%q",
				in, first, again)
		}
	}
}

// TestCandidateExpansionBoundFailsClosed is the denial-of-service and
// fail-closed test in one. An identifier with more ambiguous positions than the
// bound must be refused, never expanded partially and never allowed.
func TestCandidateExpansionBoundFailsClosed(t *testing.T) {
	m := defaultMatcher(t)

	t.Run("at the bound", func(t *testing.T) {
		in := strings.Repeat("i", maxAmbiguousRunes)
		got, ok := candidateSkeletons(in)
		if !ok {
			t.Fatalf("candidateSkeletons refused %d ambiguous runes; the bound is %d",
				maxAmbiguousRunes, maxAmbiguousRunes)
		}
		if len(got) != maxCandidateSkeletons {
			t.Errorf("got %d candidates at the bound; want %d",
				len(got), maxCandidateSkeletons)
		}
	})

	t.Run("past the bound", func(t *testing.T) {
		in := strings.Repeat("i", maxAmbiguousRunes+1)
		got, ok := candidateSkeletons(in)
		if ok {
			t.Fatalf("candidateSkeletons accepted %d ambiguous runes; the bound is %d",
				maxAmbiguousRunes+1, maxAmbiguousRunes)
		}
		if got != nil {
			t.Errorf("candidateSkeletons returned %d candidates alongside a "+
				"refusal; a truncated set would be walked and would allow the input",
				len(got))
		}
	})

	// The verdict, which is the part that matters. Every one of these is
	// entirely ambiguous runes and none is a reserved word, so a fail-OPEN
	// bound would allow them all.
	for _, in := range []string{
		strings.Repeat("1", maxAmbiguousRunes+1),
		strings.Repeat("i", maxAmbiguousRunes+1),
		strings.Repeat("I", 40),
		strings.Repeat("1", MaxInputBytes),
		"admin" + strings.Repeat("1", maxAmbiguousRunes+1),
	} {
		t.Run("check "+in[:min(len(in), 12)], func(t *testing.T) {
			got := m.Check(in)
			if !got.Blocked() {
				t.Fatalf("Check(%q) allowed an input too ambiguous to expand", in)
			}
			if got.Reason != ReasonTooAmbiguous && got.Reason != ReasonBlockedTerm {
				t.Errorf("Check(%q).Reason = %v; want %v", in, got.Reason, ReasonTooAmbiguous)
			}
			// A refusal on this ground must not invent a term.
			if got.Reason == ReasonTooAmbiguous &&
				(got.List != "" || got.Term != "" || got.Mode != MatchModeInvalid) {
				t.Errorf("Check(%q) = %+v: named a term without matching one", in, got)
			}
		})
	}
}

// TestExpansionBlocksTheLeetLBypasses is the acceptance test for the bug: each
// input is a reserved word spelled with the digit one for an l, and each was
// permitted before TableVersion 4. The reported term is asserted too, not just
// the boolean -- an audit record naming the wrong word is its own bug.
func TestExpansionBlocksTheLeetLBypasses(t *testing.T) {
	m := defaultMatcher(t)

	for _, tc := range []struct{ in, list, term string }{
		{"he1p", "routing", "help"},
		{"1ogin", "routing", "login"},
		{"1ogout", "routing", "logout"},
		{"1oca1host", "routing", "localhost"},
		{"1ega1", "routing", "legal"},
		{"nu11", "routing", "null"},
		{"ni1", "routing", "nil"},
		{"bi11ing", "impersonation", "billing"},
		{"officia1", "impersonation", "official"},
		{"wa11et", "impersonation", "wallet"},
		{"he1pdesk", "impersonation", "helpdesk"},
		{"a1erts", "impersonation", "alerts"},
		{"bo11ocks", "offensive", "bollocks"},
		{"s1ut", "offensive", "slut"},
		{"hit1er", "offensive", "hitler"},
		// Mixed readings in one identifier: the first 1 reads as l, the
		// second as i. Only a candidate SET can satisfy both at once.
		{"b1ll1ng", "impersonation", "billing"},
	} {
		t.Run(tc.in, func(t *testing.T) {
			got := m.Check(tc.in)
			if !got.Blocked() {
				t.Fatalf("Check(%q) allowed a reserved word spelled with a digit one", tc.in)
			}
			if got.Reason != ReasonBlockedTerm {
				t.Fatalf("Check(%q).Reason = %v; want %v", tc.in, got.Reason, ReasonBlockedTerm)
			}
			if got.List != tc.list || got.Term != tc.term {
				t.Errorf("Check(%q) blocked on %s/%q; want %s/%q",
					tc.in, got.List, got.Term, tc.list, tc.term)
			}
		})
	}
}

// TestExpansionDoesNotOverBlock is the false-positive direction, and it is the
// direction that costs a real user their name rather than costing an attacker
// an evasion.
//
// The expansion is one-way -- i gains a reading of l, l gains nothing -- so an
// identifier spelled with genuine letters is only blocked if it was already.
// The entries below all contain i, l, or both, and several are one i-to-l
// substitution away from a reserved word without being one.
func TestExpansionDoesNotOverBlock(t *testing.T) {
	m := defaultMatcher(t)

	for _, allowed := range []string{
		// Ordinary names built from the letters in play.
		"lima", "iima", "kelly", "keily", "lilian", "willow", "milli",
		"phillip", "gillian", "linus", "olivia", "camilla",
		// The collapse-both-directions design would have blocked these two:
		// they collide with the reserved term "mail" once l and i are made
		// interchangeable in BOTH directions. The one-way expansion does not.
		"mall", "mali",
		// Real words with many i's, well inside the expansion bound.
		"indivisibility", "invisibility", "individualistic",
		// Identifiers that merely contain a reserved word, still permitted by
		// whole-skeleton mode, and still permitted after expansion.
		"helpful", "logins", "billinger", "wallets", "officially",
		// Plausible product handles.
		"my-key-set", "prod-cluster", "ci-runner", "build-pipeline",
	} {
		t.Run(allowed, func(t *testing.T) {
			got := m.Check(allowed)
			if got.Blocked() {
				t.Fatalf("Check(%q) blocked a legitimate identifier: %+v", allowed, got)
			}
		})
	}
}

// TestExpansionPrefersTheExactSkeleton fixes which term is reported when the
// skeleton itself matches one term and an alternative reading matches another.
// candidates[0] is the skeleton untouched and Check walks candidates in order,
// so the exact reading must win. Without that the reported term would depend on
// expansion order, and an audit record would name a word the user did not type.
func TestExpansionPrefersTheExactSkeleton(t *testing.T) {
	// "il" reads as itself and, expanded, as "ll". Both are terms here.
	m, err := NewMatcher(List{
		Name: "test", Mode: MatchWholeSkeleton, Terms: []string{"ll", "il"},
	})
	if err != nil {
		t.Fatalf("NewMatcher: %v", err)
	}

	// "i1" folds to the skeleton "il", which is itself a term and also expands
	// to the term "ll". The exact reading must be the one reported.
	if got := m.Check("i1"); got.Term != "il" {
		t.Errorf("Check(\"i1\").Term = %q; want %q -- the exact skeleton must be "+
			"reported ahead of an alternative reading", got.Term, "il")
	}

	// With the exact reading absent from the list, the alternative still fires.
	// This is what proves the assertion above is about precedence rather than
	// about "ll" being unreachable.
	alt := testMatcher(t, List{
		Name: "test", Mode: MatchWholeSkeleton, Terms: []string{"ll"},
	})
	if got := alt.Check("i1"); got.Term != "ll" {
		t.Errorf("Check(\"i1\").Term = %q; want %q", got.Term, "ll")
	}
}

// TestExpansionVerdictIsStableAcrossMatchers rebuilds the matcher from scratch
// and requires an identical Result, term included. Determinism has to hold
// across processes, not just across calls on one instance, because that is the
// claim an audit record rests on.
func TestExpansionVerdictIsStableAcrossMatchers(t *testing.T) {
	for _, in := range []string{"he1p", "bi11ing", "b1ll1ng", "s1ut", "lima", "mall"} {
		t.Run(in, func(t *testing.T) {
			first, err := NewMatcher(DefaultLists()...)
			if err != nil {
				t.Fatalf("NewMatcher: %v", err)
			}
			want := first.Check(in)
			for range 50 {
				next, err := NewMatcher(DefaultLists()...)
				if err != nil {
					t.Fatalf("NewMatcher: %v", err)
				}
				if got := next.Check(in); got != want {
					t.Fatalf("Check(%q) varies between matchers: %+v then %+v",
						in, want, got)
				}
			}
		})
	}
}
