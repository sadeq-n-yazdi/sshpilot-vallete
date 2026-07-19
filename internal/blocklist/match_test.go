package blocklist

import (
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
		Reason(200):             "unknown",
	}
	for reason, want := range cases {
		if got := reason.String(); got != want {
			t.Errorf("Reason(%d).String() = %q; want %q", reason, got, want)
		}
	}
}
