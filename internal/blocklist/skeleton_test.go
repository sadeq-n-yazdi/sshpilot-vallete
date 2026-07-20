package blocklist

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// checkSkeleton asserts the skeleton of in and, as a property applied to every
// case in the file, that the result is a fixed point and valid UTF-8.
func checkSkeleton(t *testing.T, in, want string) {
	t.Helper()
	got := Skeleton(in)
	if got != want {
		t.Errorf("Skeleton(%q) = %q, want %q", in, got, want)
	}
	if again := Skeleton(got); again != got {
		t.Errorf("Skeleton not idempotent for %q: %q -> %q", in, got, again)
	}
	if !utf8.ValidString(got) {
		t.Errorf("Skeleton(%q) returned invalid UTF-8: %q", in, got)
	}
}

// TestStageIgnorables covers the two stages that discard rather than rewrite.
// Invalid UTF-8 goes in stage 0, before NFKD is allowed to see it; combining
// marks and format characters go in stage 2, after NFKD, because decomposing a
// precomposed form is what produces the marks in the first place.
func TestStageIgnorables(t *testing.T) {
	cases := []struct{ name, in, want string }{
		{"combining acute", "a\u0301dmin", "admin"},
		{"combining cedilla", "çafe", "cafe"},
		{"zero width space", "ad\u200bmin", "admin"},
		{"zero width joiner", "ad\u200dmin", "admin"},
		{"zero width non joiner", "ad\u200cmin", "admin"},
		{"soft hyphen", "ad\u00admin", "admin"},
		{"rtl override", "ad\u202emin", "admin"},
		{"byte order mark", "\ufeffadmin", "admin"},
		{"replacement char is dropped", "ad�min", "admin"},
		{"dotted capital I keeps only the i", "İstanbul", "istanbul"},
		{"only ignorables folds to empty", "\u200b\u200d\u0301", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { checkSkeleton(t, tc.in, tc.want) })
	}
}

// TestStageCaseFold covers stage 3: folding is Unicode-wide, not ASCII-only.
func TestStageCaseFold(t *testing.T) {
	cases := []struct{ name, in, want string }{
		{"ascii upper", "ADMIN", "admin"},
		{"ascii mixed", "AdMiN", "admin"},
		{"cyrillic upper folds then confuses", "АДМИН", "aдmиh"},
		{"greek upper", "ΑΟΡ", "aop"},
		{"fullwidth upper", "ＡＤＭＩＮ", "admin"},
		{"sharp s expands", "großadmin", "grossadmin"},
		{"turkish dotless i", "admın", "admin"},
		{"turkish dotless i uppercase source", "ADMİN", "admin"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { checkSkeleton(t, tc.in, tc.want) })
	}
}

// TestStageCompatibilityRanges covers stage 1, NFKD. The compatibility forms
// below -- fullwidth, mathematical, circled -- were folded by hand-maintained
// range arithmetic until TableVersion 4 replaced that with standard NFKD. The
// cases are kept as they were: which mechanism reduces them is an
// implementation detail, and that the answers did not move is the point.
func TestStageCompatibilityRanges(t *testing.T) {
	cases := []struct{ name, in, want string }{
		{"fullwidth letters", "ａｄｍｉｎ", "admin"},
		{"fullwidth digits reach leetspeak", "４ｄｍ１ｎ", "admin"},
		{"fullwidth at sign reaches leetspeak", "＠dmin", "admin"},
		{"fullwidth hyphen is a separator", "ａ－ｄ－ｍ－ｉ－ｎ", "admin"},
		{"math bold", "\U0001d41a\U0001d41d\U0001d426\U0001d422\U0001d427", "admin"},
		{"math bold capitals", "\U0001d400\U0001d403\U0001d40c\U0001d408\U0001d40d", "admin"},
		{"math italic", "\U0001d44e\U0001d451\U0001d45a\U0001d456\U0001d45b", "admin"},
		{"math double struck", "\U0001d552\U0001d555\U0001d55e\U0001d55a\U0001d55f", "admin"},
		{"math monospace", "\U0001d68a\U0001d68d\U0001d696\U0001d692\U0001d697", "admin"},
		{"math italic planck h", "\u210e", "h"},
		{"math digits reach leetspeak", "\U0001d7ce\U0001d7cf", "oi"},
		{"circled smalls", "ⓐⓓⓜⓘⓝ", "admin"},
		{"circled capitals", "ⒶⒹⓂⒾⓃ", "admin"},
		{"circled digits reach leetspeak", "①③", "ie"},
		{"circled zero reaches leetspeak", "⓪", "o"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { checkSkeleton(t, tc.in, tc.want) })
	}
}

// TestStageConfusables covers the hand-curated homoglyph table, which is
// consulted twice -- in stage 0 on the raw input and in stage 4 after NFKD.
// Both lookups are load-bearing and neither subsumes the other; see sanitize.
func TestStageConfusables(t *testing.T) {
	cases := []struct{ name, in, want string }{
		{"cyrillic a", "аdmin", "admin"},
		{"cyrillic o and e", "rооt", "root"},
		{"cyrillic p c x", "рсх", "pcx"},
		{"greek alpha omicron rho", "αορ", "aop"},
		{"accented latin", "ádmín", "admin"},
		{"o with stroke", "røøt", "root"},
		{"ligature fi", "ﬁle", "file"},
		{"ligature ffi", "oﬃce", "office"},
		{"letterlike script l", "ℓist", "list"},
		{"superscript letters", "ᵃdᵐⁱⁿ", "admin"},
		{"superscript digits reach leetspeak", "¹³⁵", "ies"},
		{"superscript digit with no leet reading", "²", "2"},
		{"ordinal indicators", "ªº", "ao"},
		{"ae ligature expands", "æon", "aeon"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { checkSkeleton(t, tc.in, tc.want) })
	}
}

// TestStageLeetspeak covers stage 5, including the documented 1 -> i choice.
func TestStageLeetspeak(t *testing.T) {
	cases := []struct{ name, in, want string }{
		{"zero", "r00t", "root"},
		{"one folds to i not l", "adm1n", "admin"},
		{"three", "th3", "the"},
		{"four", "4dmin", "admin"},
		{"five", "5udo", "sudo"},
		{"seven", "roo7", "root"},
		{"at sign", "@dmin", "admin"},
		{"dollar", "$udo", "sudo"},
		{"combined", "4dm1n", "admin"},
		{"unmapped digits survive", "user2689", "user2689"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { checkSkeleton(t, tc.in, tc.want) })
	}
}

// TestStageSeparators covers stage 6 and pins the decision NOT to collapse
// repeated-character runs.
func TestStageSeparators(t *testing.T) {
	cases := []struct{ name, in, want string }{
		{"hyphen", "a-d-m-i-n", "admin"},
		{"dot", "a.d.m.i.n", "admin"},
		{"underscore", "a_d_m_i_n", "admin"},
		{"space", "a d m i n", "admin"},
		{"tab and newline", "a\td\nmin", "admin"},
		{"non breaking space", "ad min", "admin"},
		{"en and em dash", "a–d—min", "admin"},
		{"unicode hyphen", "ad‐min", "admin"},
		{"undertie connector", "ad‿min", "admin"},
		{"mixed padding", "_-.a d.m-i_n.-_", "admin"},
		{"runs are preserved", "aaadminnn", "aaadminnn"},
		{"doubled letters stay distinct", "bobb", "bobb"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { checkSkeleton(t, tc.in, tc.want) })
	}
}

// TestEvasionsCollapseToTarget is the security requirement: every realistic
// spelling of a reserved identity must reach the same skeleton as the
// identity itself. Equality of skeletons is asserted, not a boolean verdict.
func TestEvasionsCollapseToTarget(t *testing.T) {
	targets := map[string][]string{
		"admin": {
			"Admin", "ADMIN", "aDmIn",
			"аdmin",                  // Cyrillic a
			"ａｄｍｉｎ",                  // fullwidth
			"a-d-m-i-n", "a.d.m.i.n", // separators
			"a_d_m_i_n", "a d m i n", // more separators
			"@dmin", "4dm1n", "4DM1N", // leetspeak
			"admın", // dotless i
			"\U0001d41a\U0001d41d\U0001d426\U0001d422\U0001d427", // math bold
			"ⓐⓓⓜⓘⓝ",                         // circled
			"ádmín",                         // accented
			"a\u200bd\u200bm\u200bi\u200bn", // zero width padding
			"ＡＤＭＩＮ",                         // fullwidth capitals
			"Аdmin",                         // Cyrillic capital A
			"@-D_M.ı N",                     // everything at once
		},
		"root": {"ROOT", "r00t", "rооt", "r-o-o-t", "RØØT", "ro0T"},
		"sudo": {"$UDO", "5udo", "südo", "s.u.d.o", "ѕudo"},
	}
	for target, evasions := range targets {
		want := Skeleton(target)
		if want != target {
			t.Fatalf("target %q is not its own skeleton (%q); the test is misconfigured", target, want)
		}
		for _, in := range evasions {
			if got := Skeleton(in); got != want {
				t.Errorf("evasion %q -> %q, want %q (target %q)", in, got, want, target)
			}
		}
	}
}

// TestConfirmedHomoglyphBypasses pins the concrete impersonation vectors that
// were verified to survive an earlier revision of the tables unfolded. Each one
// is a real bypass, not a hypothetical: before the entry that fixes it, the
// input below is returned unchanged and therefore never matches its target.
// They are listed by codepoint so a reader is not asked to tell "admiη" from
// "admin" by eye -- which is the whole point.
func TestConfirmedHomoglyphBypasses(t *testing.T) {
	cases := []struct{ name, in, want string }{
		{"greek eta for n (U+03B7)", "admiηn", "adminn"},
		{"greek eta as the n (U+03B7)", "admiη", "admin"},
		{"cyrillic yi for i (U+0457)", "admїn", "admin"},
		{"cyrillic shha for h (U+04BB)", "һdmin", "hdmin"},
		{"greek omega for w (U+03C9)", "ωeb", "web"},
		{"math dotless italic i (U+1D6A4)", "adm\U0001D6A4n", "admin"},
		{"math bold small alpha (U+1D6C2)", "\U0001D6C2dmin", "admin"},
		{"math bold small omicron (U+1D6D0)", "admin\U0001D6D0", "admino"},
		// The styled alphabets must agree with each other as well as with the
		// plain letter: sans-serif bold italic alpha is a different codepoint
		// from bold alpha and both must reach "a".
		{"math sans-serif bold italic alpha (U+1D7AA)", "\U0001D7AAdmin", "admin"},
		{"math bold capital alpha (U+1D6A8)", "\U0001D6A8dmin", "admin"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			checkSkeleton(t, tc.in, tc.want)
		})
	}
}

// TestNFKDRegressionsStayFolded pins the individual codepoints that version 4
// stopped folding when it moved NFKD to the front of the pipeline. Each was a
// working bypass of the reserved-word list on version 5, so each is asserted
// twice: the skeleton, and the verdict a real matcher reaches for it. The
// skeleton assertion alone would not prove the bypass is closed, and the
// verdict alone would not say why.
func TestNFKDRegressionsStayFolded(t *testing.T) {
	cases := []struct {
		name, in, wantSkeleton, wantTerm string
	}{
		// U+03F9 lowercases to ϲ, which confusables maps to c -- but NFKD
		// decomposed it to Σ, which lowercases to σ, which is nothing.
		{"greek capital lunate sigma for c (U+03F9)", "Ϲonsole", "console", "console"},
		{"greek capital lunate sigma mid-word (U+03F9)", "seϹurity", "security", "security"},
		// U+1D6A5 decomposes to ȷ (U+0237), which had no entry at all.
		{"math italic small dotless j (U+1D6A5)", "\U0001D6A5s", "js", "js"},
		{"math italic small dotless j mid-word (U+1D6A5)", "blow\U0001D6A5ob", "blowjob", "blowjob"},
		// The base character the family decomposes onto must fold on its own,
		// not only when NFKD hands it over.
		{"latin small dotless j (U+0237)", "ȷs", "js", "js"},
	}

	m, err := DefaultMatcher()
	if err != nil {
		t.Fatalf("DefaultMatcher() error = %v", err)
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			checkSkeleton(t, tc.in, tc.wantSkeleton)

			got := m.Check(tc.in)
			if !got.Blocked() {
				t.Errorf("Check(%q) allowed it; the bypass is open again", tc.in)
			}
			if got.Term != tc.wantTerm {
				t.Errorf("Check(%q) blocked on term %q, want %q", tc.in, got.Term, tc.wantTerm)
			}
		})
	}
}

// TestSkeletonIsIdempotentAcrossInvalidUTF8 pins the specific shape of the
// idempotence break that version 4 introduced, which FuzzSkeleton found in
// seconds: norm.NFKD treats an undecodable byte as a segment boundary and
// passes the neighboring text through untouched, so a compatibility character
// next to invalid UTF-8 survived the first pass and was decomposed only by the
// second. Skeleton("\xf7ʰ") was "ʰ" while Skeleton("ʰ") was "h".
//
// The property is that an invalid byte may not change the fate of any
// character near it. Asserting that directly -- fold with the junk, fold
// without it, demand the same answer -- is stronger than asserting the two
// known outputs, because it fails for any future stage that acquires the same
// segment-boundary sensitivity.
func TestSkeletonIsIdempotentAcrossInvalidUTF8(t *testing.T) {
	// Compatibility characters that only decompose if NFKD sees them in a
	// well-formed segment: modifier letters, a ligature, a styled letter, a
	// precomposed accent and the two codepoints repaired in version 6.
	clean := []string{"ʰ", "ﬁ", "ª", "²", "ǆ", "á", "\U0001D6A5", "Ϲ", "admin"}
	junk := []string{"\xf7", "\xff\xfe", "\x80", "\xc3", "\xed\xa0\x80"}

	for _, c := range clean {
		want := Skeleton(c)
		if again := Skeleton(want); again != want {
			t.Errorf("Skeleton(%q) = %q is not a fixed point (%q)", c, want, again)
		}
		for _, j := range junk {
			for _, in := range []string{j + c, c + j, j + c + j} {
				if got := Skeleton(in); got != want {
					t.Errorf("Skeleton(%q) = %q, want %q: invalid UTF-8 changed the fold of %q",
						in, got, want, c)
				}
			}
		}
	}
}

// TestDistinctIdentifiersDoNotCollide guards the other failure mode. Folding
// too aggressively refuses a legitimate user their own name, so a set of
// genuinely different identifiers must keep genuinely different skeletons.
func TestDistinctIdentifiersDoNotCollide(t *testing.T) {
	names := []string{
		"admin", "adm", "admins", "aadmin", "adminn",
		"alice", "alicia", "alison", "bob", "bobby", "bobb",
		"carol", "carl", "dave", "david", "eve", "evan",
		"mallory", "malory", "root", "roots", "toor", "sudo", "pseudo",
		"lima", "lisa", "kelly", "kelli", "ana", "anna",
		"web-01", "web-02", "db2", "db6", "db8", "db9",
		"gitlab", "github", "jürgen", "jorgen", "renee", "rene",
	}
	seen := make(map[string]string, len(names))
	for _, n := range names {
		s := Skeleton(n)
		if s == "" {
			t.Errorf("legitimate name %q folded to the empty skeleton", n)
			continue
		}
		if prev, dup := seen[s]; dup {
			t.Errorf("over-folding: %q and %q share skeleton %q", prev, n, s)
			continue
		}
		seen[s] = n
	}
}

// TestEdgeCases pins the defined behavior for degenerate input.
func TestEdgeCases(t *testing.T) {
	cases := []struct{ name, in, want string }{
		{"empty", "", ""},
		{"single space", " ", ""},
		{"whitespace only", " \t\n 　", ""},
		{"separators only fold to empty", "-_.", ""},
		{"invalid utf8 lone continuation", "\x80admin", "admin"},
		{"invalid utf8 truncated sequence", "ad\xc3min", "admin"},
		{"invalid utf8 only", "\xff\xfe\x80", ""},
		{"unmapped script survives", "漢字", "漢字"},
		{"unmapped symbol survives", "admin!", "admin!"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { checkSkeleton(t, tc.in, tc.want) })
	}
}

// TestVeryLongInput checks that a large identifier is handled linearly and
// correctly; callers are expected to length-limit before calling, but the
// function must not misbehave if they do not.
func TestVeryLongInput(t *testing.T) {
	const n = 100000
	in := strings.Repeat("а-", n)
	got := Skeleton(in)
	if want := strings.Repeat("a", n); got != want {
		t.Errorf("long input: got %d chars, want %d", len(got), len(want))
	}
	if Skeleton(got) != got {
		t.Error("long input is not idempotent")
	}
}

// TestDeterminism asserts repeated calls agree; Skeleton must be pure.
func TestDeterminism(t *testing.T) {
	inputs := []string{"admin", "аDMıN", "", "\xffx", "\U0001d41a-b_c.d"}
	for _, in := range inputs {
		first := Skeleton(in)
		for i := 0; i < 100; i++ {
			if got := Skeleton(in); got != first {
				t.Fatalf("Skeleton(%q) is not deterministic: %q then %q", in, first, got)
			}
		}
	}
}
