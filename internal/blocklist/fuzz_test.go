package blocklist

import (
	"testing"
	"unicode"
	"unicode/utf8"
)

// FuzzSkeleton asserts the three contract properties on arbitrary input:
// Skeleton never panics, always returns valid UTF-8 even when handed invalid
// UTF-8, and is idempotent. Idempotence is the one an added table entry is
// most likely to break -- a new mapping whose target is itself foldable -- so
// it is checked here as well as in the table-driven cases.
func FuzzSkeleton(f *testing.F) {
	seeds := []string{
		"", " ", "-_.", "admin", "ADMIN", "аdmin", "ａｄｍｉｎ",
		"a-d-m-i-n", "@dmin", "4dm1n", "admın", "ádmín",
		"\U0001d41a\U0001d41d\U0001d426\U0001d422\U0001d427",
		"ⓐⓓⓜⓘⓝ", "¹²³", "ﬁ", "ß", "İ", "a\u200bd\u0301min",
		"\xff\xfe", "ad\xc3min", "漢字", "root2689",
		// Confirmed bypasses: Greek eta/omega, Cyrillic yi/shha.
		"admiη", "admїn", "һdmin", "ωeb",
		// Confirmed bypasses in the mathematical Greek block and the dotless
		// i/j that precede it, plus the two runes there that stay unfolded.
		"adm\U0001D6A4n", "\U0001D6C2dmin", "admin\U0001D6D0",
		"\U0001D6A8dmin", "\U0001D7AAdmin", "\U0001D7CB",
		"\U0001D6C1\U0001D6DB",
		// Version 6: the two confusables NFKD-before-everything stopped
		// reaching, and the invalid-UTF-8 shape that broke idempotence.
		"Ϲonsole", "seϹurity", "\U0001D6A5s", "blow\U0001D6A5ob", "ȷs",
		"\xf7ʰ", "ʰ", "\xffﬁ", "á\x80",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, in string) {
		got := Skeleton(in)

		if !utf8.ValidString(got) {
			t.Fatalf("Skeleton(%q) returned invalid UTF-8: %q", in, got)
		}
		if again := Skeleton(got); again != got {
			t.Fatalf("Skeleton not idempotent: %q -> %q -> %q", in, got, again)
		}
		// No output character may be one the pipeline claims to remove; that
		// invariant is what idempotence rests on.
		for _, r := range got {
			if isSeparator(r) {
				t.Fatalf("Skeleton(%q) = %q kept separator %q", in, got, r)
			}
			if _, ok := leetspeak[r]; ok {
				t.Fatalf("Skeleton(%q) = %q kept leet source %q", in, got, r)
			}
			if _, ok := confusables[r]; ok {
				t.Fatalf("Skeleton(%q) = %q kept confusable %q", in, got, r)
			}
			if unicode.Is(unicode.Mn, r) || unicode.Is(unicode.Cf, r) {
				t.Fatalf("Skeleton(%q) = %q kept ignorable %q", in, got, r)
			}
		}
	})
}
