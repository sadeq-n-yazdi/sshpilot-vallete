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
