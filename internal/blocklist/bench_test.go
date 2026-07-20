package blocklist

import (
	"strings"
	"testing"
)

func BenchmarkSkeleton(b *testing.B) {
	for b.Loop() {
		_ = Skeleton("Admin-Team_𝐚𝐝𝐦𝐢𝐧-4dm1n")
	}
}

// BenchmarkCandidateSkeletons measures the ambiguous-reading expansion across
// the range that matters: no ambiguous rune (the common case, where the
// function must stay nearly free), one and two (what real identifiers carry --
// the most i-laden word in /usr/share/dict/words has six), and the bound
// itself, which is the worst case the engine will ever actually run.
//
// The bound case is the number to watch. It is paid once at create or rename,
// never per request, and an expansion that grew materially past it would be
// worth re-examining maxAmbiguousRunes over.
func BenchmarkCandidateSkeletons(b *testing.B) {
	for name, in := range map[string]string{
		"none":  "administrator",
		"one":   "billing",
		"two":   "biliing",
		"bound": strings.Repeat("i", maxAmbiguousRunes) + "admn",
	} {
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				_, _ = candidateSkeletons(in)
			}
		})
	}
}

// BenchmarkCheckWithExpansion measures the whole verdict, which is what a
// caller actually pays: the fold, the expansion, and the walk of every list
// against every candidate.
func BenchmarkCheckWithExpansion(b *testing.B) {
	m, err := DefaultMatcher()
	if err != nil {
		b.Fatalf("DefaultMatcher: %v", err)
	}
	for name, in := range map[string]string{
		"allowed no ambiguity": "my-key-set",
		"allowed with i":       "indivisibility",
		"blocked exact":        "admin",
		"blocked by expansion": "he1p",
	} {
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				_ = m.Check(in)
			}
		})
	}
}
