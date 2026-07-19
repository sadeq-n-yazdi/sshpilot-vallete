package blocklist

import "testing"

func BenchmarkSkeleton(b *testing.B) {
	for b.Loop() {
		_ = Skeleton("Admin-Team_𝐚𝐝𝐦𝐢𝐧-4dm1n")
	}
}
