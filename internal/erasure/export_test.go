package erasure

// IsTombstoneForTest exposes the unexported tombstone-shape check to the
// external test package, which asserts that a scrubbed metadata value has the
// exact form Tombstone produces rather than merely the prefix.
func IsTombstoneForTest(s string) bool { return isTombstone(s) }

// ScrubDetailsForTest exposes the metadata scrub helper for direct unit testing
// of the classification and idempotency, independent of a store.
func ScrubDetailsForTest(meta map[string]string, salt []byte) (map[string]string, bool) {
	return scrubDetails(meta, salt)
}
