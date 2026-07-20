// Package safetext bounds untrusted text for use in logs, errors and other
// diagnostics.
//
// # Why this is its own package
//
// Cutting remote-controlled text at a fixed byte count is the obvious way to
// keep an attacker-influenced string from filling a log, and it has a defect
// that is invisible in ASCII testing: the cut can land in the middle of a
// multi-byte UTF-8 sequence, leaving a fragment that is not valid UTF-8. The
// resulting string is then mangled by whatever encodes it downstream, and in a
// JSON log it can corrupt the record.
//
// The shape appeared independently in four places in this repository — the
// Cloudflare Origin CA client and all three DNS-01 providers — which is the
// argument for one implementation rather than a fifth copy of the fix.
//
// [Bound] therefore owns the length check, the slice AND the trim. That
// division is deliberate: the defect this package exists to prevent was
// originally introduced by hand-computed slice offsets, so the goal is that no
// caller writes s[:n] on remote text at all, not merely that a repair function
// is available to remember to call.
//
// Nothing here sanitizes content. Control characters, escape sequences and
// already-invalid UTF-8 present in the input are the caller's concern; this
// package only guarantees that IT did not introduce a new fault by cutting.
package safetext

import "unicode/utf8"

// Bound returns s limited to at most maxBytes bytes, without leaving a partial
// UTF-8 rune at the end.
//
// The result is never longer than maxBytes, and is valid UTF-8 whenever the
// retained prefix of s was. A non-positive maxBytes yields the empty string.
//
// Bound does not append an ellipsis or any other marker. A caller that wants
// one can compare lengths itself, because whether truncation is worth signaling
// depends on the sink.
func Bound(s string, maxBytes int) string {
	if maxBytes <= 0 {
		return ""
	}
	if len(s) <= maxBytes {
		return s
	}
	return TrimPartialRune(s[:maxBytes])
}

// TrimPartialRune drops a partial UTF-8 rune left at the end of a string that
// was cut at a byte offset.
//
// It is exported for the caller that must do its own length check — for
// instance one appending a truncation marker only when it actually truncated.
// Prefer [Bound], which removes the opportunity to compute the offset wrongly.
//
// The obvious implementation is []rune(s) then slice by rune count, and it is
// NOT used here on purpose: that converts the WHOLE string before truncating,
// allocating about four bytes per input byte on text whose length an attacker
// influences. It would widen the exact thing the truncation exists to narrow.
// This walks back from the end instead — no allocation, and bounded by the
// longest UTF-8 encoding rather than by the input.
//
// At most three bytes can be a fragment, so the loop is capped there. A cut
// cannot introduce more than that, and anything still invalid past it was
// invalid in the input already; sanitizing that is not this function's job.
func TrimPartialRune(s string) string {
	for range utf8.UTFMax - 1 {
		if s == "" {
			return s
		}
		// A size of 1 with RuneError means the tail is a fragment. A genuine
		// U+FFFD in the text decodes as RuneError too, but at size 3, so testing
		// the SIZE is what separates a real character from a stub. Testing only
		// the rune would silently eat U+FFFD characters that were in the input.
		if r, size := utf8.DecodeLastRuneInString(s); r != utf8.RuneError || size != 1 {
			return s
		}
		s = s[:len(s)-1]
	}
	return s
}
