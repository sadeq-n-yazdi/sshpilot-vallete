// Package blocklist reduces user-supplied identifiers (handles, key-set names,
// device names) to a canonical "skeleton" string used only for comparison
// against reserved-word and profanity blocklists.
//
// # One-way and lossy
//
// Skeleton is deliberately DESTRUCTIVE. It discards case, accents, separators,
// combining marks, and the distinction between whole families of
// visually-confusable codepoints. The result MUST NEVER be stored as the
// user's identifier, displayed back to a user, used as a database key, or
// round-tripped in any way. Its single purpose is to be compared against
// another skeleton. Persist and display the original input; compare the
// skeleton.
//
// # Why
//
// A naive string compare against a list such as {"admin", "root"} is trivially
// defeated: an attacker registers "Admin", "аdmin" (Cyrillic U+0430), "ａｄｍｉｎ"
// (fullwidth), "a-d-m-i-n", "4dm1n", or "𝐚𝐝𝐦𝐢𝐧" (mathematical bold) and
// renders an identifier that is indistinguishable from the reserved one to
// every human who reads it. Folding all of those to the same skeleton is what
// makes the later match step (a separate change) meaningful.
//
// # Scope
//
// This package implements the normalization step ONLY. It contains no
// blocklists, no allowlist, no matching, and no enforcement.
package blocklist

import (
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

// TableVersion identifies the revision of the folding tables and of the
// pipeline that consumes them. It is a monotonically increasing integer.
//
// Changing any table, or the order of the pipeline stages, changes which
// identifiers are considered equal and therefore changes what the system
// blocks and what it permits. Such a change is a deliberate, security-relevant
// act: it MUST bump TableVersion, and it MUST be reviewed. Recording this
// value alongside any persisted decision makes a later ruleset change
// detectable and auditable.
//
// Version 1: initial tables (compatibility ranges, confusables, leet,
// separators) as described in tables.go.
//
// Version 2: confusables gains Greek eta and omega and Cyrillic yi and shha.
// Each was a working impersonation vector: "admiη", "admїn" and "һdmin" all
// survived version 1 unfolded.
//
// Version 3: foldRange covers the gap between the mathematical Latin letters
// and the mathematical digits -- the italic dotless i/j at U+1D6A4..U+1D6A5 and
// the whole Mathematical Greek block at U+1D6A8..U+1D7CB. Every styled Greek
// letter previously survived unfolded, so "𝛂dmin" did not match "admin".
//
// Version 4: Rework stage 1 to use standard NFKD normalization from the
// golang.org/x/text/unicode/norm package, replacing hand-maintained range-folding tables.
const TableVersion = 4

// Skeleton reduces s to its canonical comparison form. The result is a lossy,
// one-way projection of s; see the package documentation.
//
// The pipeline runs in this order. The order is deliberate:
//
//  1. Compatibility Decomposition (NFKD). Compatibility characters (such as
//     mathematical letters/digits, fullwidth forms, circled letters/digits,
//     and ligatures) and accents are decomposed to their base form and
//     combining marks.
//  2. Ignorables. Invalid UTF-8, combining marks (Mn) and format characters
//     (Cf, e.g. zero-width space/joiner and soft hyphen) are dropped.
//  3. Case folding, via unicode.ToLower, which applies the full Unicode simple
//     lowercase mapping.
//  4. Confusables: the arbitrary, non-algorithmic visual equivalences --
//     Cyrillic, Greek lookalikes, and Latin exceptions -- from an explicit table.
//  5. Leetspeak: digit and symbol substitutions.
//  6. Separators: the padding characters an attacker inserts to break a
//     substring compare.
func Skeleton(s string) string {
	// Fast path: if the input is already a canonical skeleton (lowercase ASCII
	// letters a-z and unmapped digits 2, 6, 8, 9), return it directly to avoid
	// allocations.
	fast := true
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || c == '2' || c == '6' || c == '8' || c == '9' {
			continue
		}
		fast = false
		break
	}
	if fast && len(s) > 0 {
		return s
	}

	// Stage 1: NFKD normalization
	s = norm.NFKD.String(s)

	var out strings.Builder
	out.Grow(len(s))
	for _, r := range s {
		// A decoding error over invalid UTF-8 yields utf8.RuneError; so does a
		// literal U+FFFD in the input. Both are dropped, which is what keeps
		// the output valid UTF-8 unconditionally.
		if r == utf8.RuneError {
			continue
		}
		if unicode.Is(unicode.Mn, r) || unicode.Is(unicode.Cf, r) {
			continue
		}

		r = unicode.ToLower(r)

		if mapped, ok := confusables[r]; ok {
			// Each rune the table produced re-enters the remaining stages, so
			// a superscript "¹" becomes "1" here and then "i" below. Without
			// that, a table target could itself be a leet source and
			// idempotence would break.
			for _, m := range mapped {
				writeFolded(&out, m)
			}
			continue
		}
		writeFolded(&out, r)
	}
	return out.String()
}

// writeFolded runs the final two stages -- leetspeak and separator removal --
// and writes the result, if any, to out.
func writeFolded(out *strings.Builder, r rune) {
	if mapped, ok := leetspeak[r]; ok {
		out.WriteRune(mapped)
		return
	}
	if isSeparator(r) {
		return
	}
	out.WriteRune(r)
}
