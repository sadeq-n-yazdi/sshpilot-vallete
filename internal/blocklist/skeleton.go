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
//
// # Not NFKC
//
// The Unicode standard's answer to stage one would be NFKC. The Go standard
// library does not ship a normalizer and this module deliberately takes no new
// dependency, so what follows is a curated compatibility-and-confusable fold
// built from explicit, hand-auditable tables (see tables.go). It covers the
// compatibility forms that matter for identifier spoofing -- fullwidth,
// mathematical alphanumerics, circled, superscript, ligatures -- rather than
// the whole of NFKC. Coverage is intentionally finite and is expected to grow;
// see TableVersion.
package blocklist

import (
	"strings"
	"unicode"
	"unicode/utf8"
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
const TableVersion = 3

// Skeleton reduces s to its canonical comparison form. The result is a lossy,
// one-way projection of s; see the package documentation.
//
// The pipeline runs once per rune, in this order. The order is deliberate:
//
//  1. Ignorables. Invalid UTF-8, combining marks (Mn) and format characters
//     (Cf, e.g. zero-width space/joiner and soft hyphen) are dropped. Doing
//     this first means "a<ZWSP>dmin" and decomposed "ádmin" cannot hide behind
//     an invisible codepoint for the rest of the pipeline.
//  2. Case folding, via unicode.ToLower, which applies the full Unicode simple
//     lowercase mapping (Cyrillic А->а, Greek Α->α, fullwidth Ａ->ａ), not just
//     ASCII. Folding here means every later table needs lowercase keys only,
//     which halves them and halves what a reviewer must audit. The case the
//     simple mapping does not cover is handled by table instead: dotless ı
//     (U+0131) has no lowercase mapping to i. Its companion İ (U+0130) does
//     fold to a bare "i" under the per-rune simple mapping, so it needs no
//     entry; note this differs from the full string-level Unicode mapping,
//     which yields "i" plus a combining dot.
//  3. Compatibility ranges: algorithmically contiguous blocks (fullwidth,
//     mathematical alphanumerics, circled) are mapped by arithmetic to ASCII.
//  4. Confusables: the arbitrary, non-algorithmic visual equivalences --
//     Cyrillic, Greek, ligatures, accented Latin -- from an explicit table.
//  5. Leetspeak: digit and symbol substitutions.
//  6. Separators: the padding characters an attacker inserts to break a
//     substring compare.
//
// Stages 3, 4 and 5 chain deliberately: fullwidth "４" becomes ASCII "4" in
// stage 3 and then "a" in stage 5, so "４dmin" and "admin" agree.
//
// No character surviving the pipeline is a key of any table or a separator.
// Stage 4 emits only ASCII letters and digits; stage 3 emits ASCII except for
// the mathematical Greek rule, which emits a plain Greek letter so that stage 4
// can reduce the ones with a Latin look-alike. The Greek letters that stage 4
// does not reduce -- beta, gamma, theta and the rest, which have no Latin
// reading to give them -- survive to the output, and they are fixed points too:
// none is a key of any table, a leet source or a separator. Every digit and
// symbol with a leet reading is consumed by stage 5. Every output character is
// therefore a fixed point of the pipeline, which makes
// Skeleton(Skeleton(s)) == Skeleton(s) true by construction rather than by
// accident. Skeleton is pure and deterministic.
//
// A skeleton is consequently not guaranteed to be ASCII. It is guaranteed to be
// canonical: two inputs that draw the same glyphs share one skeleton.
//
// The result is always valid UTF-8. Empty, whitespace-only, and
// entirely-foldable inputs all return "". Callers MUST treat an empty
// skeleton as "carries no comparable content" and reject such identifiers on
// that ground rather than treating them as matching nothing.
func Skeleton(s string) string {
	// A strings.Builder rather than a []rune accumulator: runes cost four bytes
	// each and the final string(out) conversion allocates a second time, while
	// Grow reserves one byte-sized buffer that String() hands over without
	// copying. Grow(len(s)) is a hint, not a bound -- a confusables entry may
	// expand one rune into several -- so the Builder still grows when it must.
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

		if folded, ok := foldRange(r); ok {
			r = folded
		}
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
