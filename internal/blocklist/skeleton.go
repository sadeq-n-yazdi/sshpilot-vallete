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
// golang.org/x/text/unicode/norm package, replacing hand-maintained
// range-folding tables. foldRange and its tables are gone; the compatibility
// forms it enumerated by arithmetic -- fullwidth, mathematical alphanumerics,
// circled, superscript, ligatures -- are now decomposed by NFKD, which also
// covers the ones the hand table had not reached yet.
//
// Version 5: ambiguousReadings and the candidate expansion the match stage
// performs with it. Skeleton itself is unchanged and still returns exactly one
// string; what changed is that a skeleton is no longer compared only as itself.
// The digit one and every codepoint that folds to "i" alongside it draw a glyph
// with two readings, i and l, and a fold to a single output can only keep one.
// Every version through 4 kept i, which is what makes "4dm1n" equal "admin" --
// and which left every reserved word containing an l spellable past the list:
// "he1p", "1ogin", "bi11ing", "officia1" were all permitted. The match stage
// now expands the discarded reading back out; see ambiguousReadings in
// tables.go. This changes which identifiers the system refuses, so it is a
// table revision even though no folding table entry moved.
//
// Version 6: repair the confusable coverage that version 4 silently lost, and
// restore idempotence. Running NFKD ahead of every other stage let it
// canonicalize a confusable into a base form the confusables table does not
// cover, so a codepoint that used to fold survived unfolded. Ϲ (U+03F9 GREEK
// CAPITAL LUNATE SIGMA SYMBOL) decomposed to Σ and lowercased to σ instead of
// reaching the 'ϲ' entry, making "Ϲonsole" a working homoglyph bypass of the
// reserved-word list; 𝚥 (U+1D6A5 MATHEMATICAL ITALIC SMALL DOTLESS J)
// decomposed to ȷ (U+0237), for which there was no entry at all, so "blow𝚥ob"
// and "𝚥s" passed. Two changes close the class rather than the two instances: a
// sanitize pass now consults confusables BEFORE NFKD can rewrite the source
// away, and 'ȷ' joins its sibling 'ı' in the table. Version 4 also broke the
// documented idempotence guarantee, because NFKD does not decompose reliably
// across invalid UTF-8: Skeleton("\xf7ʰ") returned "ʰ" while Skeleton("ʰ")
// returned "h". The same sanitize pass drops invalid UTF-8 ahead of NFKD, which
// is what makes a second pass a no-op again.
const TableVersion = 6

// Skeleton reduces s to its canonical comparison form. The result is a lossy,
// one-way projection of s; see the package documentation.
//
// The pipeline runs in this order. The order is deliberate:
//
//  0. Sanitize. Invalid UTF-8 is dropped, and confusables is consulted on the
//     RAW input. See sanitize -- both halves exist because NFKD, left to run
//     first, destroys work the later stages depend on.
//  1. Compatibility Decomposition (NFKD). Compatibility characters (such as
//     mathematical letters/digits, fullwidth forms, circled letters/digits,
//     and ligatures) and accents are decomposed to their base form and
//     combining marks.
//  2. Ignorables. Combining marks (Mn) and format characters (Cf, e.g.
//     zero-width space/joiner and soft hyphen) are dropped. These can only be
//     recognized after stage 1, because that is what produces them from
//     precomposed forms.
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

	// Stage 0, then stage 1: NFKD normalization.
	s = norm.NFKD.String(sanitize(s))

	var out strings.Builder
	out.Grow(len(s))
	for _, r := range s {
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

// sanitize is stage 0. It does the two things that MUST happen before NFKD
// runs, because NFKD destroys the information each of them needs.
//
// # Handing NFKD well-formed UTF-8 is what makes Skeleton idempotent
//
// norm.NFKD does not decompose reliably across an invalid byte: it treats the
// undecodable region as a segment boundary and passes the neighboring segment
// through untouched. When NFKD ran on the raw input, a compatibility character
// beside an invalid byte therefore survived the first pass and was decomposed
// only by the second, once the invalid byte was gone -- Skeleton("\xf7ʰ") was
// "ʰ" while Skeleton("ʰ") was "h".
//
// The property that fixes it is that NFKD is only ever handed well-formed
// UTF-8, and this loop guarantees it structurally: it decodes and re-encodes,
// so whatever it emits is well-formed regardless of what it was given. Note
// that this is what carries the idempotence guarantee -- NOT the fact that
// invalid input is specifically DISCARDED here. Replacing each invalid byte
// with U+FFFD instead would remove the segment boundary just as well.
// Discarding is a separate, older contract: the skeleton must not contain
// U+FFFD, because a run of them would otherwise be a way to pad an identifier
// past a substring compare. A decoding error yields utf8.RuneError and so does
// a literal U+FFFD in the input, and dropping both is what keeps that contract
// and the well-formedness one in a single pass.
//
// Idempotence is restored by this reordering rather than by iterating Skeleton
// to a fixed point. The input is attacker-supplied and unauthenticated, so a
// loop is a work multiplier it is better not to own at all: a bound would have
// to be chosen, and choosing one only converts a non-idempotent result into a
// non-idempotent result that also costs N passes. Making the single pass
// closed is strictly cheaper and is the property FuzzSkeleton enforces.
//
// # Consulting confusables before NFKD is what keeps confusables reachable
//
// A confusable is folded by the glyph it DRAWS, which is a judgement no
// algorithm makes for us. NFKD folds by compatibility, which is a different
// relation, and where the two disagree NFKD wins if it runs first -- it
// rewrites the source into a base form the table was never keyed on, and the
// entry silently stops firing. Ϲ (U+03F9) is the case that proved it: it
// lowercases to ϲ, which the table maps to "c", but NFKD first decomposes it
// to Σ, which lowercases to σ, which is nothing. Looking the raw rune up here
// gets the table its answer while the source still exists.
//
// The lookup is on unicode.ToLower(r) because the table is keyed lowercase;
// runes that miss are written through unchanged rather than lowercased, so
// NFKD still sees the input it expects. The main loop repeats the confusables
// lookup after NFKD, and that second lookup is equally load-bearing in the
// other direction: it is what catches the compatibility forms NFKD decomposes
// INTO a table key, such as the mathematical dotless i at U+1D6A4 landing on
// 'ı'. Neither lookup subsumes the other; both are required.
func sanitize(s string) string {
	var out strings.Builder
	out.Grow(len(s))
	for _, r := range s {
		if r == utf8.RuneError {
			continue
		}
		if mapped, ok := confusables[unicode.ToLower(r)]; ok {
			out.WriteString(mapped)
			continue
		}
		out.WriteRune(r)
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
