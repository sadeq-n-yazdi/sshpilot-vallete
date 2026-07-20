package blocklist

import "unicode"

// This file holds the folding tables consumed by Skeleton. Any edit here
// changes what the system blocks and must bump TableVersion; see skeleton.go.
//
// Invariant enforced by review and by TestEveryEntryFoldsLikeItsTarget: every
// mapping target below is made of lowercase ASCII letters and digits; no
// lowercase ASCII letter is a key of any table or a separator; and every digit
// carrying a leet reading is consumed by the leetspeak stage, which runs after
// these tables. What the pipeline finally emits is therefore always a fixed
// point, which is what makes Skeleton idempotent by construction.
//
// The tables are deliberately finite. They cover the forms that are actually
// used to spoof identifiers, not the whole of Unicode. Under-coverage is a
// missed block (a later change adds the codepoint); over-coverage is a real
// user refused a legitimate name, which is the worse failure. When in doubt,
// an entry is left out.

// confusables maps visually-confusable codepoints to their ASCII skeleton.
// Keys are lowercase because Skeleton case-folds before consulting this table.
// The set follows the Unicode confusables concept but is curated by hand: each
// entry is one an attacker can plausibly use to impersonate a reserved word.
//
// Values are strings because a few sources expand to more than one letter
// (ß). Every value is lowercase ASCII.
var confusables = map[rune]string{
	// --- Cyrillic. The classic homograph attack: "аdmin" with U+0430.
	'а': "a", // U+0430 CYRILLIC SMALL A
	'в': "b", // U+0432 CYRILLIC SMALL VE (uppercase В reads as B)
	'с': "c", // U+0441 CYRILLIC SMALL ES
	'ԁ': "d", // U+0501 CYRILLIC SMALL KOMI DE
	'е': "e", // U+0435 CYRILLIC SMALL IE
	'ѕ': "s", // U+0455 CYRILLIC SMALL DZE
	'н': "h", // U+043D CYRILLIC SMALL EN (uppercase Н reads as H)
	'і': "i", // U+0456 CYRILLIC SMALL BYELORUSSIAN-UKRAINIAN I
	'ї': "i", // U+0457 CYRILLIC SMALL YI (і plus a diaeresis, precomposed)
	'ј': "j", // U+0458 CYRILLIC SMALL JE
	'һ': "h", // U+04BB CYRILLIC SMALL SHHA (drawn as a Latin h)
	'к': "k", // U+043A CYRILLIC SMALL KA
	'м': "m", // U+043C CYRILLIC SMALL EM (uppercase М reads as M)
	'о': "o", // U+043E CYRILLIC SMALL O
	'р': "p", // U+0440 CYRILLIC SMALL ER
	'т': "t", // U+0442 CYRILLIC SMALL TE (uppercase Т reads as T)
	'у': "y", // U+0443 CYRILLIC SMALL U (reads as Latin y)
	'х': "x", // U+0445 CYRILLIC SMALL HA
	'ѡ': "w", // U+0461 CYRILLIC SMALL OMEGA

	// --- Greek.
	'α': "a", // U+03B1 GREEK SMALL ALPHA
	'ε': "e", // U+03B5 GREEK SMALL EPSILON
	'η': "n", // U+03B7 GREEK SMALL ETA (reads as Latin n)
	'ι': "i", // U+03B9 GREEK SMALL IOTA
	'κ': "k", // U+03BA GREEK SMALL KAPPA
	'μ': "m", // U+03BC GREEK SMALL MU
	'ν': "v", // U+03BD GREEK SMALL NU (reads as Latin v)
	'ο': "o", // U+03BF GREEK SMALL OMICRON
	'ρ': "p", // U+03C1 GREEK SMALL RHO
	'τ': "t", // U+03C4 GREEK SMALL TAU
	'υ': "u", // U+03C5 GREEK SMALL UPSILON
	'χ': "x", // U+03C7 GREEK SMALL CHI
	'ω': "w", // U+03C9 GREEK SMALL OMEGA (as Cyrillic ѡ above)
	'ϲ': "c", // U+03F2 GREEK LUNATE SIGMA
	'ς': "c", // U+03C2 GREEK SMALL LETTER FINAL SIGMA (NFKD target of U+03F2)

	// --- Latin letters whose lowercase mapping does not reach ASCII.
	//
	// U+0131 DOTLESS I is the Turkish-locale trap ("admın"): unicode.ToLower
	// leaves it unchanged, so without this entry it would slip through. Its
	// companion İ (U+0130) needs no entry -- Go's per-rune simple lowercase
	// mapping already yields a bare "i", never the "i" plus combining dot that
	// the full string-level Unicode mapping produces.
	'ı': "i",
	'ł': "l",  // U+0142 LATIN SMALL L WITH STROKE
	'đ': "d",  // U+0111 LATIN SMALL D WITH STROKE
	'ø': "o",  // U+00F8 LATIN SMALL O WITH STROKE
	'ß': "ss", // U+00DF SHARP S: the standard full case fold is "ss"
	'æ': "ae", // U+00E6 LATIN SMALL AE
	'œ': "oe", // U+0153 LATIN SMALL LIGATURE OE
}

// leetspeak folds the digit and symbol substitutions used to spell a word
// without using its letters. Only substitutions with a single, widely
// recognized reading are included; ambiguous ones are omitted rather than
// guessed, because a wrong fold blocks a legitimate identifier.
//
// The ambiguous case is "1", which reads as either l or i. It is folded to i.
// The deciding consideration is that the alternative -- folding 1 to l -- only
// catches i-substitutions if l and i are ALSO folded together, and collapsing
// two real, common ASCII letters into one would make genuinely distinct names
// such as "lima" and "iima", or "kelly" and "keily", collide. Folding 1 to i
// costs nothing beyond the choice itself and keeps "4dm1n" equal to "admin",
// which is the case that matters. "l"-shaped digits are left to the confusable
// table where the source is a distinct codepoint.
//
// Deliberately excluded: 8 (b/ate), 6 (b/g), 2 (z/to), 9 (g/q), 5 also reads
// as S and is included because that reading is unambiguous in practice.
var leetspeak = map[rune]rune{
	'0': 'o', // zero for the letter O
	'1': 'i', // one for I -- see the note above on the l/i ambiguity
	'3': 'e', // mirrored E
	'4': 'a', // A without the crossbar
	'5': 's', // S
	'7': 't', // T
	'@': 'a', // "at" sign, the canonical A substitute
	'$': 's', // dollar sign for S
}

// ambiguousReadings maps a rune of a FINISHED SKELETON to the readings that the
// fold had to discard to produce it. It is the one table in this file that is
// keyed on the pipeline's output rather than its input, and that is the whole
// point of it.
//
// # Why a second reading is needed at all
//
// Every other table above is a function: a source glyph has one letter it
// draws, and folding to that letter loses nothing worth keeping. The digit one
// is not a function. "1" draws a bare vertical stroke, and a stroke is equally
// the letter i and the letter l -- both readings are in common, deliberate use.
// A fold that emits a single rune must pick one, and picking is where the
// blocklist leaks: leetspeak folds "1" to i, so "4dm1n" correctly equals
// "admin", and "he1p" equally correctly equals "heip", which is not a reserved
// word. Every reserved word containing an l -- help, login, billing, official,
// wallet, legal, null -- was registerable that way.
//
// Restoring the lost reading cannot be done by editing leetspeak, because the
// choice is between two readings and the table has room for one. It is done
// instead by the match stage, which expands a skeleton into the set of
// skeletons it might have been and blocks if ANY of them matches a term. See
// candidateSkeletons in match.go.
//
// # Why one entry covers the whole class
//
// The key is "i", not "1", and that is deliberate. By the time the pipeline
// finishes, every stroke-shaped source has already converged on i, by one of
// three routes:
//
//   - NFKD alone, into an ASCII digit that leetspeak then folds: fullwidth "１",
//     circled "①", superscript "¹" and the mathematical digits all decompose to
//     ASCII "1", which leetspeak reads as i. The ASCII digit takes the same
//     last step directly.
//   - NFKD into an ASCII letter that the case fold then lowers: ASCII capital
//     I, fullwidth "Ｉ", the mathematical capital I forms and script capital ℐ
//     (U+2110) all decompose to "I". Roman numeral ⅰ (U+2170) decomposes
//     straight to "i".
//   - NFKD into a letter that only the confusables table can reach: dotless ı
//     (U+0131) and Greek iota ι (U+03B9) are NOT decomposed by NFKD, and the
//     mathematical dotless i (U+1D6A4) and mathematical iota forms decompose
//     TO them rather than to ASCII. These reach i solely through the 'ı' and
//     'ι' entries in confusables above.
//
// That third route is load-bearing and easy to lose. The 'ı' and 'ι' confusable
// entries must not be removed on the reasoning that "NFKD handles the
// compatibility forms now" -- NFKD hands those forms to ı and ι and stops, so
// dropping the entries would strand a whole family of stroke-shaped sources
// short of i and silently reopen the evasion this table exists to close.
// TestAmbiguousExpansionCoversEveryStrokeShapedSource enforces all three
// routes.
//
// Keying the ambiguity on the fold's OUTPUT covers all of them with one entry,
// and -- more usefully -- covers any future table entry that folds a new
// stroke-shaped codepoint to i without this table needing to learn about it.
// Keying on each source would need an entry per source and would silently miss
// the next one added.
//
// # The direction is deliberately one-way
//
// i expands to l; l does not expand to i. The skeleton's l can only have come
// from a source that unambiguously draws an l (l itself, ł, ℓ), so there is no
// discarded reading to restore, and inventing one is not free. Measured against
// /usr/share/dict/words (104334 entries) and the default lists: expanding i to
// l blocks ZERO additional real words, while making i and l interchangeable in
// both directions blocks "mall" and "Mali", which collide with the reserved
// term "mail". Over-blocking refuses a real user their own name (see the note
// at the top of this file), so the cheaper direction is the only one taken.
//
// Values are slices, and their order is part of the contract: it fixes the
// order candidates are generated in and therefore which term a Result reports
// when more than one could match. The table is looked up by key and MUST NEVER
// be ranged over; see Matcher's determinism note.
//
// Keys and readings are single-byte ASCII, which TestAmbiguousReadingsAreASCII
// enforces. candidateSkeletons relies on it to scan a skeleton byte by byte:
// a UTF-8 continuation byte is always >= 0x80 and so can never be mistaken for
// a key, and an ASCII-for-ASCII substitution cannot shift the offsets of the
// bytes around it.
var ambiguousReadings = map[byte][]byte{
	'i': {'l'},
}

// maxAmbiguousRunes bounds how many ambiguous positions candidateSkeletons will
// expand. Exceeding it is refused, not truncated; see candidateSkeletons.
//
// Expansion is exponential -- k ambiguous positions produce 2^k candidates --
// and the string it expands is supplied by an unauthenticated caller, so an
// unbounded version is a denial-of-service primitive: 64 of the digit one, well
// inside the 64-character handle limit, would ask for 2^64 candidates.
//
// Twelve is chosen from the data rather than picked round. The most i-laden
// word in /usr/share/dict/words is "indivisibility" with six, so the bound
// leaves a factor of 64 of headroom over the worst legitimate identifier
// anybody has been observed to want, while capping the work at 4096 candidates
// -- a few milliseconds of substring scanning, paid once at create or rename
// and never per request. An identifier needing a thirteenth ambiguous position
// is not a name, and treating it as one is the failure this bound exists to
// prevent.
const maxAmbiguousRunes = 12

// maxCandidateSkeletons is the resulting ceiling on the candidate set.
const maxCandidateSkeletons = 1 << maxAmbiguousRunes

// isSeparator reports whether r is padding an attacker inserts to break a
// naive compare ("a-d-m-i-n", "a.d.m.i.n", "a d m i n") and is therefore
// dropped from the skeleton.
//
// Deliberate decision -- repeated-character runs are NOT collapsed. Collapsing
// them would additionally catch "aaadminnn", but it would also make "bob" and
// "bobb", "ana" and "anna", or "matt" and "mat" share a skeleton, and a false
// positive here refuses a real user their own name. Doubled letters are common
// and legitimate in human names; deliberately padded runs are not among the
// evasions this package is required to defeat. The trade is judged not worth
// it. Should that change, it belongs in a reviewed TableVersion bump.
func isSeparator(r rune) bool {
	// ASCII fast path. '-' is in unicode.Pd and '_' in unicode.Pc, so both are
	// already covered below; naming them here only skips a range-table search
	// for the separators that actually appear in identifiers.
	switch r {
	case '_', '.', '-':
		return true
	}
	// unicode.Pd covers ASCII "-" together with every other dash form
	// (en dash, em dash, U+2010 hyphen), which an attacker can substitute
	// freely. unicode.Pc covers "_" and its connector relatives. IsSpace
	// covers ASCII space, tab, NBSP and the Unicode space repertoire.
	return unicode.IsSpace(r) || unicode.Is(unicode.Pd, r) || unicode.Is(unicode.Pc, r)
}
