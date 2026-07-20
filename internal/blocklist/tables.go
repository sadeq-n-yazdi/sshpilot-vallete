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
