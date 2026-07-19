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

// foldRange maps the algorithmically contiguous compatibility blocks to ASCII
// by arithmetic. These are ranges rather than table entries because they are
// regular: writing out ~700 mathematical alphanumeric codepoints by hand would
// be unauditable, whereas the offset rules below are each one line to verify.
//
// The returned rune is re-examined by the later stages, so a fullwidth "４"
// becomes ASCII "4" here and then "a" in the leetspeak stage.
func foldRange(r rune) (rune, bool) {
	switch {
	// Fullwidth ASCII forms U+FF01..U+FF5E are the ASCII repertoire shifted by
	// a constant 0xFEE0, so one rule covers letters, digits and punctuation:
	// ａ->a, ４->4, ＠->@, －->-.
	case r >= 0xFF01 && r <= 0xFF5E:
		return r - 0xFEE0, true

	// Mathematical Alphanumeric Symbols U+1D400..U+1D6A3 are 26 consecutive
	// 26-letter alphabets (bold, italic, script, fraktur, double-struck, sans,
	// monospace, ...), so position modulo 26 is the letter index. The handful
	// of reserved holes in that range (e.g. U+1D455, unified with U+210E)
	// occupy the slot of the very letter they stand for, so the arithmetic
	// stays correct across them. Covers 𝐚𝐝𝐦𝐢𝐧 and every other styled variant.
	case r >= 0x1D400 && r <= 0x1D6A3:
		return 'a' + (r-0x1D400)%26, true

	// Mathematical digits U+1D7CE..U+1D7FF: 5 consecutive 10-digit blocks.
	case r >= 0x1D7CE && r <= 0x1D7FF:
		return '0' + (r-0x1D7CE)%10, true

	// Circled Latin capitals Ⓐ..Ⓩ. Reached only when a caller's input escapes
	// the simple lowercase mapping; kept for completeness.
	case r >= 0x24B6 && r <= 0x24CF:
		return 'a' + (r - 0x24B6), true

	// Circled Latin smalls ⓐ..ⓩ.
	case r >= 0x24D0 && r <= 0x24E9:
		return 'a' + (r - 0x24D0), true

	// Circled digits ①..⑨ (there is no ⓪ in this run; it sits at U+24EA).
	case r >= 0x2460 && r <= 0x2468:
		return '1' + (r - 0x2460), true

	// Circled digit zero ⓪.
	case r == 0x24EA:
		return '0', true
	}
	return 0, false
}

// confusables maps visually-confusable codepoints to their ASCII skeleton.
// Keys are lowercase because Skeleton case-folds before consulting this table.
// The set follows the Unicode confusables concept but is curated by hand: each
// entry is one an attacker can plausibly use to impersonate a reserved word.
//
// Values are strings because a few sources expand to more than one letter
// (ligatures, ß). Every value is lowercase ASCII.
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
	'ј': "j", // U+0458 CYRILLIC SMALL JE
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
	'ι': "i", // U+03B9 GREEK SMALL IOTA
	'κ': "k", // U+03BA GREEK SMALL KAPPA
	'μ': "m", // U+03BC GREEK SMALL MU
	'ν': "v", // U+03BD GREEK SMALL NU (reads as Latin v)
	'ο': "o", // U+03BF GREEK SMALL OMICRON
	'ρ': "p", // U+03C1 GREEK SMALL RHO
	'τ': "t", // U+03C4 GREEK SMALL TAU
	'υ': "u", // U+03C5 GREEK SMALL UPSILON
	'χ': "x", // U+03C7 GREEK SMALL CHI
	'ϲ': "c", // U+03F2 GREEK LUNATE SIGMA

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

	// --- Precomposed accented Latin. Decomposed forms are already handled by
	// the combining-mark strip; these are the precomposed equivalents, limited
	// to Latin-1 Supplement and the common Latin Extended-A letters.
	'á': "a", // U+00E1
	'à': "a", // U+00E0
	'â': "a", // U+00E2
	'ä': "a", // U+00E4
	'ã': "a", // U+00E3
	'å': "a", // U+00E5
	'ā': "a", // U+0101
	'ç': "c", // U+00E7
	'č': "c", // U+010D
	'é': "e", // U+00E9
	'è': "e", // U+00E8
	'ê': "e", // U+00EA
	'ë': "e", // U+00EB
	'ē': "e", // U+0113
	'í': "i", // U+00ED
	'ì': "i", // U+00EC
	'î': "i", // U+00EE
	'ï': "i", // U+00EF
	'ī': "i", // U+012B
	'ñ': "n", // U+00F1
	'ń': "n", // U+0144
	'ó': "o", // U+00F3
	'ò': "o", // U+00F2
	'ô': "o", // U+00F4
	'ö': "o", // U+00F6
	'õ': "o", // U+00F5
	'ō': "o", // U+014D
	'š': "s", // U+0161
	'ś': "s", // U+015B
	'ú': "u", // U+00FA
	'ù': "u", // U+00F9
	'û': "u", // U+00FB
	'ü': "u", // U+00FC
	'ū': "u", // U+016B
	'ý': "y", // U+00FD
	'ÿ': "y", // U+00FF
	'ž': "z", // U+017E
	'ź': "z", // U+017A
	'ż': "z", // U+017C

	// --- Compatibility ligatures. NFKC would decompose these; we do it by
	// table since the set is tiny and closed.
	'ﬁ': "fi",  // U+FB01
	'ﬂ': "fl",  // U+FB02
	'ﬀ': "ff",  // U+FB00
	'ﬃ': "ffi", // U+FB03
	'ﬄ': "ffl", // U+FB04
	'ﬅ': "st",  // U+FB05
	'ﬆ': "st",  // U+FB06

	// --- Letterlike Symbols. The stylistic outliers that live outside the
	// Mathematical Alphanumeric block.
	'ℂ': "c", // U+2102 DOUBLE-STRUCK CAPITAL C
	'ℊ': "g", // U+210A SCRIPT SMALL G
	'ℎ': "h", // U+210E PLANCK CONSTANT (script small h)
	'ℐ': "i", // U+2110 SCRIPT CAPITAL I
	'ℓ': "l", // U+2113 SCRIPT SMALL L
	'ℕ': "n", // U+2115 DOUBLE-STRUCK CAPITAL N
	'ℚ': "q", // U+211A DOUBLE-STRUCK CAPITAL Q
	'ℝ': "r", // U+211D DOUBLE-STRUCK CAPITAL R
	'ℯ': "e", // U+212F SCRIPT SMALL E
	'ℴ': "o", // U+2134 SCRIPT SMALL O
	'ℤ': "z", // U+2124 DOUBLE-STRUCK CAPITAL Z

	// --- Superscript and modifier letters used as ordinary letters.
	'ª': "a", // U+00AA FEMININE ORDINAL INDICATOR
	'º': "o", // U+00BA MASCULINE ORDINAL INDICATOR
	'ᵃ': "a", // U+1D43
	'ᵇ': "b", // U+1D47
	'ᶜ': "c", // U+1D9C
	'ᵈ': "d", // U+1D48
	'ᵉ': "e", // U+1D49
	'ᵍ': "g", // U+1D4D
	'ⁱ': "i", // U+2071
	'ᵏ': "k", // U+1D4F
	'ᵐ': "m", // U+1D50
	'ⁿ': "n", // U+207F
	'ᵒ': "o", // U+1D52
	'ᵖ': "p", // U+1D56
	'ʳ': "r", // U+02B3
	'ˢ': "s", // U+02E2
	'ᵗ': "t", // U+1D57
	'ᵘ': "u", // U+1D58
	'ʷ': "w", // U+02B7
	'ˣ': "x", // U+02E3
	'ʸ': "y", // U+02B8

	// --- Superscript and subscript digits. Mapped to their digit, which the
	// leetspeak stage then folds further where applicable.
	'⁰': "0", // U+2070
	'¹': "1", // U+00B9
	'²': "2", // U+00B2
	'³': "3", // U+00B3
	'⁴': "4", // U+2074
	'⁵': "5", // U+2075
	'⁶': "6", // U+2076
	'⁷': "7", // U+2077
	'⁸': "8", // U+2078
	'⁹': "9", // U+2079
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
	switch r {
	case '_', '.':
		return true
	}
	// unicode.Pd covers ASCII "-" together with every other dash form
	// (en dash, em dash, U+2010 hyphen), which an attacker can substitute
	// freely. unicode.Pc covers "_" and its connector relatives. IsSpace
	// covers ASCII space, tab, NBSP and the Unicode space repertoire.
	return unicode.IsSpace(r) || unicode.Is(unicode.Pd, r) || unicode.Is(unicode.Pc, r)
}
