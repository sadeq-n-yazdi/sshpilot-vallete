package domain

// Free-text identifier fields (device names, labels, key comments) are rendered
// back to humans and, in the case of key comments, written into the published
// authorized_keys file that operators read and AuthorizedKeysCommand consumers
// parse. Unicode formatting characters are invisible by construction, so an
// attacker can use them to make a stored string render as something other than
// what it is:
//
//   - Bidirectional overrides and isolates reorder the rendered text without
//     changing the bytes ("trojan source"). A comment carrying U+202E can be
//     made to appear to label a different key than it does.
//   - Zero-width spacers let two strings that render identically be distinct
//     values, which defeats visual review and enables confusable/homograph
//     tricks against anyone eyeballing a key list.
//   - Line and paragraph separators are not caught by unicode.IsControl, yet
//     they break the one-record-per-line authorized_keys format.
//
// unicode.IsControl only covers category Cc, so none of the above are rejected
// by it; they are Cf (format) and Zl/Zp (separator). Hence this explicit table.
//
// DELIBERATE EXCEPTIONS: U+200C ZERO WIDTH NON-JOINER and U+200D ZERO WIDTH
// JOINER are permitted. Unlike the characters below they carry real linguistic
// meaning: ZWNJ is required to correctly write Persian/Arabic compound words
// (the Persian word for "laptop" is spelled with one) and several Indic
// scripts, and ZWJ is required by both those scripts and by emoji sequences.
// Banning them would corrupt legitimate names for a very large set of users.
// The characters below, by contrast, have no legitimate role in a short
// identifier and are present only to deceive.
//
// Note that ZWNJ and ZWJ sit *between* rejected codepoints in the
// U+200B..U+200F block, so this must stay an enumeration of individual runes:
// a range check over that block would ban exactly the two that must be kept.
// All codepoints are written as \u escapes so that no invisible character is
// ever present literally in this source file.

// isDisallowedFormatRune reports whether r is an invisible formatting or
// separator character that is not permitted in free-text identifier fields.
func isDisallowedFormatRune(r rune) bool {
	switch r {
	// Bidirectional formatting, override and isolate controls. These reorder
	// rendered text relative to the underlying bytes.
	case '\u061C', // ARABIC LETTER MARK
		'\u200E', // LEFT-TO-RIGHT MARK
		'\u200F', // RIGHT-TO-LEFT MARK
		'\u202A', // LEFT-TO-RIGHT EMBEDDING
		'\u202B', // RIGHT-TO-LEFT EMBEDDING
		'\u202C', // POP DIRECTIONAL FORMATTING
		'\u202D', // LEFT-TO-RIGHT OVERRIDE
		'\u202E', // RIGHT-TO-LEFT OVERRIDE
		'\u2066', // LEFT-TO-RIGHT ISOLATE
		'\u2067', // RIGHT-TO-LEFT ISOLATE
		'\u2068', // FIRST STRONG ISOLATE
		'\u2069': // POP DIRECTIONAL ISOLATE
		return true

	// Invisible and zero-width characters. These render as nothing, so they
	// let visually identical strings differ.
	case '\u200B', // ZERO WIDTH SPACE
		'\u2060', // WORD JOINER
		'\u2061', // FUNCTION APPLICATION
		'\u2062', // INVISIBLE TIMES
		'\u2063', // INVISIBLE SEPARATOR
		'\u2064', // INVISIBLE PLUS
		'\uFEFF': // ZERO WIDTH NO-BREAK SPACE (BOM)
		return true

	// Line and paragraph separators. Not category Cc, so unicode.IsControl
	// misses them, but they still break a line-oriented file format.
	case '\u2028', // LINE SEPARATOR
		'\u2029': // PARAGRAPH SEPARATOR
		return true
	}
	return false
}
