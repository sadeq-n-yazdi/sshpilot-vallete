package domain

import "unicode"

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
// by it; they are Cf (format) and Zl/Zp (separator).
//
// The check is category-based and therefore deny-by-default: every Cf format
// character is rejected unless explicitly excepted below. This is deliberately
// broader than enumerating the known bidi and zero-width attack codepoints. It
// also covers U+00AD SOFT HYPHEN, the deprecated U+206A..U+206F format
// controls, and the U+E0000..U+E007F tag characters — all invisible, all usable
// to smuggle content past visual review — and it will cover any format
// character a future Unicode revision introduces without this file changing.
// An enumeration silently stops protecting against whatever it does not list.
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
// The two exceptions are named individually rather than carved out by range,
// because ZWNJ and ZWJ sit between rejected codepoints in the U+200B..U+200F
// block: a range carve-out would readmit the attack characters around them.
//
// ACCEPTED COST: a handful of Cf characters with narrow legitimate uses are
// also rejected — notably U+0600..U+0605 (Arabic number signs) and U+110BD
// (Kaithi number sign). These are prefixes for numeric forms and have no role
// in a device name, label, or key comment, so rejecting them is the right
// trade against admitting every current and future invisible character.
// Emoji are unaffected: sequences join with ZWJ, and variation selectors are
// category Mn, not Cf. Emoji *tag* sequences (some regional flags) do use tag
// characters and are rejected, which is intended — tag characters are a known
// smuggling vector and have no place in an identifier.
//
// All literal codepoints in this package are written as \u escapes so that no
// invisible character is ever present literally in the source.

// isDisallowedFormatRune reports whether r is an invisible formatting or
// separator character that is not permitted in free-text identifier fields.
//
// Cf (format) is rejected wholesale apart from the two linguistic exceptions;
// Zl and Zp cover the line and paragraph separators that unicode.IsControl
// misses. Do not narrow this to a fixed list of codepoints.
func isDisallowedFormatRune(r rune) bool {
	if unicode.Is(unicode.Cf, r) {
		// ZERO WIDTH NON-JOINER and ZERO WIDTH JOINER: required by Persian,
		// Arabic and Indic scripts, and by emoji sequences. See above.
		return r != '\u200C' && r != '\u200D'
	}
	return unicode.Is(unicode.Zl, r) || unicode.Is(unicode.Zp, r)
}
