package domain

import (
	"errors"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

func TestValidateSetName(t *testing.T) {
	runSlugTests(t, ValidateSetName)
}

func TestValidateHandle(t *testing.T) {
	runSlugTests(t, ValidateHandle)
}

func runSlugTests(t *testing.T, fn func(string) error) {
	t.Helper()
	tests := []struct {
		name  string
		input string
		valid bool
	}{
		{"single char", "a", true},
		{"single digit", "0", true},
		{"lowercase word", "web", true},
		{"with hyphen", "my-key-set", true},
		{"with digits", "server01", true},
		{"max length", strings.Repeat("a", MaxSlugLen), true},
		{"empty", "", false},
		{"too long", strings.Repeat("a", MaxSlugLen+1), false},
		{"leading hyphen", "-abc", false},
		{"trailing hyphen", "abc-", false},
		{"only hyphen", "-", false},
		{"uppercase", "Abc", false},
		{"underscore", "a_b", false},
		{"space", "a b", false},
		{"dot", "a.b", false},
		{"unicode", "café", false},
		{"double hyphen ok", "a--b", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := fn(tc.input)
			if tc.valid && err != nil {
				t.Fatalf("expected valid, got error: %v", err)
			}
			if !tc.valid {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				if !errors.Is(err, ErrInvalidInput) {
					t.Fatalf("error %v does not wrap ErrInvalidInput", err)
				}
			}
		})
	}
}

func TestValidatePrintableFields(t *testing.T) {
	fns := map[string]func(string) error{
		"device name":     ValidateDeviceName,
		"access key name": ValidateAccessKeyName,
		"client label":    ValidateClientLabel,
	}
	tests := []struct {
		name  string
		input string
		valid bool
	}{
		{"simple", "My Laptop", true},
		{"single char", "x", true},
		{"unicode printable", "café ☕", true},
		{"max length", strings.Repeat("a", MaxLabelLen), true},
		{"punctuation", "prod-server #1", true},
		{"empty", "", false},
		{"too long", strings.Repeat("a", MaxLabelLen+1), false},
		{"leading space", " abc", false},
		{"trailing space", "abc ", false},
		{"leading tab", "\tabc", false},
		{"trailing tab", "abc\t", false},
		{"embedded newline", "a\nb", false},
		{"embedded null", "a\x00b", false},
		{"embedded control", "a\x07b", false},
		{"del char", "a\x7fb", false},
		{"invalid utf8", "a\xffb", false},
	}
	for label, fn := range fns {
		for _, tc := range tests {
			t.Run(label+"/"+tc.name, func(t *testing.T) {
				err := fn(tc.input)
				if tc.valid && err != nil {
					t.Fatalf("expected valid, got error: %v", err)
				}
				if !tc.valid {
					if err == nil {
						t.Fatalf("expected error, got nil")
					}
					if !errors.Is(err, ErrInvalidInput) {
						t.Fatalf("error %v does not wrap ErrInvalidInput", err)
					}
				}
			})
		}
	}
}

func TestValidateKeyComment(t *testing.T) {
	tests := []struct {
		name  string
		input string
		valid bool
	}{
		{"empty allowed", "", true},
		{"typical", "user@host", true},
		{"with spaces", "my work laptop", true},
		{"unicode", "café ☕", true},
		{"max length", strings.Repeat("a", MaxCommentLen), true},
		{"too long", strings.Repeat("a", MaxCommentLen+1), false},
		{"newline", "a\nb", false},
		{"carriage return", "a\rb", false},
		{"tab is control", "a\tb", false},
		{"null", "a\x00b", false},
		{"invalid utf8", "a\xffb", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateKeyComment(tc.input)
			if tc.valid && err != nil {
				t.Fatalf("expected valid, got error: %v", err)
			}
			if !tc.valid {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				if !errors.Is(err, ErrInvalidInput) {
					t.Fatalf("error %v does not wrap ErrInvalidInput", err)
				}
			}
		})
	}
}

func TestValidateFingerprint(t *testing.T) {
	valid43 := "SHA256:" + strings.Repeat("A", 43)
	tests := []struct {
		name  string
		input string
		valid bool
	}{
		{"valid all A", valid43, true},
		{"valid mixed", "SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU", true},
		{"empty", "", false},
		{"missing prefix", strings.Repeat("A", 43), false},
		{"wrong prefix", "MD5:" + strings.Repeat("A", 43), false},
		{"too short", "SHA256:" + strings.Repeat("A", 42), false},
		{"too long", "SHA256:" + strings.Repeat("A", 44), false},
		{"padded base64", "SHA256:" + strings.Repeat("A", 42) + "=", false},
		{"invalid char", "SHA256:" + strings.Repeat("A", 42) + "!", false},
		{"lowercase prefix", "sha256:" + strings.Repeat("A", 43), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateFingerprint(tc.input)
			if tc.valid && err != nil {
				t.Fatalf("expected valid, got error: %v", err)
			}
			if !tc.valid {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				if !errors.Is(err, ErrInvalidInput) {
					t.Fatalf("error %v does not wrap ErrInvalidInput", err)
				}
			}
		})
	}
}

// rejectedFormatRunes lists every codepoint isDisallowedFormatRune must reject.
// Written as \u escapes so no invisible character appears literally in source.
var rejectedFormatRunes = []struct {
	name string
	r    rune
}{
	{"U+061C ARABIC LETTER MARK", '\u061C'},
	{"U+200E LEFT-TO-RIGHT MARK", '\u200E'},
	{"U+200F RIGHT-TO-LEFT MARK", '\u200F'},
	{"U+202A LEFT-TO-RIGHT EMBEDDING", '\u202A'},
	{"U+202B RIGHT-TO-LEFT EMBEDDING", '\u202B'},
	{"U+202C POP DIRECTIONAL FORMATTING", '\u202C'},
	{"U+202D LEFT-TO-RIGHT OVERRIDE", '\u202D'},
	{"U+202E RIGHT-TO-LEFT OVERRIDE", '\u202E'},
	{"U+2066 LEFT-TO-RIGHT ISOLATE", '\u2066'},
	{"U+2067 RIGHT-TO-LEFT ISOLATE", '\u2067'},
	{"U+2068 FIRST STRONG ISOLATE", '\u2068'},
	{"U+2069 POP DIRECTIONAL ISOLATE", '\u2069'},
	{"U+200B ZERO WIDTH SPACE", '\u200B'},
	{"U+2060 WORD JOINER", '\u2060'},
	{"U+2061 FUNCTION APPLICATION", '\u2061'},
	{"U+2062 INVISIBLE TIMES", '\u2062'},
	{"U+2063 INVISIBLE SEPARATOR", '\u2063'},
	{"U+2064 INVISIBLE PLUS", '\u2064'},
	{"U+2028 LINE SEPARATOR", '\u2028'},
	{"U+2029 PARAGRAPH SEPARATOR", '\u2029'},
	{"U+FEFF ZERO WIDTH NO-BREAK SPACE", '\uFEFF'},
}

// hardenedValidators are the free-text validators that must reject the runes
// above. The slug validators are excluded on purpose: ValidateHandle and
// ValidateSetName allowlist [a-z0-9-], which is strictly stronger already.
var hardenedValidators = map[string]func(string) error{
	"device name":     ValidateDeviceName,
	"access key name": ValidateAccessKeyName,
	"client label":    ValidateClientLabel,
	"key comment":     ValidateKeyComment,
}

func TestValidatorsRejectFormatRunes(t *testing.T) {
	for field, fn := range hardenedValidators {
		for _, rc := range rejectedFormatRunes {
			t.Run(field+"/"+rc.name, func(t *testing.T) {
				input := "prod" + string(rc.r) + "server"
				err := fn(input)
				if err == nil {
					t.Fatalf("expected %s to reject %s, got nil", field, rc.name)
				}
				if !errors.Is(err, ErrInvalidInput) {
					t.Fatalf("error %v does not wrap ErrInvalidInput", err)
				}
				// The hostile text must never be echoed back into logs.
				if strings.Contains(err.Error(), input) {
					t.Fatalf("error message echoes raw input: %q", err.Error())
				}
				if strings.ContainsRune(err.Error(), rc.r) {
					t.Fatalf("error message echoes the offending rune: %q", err.Error())
				}
			})
		}
	}
}

// TestKeyCommentRejectsRTLOAttack covers the classic trojan-source shape: a
// right-to-left override that makes the rendered comment misrepresent the key
// it labels.
func TestKeyCommentRejectsRTLOAttack(t *testing.T) {
	attack := "backup-key\u202Egro.live@rekcatta"
	if !strings.ContainsRune(attack, '\u202E') {
		t.Fatal("test fixture lost its U+202E; the test would prove nothing")
	}
	err := ValidateKeyComment(attack)
	if err == nil {
		t.Fatal("expected RTLO comment to be rejected")
	}
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("error %v does not wrap ErrInvalidInput", err)
	}
}

// TestZWNJAndZWJAccepted is a regression guard: someone "simplifying" this to a
// blanket category-Cf ban would corrupt legitimate Persian/Arabic, Indic and
// emoji names. ZWNJ and ZWJ must stay allowed.
func TestZWNJAndZWJAccepted(t *testing.T) {
	// Persian "laptop", which requires U+200C ZWNJ between the two words.
	persianLaptop := "لپ\u200Cتاپ"
	// Emoji ZWJ sequence: family, joined with U+200D.
	emojiZWJ := "\U0001F468\u200D\U0001F469\u200D\U0001F467"

	cases := []struct {
		name  string
		input string
		want  rune
	}{
		{"persian ZWNJ compound", persianLaptop, '\u200C'},
		{"emoji ZWJ sequence", emojiZWJ, '\u200D'},
		{"bare ZWNJ", "a\u200Cb", '\u200C'},
		{"bare ZWJ", "a\u200Db", '\u200D'},
	}
	for field, fn := range hardenedValidators {
		for _, tc := range cases {
			t.Run(field+"/"+tc.name, func(t *testing.T) {
				// Guard against the fixture being stripped in transit, which
				// would make this test pass for the wrong reason.
				if !strings.ContainsRune(tc.input, tc.want) {
					t.Fatalf("fixture %q lost %U; the test would prove nothing", tc.input, tc.want)
				}
				if err := fn(tc.input); err != nil {
					t.Fatalf("expected %s to accept %q, got: %v", field, tc.name, err)
				}
			})
		}
	}
}

// TestOrdinaryUnicodeAccepted checks the hardening did not over-reject.
func TestOrdinaryUnicodeAccepted(t *testing.T) {
	inputs := []struct {
		name  string
		input string
	}{
		{"plain ascii", "work laptop"},
		{"accented latin", "Café Münchén"},
		{"cjk", "开发机"},
		{"arabic no zwnj", "مفتاح"},
		{"emoji", "laptop \U0001F4BB"},
	}
	for field, fn := range hardenedValidators {
		for _, tc := range inputs {
			t.Run(field+"/"+tc.name, func(t *testing.T) {
				if err := fn(tc.input); err != nil {
					t.Fatalf("expected %s to accept %q, got: %v", field, tc.input, err)
				}
			})
		}
	}
}

// TestKeyCommentLengthCountsRunes pins that the limit is in runes, not bytes.
func TestKeyCommentLengthCountsRunes(t *testing.T) {
	exact := strings.Repeat("é", MaxCommentLen) // 2 bytes per rune
	if len(exact) <= MaxCommentLen {
		t.Fatal("fixture is not multi-byte; the test would prove nothing")
	}
	if err := ValidateKeyComment(exact); err != nil {
		t.Fatalf("expected %d multi-byte runes to be accepted, got: %v", MaxCommentLen, err)
	}
	if err := ValidateKeyComment(exact + "é"); err == nil {
		t.Fatal("expected MaxCommentLen+1 multi-byte runes to be rejected")
	}
}

// FuzzValidateKeyComment asserts the invariant: anything that validates is
// valid UTF-8 and contains none of the rejected codepoints.
func FuzzValidateKeyComment(f *testing.F) {
	f.Add("user@host")
	f.Add("a\u200Cb")
	f.Add("a\u202Eb")
	f.Add("")
	f.Add("café ☕")
	f.Fuzz(func(t *testing.T, s string) {
		if ValidateKeyComment(s) != nil {
			return
		}
		if !utf8.ValidString(s) {
			t.Fatalf("accepted invalid UTF-8: %q", s)
		}
		for _, r := range s {
			if isDisallowedFormatRune(r) {
				t.Fatalf("accepted string containing %U", r)
			}
			if unicode.IsControl(r) {
				t.Fatalf("accepted string containing control %U", r)
			}
		}
		if utf8.RuneCountInString(s) > MaxCommentLen {
			t.Fatalf("accepted over-long string of %d runes", utf8.RuneCountInString(s))
		}
	})
}
