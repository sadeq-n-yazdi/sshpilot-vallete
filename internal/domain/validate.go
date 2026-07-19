package domain

import (
	"fmt"
	"regexp"
	"unicode/utf8"
)

// Length bounds for the various validated name and label fields.
const (
	MinNameLen       = 1
	MaxSlugLen       = 64
	MaxDeviceNameLen = 64
	MaxLabelLen      = 64
	MaxCommentLen    = 256
)

// slugRe matches a slug: 1-64 chars of [a-z0-9-] with no leading or trailing
// hyphen.
var slugRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?$`)

// fingerprintRe matches a SHA256 SSH fingerprint: the literal "SHA256:" prefix
// followed by exactly 43 characters of unpadded base64.
var fingerprintRe = regexp.MustCompile(`^SHA256:[A-Za-z0-9+/]{43}$`)

// ValidateSetName validates a key set name against the slug rule: 1-64 chars,
// lowercase alphanumeric and hyphen only, no leading or trailing hyphen.
func ValidateSetName(name string) error {
	return validateSlug("set name", name)
}

// ValidateHandle validates a handle against the slug rule: 1-64 chars,
// lowercase alphanumeric and hyphen only, no leading or trailing hyphen.
func ValidateHandle(name string) error {
	return validateSlug("handle", name)
}

func validateSlug(field, name string) error {
	if name == "" {
		return fmt.Errorf("domain: %s must not be empty: %w", field, ErrInvalidInput)
	}
	if len(name) > MaxSlugLen {
		return fmt.Errorf("domain: %s exceeds %d characters: %w", field, MaxSlugLen, ErrInvalidInput)
	}
	if !slugRe.MatchString(name) {
		return fmt.Errorf("domain: %s must be lowercase [a-z0-9-] with no leading or trailing hyphen: %w", field, ErrInvalidInput)
	}
	return nil
}

// ValidateDeviceName validates a device name: 1-64 printable UTF-8 characters,
// no control characters, and no leading or trailing whitespace.
func ValidateDeviceName(name string) error {
	return validatePrintable("device name", name, MaxDeviceNameLen)
}

// ValidateAccessKeyName validates an access key name: 1-64 printable UTF-8
// characters, no control characters, and no leading or trailing whitespace.
func ValidateAccessKeyName(name string) error {
	return validatePrintable("access key name", name, MaxLabelLen)
}

// ValidateClientLabel validates a client label: 1-64 printable UTF-8
// characters, no control characters, and no leading or trailing whitespace.
func ValidateClientLabel(label string) error {
	return validatePrintable("client label", label, MaxLabelLen)
}

// validatePrintable enforces a non-empty, trimmed, control-free, valid UTF-8
// string within maxLen characters (runes).
func validatePrintable(field, s string, maxLen int) error {
	if s == "" {
		return fmt.Errorf("domain: %s must not be empty: %w", field, ErrInvalidInput)
	}
	if !utf8.ValidString(s) {
		return fmt.Errorf("domain: %s must be valid UTF-8: %w", field, ErrInvalidInput)
	}
	if s[0] == ' ' || s[0] == '\t' || s[len(s)-1] == ' ' || s[len(s)-1] == '\t' {
		return fmt.Errorf("domain: %s must not have leading or trailing whitespace: %w", field, ErrInvalidInput)
	}
	n := 0
	for _, r := range s {
		if isControl(r) {
			return fmt.Errorf("domain: %s must not contain control characters: %w", field, ErrInvalidInput)
		}
		n++
	}
	if n > maxLen {
		return fmt.Errorf("domain: %s exceeds %d characters: %w", field, maxLen, ErrInvalidInput)
	}
	return nil
}

// ValidateKeyComment validates an SSH public key comment. An empty comment is
// allowed. Otherwise it must contain no control characters or newlines and be
// at most MaxCommentLen characters long.
func ValidateKeyComment(comment string) error {
	if comment == "" {
		return nil
	}
	if !utf8.ValidString(comment) {
		return fmt.Errorf("domain: key comment must be valid UTF-8: %w", ErrInvalidInput)
	}
	n := 0
	for _, r := range comment {
		if isControl(r) {
			return fmt.Errorf("domain: key comment must not contain control characters: %w", ErrInvalidInput)
		}
		n++
	}
	if n > MaxCommentLen {
		return fmt.Errorf("domain: key comment exceeds %d characters: %w", MaxCommentLen, ErrInvalidInput)
	}
	return nil
}

// ValidateFingerprint validates an SSH SHA256 fingerprint: the literal prefix
// "SHA256:" followed by exactly 43 characters of unpadded base64.
func ValidateFingerprint(fp string) error {
	if !fingerprintRe.MatchString(fp) {
		return fmt.Errorf("domain: fingerprint must be \"SHA256:\" followed by 43 unpadded base64 characters: %w", ErrInvalidInput)
	}
	return nil
}

// isControl reports whether r is an ASCII or Unicode control character. DEL
// (0x7f) and the C1 range are treated as control characters.
func isControl(r rune) bool {
	return r < 0x20 || (r >= 0x7f && r <= 0x9f)
}
