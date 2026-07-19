package domain

import (
	"errors"
	"strings"
	"testing"
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
