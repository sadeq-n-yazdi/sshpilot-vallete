package secrets

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// blankValues are the forms a credential takes when an operator has supplied
// whitespace instead of a secret: a here-doc that produced only a newline, a
// shell variable that expanded to nothing but the quoting left a space, a copy
// that picked up a non-breaking space from a web page.
//
// The names are used in subtest names, so the raw bytes never appear in test
// output — the same discipline the production errors follow.
var blankValues = []struct {
	name  string
	value string
}{
	{"space", " "},
	{"spaces", "   "},
	{"tab", "\t"},
	{"newline", "\n"},
	{"newlines", "\n\n"},
	{"crlf", "\r\n"},
	{"mixed ascii whitespace", " \t\r\n "},
	{"no-break space", "\u00a0"},
	{"ideographic space", "\u3000"},
}

// TestRedactedIsBlank pins the predicate itself, including the two boundaries
// the doc comment claims: Unicode whitespace IS blank, and the zero-width space
// is NOT.
//
// This asserts against a literal expectation rather than by calling IsBlank a
// second time; an assertion helper that consulted the function under test would
// agree with any mutation of it.
func TestRedactedIsBlank(t *testing.T) {
	t.Parallel()

	if !Redacted("").IsBlank() {
		t.Error("the empty value must be blank")
	}
	for _, tc := range blankValues {
		if !Redacted(tc.value).IsBlank() {
			t.Errorf("%s must be blank", tc.name)
		}
	}

	nonBlank := []struct{ name, value string }{
		{"ordinary token", "cf-token-123"},
		{"surrounded by spaces", " cf-token-123 "},
		{"single character", "x"},
		{"zero-width space only", "\u200b"},
		{"newline between halves", "AKID\nSECRET"},
	}
	for _, tc := range nonBlank {
		if Redacted(tc.value).IsBlank() {
			t.Errorf("%s must NOT be blank", tc.name)
		}
	}
}

// TestEnvProviderRejectsBlank is the gate for every env-backed secret in the
// config — the DNS-01 credential, the Postgres DSN, the token signing key.
//
// Before this, the provider compared against "" alone, so "   " resolved
// successfully and the process started; the failure surfaced at the first
// certificate issuance. The error must name the variable and never the value.
func TestEnvProviderRejectsBlank(t *testing.T) {
	t.Parallel()

	const varName = "VALLET_TEST_BLANK"

	for _, tc := range blankValues {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			p := &EnvProvider{lookup: func(string) (string, bool) { return tc.value, true }}
			got, err := p.Resolve(t.Context(), varName)
			if err == nil {
				t.Fatal("a blank environment variable must be refused at resolution")
			}
			if got != "" {
				t.Error("no value may be returned alongside a refusal")
			}
			if !strings.Contains(err.Error(), "blank") {
				t.Errorf("error must say the value is blank: %v", err)
			}
			if !strings.Contains(err.Error(), varName) {
				t.Errorf("error must name the variable an operator has to fix: %v", err)
			}
			if trimmed := strings.TrimSpace(tc.value); trimmed != "" && strings.Contains(err.Error(), trimmed) {
				t.Error("error must never echo the value")
			}
		})
	}
}

// TestEnvProviderAcceptsSurroundingWhitespace records the deliberate half of the
// decision: a value with whitespace AROUND it is not blank, and is returned with
// the operator's bytes unchanged rather than silently trimmed.
//
// Without this the fix could be mistaken for "reject anything with whitespace",
// and a later change could start rewriting secrets without any test objecting.
func TestEnvProviderAcceptsSurroundingWhitespace(t *testing.T) {
	t.Parallel()

	const padded = "  cf-token-123  "

	p := &EnvProvider{lookup: func(string) (string, bool) { return padded, true }}
	got, err := p.Resolve(t.Context(), "VALLET_TEST_PADDED")
	if err != nil {
		t.Fatalf("a non-blank value must resolve: %v", err)
	}
	if got.Reveal() != padded {
		t.Error("the resolved value must be the operator's bytes, untrimmed")
	}
}

// TestFileProviderRejectsBlank is the same gate for file-backed secrets.
//
// The cases differ from the env ones on purpose: the provider strips ONE
// trailing newline before checking, so a file holding exactly "\n" was already
// refused. What was not refused, and is here, is a file of spaces, a tab, or
// more than one newline.
func TestFileProviderRejectsBlank(t *testing.T) {
	t.Parallel()

	for _, tc := range blankValues {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			path := filepath.Join(t.TempDir(), "secret")
			if err := os.WriteFile(path, []byte(tc.value), 0o600); err != nil {
				t.Fatalf("write fixture: %v", err)
			}

			p := NewFileProvider(FileOptions{})
			got, err := p.Resolve(t.Context(), path)
			if err == nil {
				t.Fatal("a blank secret file must be refused at resolution")
			}
			if got != "" {
				t.Error("no value may be returned alongside a refusal")
			}
			if !strings.Contains(err.Error(), "blank") {
				t.Errorf("error must say the file is blank: %v", err)
			}
			if !strings.Contains(err.Error(), path) {
				t.Errorf("error must name the path an operator has to fix: %v", err)
			}
		})
	}
}

// TestFileProviderAcceptsSurroundingWhitespace mirrors the env case: the file
// provider strips one trailing newline (a documented, pre-existing
// normalization) and nothing else.
func TestFileProviderAcceptsSurroundingWhitespace(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(path, []byte("  cf-token-123  \n"), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	got, err := NewFileProvider(FileOptions{}).Resolve(t.Context(), path)
	if err != nil {
		t.Fatalf("a non-blank file must resolve: %v", err)
	}
	if got.Reveal() != "  cf-token-123  " {
		t.Error("the resolved value must keep the operator's surrounding whitespace")
	}
}
