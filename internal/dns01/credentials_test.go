package dns01

import (
	"fmt"
	"strings"
	"testing"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/secrets"
)

// secretMarker is a recognizable plaintext no formatting of a Credentials may
// reveal. It is deliberately not a real credential shape.
const secretMarker = "SECRET-abc123-do-not-leak"

// TestCredentialsNeverRevealsUnderFormatting proves the fmt.Formatter on
// Credentials renders a constant under every verb, so neither the single nor a
// named value can be printed — directly or as a field of a struct formatted
// with %+v/%#v.
//
// It asserts ABSENCE of the plaintext, not merely presence of the marker: a
// leak that appended the real value after "[REDACTED]" would still contain the
// marker. The marker is checked too, to prove Format actually ran rather than
// the value being empty.
func TestCredentialsNeverRevealsUnderFormatting(t *testing.T) {
	t.Parallel()

	sets := map[string]Credentials{
		"single": NewSingleCredential(secrets.NewRedacted(secretMarker)),
		"named": NewNamedCredentials(map[string]secrets.Redacted{
			"access_key_id":     secrets.NewRedacted(secretMarker),
			"secret_access_key": secrets.NewRedacted(secretMarker),
		}),
	}

	// A holder with an EXPORTED Credentials field: fmt calls the field value's
	// Format method, which is the realistic "logged as part of a surrounding
	// struct" path.
	type holder struct{ Creds Credentials }

	verbs := []string{"%v", "%+v", "%#v", "%s", "%q"}

	for name, c := range sets {
		for _, verb := range verbs {
			for _, operand := range []any{c, holder{Creds: c}} {
				out := fmt.Sprintf(verb, operand)
				if strings.Contains(out, secretMarker) {
					t.Errorf("%s set, verb %s, operand %T: output leaked the secret: %s",
						name, verb, operand, out)
				}
				if !strings.Contains(out, "[REDACTED]") {
					t.Errorf("%s set, verb %s, operand %T: expected [REDACTED] marker, got %s",
						name, verb, operand, out)
				}
			}
		}
	}
}

// TestCredentialsSingle covers the lone-value accessor and its fail-closed
// cases.
func TestCredentialsSingle(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		creds Credentials
		want  string
		ok    bool
	}{
		{"single value", NewSingleCredential(secrets.NewRedacted("tok")), "tok", true},
		{
			"one named entry",
			NewNamedCredentials(map[string]secrets.Redacted{"only": secrets.NewRedacted("tok")}),
			"tok", true,
		},
		{"empty set", Credentials{}, "", false},
		{"nil named map", NewNamedCredentials(nil), "", false},
		{
			"several named entries is ambiguous",
			NewNamedCredentials(map[string]secrets.Redacted{
				"a": secrets.NewRedacted("x"),
				"b": secrets.NewRedacted("y"),
			}),
			"", false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, ok := tc.creds.Single()
			if ok != tc.ok {
				t.Fatalf("Single() ok = %v, want %v", ok, tc.ok)
			}
			if got.Reveal() != tc.want {
				t.Errorf("Single() = %q, want %q", got.Reveal(), tc.want)
			}
		})
	}
}

// TestCredentialsGet covers named lookup, including a miss.
func TestCredentialsGet(t *testing.T) {
	t.Parallel()

	c := NewNamedCredentials(map[string]secrets.Redacted{
		"access_key_id": secrets.NewRedacted("AKID"),
	})
	if v, ok := c.Get("access_key_id"); !ok || v.Reveal() != "AKID" {
		t.Errorf("Get(access_key_id) = %q, %v; want AKID, true", v.Reveal(), ok)
	}
	if _, ok := c.Get("missing"); ok {
		t.Error("Get(missing) reported present")
	}
	// A single-value set exposes nothing by name.
	if _, ok := NewSingleCredential(secrets.NewRedacted("tok")).Get("anything"); ok {
		t.Error("Get on a single-value set reported present")
	}
}

// TestNewNamedCredentialsClonesTheMap proves the constructor does not alias the
// caller's map: mutating the source after construction must not change the set.
func TestNewNamedCredentialsClonesTheMap(t *testing.T) {
	t.Parallel()

	src := map[string]secrets.Redacted{"k": secrets.NewRedacted("original")}
	c := NewNamedCredentials(src)
	src["k"] = secrets.NewRedacted("tampered")
	delete(src, "k")

	if v, ok := c.Get("k"); !ok || v.Reveal() != "original" {
		t.Errorf("Get(k) = %q, %v; want original, true — the stored map was aliased", v.Reveal(), ok)
	}
}
