package secrets

import (
	"context"
	"strings"
	"testing"
)

func TestRefSchemeOpaque(t *testing.T) {
	tests := []struct {
		name       string
		ref        Ref
		wantZero   bool
		wantScheme string
		wantOpaque string
	}{
		{"empty", "", true, "", ""},
		{"env", "env:VALLET_PG_DSN", false, "env", "VALLET_PG_DSN"},
		{"file", "file:/run/secrets/pg", false, "file", "/run/secrets/pg"},
		{"opaque with colon", "env:A:B", false, "env", "A:B"},
		{"no colon", "envVALLET", false, "", ""},
		{"empty scheme", ":opaque", false, "", ""},
		{"leading colon only", ":", false, "", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.ref.IsZero() != tc.wantZero {
				t.Errorf("IsZero() = %v, want %v", tc.ref.IsZero(), tc.wantZero)
			}
			if tc.ref.Scheme() != tc.wantScheme {
				t.Errorf("Scheme() = %q, want %q", tc.ref.Scheme(), tc.wantScheme)
			}
			if tc.ref.Opaque() != tc.wantOpaque {
				t.Errorf("Opaque() = %q, want %q", tc.ref.Opaque(), tc.wantOpaque)
			}
		})
	}
}

func TestRefValidate(t *testing.T) {
	tests := []struct {
		name    string
		ref     Ref
		wantErr bool
	}{
		{"valid env", "env:X", false},
		{"valid file", "file:/x", false},
		{"empty", "", true},
		{"no colon", "envX", true},
		{"empty scheme", ":x", true},
		{"empty opaque", "env:", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.ref.Validate()
			if (err != nil) != tc.wantErr {
				t.Errorf("Validate() err = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

// stubProvider is a Provider used for resolver tests.
type stubProvider struct {
	scheme string
	value  string
}

func (s stubProvider) Scheme() string { return s.scheme }
func (s stubProvider) Resolve(_ context.Context, opaque string) (Redacted, error) {
	return Redacted(s.value + ":" + opaque), nil
}

func TestNewResolverDuplicateScheme(t *testing.T) {
	_, err := NewResolver(stubProvider{scheme: "env"}, stubProvider{scheme: "env"})
	if err == nil {
		t.Fatal("expected duplicate-scheme error")
	}
}

func TestNewResolverEmptyScheme(t *testing.T) {
	_, err := NewResolver(stubProvider{scheme: ""})
	if err == nil {
		t.Fatal("expected empty-scheme error")
	}
}

func TestResolverResolve(t *testing.T) {
	r, err := NewResolver(stubProvider{scheme: "env", value: "V"})
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	ctx := context.Background()

	got, err := r.Resolve(ctx, "env:NAME")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got.Reveal() != "V:NAME" {
		t.Errorf("Resolve = %q, want %q", got.Reveal(), "V:NAME")
	}

	if _, err := r.Resolve(ctx, "file:/x"); err == nil {
		t.Error("expected error for unknown scheme")
	}
	if _, err := r.Resolve(ctx, "malformed"); err == nil {
		t.Error("expected error for malformed ref")
	}
}

func TestBuiltinSchemes(t *testing.T) {
	providers := Builtin(FileOptions{})
	got := make(map[string]bool)
	for _, p := range providers {
		got[p.Scheme()] = true
	}
	for _, want := range []string{"env", "file"} {
		if !got[want] {
			t.Errorf("Builtin missing scheme %q", want)
		}
	}
	if _, err := NewResolver(providers...); err != nil {
		t.Errorf("Builtin providers form invalid resolver: %v", err)
	}
}

// errNames verifies an error message mentions the reference but not the value.
func errNames(t *testing.T, err error, refPart, value string) {
	t.Helper()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), refPart) {
		t.Errorf("error %q does not name reference %q", err, refPart)
	}
	if value != "" && strings.Contains(err.Error(), value) {
		t.Errorf("error %q leaked value %q", err, value)
	}
}
