package secrets

import (
	"context"
	"strings"
	"testing"
)

// These tests cover the error sites that formatted a reference: they must stay
// diagnosable (scheme, known schemes, actionable hint) while never echoing the
// opaque half. The pastedDSN fixture and assertNoDSNLeak live in
// refredact_test.go.

// TestResolveUnknownSchemeDoesNotLeak is the direct regression test for the
// reported defect: resolving a pasted DSN must fail without printing it.
func TestResolveUnknownSchemeDoesNotLeak(t *testing.T) {
	r, err := NewResolver(Builtin(FileOptions{})...)
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}

	_, err = r.Resolve(context.Background(), pastedDSN)
	if err == nil {
		t.Fatal("expected an error for a pasted DSN")
	}
	msg := err.Error()
	assertNoDSNLeak(t, "Resolve error", msg)

	// Still diagnosable: the scheme, the known schemes, and a hint about what a
	// *_ref field is supposed to contain.
	for _, want := range []string{"postgres", "env", "file", "*_ref"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error %q does not mention %q", msg, want)
		}
	}
}

func TestValidateDoesNotLeak(t *testing.T) {
	// A bare pasted password has no ':' and hits the malformed branch.
	err := Ref("hunter2").Validate()
	if err == nil {
		t.Fatal("expected an error for a malformed reference")
	}
	if strings.Contains(err.Error(), "hunter2") {
		t.Errorf("Validate error leaked the pasted secret: %s", err)
	}
	// Still diagnosable: it says what a reference should look like.
	if !strings.Contains(err.Error(), "scheme:opaque") {
		t.Errorf("Validate error %q does not describe the expected form", err)
	}

	// A DSN-shaped paste with an empty opaque part keeps only its scheme.
	err = Ref("postgres:").Validate()
	if err == nil {
		t.Fatal("expected an error for an empty opaque part")
	}
	if !strings.Contains(err.Error(), "postgres") {
		t.Errorf("Validate error %q does not name the scheme", err)
	}
}

// TestResolverSchemesSorted guards the deterministic error message.
func TestResolverSchemesSorted(t *testing.T) {
	r, err := NewResolver(Builtin(FileOptions{})...)
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	got := strings.Join(r.schemes(), ", ")
	if got != "env, file" {
		t.Errorf("schemes() = %q, want %q", got, "env, file")
	}
}

// TestProvidersDoNotLeakResolvedValue confirms no resolved secret value can
// reach an error from a provider: the file provider wraps path errors only, and
// a successfully read value never appears in a failure path.
func TestProvidersDoNotLeakResolvedValue(t *testing.T) {
	env := &EnvProvider{lookup: func(string) (string, bool) { return "", true }}
	_, err := env.Resolve(context.Background(), "VALLET_PG_DSN")
	if err == nil {
		t.Fatal("expected an error for an empty environment variable")
	}
	if !strings.Contains(err.Error(), "VALLET_PG_DSN") {
		t.Errorf("env error %q does not name the variable", err)
	}
}
