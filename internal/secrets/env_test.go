package secrets

import (
	"context"
	"testing"
)

func TestEnvProviderResolve(t *testing.T) {
	env := map[string]string{
		"SET":   "value-secret",
		"EMPTY": "",
	}
	p := &EnvProvider{lookup: func(k string) (string, bool) {
		v, ok := env[k]
		return v, ok
	}}
	ctx := context.Background()

	got, err := p.Resolve(ctx, "SET")
	if err != nil {
		t.Fatalf("Resolve set: %v", err)
	}
	if got.Reveal() != "value-secret" {
		t.Errorf("Resolve = %q, want %q", got.Reveal(), "value-secret")
	}

	_, err = p.Resolve(ctx, "UNSET")
	errNames(t, err, "env:UNSET", "")

	_, err = p.Resolve(ctx, "EMPTY")
	errNames(t, err, "env:EMPTY", "")
}

func TestEnvProviderScheme(t *testing.T) {
	if NewEnvProvider().Scheme() != "env" {
		t.Fatal("env scheme mismatch")
	}
}

func TestEnvProviderRealEnv(t *testing.T) {
	t.Setenv("VALLET_TEST_SECRET", "real-secret")
	got, err := NewEnvProvider().Resolve(context.Background(), "VALLET_TEST_SECRET")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got.Reveal() != "real-secret" {
		t.Errorf("Resolve = %q", got.Reveal())
	}
}
