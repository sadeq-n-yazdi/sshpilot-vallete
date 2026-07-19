package secrets

import (
	"context"
	"fmt"
	"os"
)

// envScheme is the reference scheme handled by EnvProvider.
const envScheme = "env"

// EnvProvider resolves "env:NAME" references from the process environment.
type EnvProvider struct {
	// lookup allows tests to inject an environment; nil means os.LookupEnv.
	lookup func(string) (string, bool)
}

// NewEnvProvider returns an EnvProvider backed by the process environment.
func NewEnvProvider() *EnvProvider { return &EnvProvider{} }

// Scheme implements Provider.
func (p *EnvProvider) Scheme() string { return envScheme }

// Resolve reads the named environment variable. An unset or empty variable is
// an error that names the reference (the variable name), never any value.
func (p *EnvProvider) Resolve(_ context.Context, opaque string) (Redacted, error) {
	lookup := p.lookup
	if lookup == nil {
		lookup = os.LookupEnv
	}
	value, ok := lookup(opaque)
	if !ok {
		return "", fmt.Errorf("secrets: environment variable %q (reference %q) is not set", opaque, envScheme+":"+opaque)
	}
	if value == "" {
		return "", fmt.Errorf("secrets: environment variable %q (reference %q) is empty", opaque, envScheme+":"+opaque)
	}
	return Redacted(value), nil
}
