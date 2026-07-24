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

// Resolve reads the named environment variable. An unset variable, or one whose
// value is blank (empty or whitespace only, see [Redacted.IsBlank]), is an error
// that names the reference (the variable name), never any value.
//
// "Unset" and "blank" stay separate errors because they are separate operator
// mistakes: a missing variable is a deployment wiring problem, while a variable
// that is set to whitespace is usually a here-doc or a shell quoting artifact,
// and naming the difference is what makes the error actionable. Neither message
// reveals the value, its length, or any fragment of it.
func (p *EnvProvider) Resolve(_ context.Context, opaque string) (Redacted, error) {
	lookup := p.lookup
	if lookup == nil {
		lookup = os.LookupEnv
	}
	value, ok := lookup(opaque)
	if !ok {
		return "", fmt.Errorf("secrets: environment variable %q (reference %q) is not set", opaque, envScheme+":"+opaque)
	}
	secret := Redacted(value)
	if secret.IsBlank() {
		return "", fmt.Errorf("secrets: environment variable %q (reference %q) is blank (empty or whitespace only)", opaque, envScheme+":"+opaque)
	}
	return secret, nil
}
