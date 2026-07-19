// Package secrets provides a redaction-safe secret model and a pluggable
// secret-provider interface for the sshpilot-vallet backend.
//
// Design (see ADR-0022):
//
//   - Config files and environment variables hold only *references* to secrets
//     (type Ref, of the form "scheme:opaque", e.g. "env:VALLET_PG_DSN" or
//     "file:/run/secrets/pg-dsn"), never secret values.
//   - A Provider knows how to Resolve the opaque part of its scheme into a
//     Redacted value. The built-in providers are "env" and "file"; external
//     managers (Vault, cloud KMS) can be added later without code churn.
//   - Resolved secrets are carried as Redacted, which renders "[REDACTED]" via
//     every fmt/log/json/yaml path; only Reveal exposes the underlying value.
//
// This package must never import internal/config; the dependency direction is
// config -> secrets only.
package secrets

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// Ref is a reference to a secret of the form "scheme:opaque", for example
// "env:VALLET_PG_DSN" or "file:/run/secrets/pg-dsn". It is a defined string
// type (not an alias) so it carries methods while still unmarshalling for free
// from YAML and environment values. A Ref never holds a secret value, only the
// reference to one.
type Ref string

// IsZero reports whether the reference is empty (unset/optional).
func (r Ref) IsZero() bool { return r == "" }

// Scheme returns the scheme portion (before the first ':'), or "" if the
// reference is empty or malformed (no ':' separator, or empty scheme).
func (r Ref) Scheme() string {
	scheme, _, ok := r.split()
	if !ok {
		return ""
	}
	return scheme
}

// Opaque returns the opaque portion (after the first ':'), or "" if the
// reference is empty or malformed.
func (r Ref) Opaque() string {
	_, opaque, ok := r.split()
	if !ok {
		return ""
	}
	return opaque
}

// split parses the reference into scheme and opaque parts. ok is false when the
// reference is empty, has no ':' separator, or has an empty scheme.
func (r Ref) split() (scheme, opaque string, ok bool) {
	s := string(r)
	if s == "" {
		return "", "", false
	}
	idx := strings.IndexByte(s, ':')
	if idx <= 0 {
		return "", "", false
	}
	return s[:idx], s[idx+1:], true
}

// Validate reports whether the reference is well-formed: a non-empty scheme and
// a non-empty opaque part separated by ':'. An empty Ref is invalid; callers
// that permit optionality should check IsZero first.
func (r Ref) Validate() error {
	scheme, opaque, ok := r.split()
	if !ok {
		return fmt.Errorf("secrets: malformed reference %q: want scheme:opaque", string(r))
	}
	if opaque == "" {
		return fmt.Errorf("secrets: reference %q has empty opaque part", string(r))
	}
	_ = scheme
	return nil
}

// Provider resolves the opaque part of a single scheme into a Redacted value.
type Provider interface {
	// Scheme returns the reference scheme this provider handles (e.g. "env").
	Scheme() string
	// Resolve turns the opaque part of a reference into a secret value. It must
	// return an error that names the reference, never the value, on failure.
	Resolve(ctx context.Context, opaque string) (Redacted, error)
}

// Resolver dispatches a Ref to the Provider registered for its scheme.
type Resolver struct {
	providers map[string]Provider
}

// NewResolver builds a Resolver from the given providers. It returns an error
// if two providers declare the same scheme, or if any scheme is empty.
func NewResolver(providers ...Provider) (*Resolver, error) {
	m := make(map[string]Provider, len(providers))
	for _, p := range providers {
		scheme := p.Scheme()
		if scheme == "" {
			return nil, errors.New("secrets: provider with empty scheme")
		}
		if _, dup := m[scheme]; dup {
			return nil, fmt.Errorf("secrets: duplicate provider for scheme %q", scheme)
		}
		m[scheme] = p
	}
	return &Resolver{providers: m}, nil
}

// Resolve validates the reference, selects the provider for its scheme, and
// resolves it. Errors name the reference, never the resolved value.
func (r *Resolver) Resolve(ctx context.Context, ref Ref) (Redacted, error) {
	if err := ref.Validate(); err != nil {
		return "", err
	}
	scheme, opaque, _ := ref.split()
	p, ok := r.providers[scheme]
	if !ok {
		return "", fmt.Errorf("secrets: no provider for scheme %q (reference %q)", scheme, string(ref))
	}
	return p.Resolve(ctx, opaque)
}

// Builtin returns the providers available out of the box: the env provider and
// a file provider using the given file options.
func Builtin(fileOpts FileOptions) []Provider {
	return []Provider{
		NewEnvProvider(),
		NewFileProvider(fileOpts),
	}
}
