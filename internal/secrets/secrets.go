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
	"sort"
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
	_, opaque, ok := r.split()
	if !ok {
		// The reference is rendered redacted (see redact.go): a value pasted into
		// a *_ref field instead of a reference lands here, and a bare pasted
		// password has no ':' at all, so echoing it would print the secret whole.
		return fmt.Errorf("secrets: malformed reference %s: want scheme:opaque, e.g. env:VALLET_PG_DSN or file:/run/secrets/pg-dsn", r.redacted())
	}
	if opaque == "" {
		return fmt.Errorf("secrets: reference %s has empty opaque part", r.redacted())
	}
	// A reference carrying the redaction marker is the product of serializing a
	// Ref and reading it back -- redaction is deliberately one-way (see
	// redact.go), so such a document describes no secret at all.
	//
	// This case is rejected HERE, at load, rather than left to fail at Resolve.
	// Left alone it would parse cleanly and only surface much later as "env var
	// [REDACTED] not set", which reads like a deployment mistake and sends the
	// operator hunting for a variable they never set. Naming the real cause at
	// the point the document is read turns a confusing late failure into an
	// immediate, self-explaining one -- and keeps the marshalers fail-closed:
	// the cost of serializing a config is a loud refusal to reload it, never a
	// leaked secret.
	if opaque == redactedMarker {
		return fmt.Errorf("secrets: reference %s is redacted, not a usable reference: it came from serialized output, which never carries secret references; restore this field from the original configuration", r.redacted())
	}
	return nil
}

// Provider resolves the opaque part of a single scheme into a Redacted value.
type Provider interface {
	// Scheme returns the reference scheme this provider handles (e.g. "env").
	Scheme() string
	// Resolve turns the opaque part of a reference into a secret value. It must
	// return an error that names the reference, never the value, on failure.
	//
	// A provider is reached only when its scheme matched, so its opaque part has
	// the documented, non-secret meaning of that scheme (an environment variable
	// name, a filesystem path) and may appear in errors -- it is the diagnostic.
	// The dispatcher above is different: an unmatched or malformed reference is
	// where a pasted secret lands, so there the opaque part is always redacted.
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

// schemes returns the registered schemes in sorted order, for deterministic
// error messages.
func (r *Resolver) schemes() []string {
	out := make([]string, 0, len(r.providers))
	for scheme := range r.providers {
		out = append(out, scheme)
	}
	sort.Strings(out)
	return out
}

// Resolve validates the reference, selects the provider for its scheme, and
// resolves it. Errors render the reference in redacted form (scheme preserved,
// opaque part replaced) and never contain the resolved value.
func (r *Resolver) Resolve(ctx context.Context, ref Ref) (Redacted, error) {
	if err := ref.Validate(); err != nil {
		return "", err
	}
	scheme, opaque, _ := ref.split()
	p, ok := r.providers[scheme]
	if !ok {
		// This is the branch an operator reaches by pasting a secret (say a
		// Postgres DSN) into a *_ref field: "postgres" is a well-formed scheme
		// with no provider. The reference is rendered redacted; the known-scheme
		// list and the hint below are what make the error actionable without it.
		// The caller (config) prefixes the offending field name.
		return "", fmt.Errorf(
			"secrets: no provider for reference %s; known schemes: %s; a *_ref field must hold a reference to a secret, not the secret value itself",
			ref.redacted(), strings.Join(r.schemes(), ", "),
		)
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
