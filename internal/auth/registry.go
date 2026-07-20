package auth

import (
	"fmt"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
)

// Registry is the fixed set of providers a server will accept authentication
// from. It is built once at wiring time and is immutable afterwards.
//
// Immutability is a security property, not an optimization. A registry that
// could be mutated at runtime would let a late or mistaken registration
// introduce a provider — and therefore a whole principal namespace that maps to
// real owners — after startup, and would need locking on the hot authentication
// path. Building the full set up front means the set of trusted issuers is
// fixed by configuration and is safe for concurrent reads with no lock.
//
// The map is keyed by ProviderID alone. That is a single validated field, not a
// composed key, so it carries none of the ambiguity a joined
// provider-plus-principal string would; principals are never used as map keys
// anywhere in this package.
type Registry struct {
	providers map[ProviderID]AuthProvider
}

// NewRegistry builds a Registry from the given providers.
//
// It rejects a nil provider, a provider whose ID is malformed, and two
// providers claiming the same id. The duplicate check is the one that matters:
// two providers sharing an id would share a principal namespace, so a principal
// minted by one would resolve to an owner linked under the other — precisely the
// cross-provider confusion the (provider, principal) pairing exists to prevent.
// Silently keeping the last registration would make that collision invisible, so
// it is a hard error at startup instead.
func NewRegistry(providers ...AuthProvider) (*Registry, error) {
	m := make(map[ProviderID]AuthProvider, len(providers))
	for i, p := range providers {
		if p == nil {
			return nil, fmt.Errorf("auth: nil provider at index %d: %w", i, domain.ErrInvalidInput)
		}
		id := p.ID()
		if err := id.Validate(); err != nil {
			return nil, fmt.Errorf("auth: provider at index %d: %w", i, err)
		}
		if _, dup := m[id]; dup {
			return nil, fmt.Errorf("auth: duplicate provider id %q: %w", id, domain.ErrConflict)
		}
		m[id] = p
	}
	return &Registry{providers: m}, nil
}

// Lookup returns the provider registered under id.
//
// It returns ErrAuthFailed — not a distinct "no such provider" error — because
// this runs on the authentication path with caller-influenced input. A caller
// able to tell an unregistered provider from a rejected credential could
// enumerate which identity providers a deployment has configured, which is
// reconnaissance for choosing an attack. Wiring mistakes are caught by
// NewRegistry at startup, where a precise error is safe and useful.
func (r *Registry) Lookup(id ProviderID) (AuthProvider, error) {
	if err := id.Validate(); err != nil {
		return nil, ErrAuthFailed
	}
	p, ok := r.providers[id]
	if !ok {
		return nil, ErrAuthFailed
	}
	return p, nil
}

// Len returns the number of registered providers. It exposes no provider ids,
// so it is safe for startup logging and health reporting.
func (r *Registry) Len() int { return len(r.providers) }
