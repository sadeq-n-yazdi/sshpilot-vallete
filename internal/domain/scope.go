package domain

import "fmt"

// ScopeKind identifies what a Scope grants access to.
type ScopeKind string

// Scope kinds.
const (
	ScopeFullOwner    ScopeKind = "full-owner"
	ScopeReadOnly     ScopeKind = "read-only"
	ScopeSingleSet    ScopeKind = "single-set"
	ScopeSingleDevice ScopeKind = "single-device"
)

// IsValid reports whether k is a known ScopeKind.
func (k ScopeKind) IsValid() bool {
	switch k {
	case ScopeFullOwner, ScopeReadOnly, ScopeSingleSet, ScopeSingleDevice:
		return true
	default:
		return false
	}
}

// bindsResource reports whether the kind requires a ResourceID.
func (k ScopeKind) bindsResource() bool {
	return k == ScopeSingleSet || k == ScopeSingleDevice
}

// Scope is a permission grant. ResourceID holds the KeySetID for a single-set
// scope, the DeviceID for a single-device scope, and "" otherwise. An empty
// scope slice is never equivalent to full-owner.
type Scope struct {
	Kind       ScopeKind
	ResourceID string
}

// Validate checks the shape of a Scope only: the kind must be known, and
// ResourceID must be non-empty if and only if the kind binds a resource
// (single-set or single-device). It does not check resource existence or
// ownership.
func (s Scope) Validate() error {
	if !s.Kind.IsValid() {
		return fmt.Errorf("domain: unknown scope kind %q: %w", s.Kind, ErrInvalidInput)
	}
	if s.Kind.bindsResource() && s.ResourceID == "" {
		return fmt.Errorf("domain: scope kind %q requires a resource id: %w", s.Kind, ErrInvalidInput)
	}
	if !s.Kind.bindsResource() && s.ResourceID != "" {
		return fmt.Errorf("domain: scope kind %q must not carry a resource id: %w", s.Kind, ErrInvalidInput)
	}
	return nil
}
