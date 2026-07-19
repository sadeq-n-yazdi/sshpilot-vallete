package domain

import (
	"errors"
	"testing"
)

func TestScopeValidate(t *testing.T) {
	tests := []struct {
		name  string
		scope Scope
		valid bool
	}{
		{"full-owner no resource", Scope{Kind: ScopeFullOwner}, true},
		{"read-only no resource", Scope{Kind: ScopeReadOnly}, true},
		{"single-set with resource", Scope{Kind: ScopeSingleSet, ResourceID: "ks_123"}, true},
		{"single-device with resource", Scope{Kind: ScopeSingleDevice, ResourceID: "dev_123"}, true},
		{"unknown kind", Scope{Kind: ScopeKind("god-mode")}, false},
		{"empty kind", Scope{}, false},
		{"single-set missing resource", Scope{Kind: ScopeSingleSet}, false},
		{"single-device missing resource", Scope{Kind: ScopeSingleDevice}, false},
		{"full-owner with stray resource", Scope{Kind: ScopeFullOwner, ResourceID: "x"}, false},
		{"read-only with stray resource", Scope{Kind: ScopeReadOnly, ResourceID: "x"}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.scope.Validate()
			if tc.valid && err != nil {
				t.Fatalf("expected valid, got error: %v", err)
			}
			if !tc.valid {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				if !errors.Is(err, ErrInvalidInput) {
					t.Fatalf("error %v does not wrap ErrInvalidInput", err)
				}
			}
		})
	}
}
