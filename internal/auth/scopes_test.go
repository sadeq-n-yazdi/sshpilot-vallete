package auth_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/auth"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
)

func TestValidateScopes(t *testing.T) {
	// A set larger than MaxScopes, to exercise the count guard. Its contents are
	// otherwise irrelevant: the count guard fires before any of them is read.
	tooMany := make([]domain.Scope, auth.MaxScopes+1)
	for i := range tooMany {
		tooMany[i] = domain.Scope{Kind: domain.ScopeSingleSet, ResourceID: strings.Repeat("a", i+1)}
	}

	tests := []struct {
		name    string
		scopes  []domain.Scope
		wantErr bool
	}{
		// Accepted sets.
		{name: "full owner alone", scopes: []domain.Scope{{Kind: domain.ScopeFullOwner}}},
		{name: "read only alone", scopes: []domain.Scope{{Kind: domain.ScopeReadOnly}}},
		{name: "single set alone", scopes: []domain.Scope{{Kind: domain.ScopeSingleSet, ResourceID: "ks-1"}}},
		{name: "single device alone", scopes: []domain.Scope{{Kind: domain.ScopeSingleDevice, ResourceID: "dev-1"}}},
		// read-only is a modifier: it combines with exactly one binding, which
		// is ADR-0018's own example ("read-only + single-set").
		{name: "read only with a single set", scopes: []domain.Scope{
			{Kind: domain.ScopeReadOnly},
			{Kind: domain.ScopeSingleSet, ResourceID: "ks-1"},
		}},
		{name: "read only with a single device", scopes: []domain.Scope{
			{Kind: domain.ScopeReadOnly},
			{Kind: domain.ScopeSingleDevice, ResourceID: "dev-1"},
		}},

		// Refused sets.
		{name: "nil", wantErr: true},
		{name: "empty", scopes: []domain.Scope{}, wantErr: true},
		{name: "over the count bound", scopes: tooMany, wantErr: true},
		{name: "unknown kind", scopes: []domain.Scope{{Kind: domain.ScopeKind("admin")}}, wantErr: true},
		{name: "bound kind without a resource", scopes: []domain.Scope{{Kind: domain.ScopeSingleSet}}, wantErr: true},
		{name: "unbound kind with a resource", scopes: []domain.Scope{{Kind: domain.ScopeFullOwner, ResourceID: "ks-1"}}, wantErr: true},
		{name: "duplicate", scopes: []domain.Scope{
			{Kind: domain.ScopeSingleSet, ResourceID: "ks-1"},
			{Kind: domain.ScopeSingleSet, ResourceID: "ks-1"},
		}, wantErr: true},
		// full-owner already grants everything within the owner, so pairing it
		// with any narrower scope has no defensible reading.
		{name: "full owner with a bound scope", scopes: []domain.Scope{
			{Kind: domain.ScopeFullOwner},
			{Kind: domain.ScopeSingleSet, ResourceID: "ks-1"},
		}, wantErr: true},
		{name: "bound scope then full owner", scopes: []domain.Scope{
			{Kind: domain.ScopeSingleSet, ResourceID: "ks-1"},
			{Kind: domain.ScopeFullOwner},
		}, wantErr: true},
		{name: "read only with full owner", scopes: []domain.Scope{
			{Kind: domain.ScopeReadOnly},
			{Kind: domain.ScopeFullOwner},
		}, wantErr: true},
		// read-only repeated: it is a single modifier, not a stackable grant.
		// (Two identical read-only scopes are also caught as a duplicate.)
		{name: "read only twice", scopes: []domain.Scope{
			{Kind: domain.ScopeReadOnly},
			{Kind: domain.ScopeReadOnly},
		}, wantErr: true},
		// At most one resource binding per token (ADR-0018). Two bindings of the
		// same kind or of different kinds are both refused, so the enforcement
		// union can never widen one narrow grant with another.
		{name: "two single sets", scopes: []domain.Scope{
			{Kind: domain.ScopeSingleSet, ResourceID: "ks-1"},
			{Kind: domain.ScopeSingleSet, ResourceID: "ks-2"},
		}, wantErr: true},
		{name: "single set and single device", scopes: []domain.Scope{
			{Kind: domain.ScopeSingleSet, ResourceID: "ks-1"},
			{Kind: domain.ScopeSingleDevice, ResourceID: "dev-1"},
		}, wantErr: true},
		{name: "read only with two bindings", scopes: []domain.Scope{
			{Kind: domain.ScopeReadOnly},
			{Kind: domain.ScopeSingleSet, ResourceID: "ks-1"},
			{Kind: domain.ScopeSingleDevice, ResourceID: "dev-1"},
		}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := auth.ValidateScopes(tt.scopes)
			if tt.wantErr && !errors.Is(err, domain.ErrInvalidInput) {
				t.Fatalf("error = %v, want ErrInvalidInput", err)
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}
