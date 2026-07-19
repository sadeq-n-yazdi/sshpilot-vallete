package auth_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/auth"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
)

func TestValidateScopes(t *testing.T) {
	many := make([]domain.Scope, auth.MaxScopes)
	for i := range many {
		many[i] = domain.Scope{Kind: domain.ScopeSingleSet, ResourceID: strings.Repeat("a", i+1)}
	}
	tooMany := append(append([]domain.Scope(nil), many...), domain.Scope{Kind: domain.ScopeSingleDevice, ResourceID: "d"})

	tests := []struct {
		name    string
		scopes  []domain.Scope
		wantErr bool
	}{
		{name: "full owner alone", scopes: []domain.Scope{{Kind: domain.ScopeFullOwner}}},
		{name: "read only alone", scopes: []domain.Scope{{Kind: domain.ScopeReadOnly}}},
		{name: "one bound scope", scopes: []domain.Scope{{Kind: domain.ScopeSingleSet, ResourceID: "ks-1"}}},
		{name: "several bound scopes", scopes: []domain.Scope{
			{Kind: domain.ScopeSingleSet, ResourceID: "ks-1"},
			{Kind: domain.ScopeSingleDevice, ResourceID: "dev-1"},
		}},
		{name: "at the count bound", scopes: many},

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
		// The mixes below are the ones with no single defensible reading. A
		// permission check that has to guess resolves to more access than
		// someone intended, so the set is refused at the door instead.
		{name: "full owner with a bound scope", scopes: []domain.Scope{
			{Kind: domain.ScopeFullOwner},
			{Kind: domain.ScopeSingleSet, ResourceID: "ks-1"},
		}, wantErr: true},
		{name: "bound scope then full owner", scopes: []domain.Scope{
			{Kind: domain.ScopeSingleSet, ResourceID: "ks-1"},
			{Kind: domain.ScopeFullOwner},
		}, wantErr: true},
		{name: "read only with a bound scope", scopes: []domain.Scope{
			{Kind: domain.ScopeReadOnly},
			{Kind: domain.ScopeSingleDevice, ResourceID: "dev-1"},
		}, wantErr: true},
		{name: "read only with full owner", scopes: []domain.Scope{
			{Kind: domain.ScopeReadOnly},
			{Kind: domain.ScopeFullOwner},
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
