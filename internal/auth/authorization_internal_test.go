package auth

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/counter"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
)

// The branches exercised here are unreachable from outside the package: the
// access-token verifier refuses a token with no owner, and ValidateScopes
// refuses a scope kind it does not know, so neither shape can be presented to
// Guard.Authorize. They are still tested rather than deleted, because their job
// is to keep the guarantee local -- a future change to the verifier must not be
// able to make an empty owner or an unknown kind mean "allow" -- and a defense
// nobody has ever run is a defense nobody knows works.

// newInternalGuard builds a Guard whose denylist permits everything, so that a
// denial in these tests can only come from the branch under test.
func newInternalGuard(t *testing.T) *Guard {
	t.Helper()
	store, err := counter.NewMemoryStore(time.Now)
	if err != nil {
		t.Fatalf("NewMemoryStore: %v", err)
	}
	list, err := NewDenylist(store)
	if err != nil {
		t.Fatalf("NewDenylist: %v", err)
	}
	signer, err := NewAccessTokenSigner([]byte(strings.Repeat("k", MinSigningKeyLen)))
	if err != nil {
		t.Fatalf("NewAccessTokenSigner: %v", err)
	}
	g, err := NewGuard(signer, list)
	if err != nil {
		t.Fatalf("NewGuard: %v", err)
	}
	return g
}

// TestDecideRefusesATokenWithNoOwner covers the defensive branch: a token that
// names no owner cannot be owner-checked, so it cannot be permitted. It must
// not fall through to a comparison against the empty string, which an Access
// naming no owner would trivially pass.
func TestDecideRefusesATokenWithNoOwner(t *testing.T) {
	g := newInternalGuard(t)
	tests := []struct {
		name string
		tok  *domain.AccessToken
	}{
		{name: "nil token"},
		{
			name: "empty owner",
			tok: &domain.AccessToken{
				ID:                  "jti-1",
				RefreshCredentialID: "cred-1",
				Scopes:              []domain.Scope{{Kind: domain.ScopeFullOwner}},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := g.decide(context.Background(), tt.tok, Access{})
			if !errors.Is(err, ErrAuthFailed) {
				t.Fatalf("err = %v, want ErrAuthFailed", err)
			}
		})
	}
}

// TestScopePermitsRefusesAnUnknownKind covers the switch's default. A scope
// kind this code does not understand -- one minted by a future version, or a
// corrupted one -- must permit nothing, so it can never be the reason a request
// succeeds.
func TestScopePermitsRefusesAnUnknownKind(t *testing.T) {
	unknown := domain.Scope{Kind: domain.ScopeKind("admin")}
	accesses := []Access{
		{},
		{Mutating: true},
		{Resource: ResourceKeySet, ResourceID: "ks-alpha"},
		{Resource: ResourceDevice, ResourceID: "dev-alpha"},
	}
	for _, acc := range accesses {
		if scopePermits(unknown, acc) {
			t.Fatalf("an unknown scope kind permitted %+v", acc)
		}
		if permitsAccess([]domain.Scope{unknown}, acc) {
			t.Fatalf("a set of one unknown scope permitted %+v", acc)
		}
	}
	// And an empty set permits nothing, which is the case the loop would
	// silently invert if it were ever rewritten as "no objections, so allow".
	for _, acc := range accesses {
		if permitsAccess(nil, acc) {
			t.Fatalf("an empty scope set permitted %+v", acc)
		}
	}
}
