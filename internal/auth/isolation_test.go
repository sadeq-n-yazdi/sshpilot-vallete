package auth_test

import (
	"context"
	"errors"
	"testing"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/auth"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
)

// TestCrossProviderIsolation is the core security property: a principal issued
// by one provider must never resolve to an owner linked only under another,
// even when the two principals are byte-identical.
func TestCrossProviderIsolation(t *testing.T) {
	const shared = auth.Principal("1234")
	const ownerAPI = domain.OwnerID("own-api")
	const ownerOIDC = domain.OwnerID("own-oidc")

	apiProvider := &fakeProvider{id: "api-token", identity: auth.Identity{Provider: "api-token", Principal: shared}}
	oidcProvider := &fakeProvider{id: "oidc", identity: auth.Identity{Provider: "oidc", Principal: shared}}
	// A third provider whose principal is linked under nobody: same bytes,
	// no link of its own.
	loneProvider := &fakeProvider{id: "webauthn", identity: auth.Identity{Provider: "webauthn", Principal: shared}}

	links := &fakeLinks{rows: map[linkKey]*domain.LinkedIdentity{
		{provider: "api-token", subject: string(shared)}: link("api-token", string(shared), ownerAPI),
		{provider: "oidc", subject: string(shared)}:      link("oidc", string(shared), ownerOIDC),
	}}
	owners := &fakeOwners{rows: map[domain.OwnerID]*domain.Owner{
		ownerAPI:  activeOwner(ownerAPI),
		ownerOIDC: activeOwner(ownerOIDC),
	}}
	reg, err := auth.NewRegistry(apiProvider, oidcProvider, loneProvider)
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	a, err := auth.NewAuthenticator(reg, links, owners)
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}

	tests := []struct {
		name      string
		provider  auth.ProviderID
		wantOwner domain.OwnerID
		wantDeny  bool
	}{
		{name: "api-token principal resolves to its own owner", provider: "api-token", wantOwner: ownerAPI},
		{name: "oidc principal resolves to its own owner", provider: "oidc", wantOwner: ownerOIDC},
		// The same principal bytes under a provider with no link must deny,
		// not fall through to either of the other two owners.
		{name: "unlinked provider with identical principal denies", provider: "webauthn", wantDeny: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := a.Authenticate(context.Background(), tt.provider, testCred())
			if tt.wantDeny {
				if err != auth.ErrAuthFailed { //nolint:errorlint,err113 // identity is the property under test
					t.Fatalf("error = %v, want the bare sentinel", err)
				}
				if got != "" {
					t.Fatalf("denied but returned owner %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("Authenticate: %v", err)
			}
			if got != tt.wantOwner {
				t.Fatalf("owner = %q, want %q — the principal crossed a provider boundary", got, tt.wantOwner)
			}
		})
	}
}

// TestKeyHalvesAreNeverJoined asserts the ambiguity that any delimiter-joined
// key would create: ("a", "b:c") and ("a:b", "c") join to the same string under
// ':' yet are different identities that must map to different owners.
//
// The resolver must pass both halves through as separate, unmodified arguments;
// the assertions on the captured arguments are what fail if someone later
// "simplifies" the key into a concatenation.
func TestKeyHalvesAreNeverJoined(t *testing.T) {
	const ownerA = domain.OwnerID("own-a")
	const ownerB = domain.OwnerID("own-b")

	// Both rows exist in the store. Note that "a:b" is not a currently valid
	// ProviderID — the slug charset excludes ':' precisely so this cannot be
	// reached from a live provider — but the row is present to prove the
	// lookup would not confuse the two even if it were.
	links := &fakeLinks{rows: map[linkKey]*domain.LinkedIdentity{
		{provider: "a", subject: "b:c"}: link("a", "b:c", ownerA),
		{provider: "a:b", subject: "c"}: link("a:b", "c", ownerB),
	}}
	owners := &fakeOwners{rows: map[domain.OwnerID]*domain.Owner{
		ownerA: activeOwner(ownerA),
		ownerB: activeOwner(ownerB),
	}}
	reg, err := auth.NewRegistry(&fakeProvider{id: "a", identity: auth.Identity{Provider: "a", Principal: "b:c"}})
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	a, err := auth.NewAuthenticator(reg, links, owners)
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}

	got, err := a.Authenticate(context.Background(), "a", testCred())
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if got != ownerA {
		t.Fatalf("owner = %q, want %q — the (provider, principal) halves were confused", got, ownerA)
	}
	if links.gotProvider != "a" {
		t.Fatalf("provider argument = %q, want %q: the halves were joined or rewritten", links.gotProvider, "a")
	}
	if links.gotSubject != "b:c" {
		t.Fatalf("subject argument = %q, want %q: the halves were joined or rewritten", links.gotSubject, "b:c")
	}

	// The other row is reachable only by its own exact key, confirming the two
	// are distinct entries and not one collided entry.
	other, err := links.GetByProviderSubject(context.Background(), "a:b", "c")
	if err != nil {
		t.Fatalf("second row lookup: %v", err)
	}
	if other.OwnerID != ownerB {
		t.Fatalf("second row owner = %q, want %q", other.OwnerID, ownerB)
	}
}

// TestProviderCannotMintInAnotherNamespace is the account-takeover test. A
// compromised or buggy provider returns an Identity stamped with a *different*
// provider's id, for a principal that really is linked under that other
// provider to a real owner. If the authenticator trusted the returned
// Identity.Provider instead of the id of the instance it invoked, this would
// hand the attacker the victim's owner id.
//
// The victim link must exist for this test to discriminate: without it the
// lookup would miss and deny for the wrong reason, and the test would pass even
// with the check removed.
func TestProviderCannotMintInAnotherNamespace(t *testing.T) {
	const victimPrincipal = auth.Principal("victim-sub")
	const victimOwner = domain.OwnerID("own-victim")

	// The attacker-controlled provider claims the oidc namespace.
	rogue := &fakeProvider{
		id:       "api-token",
		identity: auth.Identity{Provider: "oidc", Principal: victimPrincipal},
	}
	links := &fakeLinks{rows: map[linkKey]*domain.LinkedIdentity{
		{provider: "oidc", subject: string(victimPrincipal)}: link("oidc", string(victimPrincipal), victimOwner),
	}}
	owners := &fakeOwners{rows: map[domain.OwnerID]*domain.Owner{victimOwner: activeOwner(victimOwner)}}
	reg, err := auth.NewRegistry(rogue, &fakeProvider{id: "oidc"})
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	a, err := auth.NewAuthenticator(reg, links, owners)
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}

	got, err := a.Authenticate(context.Background(), "api-token", testCred())
	if got != "" {
		t.Fatalf("a provider minted an identity in another namespace and got owner %q", got)
	}
	if err != auth.ErrAuthFailed { //nolint:errorlint,err113 // identity is the property under test
		t.Fatalf("error = %v, want the bare sentinel", err)
	}
	// The rogue identity must never have reached the store: the mismatch is
	// caught before any lookup, so no timing or load signal is produced either.
	if links.calls != 0 {
		t.Fatal("a cross-namespace identity reached the link store")
	}
}

// TestAuthenticateIsConcurrencySafe exercises the shared Registry and
// Authenticator from many goroutines, since one instance serves all requests.
// Run with -race, this is the check that the immutable-after-construction
// design actually holds.
func TestAuthenticateIsConcurrencySafe(t *testing.T) {
	p := &fakeProvider{id: testProvider, identity: auth.Identity{Provider: testProvider, Principal: testSubject}}
	links := &fakeLinks{rows: map[linkKey]*domain.LinkedIdentity{
		{provider: string(testProvider), subject: string(testSubject)}: link(string(testProvider), string(testSubject), testOwner),
	}}
	owners := &fakeOwners{rows: map[domain.OwnerID]*domain.Owner{testOwner: activeOwner(testOwner)}}
	reg, err := auth.NewRegistry(p)
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	a, err := auth.NewAuthenticator(reg, links, owners)
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}

	const goroutines = 16
	done := make(chan error, goroutines)
	for range goroutines {
		go func() {
			// Resolve touches only the registry-free path, so both the
			// Registry map and the Authenticator fields are read concurrently.
			owner, err := a.Resolve(context.Background(), auth.Identity{Provider: testProvider, Principal: testSubject})
			if err == nil && owner != testOwner {
				err = errors.New("wrong owner")
			}
			done <- err
		}()
	}
	for range goroutines {
		if err := <-done; err != nil {
			t.Fatalf("concurrent Resolve: %v", err)
		}
	}
}
