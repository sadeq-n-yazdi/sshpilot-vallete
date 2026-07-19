package auth_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/auth"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/repository"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/secrets"
)

const (
	testProvider = auth.ProviderID("api-token")
	testSubject  = auth.Principal("device-42")
	testOwner    = domain.OwnerID("own-1")
)

// newFixture wires an Authenticator over a single provider that authenticates
// testSubject, a link from that principal to testOwner, and an active owner.
// Tests mutate the returned fakes to break exactly one thing at a time.
func newFixture(t *testing.T) (*auth.Authenticator, *fakeProvider, *fakeLinks, *fakeOwners) {
	t.Helper()
	p := &fakeProvider{
		id:       testProvider,
		identity: auth.Identity{Provider: testProvider, Principal: testSubject},
	}
	links := &fakeLinks{rows: map[linkKey]*domain.LinkedIdentity{
		{provider: string(testProvider), subject: string(testSubject)}: link(string(testProvider), string(testSubject), testOwner),
	}}
	owners := &fakeOwners{rows: map[domain.OwnerID]*domain.Owner{
		testOwner: activeOwner(testOwner),
	}}
	reg, err := auth.NewRegistry(p)
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	a, err := auth.NewAuthenticator(reg, links, owners)
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}
	return a, p, links, owners
}

func testCred() auth.Credential {
	return auth.Credential{Secret: secrets.NewRedacted("token-value")}
}

func TestNewAuthenticatorRejectsNilDependencies(t *testing.T) {
	reg, err := auth.NewRegistry()
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	links := &fakeLinks{}
	owners := &fakeOwners{}

	tests := []struct {
		name   string
		reg    *auth.Registry
		links  repository.LinkedIdentityRepository
		owners repository.OwnerRepository
	}{
		{name: "nil registry", reg: nil, links: links, owners: owners},
		{name: "nil links", reg: reg, links: nil, owners: owners},
		{name: "nil owners", reg: reg, links: links, owners: nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, err := auth.NewAuthenticator(tt.reg, tt.links, tt.owners)
			if !errors.Is(err, domain.ErrInvalidInput) {
				t.Fatalf("error = %v, want domain.ErrInvalidInput", err)
			}
			if a != nil {
				t.Fatal("returned an Authenticator alongside an error")
			}
		})
	}

	a, err := auth.NewAuthenticator(reg, links, owners)
	if err != nil || a == nil {
		t.Fatalf("fully wired NewAuthenticator = (%v, %v), want (non-nil, nil)", a, err)
	}
}

// TestAuthenticateHappyPath is the one path that must succeed, and it also
// confirms the credential reaches the provider unaltered.
func TestAuthenticateHappyPath(t *testing.T) {
	a, p, links, _ := newFixture(t)

	got, err := a.Authenticate(context.Background(), testProvider, testCred())
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if got != testOwner {
		t.Fatalf("owner = %q, want %q", got, testOwner)
	}
	if p.gotCred == nil || p.gotCred.Secret.Reveal() != "token-value" {
		t.Fatal("provider did not receive the credential unaltered")
	}
	// Both halves of the key must arrive separately and byte-for-byte.
	if links.gotProvider != string(testProvider) || links.gotSubject != string(testSubject) {
		t.Fatalf("lookup key = (%q, %q), want (%q, %q)", links.gotProvider, links.gotSubject, testProvider, testSubject)
	}
}

func TestResolveHappyPath(t *testing.T) {
	a, _, _, _ := newFixture(t)

	got, err := a.Resolve(context.Background(), auth.Identity{Provider: testProvider, Principal: testSubject})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got != testOwner {
		t.Fatalf("owner = %q, want %q", got, testOwner)
	}
}

// failureCase describes one way authentication can be denied. Each breaks
// exactly one thing in the otherwise-working fixture.
type failureCase struct {
	name string
	// setup mutates the fixture to create the failure.
	setup func(p *fakeProvider, links *fakeLinks, owners *fakeOwners)
	// providerID overrides the provider selector passed to Authenticate.
	providerID *auth.ProviderID
}

func failureCases() []failureCase {
	id := func(s auth.ProviderID) *auth.ProviderID { return &s }
	return []failureCase{
		{
			name:       "unregistered provider",
			providerID: id("webauthn"),
		},
		{
			name:       "malformed provider selector",
			providerID: id("API:TOKEN"),
		},
		{
			name:       "empty provider selector",
			providerID: id(""),
		},
		{
			name: "provider rejected the credential",
			setup: func(p *fakeProvider, _ *fakeLinks, _ *fakeOwners) {
				p.err = auth.ErrAuthFailed
			},
		},
		{
			name: "provider infrastructure fault",
			setup: func(p *fakeProvider, _ *fakeLinks, _ *fakeOwners) {
				p.err = errStore
			},
		},
		{
			// A provider claiming another provider's namespace is the account
			// takeover case; the invoked instance's own id is authoritative.
			name: "provider claims another namespace",
			setup: func(p *fakeProvider, _ *fakeLinks, _ *fakeOwners) {
				p.identity.Provider = "oidc"
			},
		},
		{
			name: "provider returned an empty principal",
			setup: func(p *fakeProvider, _ *fakeLinks, _ *fakeOwners) {
				p.identity.Principal = ""
			},
		},
		{
			name: "provider returned an over-long principal",
			setup: func(p *fakeProvider, _ *fakeLinks, _ *fakeOwners) {
				b := make([]byte, auth.MaxPrincipalLen+1)
				for i := range b {
					b[i] = 'a'
				}
				p.identity.Principal = auth.Principal(b)
			},
		},
		{
			name: "unknown principal",
			setup: func(p *fakeProvider, _ *fakeLinks, _ *fakeOwners) {
				p.identity.Principal = "device-does-not-exist"
			},
		},
		{
			name: "link store unreachable",
			setup: func(_ *fakeProvider, links *fakeLinks, _ *fakeOwners) {
				links.err = errStore
			},
		},
		{
			name: "link store returned nil row and nil error",
			setup: func(_ *fakeProvider, links *fakeLinks, _ *fakeOwners) {
				links.nilRow = true
			},
		},
		{
			name: "link store returned a row for a different provider",
			setup: func(_ *fakeProvider, links *fakeLinks, _ *fakeOwners) {
				links.override = link("oidc", string(testSubject), testOwner)
			},
		},
		{
			name: "link store returned a row for a different subject",
			setup: func(_ *fakeProvider, links *fakeLinks, _ *fakeOwners) {
				links.override = link(string(testProvider), "someone-else", testOwner)
			},
		},
		{
			name: "linked owner does not exist",
			setup: func(_ *fakeProvider, _ *fakeLinks, owners *fakeOwners) {
				owners.rows = nil
			},
		},
		{
			name: "owner store unreachable",
			setup: func(_ *fakeProvider, _ *fakeLinks, owners *fakeOwners) {
				owners.err = errStore
			},
		},
		{
			name: "owner store returned nil row and nil error",
			setup: func(_ *fakeProvider, _ *fakeLinks, owners *fakeOwners) {
				owners.nilRow = true
			},
		},
		{
			name: "owner store returned a different owner",
			setup: func(_ *fakeProvider, _ *fakeLinks, owners *fakeOwners) {
				owners.override = activeOwner("own-other")
			},
		},
		{
			name: "owner suspended",
			setup: func(_ *fakeProvider, _ *fakeLinks, owners *fakeOwners) {
				owners.rows[testOwner].Status = domain.OwnerStatusSuspended
			},
		},
		{
			name: "owner status deleted",
			setup: func(_ *fakeProvider, _ *fakeLinks, owners *fakeOwners) {
				owners.rows[testOwner].Status = domain.OwnerStatusDeleted
			},
		},
		{
			name: "owner soft deleted",
			setup: func(_ *fakeProvider, _ *fakeLinks, owners *fakeOwners) {
				now := time.Unix(0, 0).UTC()
				owners.rows[testOwner].DeletedAt = &now
			},
		},
		{
			name: "owner status empty",
			setup: func(_ *fakeProvider, _ *fakeLinks, owners *fakeOwners) {
				owners.rows[testOwner].Status = ""
			},
		},
	}
}

// TestAuthenticateFailsClosed walks every way authentication can be denied and
// asserts each one denies, returns no owner, and returns the single sentinel.
func TestAuthenticateFailsClosed(t *testing.T) {
	for _, tt := range failureCases() {
		t.Run(tt.name, func(t *testing.T) {
			a, p, links, owners := newFixture(t)
			if tt.setup != nil {
				tt.setup(p, links, owners)
			}
			id := testProvider
			if tt.providerID != nil {
				id = *tt.providerID
			}

			owner, err := a.Authenticate(context.Background(), id, testCred())
			if owner != "" {
				t.Fatalf("denied authentication returned owner %q, want empty", owner)
			}
			if !errors.Is(err, auth.ErrAuthFailed) {
				t.Fatalf("error = %v, want auth.ErrAuthFailed", err)
			}
		})
	}
}

// TestAuthenticateFailuresAreIndistinguishable is the anti-oracle test. Every
// denial must be the identical error value: same identity, same text, no
// wrapped cause. If any cause leaked through — a domain.ErrNotFound from the
// link store, an infrastructure error from a provider — a caller could probe
// which credentials and which providers exist.
func TestAuthenticateFailuresAreIndistinguishable(t *testing.T) {
	cases := failureCases()
	errs := make([]error, 0, len(cases))
	for _, tt := range cases {
		a, p, links, owners := newFixture(t)
		if tt.setup != nil {
			tt.setup(p, links, owners)
		}
		id := testProvider
		if tt.providerID != nil {
			id = *tt.providerID
		}
		_, err := a.Authenticate(context.Background(), id, testCred())
		if err == nil {
			t.Fatalf("%s: expected a denial", tt.name)
		}
		errs = append(errs, err)
	}

	for i, err := range errs {
		name := cases[i].name
		// Identical value: not merely errors.Is-compatible, the same error.
		if err != auth.ErrAuthFailed { //nolint:errorlint,err113 // identity is the property under test
			t.Fatalf("%s: error is a distinct value %#v, want the bare sentinel", name, err)
		}
		if err.Error() != auth.ErrAuthFailed.Error() {
			t.Fatalf("%s: error text %q differs from the sentinel", name, err.Error())
		}
		// No wrapped cause: a cause is readable via errors.Is/As and would
		// reinstate the distinction the sentinel exists to erase.
		if cause := errors.Unwrap(err); cause != nil {
			t.Fatalf("%s: error wraps a cause %v", name, cause)
		}
		// Specific leaks worth naming, since these are the values in flight.
		for _, leak := range []error{domain.ErrNotFound, domain.ErrInvalidInput, domain.ErrUnauthorized, errStore} {
			if errors.Is(err, leak) {
				t.Fatalf("%s: denial is distinguishable as %v", name, leak)
			}
		}
	}
}

// TestResolveFailsClosedOnMalformedIdentity covers Resolve's own gate: an
// identity that never came from a provider must not reach the store.
func TestResolveFailsClosedOnMalformedIdentity(t *testing.T) {
	tests := []struct {
		name string
		id   auth.Identity
	}{
		{name: "zero identity", id: auth.Identity{}},
		{name: "empty provider", id: auth.Identity{Principal: testSubject}},
		{name: "empty principal", id: auth.Identity{Provider: testProvider}},
		{name: "provider with separator", id: auth.Identity{Provider: "api:token", Principal: testSubject}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, _, links, _ := newFixture(t)
			owner, err := a.Resolve(context.Background(), tt.id)
			if owner != "" {
				t.Fatalf("owner = %q, want empty", owner)
			}
			if err != auth.ErrAuthFailed { //nolint:errorlint,err113 // identity is the property under test
				t.Fatalf("error = %v, want the bare sentinel", err)
			}
			if links.calls != 0 {
				t.Fatal("a malformed identity reached the link store")
			}
		})
	}
}
