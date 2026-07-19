package auth_test

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/auth"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/repository"
)

// errStore stands in for an infrastructure fault, so tests can prove that a
// storage failure is reported to the caller identically to a rejected
// credential.
var errStore = errors.New("test: store unreachable")

// fakeProvider is a scriptable AuthProvider. The identity it returns is set
// independently of its id so that tests can construct the misbehaving case
// where a provider claims another provider's namespace.
type fakeProvider struct {
	id       auth.ProviderID
	identity auth.Identity
	err      error
	// gotCred records the credential passed in, so a test can confirm the
	// credential reaches the provider unaltered.
	gotCred *auth.Credential
}

func (p *fakeProvider) ID() auth.ProviderID { return p.id }

func (p *fakeProvider) Authenticate(_ context.Context, cred auth.Credential) (auth.Identity, error) {
	c := cred
	p.gotCred = &c
	if p.err != nil {
		return auth.Identity{}, p.err
	}
	return p.identity, nil
}

// linkKey is the composite key of the fake link store. It is a struct key
// rather than a joined string for the same reason production code never joins:
// any delimiter makes ("a", "b:c") and ("a:b", "c") the same key. A test store
// that collided them would mask the very property these tests assert.
type linkKey struct {
	provider string
	subject  string
}

// fakeLinks is an in-memory LinkedIdentityRepository. Only the methods the
// authenticator uses have real behavior; the rest satisfy the port so the
// compile-time assertion below is meaningful.
type fakeLinks struct {
	// mu guards only the call-recording fields below. The rows map is written
	// before the fake is shared and read-only afterwards. Without this the
	// concurrency test would report a race in the test double rather than in
	// the code under test.
	mu   sync.Mutex
	rows map[linkKey]*domain.LinkedIdentity
	err  error
	// nilRow makes GetByProviderSubject return (nil, nil), the contract
	// violation the resolver must survive without panicking.
	nilRow bool
	// override replaces the returned row wholesale, letting a test simulate a
	// repository that hands back a row other than the one asked for.
	override *domain.LinkedIdentity
	// gotProvider and gotSubject record the arguments of the last lookup, so a
	// test can assert both halves of the key arrive separately and unmodified.
	gotProvider string
	gotSubject  string
	calls       int
}

var _ repository.LinkedIdentityRepository = (*fakeLinks)(nil)

func (f *fakeLinks) GetByProviderSubject(_ context.Context, provider, subject string) (*domain.LinkedIdentity, error) {
	f.mu.Lock()
	f.gotProvider, f.gotSubject, f.calls = provider, subject, f.calls+1
	f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	if f.nilRow {
		return nil, nil //nolint:nilnil // deliberately models a port violation
	}
	if f.override != nil {
		return f.override, nil
	}
	li, ok := f.rows[linkKey{provider: provider, subject: subject}]
	if !ok {
		return nil, domain.ErrNotFound
	}
	return li, nil
}

func (f *fakeLinks) Create(context.Context, *domain.LinkedIdentity) error { return nil }

func (f *fakeLinks) ListByOwner(context.Context, domain.OwnerID) ([]domain.LinkedIdentity, error) {
	return nil, nil
}

func (f *fakeLinks) Delete(context.Context, domain.OwnerID, domain.LinkedIdentityID) error {
	return nil
}

func (f *fakeLinks) DeleteByOwner(context.Context, domain.OwnerID) (int64, error) { return 0, nil }

// fakeOwners is an in-memory OwnerRepository.
type fakeOwners struct {
	rows map[domain.OwnerID]*domain.Owner
	err  error
	// nilRow makes Get return (nil, nil), the contract violation the resolver
	// must survive.
	nilRow bool
	// override replaces the returned owner, simulating a repository that
	// ignored the requested id.
	override *domain.Owner
}

var _ repository.OwnerRepository = (*fakeOwners)(nil)

func (f *fakeOwners) Get(_ context.Context, id domain.OwnerID) (*domain.Owner, error) {
	if f.err != nil {
		return nil, f.err
	}
	if f.nilRow {
		return nil, nil //nolint:nilnil // deliberately models a port violation
	}
	if f.override != nil {
		return f.override, nil
	}
	o, ok := f.rows[id]
	if !ok {
		return nil, domain.ErrNotFound
	}
	return o, nil
}

func (f *fakeOwners) Create(context.Context, *domain.Owner) error { return nil }

func (f *fakeOwners) UpdateStatus(context.Context, domain.OwnerID, domain.OwnerStatus, time.Time) error {
	return nil
}

func (f *fakeOwners) SoftDelete(context.Context, domain.OwnerID, time.Time) error { return nil }

func (f *fakeOwners) List(context.Context, repository.Page) ([]domain.Owner, string, error) {
	return nil, "", nil
}

// link builds a LinkedIdentity row for the fake store.
func link(provider, subject string, owner domain.OwnerID) *domain.LinkedIdentity {
	return &domain.LinkedIdentity{
		ID:       domain.LinkedIdentityID("li-" + provider + "-" + subject),
		OwnerID:  owner,
		Provider: provider,
		Subject:  subject,
	}
}

// activeOwner builds an active, non-deleted owner.
func activeOwner(id domain.OwnerID) *domain.Owner {
	return &domain.Owner{ID: id, Status: domain.OwnerStatusActive}
}
