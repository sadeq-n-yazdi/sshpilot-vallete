package auth_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/auth"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/counter"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/repository"
)

// These tests cover a Store that is itself non-nil but hands out a Repos with a
// field the service dereferences left nil. That is a wiring bug rather than a
// contract the type system can express, and before the construction-time checks
// it surfaced as a nil dereference on the first token exchange or pairing
// approval -- a remotely reachable process kill on an authorization path, not a
// refused request. The assertion in each case is on what New returns, and
// nothing here calls a method afterwards: a panic from a method would say the
// guard is missing just as loudly, but would not say which guard.

// partialStore hands out whatever Repos a test gives it. WithTx is never
// reached by these tests -- construction fails first -- so it refuses rather
// than pretending to run.
type partialStore struct{ repos repository.Repos }

func (s partialStore) Repos() repository.Repos { return s.repos }

func (partialStore) WithTx(context.Context, func(context.Context, repository.Repos) error) error {
	return errors.New("partialStore: WithTx must not be reached")
}

// The stubs below are non-nil interface values whose embedded interface is nil,
// so a field set to one satisfies the guard and panics loudly if anything
// actually calls it. That keeps each test's nil field the only one under test.
type (
	stubCreds struct {
		repository.RefreshCredentialRepository
	}
	stubOwners   struct{ repository.OwnerRepository }
	stubPairings struct {
		repository.DevicePairingRepository
	}
	stubLinks struct {
		repository.LinkedIdentityRepository
	}
)

// fullRepos is the populated baseline each test blanks one field of.
func fullRepos() repository.Repos {
	return repository.Repos{
		RefreshCredentials: stubCreds{},
		Owners:             stubOwners{},
		DevicePairings:     stubPairings{},
		LinkedIdentities:   stubLinks{},
	}
}

func TestNewTokenServiceRejectsNilRepositories(t *testing.T) {
	for _, tt := range []struct {
		name  string
		blank func(*repository.Repos)
	}{
		{"refresh credentials", func(r *repository.Repos) { r.RefreshCredentials = nil }},
		{"owners", func(r *repository.Repos) { r.Owners = nil }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			repos := fullRepos()
			tt.blank(&repos)

			svc, err := auth.NewTokenService(partialStore{repos}, newSigner(t, 0x11), mustDenylist(t))
			if svc != nil {
				t.Errorf("NewTokenService returned a service over a nil %s repository", tt.name)
			}
			if !errors.Is(err, domain.ErrInvalidInput) {
				t.Fatalf("NewTokenService error = %v, want one wrapping domain.ErrInvalidInput", err)
			}
		})
	}
}

func TestNewEnrollmentServiceRejectsNilRepositories(t *testing.T) {
	for _, tt := range []struct {
		name  string
		blank func(*repository.Repos)
	}{
		{"device pairings", func(r *repository.Repos) { r.DevicePairings = nil }},
		{"linked identities", func(r *repository.Repos) { r.LinkedIdentities = nil }},
		{"refresh credentials", func(r *repository.Repos) { r.RefreshCredentials = nil }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			repos := fullRepos()
			tt.blank(&repos)
			denylist := mustDenylist(t)
			// The token service is built over a COMPLETE Repos so it constructs
			// successfully whichever field this case blanks; only the
			// enrollment service sees the incomplete one.
			tokens, err := auth.NewTokenService(partialStore{fullRepos()}, newSigner(t, 0x11), denylist)
			if err != nil {
				t.Fatalf("building the token service: %v", err)
			}
			authenticator, err := auth.NewAuthenticator(mustRegistry(t), stubLinks{}, stubOwners{})
			if err != nil {
				t.Fatalf("building the authenticator: %v", err)
			}

			svc, err := auth.NewEnrollmentService(
				partialStore{repos}, authenticator, tokens, denylist,
				mustCounters(t), func() time.Time { return testClock },
			)
			if svc != nil {
				t.Errorf("NewEnrollmentService returned a service over a nil %s repository", tt.name)
			}
			if !errors.Is(err, domain.ErrInvalidInput) {
				t.Fatalf("NewEnrollmentService error = %v, want one wrapping domain.ErrInvalidInput", err)
			}
		})
	}
}

// TestNewAcceptsCompleteRepos pins the other side of the guards: a Store whose
// Repos is fully populated must still construct. Without it, a guard that
// rejected everything would pass every test above.
func TestNewAcceptsCompleteRepos(t *testing.T) {
	denylist := mustDenylist(t)
	tokens, err := auth.NewTokenService(partialStore{fullRepos()}, newSigner(t, 0x11), denylist)
	if err != nil {
		t.Fatalf("NewTokenService over a complete Repos: %v", err)
	}
	authenticator, err := auth.NewAuthenticator(mustRegistry(t), stubLinks{}, stubOwners{})
	if err != nil {
		t.Fatalf("building the authenticator: %v", err)
	}
	if _, err := auth.NewEnrollmentService(
		partialStore{fullRepos()}, authenticator, tokens, denylist,
		mustCounters(t), func() time.Time { return testClock },
	); err != nil {
		t.Fatalf("NewEnrollmentService over a complete Repos: %v", err)
	}
}

func mustDenylist(t *testing.T) *auth.Denylist {
	t.Helper()
	c, err := counter.NewMemoryStore(func() time.Time { return testClock })
	if err != nil {
		t.Fatalf("building the counter store: %v", err)
	}
	dl, err := auth.NewDenylist(c)
	if err != nil {
		t.Fatalf("building the denylist: %v", err)
	}
	return dl
}

func mustCounters(t *testing.T) counter.Store {
	t.Helper()
	c, err := counter.NewMemoryStore(func() time.Time { return testClock })
	if err != nil {
		t.Fatalf("building the counter store: %v", err)
	}
	return c
}
