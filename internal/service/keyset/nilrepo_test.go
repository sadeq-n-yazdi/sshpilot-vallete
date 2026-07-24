package keyset_test

import (
	"context"
	"errors"
	"testing"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/repository"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/service/keyset"
)

// A Store can be non-nil and still hand out a Repos whose KeySets field is nil.
// Every method on this service dereferences that field, so before the
// construction-time check the wiring bug surfaced as a nil dereference on the
// first request naming a key set rather than as a startup failure.
//
// The assertion is on what New returns, and nothing here calls a method
// afterwards: a panic from a method would prove the guard missing just as
// loudly but would not say which guard.

// partialStore hands out whatever Repos the test gives it. WithTx is never
// reached -- construction fails first -- so it refuses rather than pretending.
type partialStore struct{ repos repository.Repos }

func (s partialStore) Repos() repository.Repos { return s.repos }

func (partialStore) WithTx(context.Context, func(context.Context, repository.Repos) error) error {
	return errors.New("partialStore: WithTx must not be reached")
}

// stubKeySets is a non-nil interface value with a nil embedded interface: it
// satisfies the guard and panics loudly if anything actually calls it.
type stubKeySets struct{ repository.KeySetRepository }

func TestNewRejectsStoreWithNilKeySetRepository(t *testing.T) {
	svc, err := keyset.New(partialStore{}, mustGuard(t), &recordingAuditor{})
	if svc != nil {
		t.Error("New returned a Service over a nil key set repository")
	}
	if !errors.Is(err, keyset.ErrMissingDependency) {
		t.Fatalf("New error = %v, want one wrapping ErrMissingDependency", err)
	}
}

// TestNewAcceptsStoreWithKeySetRepository pins the other side: a populated
// Repos must still construct, so a guard that rejected everything would not
// pass both tests.
func TestNewAcceptsStoreWithKeySetRepository(t *testing.T) {
	store := partialStore{repository.Repos{KeySets: stubKeySets{}}}
	if _, err := keyset.New(store, mustGuard(t), &recordingAuditor{}); err != nil {
		t.Fatalf("New over a populated Repos: %v", err)
	}
}
