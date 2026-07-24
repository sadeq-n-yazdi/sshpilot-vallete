package httpserver_test

import (
	"context"
	"testing"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/counter"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
)

// breakableStore is a counter.Store that can be taken offline mid-test. It is
// how the fail-closed rule is exercised through the transport: a denylist that
// cannot be consulted must deny, and the only way to show that is to break the
// store under a token that would otherwise be admitted.
type breakableStore struct {
	inner counter.Store
	down  bool
}

func (s *breakableStore) Increment(ctx context.Context, key string, delta int64, ttl time.Duration) (counter.Count, error) {
	if s.down {
		return counter.Count{}, counter.ErrStoreUnavailable
	}
	return s.inner.Increment(ctx, key, delta, ttl)
}

func (s *breakableStore) Get(ctx context.Context, key string) (counter.Count, error) {
	if s.down {
		return counter.Count{}, counter.ErrStoreUnavailable
	}
	return s.inner.Get(ctx, key)
}

func (s *breakableStore) Delete(ctx context.Context, key string) error {
	if s.down {
		return counter.ErrStoreUnavailable
	}
	return s.inner.Delete(ctx, key)
}

func newTestCounterStore(now func() time.Time) (*breakableStore, error) {
	mem, err := counter.NewMemoryStore(now)
	if err != nil {
		return nil, err
	}
	return &breakableStore{inner: mem}, nil
}

// revoke lists a refresh credential, so every access token minted from it stops
// being accepted.
func (rg *realGuard) revoke(t *testing.T, id domain.RefreshCredentialID) {
	t.Helper()
	if err := rg.denylist.RevokeCredential(context.Background(), id); err != nil {
		t.Fatalf("RevokeCredential: %v", err)
	}
}

// takeStoreDown makes the denylist unconsultable.
func (rg *realGuard) takeStoreDown() { rg.store.down = true }
