package ratelimit_test

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/counter"
)

// testClock is a hand-wound clock, matching the counter package's convention:
// expiry boundaries are crossed by moving time, never by sleeping, so the
// boundary instant itself is testable and the suite stays fast under -race.
type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func newTestClock() *testClock {
	return &testClock{t: time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)}
}

func (c *testClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *testClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// failingStore is a counter.Store that always reports itself unavailable.
//
// The fail-open/fail-closed behavior is tested against THIS rather than against
// a MemoryStore, because MemoryStore realistically only fails on a canceled
// context -- so a test that drove it into failure would be testing context
// plumbing, not the tier's outage policy. The policy exists for the
// network-backed store ADR-0023 anticipates, and this fake is that store's
// worst day.
type failingStore struct{}

func (failingStore) Increment(context.Context, string, int64, time.Duration) (counter.Count, error) {
	return counter.Count{}, fmt.Errorf("boom: %w", counter.ErrStoreUnavailable)
}

func (failingStore) Get(context.Context, string) (counter.Count, error) {
	return counter.Count{}, fmt.Errorf("boom: %w", counter.ErrStoreUnavailable)
}

func (failingStore) Delete(context.Context, string) error {
	return fmt.Errorf("boom: %w", counter.ErrStoreUnavailable)
}

// lockFailingStore succeeds on the failure counter and fails only on the
// lockout key, which is the partial-failure path an AuthLimiter must still
// answer safely.
type lockFailingStore struct {
	inner counter.Store
	// failPrefix selects which keys fail; keys containing it are refused.
	failPrefix string
}

func (s lockFailingStore) Increment(ctx context.Context, key string, delta int64, ttl time.Duration) (counter.Count, error) {
	if contains(key, s.failPrefix) {
		return counter.Count{}, fmt.Errorf("boom: %w", counter.ErrStoreUnavailable)
	}
	return s.inner.Increment(ctx, key, delta, ttl)
}

func (s lockFailingStore) Get(ctx context.Context, key string) (counter.Count, error) {
	if contains(key, s.failPrefix) {
		return counter.Count{}, fmt.Errorf("boom: %w", counter.ErrStoreUnavailable)
	}
	return s.inner.Get(ctx, key)
}

func (s lockFailingStore) Delete(ctx context.Context, key string) error {
	return s.inner.Delete(ctx, key)
}

func contains(s, sub string) bool { return sub != "" && strings.Contains(s, sub) }
