package counter_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/counter"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
)

// testClock is a hand-wound clock. Expiry is tested by moving it, never by
// sleeping: a test that sleeps to cross a boundary is slow when it passes and
// flaky when the machine is loaded, and it cannot test the boundary instant
// itself.
type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *testClock {
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

func newStore(t *testing.T) (*counter.MemoryStore, *testClock) {
	t.Helper()
	clk := newClock()
	s, err := counter.NewMemoryStore(clk.now)
	if err != nil {
		t.Fatalf("NewMemoryStore: %v", err)
	}
	return s, clk
}

func TestNewMemoryStoreRejectsNilClock(t *testing.T) {
	s, err := counter.NewMemoryStore(nil)
	if !errors.Is(err, domain.ErrInvalidInput) {
		t.Fatalf("nil clock error = %v, want domain.ErrInvalidInput", err)
	}
	if s != nil {
		t.Fatal("a rejected construction must not return a store")
	}
}

func TestIncrementCreatesAndAccumulates(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()

	got, err := s.Increment(ctx, "k", 1, time.Minute)
	if err != nil {
		t.Fatalf("Increment: %v", err)
	}
	if got.Value != 1 {
		t.Fatalf("first increment value = %d, want 1", got.Value)
	}
	if got.TTL != time.Minute {
		t.Fatalf("first increment TTL = %v, want %v", got.TTL, time.Minute)
	}

	// The returned value must be the one produced by this call's own addition,
	// which is what a limiter compares against its threshold.
	got, err = s.Increment(ctx, "k", 2, time.Minute)
	if err != nil {
		t.Fatalf("Increment: %v", err)
	}
	if got.Value != 3 {
		t.Fatalf("second increment value = %d, want 3", got.Value)
	}
}

// TestIncrementDoesNotExtendTTL pins the fixed window. A sliding window would
// let a caller that keeps attempting hold its bucket open forever, and would let
// a denylist entry outlive the token it denies.
func TestIncrementDoesNotExtendTTL(t *testing.T) {
	s, clk := newStore(t)
	ctx := context.Background()

	if _, err := s.Increment(ctx, "k", 1, time.Minute); err != nil {
		t.Fatalf("Increment: %v", err)
	}
	clk.advance(30 * time.Second)

	got, err := s.Increment(ctx, "k", 1, time.Hour)
	if err != nil {
		t.Fatalf("Increment: %v", err)
	}
	if got.TTL != 30*time.Second {
		t.Fatalf("TTL after re-increment = %v, want 30s (the original expiry, not the new ttl)", got.TTL)
	}
	if got.Value != 2 {
		t.Fatalf("value = %d, want 2", got.Value)
	}
}

// TestExpiryBoundaryDenies covers the exact expiry instant. The boundary belongs
// to the side that treats the key as gone, matching the half-open rule the
// access-token verifier already uses.
func TestExpiryBoundaryDenies(t *testing.T) {
	s, clk := newStore(t)
	ctx := context.Background()

	if _, err := s.Increment(ctx, "k", 1, time.Minute); err != nil {
		t.Fatalf("Increment: %v", err)
	}

	clk.advance(time.Minute - time.Nanosecond)
	if got, err := s.Get(ctx, "k"); err != nil || got.Value != 1 {
		t.Fatalf("just before expiry: value=%d err=%v, want 1, nil", got.Value, err)
	}

	clk.advance(time.Nanosecond)
	got, err := s.Get(ctx, "k")
	if err != nil {
		t.Fatalf("Get at expiry: %v", err)
	}
	if got != (counter.Count{}) {
		t.Fatalf("at the expiry instant Get = %+v, want the zero Count", got)
	}
}

// TestExpiredKeyStartsAFreshWindow shows a spent window's value is not carried
// forward: an attacker's exhausted attempts must not follow them into the next
// window, and a re-revoked identifier starts a clean entry.
func TestExpiredKeyStartsAFreshWindow(t *testing.T) {
	s, clk := newStore(t)
	ctx := context.Background()

	if _, err := s.Increment(ctx, "k", 5, time.Minute); err != nil {
		t.Fatalf("Increment: %v", err)
	}
	clk.advance(time.Minute)

	got, err := s.Increment(ctx, "k", 1, time.Minute)
	if err != nil {
		t.Fatalf("Increment: %v", err)
	}
	if got.Value != 1 {
		t.Fatalf("value after expiry = %d, want 1 (a fresh window, not 6)", got.Value)
	}
}

// TestExpiredEntriesAreEvicted is the unbounded-growth test. It asserts on
// resident size, not on what a read reports: a store that only drops expired
// keys when they happen to be read still grows forever under the access pattern
// both consumers have, where most keys are never touched again.
func TestExpiredEntriesAreEvicted(t *testing.T) {
	s, clk := newStore(t)
	ctx := context.Background()

	// Enough distinct keys to drive at least one amortized sweep, none of them
	// ever read again -- the pattern a lazy-expiry store leaks under.
	const keys = 600
	for i := range keys {
		if _, err := s.Increment(ctx, fmt.Sprintf("k%d", i), 1, time.Minute); err != nil {
			t.Fatalf("Increment: %v", err)
		}
	}
	if s.Len() == 0 {
		t.Fatal("store should hold live entries")
	}

	clk.advance(2 * time.Minute)

	// Drive further operations on unrelated keys; the expired ones must be
	// released without anyone reading them.
	for i := range keys {
		if _, err := s.Increment(ctx, fmt.Sprintf("fresh%d", i), 1, time.Minute); err != nil {
			t.Fatalf("Increment: %v", err)
		}
	}
	if got := s.Len(); got > keys {
		t.Fatalf("resident entries = %d, want <= %d: expired entries were not evicted", got, keys)
	}
}

// TestSweepReleasesEverything covers the explicit maintenance trigger, including
// that it leaves live entries alone.
func TestSweepReleasesEverything(t *testing.T) {
	s, clk := newStore(t)
	ctx := context.Background()

	if _, err := s.Increment(ctx, "short", 1, time.Minute); err != nil {
		t.Fatalf("Increment: %v", err)
	}
	if _, err := s.Increment(ctx, "long", 1, time.Hour); err != nil {
		t.Fatalf("Increment: %v", err)
	}
	clk.advance(2 * time.Minute)

	if removed := s.Sweep(); removed != 1 {
		t.Fatalf("Sweep removed %d, want 1", removed)
	}
	if got := s.Len(); got != 1 {
		t.Fatalf("resident entries after sweep = %d, want 1 (the live one)", got)
	}
	if removed := s.Sweep(); removed != 0 {
		t.Fatalf("second Sweep removed %d, want 0", removed)
	}
}

func TestDelete(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()

	if _, err := s.Increment(ctx, "k", 3, time.Minute); err != nil {
		t.Fatalf("Increment: %v", err)
	}
	if err := s.Delete(ctx, "k"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	got, err := s.Get(ctx, "k")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got != (counter.Count{}) {
		t.Fatalf("after Delete, Get = %+v, want the zero Count", got)
	}
	// Deleting an absent key is not an error; the limiter clears a key on every
	// successful login without first checking whether one exists.
	if err := s.Delete(ctx, "k"); err != nil {
		t.Fatalf("Delete of an absent key: %v", err)
	}
}

func TestGetOfAbsentKeyIsNotAnError(t *testing.T) {
	s, _ := newStore(t)

	got, err := s.Get(context.Background(), "never-written")
	if err != nil {
		t.Fatalf("Get of an absent key returned an error: %v", err)
	}
	if got != (counter.Count{}) {
		t.Fatalf("Get of an absent key = %+v, want the zero Count", got)
	}
}

func TestInvalidArguments(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()

	t.Run("empty key on Increment", func(t *testing.T) {
		_, err := s.Increment(ctx, "", 1, time.Minute)
		if !errors.Is(err, counter.ErrInvalidKey) || !errors.Is(err, domain.ErrInvalidInput) {
			t.Fatalf("err = %v, want both ErrInvalidKey and domain.ErrInvalidInput", err)
		}
	})
	t.Run("empty key on Get", func(t *testing.T) {
		if _, err := s.Get(ctx, ""); !errors.Is(err, counter.ErrInvalidKey) {
			t.Fatalf("err = %v, want ErrInvalidKey", err)
		}
	})
	t.Run("empty key on Delete", func(t *testing.T) {
		if err := s.Delete(ctx, ""); !errors.Is(err, counter.ErrInvalidKey) {
			t.Fatalf("err = %v, want ErrInvalidKey", err)
		}
	})
	// A non-positive delta would let a caller count its own bucket back down
	// below a limit it had already crossed.
	for _, delta := range []int64{0, -1} {
		t.Run(fmt.Sprintf("delta %d", delta), func(t *testing.T) {
			if _, err := s.Increment(ctx, "k", delta, time.Minute); !errors.Is(err, domain.ErrInvalidInput) {
				t.Fatalf("err = %v, want domain.ErrInvalidInput", err)
			}
		})
	}
	// A non-positive TTL would create an entry that is already expired, so a
	// revocation would appear recorded and deny nothing.
	for _, ttl := range []time.Duration{0, -time.Second} {
		t.Run(fmt.Sprintf("ttl %v", ttl), func(t *testing.T) {
			if _, err := s.Increment(ctx, "k", 1, ttl); !errors.Is(err, domain.ErrInvalidInput) {
				t.Fatalf("err = %v, want domain.ErrInvalidInput", err)
			}
		})
	}
}

// TestCancelledContextIsUnavailableNotZero is what the denylist's fail-closed
// rule rests on: a store that cannot answer must say so, rather than returning a
// zero count that reads as "not revoked".
func TestCancelledContextIsUnavailableNotZero(t *testing.T) {
	s, _ := newStore(t)
	if _, err := s.Increment(context.Background(), "k", 1, time.Minute); err != nil {
		t.Fatalf("Increment: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	t.Run("Get", func(t *testing.T) {
		_, err := s.Get(ctx, "k")
		if !errors.Is(err, counter.ErrStoreUnavailable) {
			t.Fatalf("err = %v, want ErrStoreUnavailable", err)
		}
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("err = %v, want the cause to survive for logs", err)
		}
	})
	t.Run("Increment", func(t *testing.T) {
		if _, err := s.Increment(ctx, "k", 1, time.Minute); !errors.Is(err, counter.ErrStoreUnavailable) {
			t.Fatalf("err = %v, want ErrStoreUnavailable", err)
		}
	})
	t.Run("Delete", func(t *testing.T) {
		if err := s.Delete(ctx, "k"); !errors.Is(err, counter.ErrStoreUnavailable) {
			t.Fatalf("err = %v, want ErrStoreUnavailable", err)
		}
	})
}

// TestConcurrentIncrementsDoNotLoseCounts is the test the port requires of every
// implementation, and the one that catches a read-then-write increment.
//
// It proves two things a single-goroutine test cannot. First, the final value is
// exactly the number of increments: a lost update under a read-modify-write race
// is an under-count, which in a limiter means a parallel burst of credential
// guesses passes a limit a serial attacker would hit. Second, the values
// returned by the calls are a permutation of 1..N with no repeats -- so no two
// callers were told they were the same nth attempt, which is what a limiter's
// threshold comparison depends on.
//
// Run under -race, it also covers the data race itself.
func TestConcurrentIncrementsDoNotLoseCounts(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()

	const goroutines = 64
	const perGoroutine = 50
	const total = goroutines * perGoroutine

	seen := make([]atomic.Bool, total+1)
	var failures atomic.Int64
	var wg sync.WaitGroup
	start := make(chan struct{})

	for range goroutines {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for range perGoroutine {
				got, err := s.Increment(ctx, "shared", 1, time.Hour)
				if err != nil {
					failures.Add(1)
					return
				}
				if got.Value < 1 || got.Value > total {
					failures.Add(1)
					return
				}
				// Swap reports the previous value: true means some other
				// caller was already handed this count.
				if seen[got.Value].Swap(true) {
					failures.Add(1)
					return
				}
			}
		}()
	}
	close(start)
	wg.Wait()

	if n := failures.Load(); n != 0 {
		t.Fatalf("%d increments failed or returned a duplicate count", n)
	}
	got, err := s.Get(ctx, "shared")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Value != total {
		t.Fatalf("final value = %d, want %d: increments were lost to a race", got.Value, total)
	}
}

// TestConcurrentMixedOperations exercises Increment, Get, Delete and Sweep
// against one another under -race. It asserts no invariant beyond "nothing
// races and nothing panics", which is the point: the eviction path runs while
// other goroutines hold references into the same map.
func TestConcurrentMixedOperations(t *testing.T) {
	s, clk := newStore(t)
	ctx := context.Background()

	var wg sync.WaitGroup
	for i := range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			key := fmt.Sprintf("k%d", i%4)
			for range 100 {
				if _, err := s.Increment(ctx, key, 1, time.Minute); err != nil {
					t.Errorf("Increment: %v", err)
					return
				}
				if _, err := s.Get(ctx, key); err != nil {
					t.Errorf("Get: %v", err)
					return
				}
				if err := s.Delete(ctx, key); err != nil {
					t.Errorf("Delete: %v", err)
					return
				}
				clk.advance(time.Second)
				s.Sweep()
				s.Len()
			}
		}()
	}
	wg.Wait()
}
