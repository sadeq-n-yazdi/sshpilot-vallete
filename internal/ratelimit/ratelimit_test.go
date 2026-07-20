package ratelimit_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/counter"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/ratelimit"
)

// newLimiter builds a limiter over a fresh MemoryStore on a hand-wound clock.
func newLimiter(t *testing.T, tier ratelimit.Tier) (*ratelimit.Limiter, *testClock) {
	t.Helper()
	clk := newTestClock()
	store, err := counter.NewMemoryStore(clk.now)
	if err != nil {
		t.Fatalf("NewMemoryStore: %v", err)
	}
	lim, err := ratelimit.NewLimiter(store, "test", tier)
	if err != nil {
		t.Fatalf("NewLimiter: %v", err)
	}
	return lim, clk
}

func TestNewLimiterRejectsBadConfig(t *testing.T) {
	t.Parallel()

	store, err := counter.NewMemoryStore(time.Now)
	if err != nil {
		t.Fatalf("NewMemoryStore: %v", err)
	}
	good := ratelimit.Tier{Limit: 5, Window: time.Minute}

	tests := []struct {
		name  string
		store counter.Store
		tname string
		tier  ratelimit.Tier
	}{
		{"nil store", nil, "t", good},
		{"empty name", store, "", good},
		{"zero limit", store, "t", ratelimit.Tier{Limit: 0, Window: time.Minute}},
		{"negative limit", store, "t", ratelimit.Tier{Limit: -1, Window: time.Minute}},
		{"zero window", store, "t", ratelimit.Tier{Limit: 5, Window: 0}},
		{"negative window", store, "t", ratelimit.Tier{Limit: 5, Window: -time.Second}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := ratelimit.NewLimiter(tc.store, tc.tname, tc.tier); !errors.Is(err, domain.ErrInvalidInput) {
				t.Fatalf("NewLimiter error = %v, want domain.ErrInvalidInput", err)
			}
		})
	}
}

// TestAllowBoundary is the core boundary case: exactly at the limit passes, one
// over is refused. An off-by-one here is a limiter that is either one request
// too generous or one too strict, and neither is visible without this test.
func TestAllowBoundary(t *testing.T) {
	t.Parallel()

	lim, _ := newLimiter(t, ratelimit.Tier{Limit: 3, Window: time.Minute})
	ctx := context.Background()

	for i := int64(1); i <= 3; i++ {
		d, err := lim.Allow(ctx, "ip")
		if err != nil {
			t.Fatalf("Allow #%d: %v", i, err)
		}
		if !d.Allowed {
			t.Fatalf("request #%d refused, want allowed (limit 3)", i)
		}
		if d.Count != i {
			t.Fatalf("request #%d: Count = %d, want %d", i, d.Count, i)
		}
	}

	d, err := lim.Allow(ctx, "ip")
	if err != nil {
		t.Fatalf("Allow #4: %v", err)
	}
	if d.Allowed {
		t.Fatal("request #4 allowed, want refused (limit 3)")
	}
	if d.Count != 4 {
		t.Fatalf("Count = %d, want 4 (over-limit requests must still be counted)", d.Count)
	}
	if d.Limit != 3 {
		t.Fatalf("Limit = %d, want 3", d.Limit)
	}
}

// TestAllowWindowRollover proves the window is fixed: the count resets when the
// window elapses, and -- just as important -- does NOT reset one nanosecond
// before it does.
func TestAllowWindowRollover(t *testing.T) {
	t.Parallel()

	lim, clk := newLimiter(t, ratelimit.Tier{Limit: 2, Window: time.Minute})
	ctx := context.Background()

	for range 3 {
		if _, err := lim.Allow(ctx, "ip"); err != nil {
			t.Fatalf("Allow: %v", err)
		}
	}

	// One nanosecond before the window closes, still refused.
	clk.advance(time.Minute - time.Nanosecond)
	d, err := lim.Allow(ctx, "ip")
	if err != nil {
		t.Fatalf("Allow: %v", err)
	}
	if d.Allowed {
		t.Fatal("allowed 1ns before window close; the window rolled over early")
	}

	// At the boundary the window has closed and the budget is fresh.
	clk.advance(time.Nanosecond)
	d, err = lim.Allow(ctx, "ip")
	if err != nil {
		t.Fatalf("Allow: %v", err)
	}
	if !d.Allowed {
		t.Fatal("refused at window boundary; the window did not roll over")
	}
	if d.Count != 1 {
		t.Fatalf("Count = %d, want 1: the previous window's attempts followed the caller across", d.Count)
	}
}

// TestRetryAfterIsTheRemainingWindow asserts the value, not its presence. A
// constant Retry-After is the easy bug: it is present, it looks right in a
// header dump, and it is wrong for every request that is not the first.
func TestRetryAfterIsTheRemainingWindow(t *testing.T) {
	t.Parallel()

	lim, clk := newLimiter(t, ratelimit.Tier{Limit: 1, Window: time.Minute})
	ctx := context.Background()

	if _, err := lim.Allow(ctx, "ip"); err != nil {
		t.Fatalf("Allow: %v", err)
	}

	// 20s into the window, the correct answer is the remaining 40s -- not the
	// full 60s window.
	clk.advance(20 * time.Second)
	d, err := lim.Allow(ctx, "ip")
	if err != nil {
		t.Fatalf("Allow: %v", err)
	}
	if d.Allowed {
		t.Fatal("second request allowed, want refused")
	}
	if want := 40 * time.Second; d.RetryAfter != want {
		t.Fatalf("RetryAfter = %v, want %v (remaining window, not the full window)", d.RetryAfter, want)
	}
	if got := d.RetryAfterSeconds(); got != 40 {
		t.Fatalf("RetryAfterSeconds = %d, want 40", got)
	}
}

// TestRetryAfterSecondsRoundsUp: a client that obeys a rounded-DOWN header
// retries while the window is still open and earns a second 429, so the header
// must never name an instant that is too early.
func TestRetryAfterSecondsRoundsUp(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		d    time.Duration
		want int64
	}{
		{"sub-second rounds up to 1", 250 * time.Millisecond, 1},
		{"just over a second rounds up to 2", time.Second + time.Nanosecond, 2},
		{"exact second is exact", 40 * time.Second, 40},
		{"fractional rounds up", 40*time.Second + 1, 41},
		{"zero reports 1", 0, 1},
		{"negative reports 1", -time.Second, 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			d := ratelimit.Decision{RetryAfter: tc.d}
			if got := d.RetryAfterSeconds(); got != tc.want {
				t.Fatalf("RetryAfterSeconds(%v) = %d, want %d", tc.d, got, tc.want)
			}
		})
	}
}

// TestAllowKeysAreIndependent: one caller's spend must not touch another's.
func TestAllowKeysAreIndependent(t *testing.T) {
	t.Parallel()

	lim, _ := newLimiter(t, ratelimit.Tier{Limit: 1, Window: time.Minute})
	ctx := context.Background()

	if _, err := lim.Allow(ctx, "a"); err != nil {
		t.Fatalf("Allow(a): %v", err)
	}
	if _, err := lim.Allow(ctx, "a"); err != nil {
		t.Fatalf("Allow(a): %v", err)
	}
	d, err := lim.Allow(ctx, "b")
	if err != nil {
		t.Fatalf("Allow(b): %v", err)
	}
	if !d.Allowed {
		t.Fatal("key b refused after key a exhausted its budget; keys are not independent")
	}
}

// TestAllowEmptyKeyFailsClosed: a keying function that could not identify the
// caller must not yield a free pass.
func TestAllowEmptyKeyFailsClosed(t *testing.T) {
	t.Parallel()

	lim, _ := newLimiter(t, ratelimit.Tier{Limit: 5, Window: time.Minute, FailOpen: true})
	d, err := lim.Allow(context.Background(), "")
	if !errors.Is(err, domain.ErrInvalidInput) {
		t.Fatalf("error = %v, want domain.ErrInvalidInput", err)
	}
	if d.Allowed {
		t.Fatal("empty key allowed; an unattributable caller must be refused even on a fail-open tier")
	}
}

func TestResetClearsTheCount(t *testing.T) {
	t.Parallel()

	lim, _ := newLimiter(t, ratelimit.Tier{Limit: 1, Window: time.Minute})
	ctx := context.Background()

	for range 2 {
		if _, err := lim.Allow(ctx, "ip"); err != nil {
			t.Fatalf("Allow: %v", err)
		}
	}
	if err := lim.Reset(ctx, "ip"); err != nil {
		t.Fatalf("Reset: %v", err)
	}
	d, err := lim.Allow(ctx, "ip")
	if err != nil {
		t.Fatalf("Allow: %v", err)
	}
	if !d.Allowed || d.Count != 1 {
		t.Fatalf("after Reset: Allowed=%v Count=%d, want true/1", d.Allowed, d.Count)
	}

	if err := lim.Reset(ctx, ""); !errors.Is(err, domain.ErrInvalidInput) {
		t.Fatalf("Reset(\"\") error = %v, want domain.ErrInvalidInput", err)
	}
}

// TestStoreOutagePolicy pins the per-tier fail-open/fail-closed decision. Both
// branches are asserted because the whole point is that the tiers differ.
func TestStoreOutagePolicy(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		failOpen    bool
		wantAllowed bool
	}{
		{"fail-open tier serves during an outage", true, true},
		{"fail-closed tier refuses during an outage", false, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			lim, err := ratelimit.NewLimiter(failingStore{}, "test",
				ratelimit.Tier{Limit: 5, Window: time.Minute, FailOpen: tc.failOpen})
			if err != nil {
				t.Fatalf("NewLimiter: %v", err)
			}

			d, err := lim.Allow(context.Background(), "ip")
			if !ratelimit.Unavailable(err) {
				t.Fatalf("error = %v, want a counter.ErrStoreUnavailable", err)
			}
			if d.Allowed != tc.wantAllowed {
				t.Fatalf("Allowed = %v, want %v", d.Allowed, tc.wantAllowed)
			}
			if !tc.wantAllowed && d.RetryAfter != time.Minute {
				t.Fatalf("RetryAfter = %v, want the full window %v", d.RetryAfter, time.Minute)
			}
		})
	}
}

func TestUnavailableDiscriminates(t *testing.T) {
	t.Parallel()

	if ratelimit.Unavailable(nil) {
		t.Fatal("Unavailable(nil) = true")
	}
	if ratelimit.Unavailable(domain.ErrInvalidInput) {
		t.Fatal("Unavailable(ErrInvalidInput) = true; an input error is not an outage")
	}
	if !ratelimit.Unavailable(counter.ErrStoreUnavailable) {
		t.Fatal("Unavailable(ErrStoreUnavailable) = false")
	}
}

func TestTierAccessor(t *testing.T) {
	t.Parallel()

	want := ratelimit.Tier{Limit: 7, Window: 2 * time.Minute, FailOpen: true}
	lim, _ := newLimiter(t, want)
	if got := lim.Tier(); got != want {
		t.Fatalf("Tier() = %+v, want %+v", got, want)
	}
}

// TestAllowIsAtomicUnderConcurrency is the test the counter port demands and
// the one that catches a read-then-write increment. N goroutines race on ONE
// key; exactly Limit of them may be allowed. A non-atomic increment
// under-counts here and lets more than Limit through -- which is precisely the
// burst of parallel guesses a limiter exists to stop -- while remaining
// invisible to every single-goroutine test above.
func TestAllowIsAtomicUnderConcurrency(t *testing.T) {
	t.Parallel()

	const (
		limit   = 50
		callers = 400
	)
	lim, _ := newLimiter(t, ratelimit.Tier{Limit: limit, Window: time.Minute})
	ctx := context.Background()

	var (
		mu      sync.Mutex
		allowed int
		wg      sync.WaitGroup
		start   = make(chan struct{})
	)
	for range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			d, err := lim.Allow(ctx, "shared")
			if err != nil {
				t.Errorf("Allow: %v", err)
				return
			}
			if d.Allowed {
				mu.Lock()
				allowed++
				mu.Unlock()
			}
		}()
	}
	close(start)
	wg.Wait()

	if allowed != limit {
		t.Fatalf("allowed %d of %d concurrent requests, want exactly %d; "+
			"a non-atomic increment under-counts and over-admits", allowed, callers, limit)
	}
}
