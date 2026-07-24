package ratelimit_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/counter"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/ratelimit"
)

func testAuthTier() ratelimit.AuthTier {
	return ratelimit.AuthTier{
		Limit:   3,
		Window:  time.Minute,
		Horizon: 24 * time.Hour,
		Cap:     30 * time.Minute,
	}
}

func newAuthLimiter(t *testing.T, tier ratelimit.AuthTier) (*ratelimit.AuthLimiter, *testClock) {
	t.Helper()
	clk := newTestClock()
	store, err := counter.NewMemoryStore(clk.now)
	if err != nil {
		t.Fatalf("NewMemoryStore: %v", err)
	}
	lim, err := ratelimit.NewAuthLimiter(store, "auth", tier)
	if err != nil {
		t.Fatalf("NewAuthLimiter: %v", err)
	}
	return lim, clk
}

func TestNewAuthLimiterRejectsBadConfig(t *testing.T) {
	t.Parallel()

	store, err := counter.NewMemoryStore(time.Now)
	if err != nil {
		t.Fatalf("NewMemoryStore: %v", err)
	}
	bad := func(mut func(*ratelimit.AuthTier)) ratelimit.AuthTier {
		tier := testAuthTier()
		mut(&tier)
		return tier
	}

	tests := []struct {
		name  string
		store counter.Store
		tname string
		tier  ratelimit.AuthTier
	}{
		{"nil store", nil, "a", testAuthTier()},
		{"empty name", store, "", testAuthTier()},
		{"zero limit", store, "a", bad(func(x *ratelimit.AuthTier) { x.Limit = 0 })},
		{"zero window", store, "a", bad(func(x *ratelimit.AuthTier) { x.Window = 0 })},
		{"zero horizon", store, "a", bad(func(x *ratelimit.AuthTier) { x.Horizon = 0 })},
		{"zero cap", store, "a", bad(func(x *ratelimit.AuthTier) { x.Cap = 0 })},
		// The horizon-exceeds-cap invariant: without it, waiting out a lockout
		// resets the backoff curve and the tier degrades to a flat cap.
		{"horizon equal to cap", store, "a", bad(func(x *ratelimit.AuthTier) { x.Horizon = x.Cap })},
		{"horizon below cap", store, "a", bad(func(x *ratelimit.AuthTier) { x.Horizon = x.Cap - time.Second })},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := ratelimit.NewAuthLimiter(tc.store, tc.tname, tc.tier); !errors.Is(err, domain.ErrInvalidInput) {
				t.Fatalf("NewAuthLimiter error = %v, want domain.ErrInvalidInput", err)
			}
		})
	}
}

// TestFreeAttemptsThenLockout walks the boundary: the Limit-th failure is still
// free, the (Limit+1)-th arms the first lockout.
func TestFreeAttemptsThenLockout(t *testing.T) {
	t.Parallel()

	lim, _ := newAuthLimiter(t, testAuthTier())
	ctx := context.Background()

	for i := int64(1); i <= 3; i++ {
		d, err := lim.RecordFailure(ctx, "ip")
		if err != nil {
			t.Fatalf("RecordFailure #%d: %v", i, err)
		}
		if !d.Allowed {
			t.Fatalf("failure #%d locked out; the first %d are free", i, 3)
		}
		chk, err := lim.Check(ctx, "ip")
		if err != nil {
			t.Fatalf("Check: %v", err)
		}
		if !chk.Allowed {
			t.Fatalf("Check refused after failure #%d, want allowed", i)
		}
	}

	d, err := lim.RecordFailure(ctx, "ip")
	if err != nil {
		t.Fatalf("RecordFailure #4: %v", err)
	}
	if d.Allowed {
		t.Fatal("failure #4 not locked out, want lockout (limit 3)")
	}
	// Level 4 is the first over the limit, so lockout = Window * 2^0.
	if want := time.Minute; d.RetryAfter != want {
		t.Fatalf("RetryAfter = %v, want %v", d.RetryAfter, want)
	}

	chk, err := lim.Check(ctx, "ip")
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if chk.Allowed {
		t.Fatal("Check allowed during an armed lockout")
	}
}

// TestBackoffDoublesAndCaps is the curve itself. It is asserted level by level
// because "there is some backoff" and "the backoff doubles" are different
// claims, and only the second one makes a sustained campaign infeasible.
func TestBackoffDoublesAndCaps(t *testing.T) {
	t.Parallel()

	tier := testAuthTier() // Limit 3, Window 1m, Cap 30m.
	lim, clk := newAuthLimiter(t, tier)
	ctx := context.Background()

	for i := int64(1); i <= 3; i++ {
		if _, err := lim.RecordFailure(ctx, "ip"); err != nil {
			t.Fatalf("RecordFailure: %v", err)
		}
	}

	want := []time.Duration{
		time.Minute,      // failure 4
		2 * time.Minute,  // 5
		4 * time.Minute,  // 6
		8 * time.Minute,  // 7
		16 * time.Minute, // 8
		30 * time.Minute, // 9 would be 32m -> capped
		30 * time.Minute, // 10 stays capped
	}
	for i, w := range want {
		d, err := lim.RecordFailure(ctx, "ip")
		if err != nil {
			t.Fatalf("RecordFailure level %d: %v", i+4, err)
		}
		if d.Allowed {
			t.Fatalf("level %d allowed, want lockout", i+4)
		}
		if d.RetryAfter != w {
			t.Fatalf("level %d: RetryAfter = %v, want %v", i+4, d.RetryAfter, w)
		}
		// Serve out the lockout so the next failure escalates rather than
		// bouncing off the one already armed.
		clk.advance(w)
	}
}

// TestLockoutExpiresButTheCountSurvives is the property that makes the curve
// monotonic: an attacker who waits out a lockout resumes at the NEXT level, not
// at the start. Without it, "wait and retry" resets the whole defense.
func TestLockoutExpiresButTheCountSurvives(t *testing.T) {
	t.Parallel()

	lim, clk := newAuthLimiter(t, testAuthTier())
	ctx := context.Background()

	for range 4 {
		if _, err := lim.RecordFailure(ctx, "ip"); err != nil {
			t.Fatalf("RecordFailure: %v", err)
		}
	}

	// Just before the 1m lockout elapses: still locked.
	clk.advance(time.Minute - time.Nanosecond)
	d, err := lim.Check(ctx, "ip")
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if d.Allowed {
		t.Fatal("allowed 1ns before the lockout elapsed")
	}

	// After it elapses: allowed to try again.
	clk.advance(time.Nanosecond)
	d, err = lim.Check(ctx, "ip")
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if !d.Allowed {
		t.Fatal("still locked out after the lockout elapsed; the tier never releases")
	}
	if d.Count != 4 {
		t.Fatalf("Count = %d, want 4: the failure history must survive the lockout", d.Count)
	}

	// And the next failure costs 2m, not 1m again.
	next, err := lim.RecordFailure(ctx, "ip")
	if err != nil {
		t.Fatalf("RecordFailure: %v", err)
	}
	if want := 2 * time.Minute; next.RetryAfter != want {
		t.Fatalf("RetryAfter after waiting out a lockout = %v, want %v (the curve restarted)", next.RetryAfter, want)
	}
}

// TestHorizonForgetsOldFailures: the count is not permanent, so a user who
// mistyped a password last week starts clean.
func TestHorizonForgetsOldFailures(t *testing.T) {
	t.Parallel()

	lim, clk := newAuthLimiter(t, testAuthTier())
	ctx := context.Background()

	for range 4 {
		if _, err := lim.RecordFailure(ctx, "ip"); err != nil {
			t.Fatalf("RecordFailure: %v", err)
		}
	}
	clk.advance(testAuthTier().Horizon)

	d, err := lim.Check(ctx, "ip")
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if !d.Allowed || d.Count != 0 {
		t.Fatalf("after the horizon: Allowed=%v Count=%d, want true/0", d.Allowed, d.Count)
	}
}

// TestRecordSuccessClearsFailures: a correct login must not leave the legitimate
// user part-way up the backoff curve.
func TestRecordSuccessClearsFailures(t *testing.T) {
	t.Parallel()

	lim, _ := newAuthLimiter(t, testAuthTier())
	ctx := context.Background()

	for range 2 {
		if _, err := lim.RecordFailure(ctx, "ip"); err != nil {
			t.Fatalf("RecordFailure: %v", err)
		}
	}
	if err := lim.RecordSuccess(ctx, "ip"); err != nil {
		t.Fatalf("RecordSuccess: %v", err)
	}

	d, err := lim.Check(ctx, "ip")
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if d.Count != 0 {
		t.Fatalf("Count = %d after RecordSuccess, want 0", d.Count)
	}

	if err := lim.RecordSuccess(ctx, ""); !errors.Is(err, domain.ErrInvalidInput) {
		t.Fatalf("RecordSuccess(\"\") error = %v, want domain.ErrInvalidInput", err)
	}
}

// TestAuthFailsClosedOnStoreOutage pins the tier's deliberate opposite choice
// to the publish tier's.
func TestAuthFailsClosedOnStoreOutage(t *testing.T) {
	t.Parallel()

	lim, err := ratelimit.NewAuthLimiter(failingStore{}, "auth", testAuthTier())
	if err != nil {
		t.Fatalf("NewAuthLimiter: %v", err)
	}
	ctx := context.Background()

	d, err := lim.Check(ctx, "ip")
	if !ratelimit.Unavailable(err) {
		t.Fatalf("Check error = %v, want ErrStoreUnavailable", err)
	}
	if d.Allowed {
		t.Fatal("Check allowed during a store outage; the auth tier must fail CLOSED")
	}

	d, err = lim.RecordFailure(ctx, "ip")
	if !ratelimit.Unavailable(err) {
		t.Fatalf("RecordFailure error = %v, want ErrStoreUnavailable", err)
	}
	if d.Allowed {
		t.Fatal("RecordFailure allowed during a store outage; must fail CLOSED")
	}
}

// TestAuthLockoutKeyOutageFailsClosed covers the partial failure: the failure
// counter answers, the lockout key does not. The tier must still refuse.
func TestAuthLockoutKeyOutageFailsClosed(t *testing.T) {
	t.Parallel()

	clk := newTestClock()
	mem, err := counter.NewMemoryStore(clk.now)
	if err != nil {
		t.Fatalf("NewMemoryStore: %v", err)
	}
	tier := testAuthTier()

	// First drive the failure count over the limit through a healthy limiter.
	healthy, err := ratelimit.NewAuthLimiter(mem, "auth", tier)
	if err != nil {
		t.Fatalf("NewAuthLimiter: %v", err)
	}
	ctx := context.Background()
	for range 4 {
		if _, err := healthy.RecordFailure(ctx, "ip"); err != nil {
			t.Fatalf("RecordFailure: %v", err)
		}
	}

	// Now the lockout key space goes dark. ":l" is the lockout namespace.
	broken, err := ratelimit.NewAuthLimiter(lockFailingStore{inner: mem, failPrefix: ":l"}, "auth", tier)
	if err != nil {
		t.Fatalf("NewAuthLimiter: %v", err)
	}

	d, err := broken.Check(ctx, "ip")
	if !ratelimit.Unavailable(err) {
		t.Fatalf("Check error = %v, want ErrStoreUnavailable", err)
	}
	if d.Allowed {
		t.Fatal("Check allowed when the lockout key was unreadable; must fail CLOSED")
	}

	d, err = broken.RecordFailure(ctx, "ip")
	if !ratelimit.Unavailable(err) {
		t.Fatalf("RecordFailure error = %v, want ErrStoreUnavailable", err)
	}
	if d.Allowed {
		t.Fatal("RecordFailure allowed when the lockout key was unwritable; must fail CLOSED")
	}
	if d.RetryAfter <= 0 {
		t.Fatalf("RetryAfter = %v, want the computed lockout even when the store failed", d.RetryAfter)
	}
}

func TestAuthEmptyKeyFailsClosed(t *testing.T) {
	t.Parallel()

	lim, _ := newAuthLimiter(t, testAuthTier())
	ctx := context.Background()

	if d, err := lim.Check(ctx, ""); d.Allowed || !errors.Is(err, domain.ErrInvalidInput) {
		t.Fatalf("Check(\"\") = %+v, %v; want refused with ErrInvalidInput", d, err)
	}
	if d, err := lim.RecordFailure(ctx, ""); d.Allowed || !errors.Is(err, domain.ErrInvalidInput) {
		t.Fatalf("RecordFailure(\"\") = %+v, %v; want refused with ErrInvalidInput", d, err)
	}
}

// TestBackoffNeverOverflowsToNoLockout: a very large failure count shifts the
// exponent past a Duration's range. If that wrapped negative it would read as
// "no lockout" and silently disable the tier for the worst offenders --
// exactly backwards.
func TestBackoffNeverOverflowsToNoLockout(t *testing.T) {
	t.Parallel()

	clk := newTestClock()
	store, err := counter.NewMemoryStore(clk.now)
	if err != nil {
		t.Fatalf("NewMemoryStore: %v", err)
	}
	// A large Window makes the doubling reach a Duration's limit within a
	// realistic number of failures, which is what exercises the clamp.
	tier := ratelimit.AuthTier{Limit: 1, Window: time.Hour, Horizon: 240 * time.Hour, Cap: 2 * time.Hour}
	lim, err := ratelimit.NewAuthLimiter(store, "auth", tier)
	if err != nil {
		t.Fatalf("NewAuthLimiter: %v", err)
	}
	ctx := context.Background()

	// The clock is deliberately NOT advanced: the failure count must climb past
	// the shift clamp within one horizon. Every level beyond the first must
	// still be a lockout bounded by the cap -- never zero, never negative.
	for i := range 80 {
		d, err := lim.RecordFailure(ctx, "ip")
		if err != nil {
			t.Fatalf("RecordFailure #%d: %v", i+1, err)
		}
		if i == 0 {
			continue // The first failure is within the free limit.
		}
		if d.Allowed {
			t.Fatalf("failure #%d allowed; the backoff overflowed to no lockout", i+1)
		}
		if d.RetryAfter <= 0 || d.RetryAfter > tier.Cap {
			t.Fatalf("failure #%d: RetryAfter = %v, want (0, %v]", i+1, d.RetryAfter, tier.Cap)
		}
	}
}

func TestAuthTierAccessor(t *testing.T) {
	t.Parallel()

	want := testAuthTier()
	lim, _ := newAuthLimiter(t, want)
	if got := lim.Tier(); got != want {
		t.Fatalf("Tier() = %+v, want %+v", got, want)
	}
}
