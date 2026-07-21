package counter

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

// fakePrimary is a controllable Primary: it delegates to an embedded MemoryStore
// while "up" and returns wrapped ErrStoreUnavailable while "down". Ping reports
// whatever the test has set. It is safe for concurrent use so the -race test can
// toggle its health while requests run.
type fakePrimary struct {
	mu      sync.Mutex
	mem     *MemoryStore
	down    bool
	pingErr error
	pings   int
	closed  bool
}

func newFakePrimary(t *testing.T) *fakePrimary {
	t.Helper()
	mem, err := NewMemoryStore(time.Now)
	if err != nil {
		t.Fatalf("NewMemoryStore: %v", err)
	}
	return &fakePrimary{mem: mem}
}

func (p *fakePrimary) setDown(down bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.down = down
	if down {
		p.pingErr = fmt.Errorf("primary: %w: connection refused", ErrStoreUnavailable)
	} else {
		p.pingErr = nil
	}
}

func (p *fakePrimary) isDown() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.down
}

func (p *fakePrimary) Increment(ctx context.Context, key string, delta int64, ttl time.Duration) (Count, error) {
	if p.isDown() {
		return Count{}, fmt.Errorf("primary: %w", ErrStoreUnavailable)
	}
	return p.mem.Increment(ctx, key, delta, ttl)
}

func (p *fakePrimary) Get(ctx context.Context, key string) (Count, error) {
	if p.isDown() {
		return Count{}, fmt.Errorf("primary: %w", ErrStoreUnavailable)
	}
	return p.mem.Get(ctx, key)
}

func (p *fakePrimary) Delete(ctx context.Context, key string) error {
	if p.isDown() {
		return fmt.Errorf("primary: %w", ErrStoreUnavailable)
	}
	return p.mem.Delete(ctx, key)
}

func (p *fakePrimary) Ping(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.pings++
	return p.pingErr
}

func (p *fakePrimary) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = true
	return nil
}

func newMemFallback(t *testing.T) *MemoryStore {
	t.Helper()
	mem, err := NewMemoryStore(time.Now)
	if err != nil {
		t.Fatalf("NewMemoryStore: %v", err)
	}
	return mem
}

func TestFailoverConstructionRefusesNil(t *testing.T) {
	t.Parallel()
	if _, err := NewFailoverStore(nil, newMemFallback(t)); err == nil {
		t.Fatal("nil primary accepted")
	}
	if _, err := NewFailoverStore(newFakePrimary(t), nil); err == nil {
		t.Fatal("nil fallback accepted")
	}
}

// TestHealthyDelegatesToPrimary shows that with a healthy primary the store is a
// transparent pass-through: the same calls yield the same counts a bare store
// would, and it never degrades.
func TestHealthyDelegatesToPrimary(t *testing.T) {
	t.Parallel()
	p := newFakePrimary(t)
	f, err := NewFailoverStore(p, newMemFallback(t))
	if err != nil {
		t.Fatalf("NewFailoverStore: %v", err)
	}
	defer func() { _ = f.Close() }()
	ctx := context.Background()

	c1, err := f.Increment(ctx, "k", 1, time.Minute)
	if err != nil || c1.Value != 1 {
		t.Fatalf("Increment 1 = %+v, %v", c1, err)
	}
	c2, err := f.Increment(ctx, "k", 1, time.Minute)
	if err != nil || c2.Value != 2 {
		t.Fatalf("Increment 2 = %+v, %v", c2, err)
	}
	if f.Degraded() {
		t.Fatal("store degraded while primary was healthy")
	}
	// The count lives in the primary, not the fallback.
	got, err := f.Get(ctx, "k")
	if err != nil || got.Value != 2 {
		t.Fatalf("Get = %+v, %v; want Value 2", got, err)
	}
}

// TestValidationPassesThrough proves an invalid input is returned unchanged and
// never triggers a failover: it is a caller bug, not an outage.
func TestValidationPassesThrough(t *testing.T) {
	t.Parallel()
	p := newFakePrimary(t)
	f, err := NewFailoverStore(p, newMemFallback(t))
	if err != nil {
		t.Fatalf("NewFailoverStore: %v", err)
	}
	defer func() { _ = f.Close() }()
	ctx := context.Background()

	if _, err := f.Increment(ctx, "", 1, time.Minute); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("empty key = %v, want Is ErrInvalidKey", err)
	}
	if f.Degraded() {
		t.Fatal("a validation error must not degrade the store")
	}
}

// TestFailoverServesFromFallbackWithoutSurfacingOutage is the core guarantee:
// a primary outage is answered from memory and the wrapped ErrStoreUnavailable
// never reaches the caller.
func TestFailoverServesFromFallbackWithoutSurfacingOutage(t *testing.T) {
	t.Parallel()
	p := newFakePrimary(t)
	p.setDown(true)
	// Base interval huge so the reprobe loop never fires during this test; we
	// are asserting the request-path behavior only.
	f, err := NewFailoverStore(p, newMemFallback(t), WithReprobeInterval(time.Hour))
	if err != nil {
		t.Fatalf("NewFailoverStore: %v", err)
	}
	defer func() { _ = f.Close() }()
	ctx := context.Background()

	c1, err := f.Increment(ctx, "k", 1, time.Minute)
	if err != nil {
		t.Fatalf("Increment during outage surfaced error: %v", err)
	}
	if c1.Value != 1 {
		t.Fatalf("fallback value = %d, want 1", c1.Value)
	}
	if !f.Degraded() {
		t.Fatal("store did not mark itself degraded on a primary outage")
	}
	// A second increment accumulates in the fallback: limits keep being enforced.
	c2, err := f.Increment(ctx, "k", 1, time.Minute)
	if err != nil || c2.Value != 2 {
		t.Fatalf("Increment 2 = %+v, %v; want Value 2, nil", c2, err)
	}
	// Get and Delete are equally non-surfacing during the outage.
	if _, err := f.Get(ctx, "k"); err != nil {
		t.Fatalf("Get during outage surfaced error: %v", err)
	}
	if err := f.Delete(ctx, "k"); err != nil {
		t.Fatalf("Delete during outage surfaced error: %v", err)
	}
}

// fakeTimer drives the reprobe loop deterministically. after records the
// interval the loop asked to wait, and the loop unblocks only when the test
// sends on fire.
type fakeTimer struct {
	reqs chan time.Duration
	fire chan time.Time
}

func newFakeTimer() *fakeTimer {
	return &fakeTimer{reqs: make(chan time.Duration, 8), fire: make(chan time.Time)}
}

func (ft *fakeTimer) after(d time.Duration) <-chan time.Time {
	ft.reqs <- d
	return ft.fire
}

// waitInterval reports the next interval the reprobe loop requested, failing if
// none arrives promptly.
func (ft *fakeTimer) waitInterval(t *testing.T) time.Duration {
	t.Helper()
	select {
	case d := <-ft.reqs:
		return d
	case <-time.After(2 * time.Second):
		t.Fatal("reprobe loop did not schedule a probe")
		return 0
	}
}

// TestReprobeGrowsAndSwitchesBack drives the loop through a failover, a failed
// probe (interval doubles), and a successful probe (switch back, interval
// resets for the next outage).
func TestReprobeGrowsAndSwitchesBack(t *testing.T) {
	t.Parallel()
	const base = 2 * time.Second
	ft := newFakeTimer()
	p := newFakePrimary(t)
	p.setDown(true)

	inject := FailoverOption(func(f *FailoverStore) { f.after = ft.after })
	f, err := NewFailoverStore(p, newMemFallback(t), WithReprobeInterval(base), inject)
	if err != nil {
		t.Fatalf("NewFailoverStore: %v", err)
	}
	defer func() { _ = f.Close() }()
	ctx := context.Background()

	// Trigger the failover.
	if _, err := f.Increment(ctx, "k", 1, time.Minute); err != nil {
		t.Fatalf("Increment: %v", err)
	}

	// First probe is scheduled at the base interval.
	if d := ft.waitInterval(t); d != base {
		t.Fatalf("first probe interval = %s, want %s", d, base)
	}
	ft.fire <- time.Now() // probe runs; primary still down -> stays degraded.

	// Second probe is scheduled at double the base.
	if d := ft.waitInterval(t); d != 2*base {
		t.Fatalf("second probe interval = %s, want %s", d, 2*base)
	}
	// Recover the primary, then let the probe run: it succeeds and switches back.
	p.setDown(false)
	ft.fire <- time.Now()

	// Degraded clears shortly after the successful probe.
	waitUntil(t, func() bool { return !f.Degraded() }, "store did not switch back after recovery")

	// A fresh outage starts the interval over at base, proving the reset.
	p.setDown(true)
	if _, err := f.Increment(ctx, "k2", 1, time.Minute); err != nil {
		t.Fatalf("Increment after recovery: %v", err)
	}
	if d := ft.waitInterval(t); d != base {
		t.Fatalf("post-recovery first probe interval = %s, want reset to %s", d, base)
	}
}

// waitUntil polls cond until it holds or a short deadline passes.
func waitUntil(t *testing.T, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal(msg)
}

func TestNextInterval(t *testing.T) {
	t.Parallel()
	const max = time.Hour
	tests := []struct {
		cur, want time.Duration
	}{
		{5 * time.Minute, 10 * time.Minute},
		{10 * time.Minute, 20 * time.Minute},
		{20 * time.Minute, 40 * time.Minute},
		{40 * time.Minute, max},       // 80m > 60m -> capped exactly at 1h.
		{time.Hour, max},              // already at cap.
		{45 * time.Minute, max},       // overshoot clamps to exactly 1h.
		{time.Duration(1) << 62, max}, // overflow guard clamps to the cap.
	}
	for _, tt := range tests {
		if got := nextInterval(tt.cur, max); got != tt.want {
			t.Errorf("nextInterval(%s) = %s, want %s", tt.cur, got, tt.want)
		}
	}
	if maxReprobeInterval != time.Hour {
		t.Fatalf("maxReprobeInterval = %s, want exactly 1h", maxReprobeInterval)
	}
}

// TestCloseStopsReprobeAndClosesPrimary proves Close is clean: it stops the
// goroutine (the -race and goroutine-leak checks would catch a leak) and closes
// the primary. It is also idempotent.
func TestCloseStopsReprobeAndClosesPrimary(t *testing.T) {
	t.Parallel()
	p := newFakePrimary(t)
	f, err := NewFailoverStore(p, newMemFallback(t))
	if err != nil {
		t.Fatalf("NewFailoverStore: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	p.mu.Lock()
	closed := p.closed
	p.mu.Unlock()
	if !closed {
		t.Fatal("Close did not close the primary")
	}
}

// TestConcurrentIncrementDuringTransition exercises the request path against a
// primary whose health flips underneath it. It exists to run under -race: the
// degraded flag and the reprobe loop must stay coherent, and no primary outage
// may ever surface as an error.
func TestConcurrentIncrementDuringTransition(t *testing.T) {
	t.Parallel()
	p := newFakePrimary(t)
	ft := newFakeTimer()
	inject := FailoverOption(func(f *FailoverStore) { f.after = ft.after })
	f, err := NewFailoverStore(p, newMemFallback(t), WithReprobeInterval(time.Millisecond), inject)
	if err != nil {
		t.Fatalf("NewFailoverStore: %v", err)
	}
	defer func() { _ = f.Close() }()

	// Keep the reprobe loop fed so it never blocks the test's shutdown.
	go func() {
		for {
			select {
			case <-ft.reqs:
				select {
				case ft.fire <- time.Now():
				case <-time.After(time.Second):
					return
				}
			case <-time.After(time.Second):
				return
			}
		}
	}()

	// Flip the primary up and down while requests run.
	go func() {
		for i := 0; i < 200; i++ {
			p.setDown(i%2 == 0)
			time.Sleep(50 * time.Microsecond)
		}
		p.setDown(false)
	}()

	var wg sync.WaitGroup
	ctx := context.Background()
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			key := fmt.Sprintf("k%d", g)
			for i := 0; i < 300; i++ {
				if _, err := f.Increment(ctx, key, 1, time.Minute); err != nil {
					t.Errorf("Increment surfaced an error during transition: %v", err)
					return
				}
			}
		}(g)
	}
	wg.Wait()
}
