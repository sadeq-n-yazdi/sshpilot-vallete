package counter

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
)

// defaultReprobeInterval is the first delay between health probes after a
// failover: a few minutes, short enough to recover promptly from a brief blip,
// long enough not to hammer a backend that is genuinely down.
const defaultReprobeInterval = 5 * time.Minute

// maxReprobeInterval caps the growing probe delay at exactly one hour. It is a
// hard ceiling, not a default: the interval doubles after each failed probe but
// never exceeds this, so a long outage settles at one probe per hour rather
// than backing off toward never noticing recovery.
const maxReprobeInterval = time.Hour

// probeTimeout bounds a single health probe so a backend that accepts a
// connection and then hangs cannot wedge the reprobe loop.
const probeTimeout = 5 * time.Second

// Primary is the network-backed store a FailoverStore prefers: a counter.Store
// that can also report whether its backend is reachable. *redisstore.Store
// satisfies it.
type Primary interface {
	Store
	// Ping reports nil when the backend is reachable and a wrap of
	// ErrStoreUnavailable when it is not. It is how the reprobe loop decides to
	// switch back from the memory fallback.
	Ping(ctx context.Context) error
}

// FailoverStore is a counter.Store that prefers a network-backed Primary and
// degrades to an in-process fallback whenever the Primary cannot answer, so
// rate limiting keeps working through a Redis/Valkey outage instead of failing.
//
// # What "degrade" means, and its tradeoff
//
// While degraded, every operation is served from the fallback MemoryStore. That
// makes the counters PER INSTANCE for the duration of the outage: two instances
// behind a load balancer each enforce their own limits, and the memory counts
// are discarded when the Primary recovers (the Primary is authoritative again)
// and are lost on restart. This is the availability/security tradeoff the
// operator opts into by configuring failover: limits stay ENFORCED per instance
// and are never disabled or bypassed, at the cost of not being shared during
// the outage. A single-node deployment behaves the same as it would with the
// memory store alone.
//
// # It NEVER surfaces the Primary's outage to its caller
//
// A Primary failure is caught, recorded, and answered from the fallback; the
// wrapped ErrStoreUnavailable from the Primary never propagates out. That is the
// point: the rate limiter's fail-open/fail-closed store-outage branch is
// deliberately not reached, so during a Primary outage every tier is enforced
// per instance rather than taking its configured outage posture. For the
// publish tier -- whose store-outage default is fail-OPEN -- this is a behavior
// change worth naming: during a Primary outage it is enforced per instance
// instead of waved through. That is the safer half of the degradation and is
// the operator's stated intent when they choose failover. (The only unavailable
// error a caller can still see originates in the fallback itself on a canceled
// context -- the caller's own cancellation, passed through honestly.)
//
// # For the rate limiter ONLY -- never the denylist
//
// One counter.Store interface backs both the rate limiter and the ADR-0018 auth
// revocation denylist, but this type is safe for the rate limiter ALONE.
// Swallowing ErrStoreUnavailable is correct for a limiter (a per-instance limit
// is a safe answer during an outage) and is a FAIL-OPEN bug for the denylist,
// whose fail-closed rule turns on seeing that error: a revocation check served
// from an empty memory map would report "not revoked" and let a killed
// credential through. Never wrap the denylist store in a FailoverStore.
//
// FailoverStore is safe for concurrent use; the degraded flag is atomic and the
// reprobe loop owns its own state.
type FailoverStore struct {
	primary  Primary
	fallback Store

	// degraded is the whole coordination point between the request path and the
	// reprobe loop: the request path flips it true on a Primary failure and
	// reads it to route; the reprobe loop flips it false on a successful probe.
	degraded atomic.Bool

	baseInterval time.Duration
	maxInterval  time.Duration

	// after returns a channel that fires after d together with a stop function
	// that releases the underlying timer. It is a field so a test can drive the
	// reprobe schedule without waiting real minutes; it defaults to a
	// time.NewTimer pair. Returning the stop function -- rather than the bare
	// channel time.After would give -- lets the loop release a pending timer
	// when Close races the wait, so a long (up to one-hour) interval does not
	// leave a timer alive well past Close.
	after func(d time.Duration) (<-chan time.Time, func() bool)

	// degradedCh carries the healthy->degraded transition to the reprobe loop.
	// It is buffered with one slot and sent to non-blockingly, so a failover
	// never blocks a request and repeated failures while already degraded do not
	// pile up.
	degradedCh chan struct{}
	done       chan struct{}
	stopped    chan struct{}
	closeOnce  sync.Once
}

// FailoverOption configures a FailoverStore.
type FailoverOption func(*FailoverStore)

// WithReprobeInterval sets the first delay between health probes after a
// failover. A non-positive value is ignored, leaving the default. The one-hour
// ceiling is fixed and not configurable.
func WithReprobeInterval(d time.Duration) FailoverOption {
	return func(f *FailoverStore) {
		if d > 0 {
			f.baseInterval = d
		}
	}
}

// NewFailoverStore wraps primary with fallback. Both are required: a nil either
// side is a wiring bug that would produce a store which fails on first use, so
// it is refused at construction rather than defaulted.
//
// The returned store starts a background reprobe goroutine; call Close to stop
// it.
func NewFailoverStore(primary Primary, fallback Store, opts ...FailoverOption) (*FailoverStore, error) {
	if primary == nil {
		return nil, fmt.Errorf("counter: nil primary store: %w", domain.ErrInvalidInput)
	}
	if fallback == nil {
		return nil, fmt.Errorf("counter: nil fallback store: %w", domain.ErrInvalidInput)
	}
	f := &FailoverStore{
		primary:      primary,
		fallback:     fallback,
		baseInterval: defaultReprobeInterval,
		maxInterval:  maxReprobeInterval,
		after: func(d time.Duration) (<-chan time.Time, func() bool) {
			t := time.NewTimer(d)
			return t.C, t.Stop
		},
		degradedCh: make(chan struct{}, 1),
		done:       make(chan struct{}),
		stopped:    make(chan struct{}),
	}
	for _, opt := range opts {
		if opt != nil {
			opt(f)
		}
	}
	go f.reprobe()
	return f, nil
}

// Increment implements Store. It tries the Primary while healthy and falls back
// to memory on a Primary outage, marking the store degraded so the reprobe loop
// takes over.
func (f *FailoverStore) Increment(ctx context.Context, key string, delta int64, ttl time.Duration) (Count, error) {
	if !f.degraded.Load() {
		c, err := f.primary.Increment(ctx, key, delta, ttl)
		if err == nil {
			return c, nil
		}
		if !errors.Is(err, ErrStoreUnavailable) {
			// A validation error (bad key, non-positive delta/ttl) is a caller
			// bug, not an outage; it is returned unchanged and is identical on
			// both stores anyway, so there is nothing to fail over to.
			return c, err
		}
		f.markDegraded()
	}
	return f.fallback.Increment(ctx, key, delta, ttl)
}

// Get implements Store.
func (f *FailoverStore) Get(ctx context.Context, key string) (Count, error) {
	if !f.degraded.Load() {
		c, err := f.primary.Get(ctx, key)
		if err == nil {
			return c, nil
		}
		if !errors.Is(err, ErrStoreUnavailable) {
			return c, err
		}
		f.markDegraded()
	}
	return f.fallback.Get(ctx, key)
}

// Delete implements Store.
func (f *FailoverStore) Delete(ctx context.Context, key string) error {
	if !f.degraded.Load() {
		err := f.primary.Delete(ctx, key)
		if err == nil {
			return nil
		}
		if !errors.Is(err, ErrStoreUnavailable) {
			return err
		}
		f.markDegraded()
	}
	return f.fallback.Delete(ctx, key)
}

// Degraded reports whether the store is currently serving from the fallback.
// It is exported for tests and as the natural gauge to export as a metric.
func (f *FailoverStore) Degraded() bool { return f.degraded.Load() }

// Close stops the reprobe goroutine and closes the Primary and, when it too
// holds releasable resources, the fallback -- each only if it implements
// Close() error. The two close errors are joined so neither is hidden by the
// other. It is idempotent: the closes run inside the once, so a second call is
// a no-op rather than a double close.
func (f *FailoverStore) Close() error {
	var err error
	f.closeOnce.Do(func() {
		close(f.done)
		<-f.stopped // wait for the goroutine to exit so no probe outlives Close.
		if c, ok := f.primary.(interface{ Close() error }); ok {
			err = errors.Join(err, c.Close())
		}
		if c, ok := f.fallback.(interface{ Close() error }); ok {
			err = errors.Join(err, c.Close())
		}
	})
	return err
}

// markDegraded flips to the degraded state and, only on the healthy->degraded
// transition, wakes the reprobe loop. Doing the send only on the transition
// keeps a burst of failures from stacking signals.
func (f *FailoverStore) markDegraded() {
	if f.degraded.CompareAndSwap(false, true) {
		select {
		case f.degradedCh <- struct{}{}:
		default:
		}
	}
}

// reprobe waits for a failover, then probes the Primary on a growing interval
// until it answers, at which point it switches back and the interval resets for
// the next outage.
func (f *FailoverStore) reprobe() {
	defer close(f.stopped)
	for {
		select {
		case <-f.done:
			return
		case <-f.degradedCh:
		}

		interval := f.baseInterval
		for f.degraded.Load() {
			ch, stop := f.after(interval)
			select {
			case <-f.done:
				// Release the pending timer rather than let it live out a
				// possibly hour-long interval after Close has returned.
				stop()
				return
			case <-ch:
			}
			if f.probeHealthy() {
				// Switch back: the Primary is authoritative again, and the
				// interval resets by leaving this loop.
				f.degraded.Store(false)
				break
			}
			interval = nextInterval(interval, f.maxInterval)
		}
	}
}

// probeHealthy runs one bounded health probe.
func (f *FailoverStore) probeHealthy() bool {
	ctx, cancel := context.WithTimeout(context.Background(), probeTimeout)
	defer cancel()
	return f.primary.Ping(ctx) == nil
}

// nextInterval doubles cur but never exceeds max. It is a pure function so the
// growth and the exact one-hour cap are unit-testable without the clock.
func nextInterval(cur, max time.Duration) time.Duration {
	next := cur * 2
	if next > max || next <= 0 { // next <= 0 guards the overflow of a huge cur.
		return max
	}
	return next
}

// Compile-time proof that FailoverStore satisfies the port.
var _ Store = (*FailoverStore)(nil)
