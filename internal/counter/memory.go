package counter

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
)

// sweepInterval is how many mutating operations pass between full sweeps of the
// map. It bounds memory: every key is created by an operation, so a sweep every
// sweepInterval operations means the number of expired keys still resident is
// bounded by sweepInterval regardless of how long the store runs, without a
// background goroutine to own and shut down.
//
// A larger value amortizes the O(n) scan over more work; a smaller one keeps
// less garbage. 256 is chosen so the scan is a rounding error next to the
// request handling that produced those 256 operations.
const sweepInterval = 256

// MemoryStore is the in-process Store: a map behind a mutex, with expiry.
//
// It is the single-node implementation and the reference for the atomicity the
// port requires. It is also the fallback that keeps a self-hosted deployment
// from needing Redis to get either rate limiting or revocation.
//
// # Scope, stated plainly
//
// The counters are per process. Two instances behind a load balancer each
// enforce their own limits and hold their own denylist, so a limit is
// effectively multiplied by the instance count and a revocation only takes
// effect on the instance that recorded it. That is exactly why the port exists;
// a multi-instance deployment configures the shared backend instead. This type
// must not be presented as safe for multi-instance use.
type MemoryStore struct {
	// now is the clock, injected so expiry boundaries are testable without
	// sleeping. It is never nil after construction.
	now func() time.Time

	// mu guards every field below. One mutex, not a sharded or lock-free
	// scheme: correctness of the read-modify-write in Increment is the entire
	// point of this type, and a plain mutex is the version that is obviously
	// correct on inspection. If contention ever shows up in a profile, the fix
	// is sharding by key hash, with each shard keeping this same discipline.
	mu sync.Mutex

	entries map[string]entry

	// ops counts mutating operations since the last sweep; see sweepInterval.
	ops int
}

// entry is one live counter. expiresAt is absolute so that a stored TTL cannot
// be silently refreshed by a later write.
type entry struct {
	value     int64
	expiresAt time.Time
}

// NewMemoryStore returns an empty MemoryStore reading time from now.
//
// A nil clock is refused rather than defaulted to time.Now. A store with no
// working clock cannot expire anything, which turns a rate-limit bucket into a
// permanent lockout and a denylist into a list that never releases; that is a
// wiring bug and it should stop the process at startup, not degrade quietly.
func NewMemoryStore(now func() time.Time) (*MemoryStore, error) {
	if now == nil {
		return nil, fmt.Errorf("counter: nil clock: %w", domain.ErrInvalidInput)
	}
	return &MemoryStore{now: now, entries: make(map[string]entry)}, nil
}

// Increment implements Store.
//
// The whole read-modify-write runs under one lock acquisition, which is what
// satisfies the port's atomicity requirement: no other goroutine can observe or
// interleave with the intermediate state, so N concurrent increments produce N.
// Splitting this into a Get followed by a Set -- even with each half locked --
// is the under-counting bug the port documents, and it would still pass every
// single-goroutine test.
func (s *MemoryStore) Increment(ctx context.Context, key string, delta int64, ttl time.Duration) (Count, error) {
	if err := validKey(key); err != nil {
		return Count{}, err
	}
	if delta <= 0 {
		return Count{}, fmt.Errorf("counter: delta must be positive: %w", domain.ErrInvalidInput)
	}
	if ttl <= 0 {
		return Count{}, fmt.Errorf("counter: ttl must be positive: %w", domain.ErrInvalidInput)
	}
	if err := ctx.Err(); err != nil {
		// A cancelled context is a store that cannot answer, not a zero count.
		// Reporting it as unavailable is what lets the denylist deny on it.
		return Count{}, fmt.Errorf("counter: %w: %w", ErrStoreUnavailable, err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now()
	e, ok := s.entries[key]
	if !ok || !now.Before(e.expiresAt) {
		// Absent, or present but expired. An expired entry is replaced rather
		// than added to: its value belongs to a window that has closed, and
		// carrying it forward would let a caller's spent attempts follow it
		// into the next window forever.
		e = entry{value: 0, expiresAt: now.Add(ttl)}
	}
	// The expiry of a live entry is deliberately not touched, which is what
	// makes the window fixed rather than sliding; see Store.
	e.value += delta
	s.entries[key] = e

	s.sweepLocked(now)
	return Count{Value: e.value, TTL: e.expiresAt.Sub(now)}, nil
}

// Get implements Store.
func (s *MemoryStore) Get(ctx context.Context, key string) (Count, error) {
	if err := validKey(key); err != nil {
		return Count{}, err
	}
	if err := ctx.Err(); err != nil {
		return Count{}, fmt.Errorf("counter: %w: %w", ErrStoreUnavailable, err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now()
	e, ok := s.entries[key]
	// An expired entry reads as absent even before a sweep removes it, so the
	// answer never depends on when the sweep last ran.
	if !ok || !now.Before(e.expiresAt) {
		return Count{}, nil
	}
	return Count{Value: e.value, TTL: e.expiresAt.Sub(now)}, nil
}

// Delete implements Store.
func (s *MemoryStore) Delete(ctx context.Context, key string) error {
	if err := validKey(key); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("counter: %w: %w", ErrStoreUnavailable, err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.entries, key)
	s.sweepLocked(s.now())
	return nil
}

// Len returns the number of entries currently resident, expired-but-not-yet-
// swept ones included.
//
// It exists so that the bound on memory is an assertable property rather than a
// claim in a comment: a test can show that a store driven past a TTL releases
// its entries instead of merely reporting them absent. It is also the natural
// gauge to export as a metric.
func (s *MemoryStore) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.entries)
}

// Sweep drops every expired entry and returns how many it removed. The
// amortized sweep in Increment and Delete calls the same code; this is the
// explicit trigger, for an operator-facing maintenance hook and for tests.
func (s *MemoryStore) Sweep() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	before := len(s.entries)
	s.purgeLocked(s.now())
	return before - len(s.entries)
}

// sweepLocked runs a purge every sweepInterval mutating operations. The counter
// is reset even when nothing was expired, so a store full of live keys does not
// rescan itself on every subsequent operation.
func (s *MemoryStore) sweepLocked(now time.Time) {
	s.ops++
	if s.ops < sweepInterval {
		return
	}
	s.ops = 0
	s.purgeLocked(now)
}

// purgeLocked removes every entry that has expired at now. The caller holds mu.
func (s *MemoryStore) purgeLocked(now time.Time) {
	for k, e := range s.entries {
		if !now.Before(e.expiresAt) {
			delete(s.entries, k)
		}
	}
}

// validKey rejects the keys no store accepts; see ErrInvalidKey.
func validKey(key string) error {
	if key == "" {
		return fmt.Errorf("counter: empty key: %w: %w", ErrInvalidKey, domain.ErrInvalidInput)
	}
	return nil
}

// Compile-time proof that MemoryStore satisfies the port.
var _ Store = (*MemoryStore)(nil)
