// Package counter defines the shared counter-store port and an in-process
// implementation of it.
//
// One store backs two consumers (ADR-0023): the rate limiter, which counts
// attempts per key inside a window, and the auth revocation denylist
// (ADR-0018), which records "this identifier is dead" until the access-token
// TTL makes the record redundant. Both are the same primitive -- a number
// attached to a key that disappears on its own -- so they share one interface
// and one backing store rather than each growing its own, which would mean two
// things to configure, two to monitor, and two to keep coherent across
// instances.
//
// # Keys are opaque
//
// A key is an opaque string chosen by the caller, and the store attaches no
// meaning to it. In particular this port has no ownerID parameter and does not
// use domain.ErrNotFound, which is a deliberate departure from the
// internal/repository convention: those exist to enforce the owner boundary on
// owner-owned rows (ADR-0004), and there are no rows here. A counter is not
// owned by anyone; whatever scoping a consumer needs -- per owner, per IP, per
// credential -- it encodes into the key itself, where this package cannot
// weaken it. Callers that build keys from identifiers should derive them rather
// than concatenate them, so that a store dump does not enumerate which owners
// or credentials the system has acted on; see auth.denylistKey.
//
// # No clock
//
// Like the rest of the codebase, expiry decisions take an explicit time rather
// than reading a clock, so behavior at a boundary is testable without waiting
// for one. The port expresses this as a relative TTL, and implementations are
// responsible for their own now; MemoryStore takes its clock as a constructor
// argument for that reason.
package counter

import (
	"context"
	"errors"
	"time"
)

// ErrInvalidKey is returned for a key a store will not accept: currently only
// the empty string.
//
// An empty key is refused rather than tolerated because of what it would mean
// to the consumers. A rate limiter that fails to derive a client key and passes
// "" would count every unidentified caller into one bucket, so one client's
// traffic locks out all of them. A denylist that stored "" would hold an entry
// matching nothing while looking like a successful revocation. Both are worse
// than an error the caller must handle.
var ErrInvalidKey = errors.New("counter: invalid key")

// ErrStoreUnavailable is returned when a store cannot answer -- a network
// backend that is down, a timeout, a closed store.
//
// It exists so a consumer can distinguish "the count is zero" from "there is no
// count to be had", which is the distinction the denylist's fail-closed rule
// turns on. Implementations wrap it rather than returning it bare, so the cause
// survives for logs while errors.Is still identifies the class.
var ErrStoreUnavailable = errors.New("counter: store unavailable")

// Count is the state of one key: its current value and how long that value has
// left to live.
type Count struct {
	// Value is the counter's value; zero for a key that is absent or expired.
	Value int64
	// TTL is the time remaining before the key expires, and is zero whenever
	// Value is zero. A rate limiter reports it as Retry-After, which is why it
	// is returned by Increment rather than requiring a second round trip: on a
	// network-backed store, the answer to "are you over the limit" and "for how
	// long" must come from one atomic operation, or the second read can observe
	// a window that the first one's increment has already rolled over.
	TTL time.Duration
}

// Store is the shared counter port. Implementations must be safe for concurrent
// use by multiple goroutines.
//
// # Required atomicity
//
// Increment MUST apply the read, the addition and the write as one indivisible
// operation with respect to every other operation on the same key, and MUST
// return the value that results from its own addition.
//
// This is the whole security value of the interface and it is stated as a
// requirement rather than left to an implementer's judgment. A limiter built on
// a read-then-write increment under-counts under exactly the conditions it
// exists to defend against: N concurrent requests each read the same value v
// and each write v+1, so N attempts register as one, and a burst of parallel
// credential guesses passes a limit that a slow serial attacker would hit. The
// same flaw in the denylist is a revocation that appears to be recorded and is
// not. Neither failure is visible in a passing single-goroutine test, so
// implementations MUST carry a concurrency test under -race; MemoryStore's is
// the reference for what that has to prove.
//
// A distributed implementation therefore cannot use a plain GET/SET pair. On a
// Redis- or Valkey-style backend the operation is a server-side INCRBY together
// with the conditional expiry below, issued as one script or transaction, not
// as two round trips.
//
// # Expiry
//
// The TTL is set when Increment creates a key and is NOT extended by subsequent
// increments of a live key. That is what makes the window fixed: a limiter
// whose window slid forward on every attempt would let a caller who keeps
// attempting hold its own bucket open indefinitely, and a denylist entry whose
// expiry moved on every check would outlive the token it denies for as long as
// anyone kept presenting it.
//
// Implementations MUST make expiry active rather than only lazy: a key that is
// never read again must still stop consuming memory. A store that only drops
// expired keys when they happen to be read grows without bound under the access
// pattern both consumers actually have -- a key per attacker IP, a key per
// revoked credential -- where the great majority of keys are never touched
// again.
type Store interface {
	// Increment atomically adds delta to key and returns the resulting count.
	//
	// If key does not exist (or has expired), it is created with the value
	// delta and the given ttl. If it does exist, its expiry is left alone and
	// ttl is ignored.
	//
	// delta must be positive and ttl must be positive; both consumers only ever
	// count upward within a bounded window, and permitting a negative delta
	// would let a caller talk its own counter back down below a limit. A
	// non-positive value of either returns an error wrapping
	// domain.ErrInvalidInput.
	Increment(ctx context.Context, key string, delta int64, ttl time.Duration) (Count, error)

	// Get returns the current count for key, or the zero Count if the key is
	// absent or expired.
	//
	// An absent key is NOT an error: "no attempts recorded" and "not revoked"
	// are ordinary answers, and modeling them as domain.ErrNotFound would force
	// every caller to treat the common case as an exception -- the shape that
	// invites a caller to collapse "absent" and "failed" into one branch, which
	// on the denylist path is precisely the fail-open bug. An error from Get
	// means the store could not answer, and nothing else.
	Get(ctx context.Context, key string) (Count, error)

	// Delete removes key. Deleting an absent key is not an error.
	//
	// This is the rate limiter's success path -- a correct login clears the
	// failed-attempt count for that account -- and it is deliberately absent
	// from the denylist's vocabulary: an entry is retracted by expiring, never
	// by being deleted early.
	Delete(ctx context.Context, key string) error
}
