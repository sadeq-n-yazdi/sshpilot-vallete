// Package ratelimit implements the tiered rate limiting of ADR-0023 on top of
// the shared counter store (internal/counter).
//
// Two shapes live here, because the ADR's tiers are not all the same thing:
//
//   - Limiter counts REQUESTS in a fixed window and refuses the ones over the
//     limit. It backs the publish, management and admin tiers, which differ from
//     each other only in their numbers and in what they key on.
//   - AuthLimiter counts FAILURES with exponential backoff, and is cleared by a
//     success. It backs the auth/enrollment tier, where the thing worth limiting
//     is a wrong guess rather than a request; see backoff.go.
//
// # Tiers are configuration, not constants
//
// Every number the ADR gives is a starting default (ADR-0023: "all
// config-tunable"). Nothing in this package hardcodes a limit at a call site;
// DefaultTiers supplies the defaults and an operator replaces them wholesale.
//
// # Keys are namespaced, never concatenated raw
//
// One counter.Store backs every tier and also the ADR-0018 denylist, so a tier
// that used a bare client IP as its key would collide with any other consumer
// that happened to choose the same string. Each Limiter carries a name that
// prefixes its keys, which both separates the tiers and makes a store dump
// self-describing.
package ratelimit

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/counter"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
)

// Tier is the configuration of one rate-limit tier.
//
// The zero value is not usable; NewLimiter rejects it. A limiter that silently
// defaulted a missing limit would be a control that reads as enforced in the
// route table and enforces something nobody chose.
type Tier struct {
	// Limit is the number of requests permitted within one Window. The
	// (Limit+1)th is the first to be refused.
	Limit int64

	// Window is the fixed period the Limit applies to.
	//
	// It is fixed rather than sliding, because counter.Store deliberately does
	// not extend the TTL of a live key: a sliding window would let a caller who
	// keeps attempting hold its own bucket open forever. The cost, accepted
	// here, is the usual fixed-window burst at a boundary -- up to 2*Limit
	// across two adjacent windows. For the traffic these tiers describe (poll
	// pacing, not billing) that is immaterial.
	Window time.Duration

	// FailOpen decides what happens when the counter store cannot answer.
	//
	// This is a real decision and it differs per tier, so it is a required
	// field of the configuration rather than a package-wide policy. See
	// DefaultTiers for the reasoning behind each shipped value; the short
	// version is that a tier defending a security boundary fails CLOSED, and a
	// tier that only sheds load on an availability-critical public path fails
	// OPEN.
	FailOpen bool
}

// validate reports why a tier is unusable, or nil.
func (t Tier) validate() error {
	if t.Limit <= 0 {
		return fmt.Errorf("ratelimit: limit must be positive: %w", domain.ErrInvalidInput)
	}
	if t.Window <= 0 {
		return fmt.Errorf("ratelimit: window must be positive: %w", domain.ErrInvalidInput)
	}
	return nil
}

// Decision is the outcome of one limit check.
type Decision struct {
	// Allowed reports whether the request may proceed.
	Allowed bool

	// RetryAfter is how long the caller should wait before retrying. It is
	// meaningful only when Allowed is false, and it is the ACTUAL remaining
	// life of the caller's window rather than a constant -- a caller refused
	// one second into a minute-long window is told 59s, not 60s.
	RetryAfter time.Duration

	// Count is the caller's request count including this one, and Limit is the
	// tier's limit. Both are reported so a caller can emit RateLimit-* headers
	// or a metric without a second round trip.
	Count int64
	Limit int64
}

// RetryAfterSeconds renders RetryAfter as an RFC 9110 delta-seconds value.
//
// The duration is rounded UP. Rounding down would name an instant at which the
// window has not yet rolled over, so a client that obeys the header exactly
// earns a second 429 -- the header would be actively wrong for the only clients
// that honor it. A refusal always reports at least 1, because "Retry-After: 0"
// invites an immediate retry that is certain to fail.
func (d Decision) RetryAfterSeconds() int64 {
	if d.RetryAfter <= 0 {
		return 1
	}
	// Ceiling division. The guard above makes this at least 1 for every
	// reachable input, so there is no second clamp below: an unreachable branch
	// would be untestable code sitting in the middle of a security control.
	return (int64(d.RetryAfter) + int64(time.Second) - 1) / int64(time.Second)
}

// Limiter enforces one request-rate tier against a counter store. It is
// immutable after construction and safe for concurrent use.
type Limiter struct {
	store counter.Store
	tier  Tier
	name  string
}

// NewLimiter builds a Limiter for tier, namespacing its keys under name.
//
// A nil store and an empty name are refused rather than defaulted. Both would
// produce a limiter that mounts cleanly and enforces nothing: a nil store
// panics on first use, and an unnamed tier shares a key space with every other
// unnamed one, so two tiers with different limits would decrement each other's
// budget.
func NewLimiter(store counter.Store, name string, tier Tier) (*Limiter, error) {
	if store == nil {
		return nil, fmt.Errorf("ratelimit: nil counter store: %w", domain.ErrInvalidInput)
	}
	if name == "" {
		return nil, fmt.Errorf("ratelimit: empty tier name: %w", domain.ErrInvalidInput)
	}
	if err := tier.validate(); err != nil {
		return nil, err
	}
	return &Limiter{store: store, tier: tier, name: name}, nil
}

// Tier returns the limiter's configuration.
func (l *Limiter) Tier() Tier { return l.tier }

// Allow records one request against key and reports whether it may proceed.
//
// The increment happens BEFORE the comparison and is never skipped, including
// for a request that is already over the limit. Counting only the requests it
// permits would let a caller who ignores 429s keep its count pinned at the
// limit and never be counted past it, which matters for the auth tier's
// backoff and for any metric derived from these counts.
//
// The returned error is non-nil only when the store failed. Callers MUST branch
// on Decision.Allowed rather than on the error: on a store failure the decision
// already carries the tier's configured fail-open/fail-closed answer, and a
// caller that treated "error" as "deny" would silently override a fail-open
// tier back to fail-closed. The error is returned alongside so it can be
// logged, since a limiter that has stopped limiting must be visible.
func (l *Limiter) Allow(ctx context.Context, key string) (Decision, error) {
	if key == "" {
		// An empty key cannot be attributed to anyone, so every unattributable
		// caller would share one bucket and lock each other out. Refusing is
		// also fail-closed: a keying function that failed must not yield a free
		// pass. This is the same reasoning as counter.ErrInvalidKey.
		return Decision{Allowed: false, RetryAfter: l.tier.Window, Limit: l.tier.Limit},
			fmt.Errorf("ratelimit: empty key for tier %q: %w", l.name, domain.ErrInvalidInput)
	}

	count, err := l.store.Increment(ctx, l.key(key), 1, l.tier.Window)
	if err != nil {
		return l.storeFailure(err), err
	}

	if count.Value > l.tier.Limit {
		return Decision{
			Allowed:    false,
			RetryAfter: count.TTL,
			Count:      count.Value,
			Limit:      l.tier.Limit,
		}, nil
	}
	return Decision{Allowed: true, Count: count.Value, Limit: l.tier.Limit}, nil
}

// Reset clears key's count. It is the success path for tiers that have one, and
// a no-op for a key that was never counted.
func (l *Limiter) Reset(ctx context.Context, key string) error {
	if key == "" {
		return fmt.Errorf("ratelimit: empty key for tier %q: %w", l.name, domain.ErrInvalidInput)
	}
	return l.store.Delete(ctx, l.key(key))
}

// storeFailure applies the tier's fail-open/fail-closed policy.
//
// A fail-closed tier reports a full Window as Retry-After. It cannot know how
// long the outage will last, and the window is the only bound it has that is
// not invented; naming a shorter one would just concentrate retries.
func (l *Limiter) storeFailure(err error) Decision {
	_ = err // The caller logs it; the policy below does not depend on which failure it was.
	if l.tier.FailOpen {
		return Decision{Allowed: true, Limit: l.tier.Limit}
	}
	return Decision{Allowed: false, RetryAfter: l.tier.Window, Limit: l.tier.Limit}
}

// key namespaces a caller-supplied key under this tier.
func (l *Limiter) key(k string) string { return "rl:" + l.name + ":" + k }

// Unavailable reports whether err is a counter-store outage rather than a
// programming error such as an invalid key. Callers use it to log an outage at
// a louder level than a rejected request.
func Unavailable(err error) bool { return errors.Is(err, counter.ErrStoreUnavailable) }
