package ratelimit

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/counter"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
)

// AuthTier configures the auth/enrollment tier: a failure counter with
// exponential backoff (ADR-0023, "~5 attempts/min with exponential failed-auth
// backoff/lockout").
//
// # Why this is not just a Limiter with small numbers
//
// A flat cap of N per minute is a fixed budget an attacker can spend forever:
// 5/min is 7200 guesses a day, every day, at no increasing cost. Backoff
// changes the shape of the attack rather than its rate -- the tenth wrong guess
// costs minutes and the twentieth costs hours, so a sustained campaign becomes
// arithmetically infeasible while a human who mistypes a password twice notices
// nothing. That is why the ADR asks for backoff specifically and why this type
// exists separately.
//
// # The curve: doubling from the window, capped
//
//	lockout(n) = min(Cap, Window * 2^(n-Limit-1))   for n > Limit
//
// Doubling is chosen over a linear or polynomial ramp because it is the only
// common curve where the attacker's total achievable guess count converges: the
// guesses available in time T grow as log(T), so extending an attack from a day
// to a year buys single-digit additional attempts. Linear backoff still permits
// O(sqrt(T)) guesses, which over months is thousands.
//
// The Cap exists because an uncapped exponential is a permanent account
// lockout, which is a denial-of-service an attacker can inflict on a victim by
// guessing wrong on purpose. With the shipped defaults an attacker can hold a
// key locked, but never for longer than Cap, and the legitimate owner is back
// in within that bound without an operator in the loop. Capping is the standard
// trade and it is deliberate: the counter defends against guessing, not against
// a determined nuisance.
type AuthTier struct {
	// Limit is how many failures are free within Window before backoff begins.
	Limit int64

	// Window is the period the free Limit applies to, and the base of the
	// doubling curve.
	Window time.Duration

	// Horizon is how long a failure is remembered for the purpose of computing
	// the backoff level. It is deliberately much longer than Window: if
	// failures were forgotten as fast as the free budget refilled, an attacker
	// pacing themselves just under the limit would never climb the curve at
	// all, which is the exact behavior backoff exists to punish.
	Horizon time.Duration

	// Cap bounds the lockout; see the type comment.
	Cap time.Duration
}

// validate reports why an auth tier is unusable, or nil.
func (t AuthTier) validate() error {
	switch {
	case t.Limit <= 0:
		return fmt.Errorf("ratelimit: auth limit must be positive: %w", domain.ErrInvalidInput)
	case t.Window <= 0:
		return fmt.Errorf("ratelimit: auth window must be positive: %w", domain.ErrInvalidInput)
	case t.Horizon <= 0:
		return fmt.Errorf("ratelimit: auth horizon must be positive: %w", domain.ErrInvalidInput)
	case t.Cap <= 0:
		return fmt.Errorf("ratelimit: auth cap must be positive: %w", domain.ErrInvalidInput)
	case t.Horizon <= t.Cap:
		// A horizon no longer than the cap makes the whole curve escapable, and
		// this invariant is enforced rather than documented because the failure
		// is silent. If the failure count can expire while a lockout is still
		// being served, an attacker who simply waits out each lockout finds the
		// count back at zero when they return -- so the backoff resets to its
		// first rung forever and the tier degrades to a flat cap, which is the
		// exact property it exists not to be. The horizon must outlast the
		// longest lockout by enough that waiting is never cheaper than stopping.
		return fmt.Errorf("ratelimit: auth horizon must exceed cap, else backoff resets by waiting: %w",
			domain.ErrInvalidInput)
	}
	return nil
}

// maxShift bounds the exponent so the doubling cannot overflow a
// time.Duration's int64 nanoseconds. 2^62 ns is ~146 years, far beyond any
// sane Cap, so clamping here changes no reachable result -- it only removes the
// possibility that a large failure count wraps the shift around to a NEGATIVE
// duration, which would read as "no lockout" and silently disable the tier.
const maxShift = 62

// lockout returns how long level n should be locked out for, or zero if n is
// within the free limit.
func (t AuthTier) lockout(n int64) time.Duration {
	if n <= t.Limit {
		return 0
	}
	shift := n - t.Limit - 1
	if shift > maxShift {
		return t.Cap
	}
	d := t.Window << uint(shift)
	// A negative result means the shift overflowed despite the clamp (a very
	// large Window); treat it as the cap rather than as no lockout.
	if d <= 0 || d > t.Cap {
		return t.Cap
	}
	return d
}

// AuthLimiter is the auth tier: failure counting with exponential backoff.
//
// # It is outcome-coupled, so it is not a middleware
//
// This type is driven by the auth handler around the credential check --
// Check before, then RecordFailure or RecordSuccess after -- rather than
// wrapping it transparently. It has to be: a limiter that counted requests
// could not tell a correct login from a wrong one, so a legitimate user would
// climb the same backoff curve as an attacker, and the tier would lock out the
// people it exists to protect.
//
// It is immutable after construction and safe for concurrent use.
type AuthLimiter struct {
	store counter.Store
	tier  AuthTier
	name  string
}

// NewAuthLimiter builds an AuthLimiter. A nil store or empty name is refused
// for the same reasons as in NewLimiter.
func NewAuthLimiter(store counter.Store, name string, tier AuthTier) (*AuthLimiter, error) {
	if store == nil {
		return nil, fmt.Errorf("ratelimit: nil counter store: %w", domain.ErrInvalidInput)
	}
	if name == "" {
		return nil, fmt.Errorf("ratelimit: empty tier name: %w", domain.ErrInvalidInput)
	}
	if err := tier.validate(); err != nil {
		return nil, err
	}
	return &AuthLimiter{store: store, tier: tier, name: name}, nil
}

// Tier returns the limiter's configuration.
func (a *AuthLimiter) Tier() AuthTier { return a.tier }

// Check reports whether key may attempt an authentication right now.
//
// It reads state and records nothing, so a caller that checks and then never
// attempts has not spent anything.
//
// # This tier fails CLOSED
//
// If the store cannot answer, the attempt is REFUSED. The publish tier makes
// the opposite choice, and the difference is the point: failing open here
// re-opens the unlimited brute-force window that this tier is the only defense
// against, and it does so precisely during an incident, when an attacker is
// most likely to be the reason the store is unhealthy. Refusing logins during a
// counter-store outage is a visible, bounded degradation; serving an
// unmetered credential-guessing oracle is not.
//
// This matches the fail-closed rule the denylist applies to the same store
// (see counter.ErrStoreUnavailable), which is the other control where "the
// store did not answer" must never read as "nothing was recorded".
func (a *AuthLimiter) Check(ctx context.Context, key string) (Decision, error) {
	if key == "" {
		return Decision{Allowed: false, RetryAfter: a.tier.Window, Limit: a.tier.Limit},
			fmt.Errorf("ratelimit: empty key for tier %q: %w", a.name, domain.ErrInvalidInput)
	}

	failures, err := a.store.Get(ctx, a.failKey(key))
	if err != nil {
		return Decision{Allowed: false, RetryAfter: a.tier.Window, Limit: a.tier.Limit}, err
	}
	if failures.Value <= a.tier.Limit {
		return Decision{Allowed: true, Count: failures.Value, Limit: a.tier.Limit}, nil
	}

	// Over the free limit: a lockout key for the current level decides. Its own
	// TTL is the remaining lockout, so Retry-After is read from the store
	// rather than recomputed against a clock this type does not have.
	lock, err := a.store.Get(ctx, a.lockKey(key, failures.Value))
	if err != nil {
		return Decision{Allowed: false, RetryAfter: a.tier.Window, Limit: a.tier.Limit}, err
	}
	if lock.Value == 0 {
		// The lockout for this level has elapsed. The failure count survives it
		// (Horizon outlives any single lockout), so the NEXT failure escalates
		// to a longer one instead of restarting the curve.
		return Decision{Allowed: true, Count: failures.Value, Limit: a.tier.Limit}, nil
	}
	return Decision{
		Allowed:    false,
		RetryAfter: lock.TTL,
		Count:      failures.Value,
		Limit:      a.tier.Limit,
	}, nil
}

// RecordFailure counts one failed authentication and arms the lockout for the
// level it reaches.
//
// # Why the lockout is a per-level key
//
// counter.Store fixes a key's TTL when the key is created and never extends it,
// which is what keeps windows from sliding. An escalating lockout therefore
// cannot be expressed by re-arming one key with a longer TTL. Encoding the
// level INTO the key name means each escalation creates a genuinely new key
// whose TTL is longer than the last -- the escalation rides the store's
// existing semantics instead of needing an extension operation the port
// deliberately does not offer.
func (a *AuthLimiter) RecordFailure(ctx context.Context, key string) (Decision, error) {
	if key == "" {
		return Decision{Allowed: false, RetryAfter: a.tier.Window, Limit: a.tier.Limit},
			fmt.Errorf("ratelimit: empty key for tier %q: %w", a.name, domain.ErrInvalidInput)
	}

	failures, err := a.store.Increment(ctx, a.failKey(key), 1, a.tier.Horizon)
	if err != nil {
		return Decision{Allowed: false, RetryAfter: a.tier.Window, Limit: a.tier.Limit}, err
	}

	lockout := a.tier.lockout(failures.Value)
	if lockout == 0 {
		return Decision{Allowed: true, Count: failures.Value, Limit: a.tier.Limit}, nil
	}

	lock, err := a.store.Increment(ctx, a.lockKey(key, failures.Value), 1, lockout)
	if err != nil {
		return Decision{Allowed: false, RetryAfter: lockout, Limit: a.tier.Limit}, err
	}
	return Decision{
		Allowed:    false,
		RetryAfter: lock.TTL,
		Count:      failures.Value,
		Limit:      a.tier.Limit,
	}, nil
}

// RecordSuccess clears the failure count after a correct authentication.
//
// Only the failure counter is deleted; an armed lockout key is left to expire.
// That is deliberate rather than an oversight -- with the count back at zero
// the lockout key for that level is unreachable, and deleting it would let a
// caller who guesses a SECOND credential correctly mid-lockout clear a penalty
// earned against the first.
func (a *AuthLimiter) RecordSuccess(ctx context.Context, key string) error {
	if key == "" {
		return fmt.Errorf("ratelimit: empty key for tier %q: %w", a.name, domain.ErrInvalidInput)
	}
	return a.store.Delete(ctx, a.failKey(key))
}

// failKey and lockKey namespace this tier's two key spaces.
func (a *AuthLimiter) failKey(k string) string { return "rl:" + a.name + ":f:" + k }

func (a *AuthLimiter) lockKey(k string, level int64) string {
	return "rl:" + a.name + ":l" + strconv.FormatInt(level, 10) + ":" + k
}
