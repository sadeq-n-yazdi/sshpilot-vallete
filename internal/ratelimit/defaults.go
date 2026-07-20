package ratelimit

import "time"

// Tier names. They are the key-space prefixes as well as the configuration
// labels, so they are constants rather than strings written at call sites: a
// typo would silently create a fresh, unlimited key space instead of failing.
const (
	TierAuth       = "auth"
	TierPublish    = "publish"
	TierManagement = "mgmt"
	TierAdmin      = "admin"
)

// Tiers is the full set of rate-limit tiers, as ADR-0023 defines them.
//
// It is a struct rather than a map so that a missing tier is a compile error
// instead of a nil lookup that disables a limit at runtime.
type Tiers struct {
	// Auth covers login, enrollment and onboarding/signup. Keyed per-IP and,
	// where the account is known, per-account (ADR-0023).
	Auth AuthTier

	// Publish covers the public GET /{handle}/{set} fetch path. Keyed per-IP.
	Publish Tier

	// Management covers the owner-facing management API. ADR-0023 keys this
	// PER CREDENTIAL, not per IP -- an owner's automation legitimately runs
	// behind one NAT with colleagues, and per-IP keying there would have them
	// throttle each other.
	Management Tier

	// Admin covers instance-administration operations, keyed per admin.
	Admin Tier
}

// DefaultTiers returns the starting defaults of ADR-0023.
//
// These are defaults, not constants: the ADR says every number is
// config-tunable, and nothing in this package reads them except as the base an
// operator's configuration overrides.
func DefaultTiers() Tiers {
	return Tiers{
		// ~5 attempts/min with exponential backoff. The free budget is small
		// because a human logging in needs one attempt and forgives two; the
		// backoff, not the budget, is what defeats a sustained campaign.
		//
		// Cap is an hour so a deliberately-locked-out victim recovers without
		// an operator in the loop. Horizon is a DAY, and must comfortably
		// exceed Cap (AuthTier.validate enforces this): if failures were
		// forgotten while a lockout was still being served, waiting one out
		// would reset the curve to its first rung and the tier would collapse
		// into a flat cap.
		//
		// The curve with these values: failure 6 locks for 1m, 7 for 2m, 8 for
		// 4m ... 11 for 32m, 12 onward capped at 60m. An attacker who serves
		// every lockout gets ~11 guesses in the first hour and ~23 more over
		// the rest of the day, against 5/min of free budget -- while a user who
		// mistypes twice and then succeeds is never delayed at all.
		Auth: AuthTier{
			Limit:   5,
			Window:  time.Minute,
			Horizon: 24 * time.Hour,
			Cap:     time.Hour,
		},

		// ~60 requests/min per IP: one poll per second sustained, which is far
		// above what an AuthorizedKeysCommand or a cron'd curl needs, and the
		// output is TTL-cached anyway (ADR-0019).
		//
		// FAIL OPEN. This is the public read path and the reason the service
		// exists: a counter-store outage that closed it would break every
		// customer's SSH login at once, an outage this limiter inflicted rather
		// than prevented. Failing open degrades to exactly the pre-limiter
		// posture -- still protected by upstream limiters, TTL caching, and the
		// fact that this route reveals only already-public key material -- so
		// the downside is bounded and reversible, while the alternative is a
		// self-inflicted total outage.
		Publish: Tier{Limit: 60, Window: time.Minute, FailOpen: true},

		// ~120 requests/min per credential.
		//
		// FAIL CLOSED. Every request here is authenticated and mutating, so the
		// caller is a known account holder who receives a clear 429 and retries
		// -- there is no anonymous public traffic to break. Refusing writes
		// during a counter-store outage is the conservative half of a
		// read-available/write-refused degradation, which is the standard shape
		// and the one an operator can reason about.
		Management: Tier{Limit: 120, Window: time.Minute, FailOpen: false},

		// ~60 requests/min per admin. FAIL CLOSED, and for a stronger reason
		// than management: these operations change instance-wide security
		// posture, so "the limiter is blind" is never an acceptable state in
		// which to keep serving them.
		Admin: Tier{Limit: 60, Window: time.Minute, FailOpen: false},
	}
}

// Validate reports the first tier that is unusable, or nil.
func (t Tiers) Validate() error {
	if err := t.Auth.validate(); err != nil {
		return err
	}
	if err := t.Publish.validate(); err != nil {
		return err
	}
	if err := t.Management.validate(); err != nil {
		return err
	}
	return t.Admin.validate()
}
