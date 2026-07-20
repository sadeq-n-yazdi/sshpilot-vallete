package httpserver

import (
	"context"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/config"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/counter"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/ratelimit"
)

// RetryAfterHeader tells a refused client when to come back (RFC 9110 §10.2.3).
const RetryAfterHeader = "Retry-After"

// tiersFromConfig maps operator configuration onto the limiter's tiers.
//
// Requests and Window come from config, which is what ADR-0023 makes
// tunable and what an operator actually turns. The outage policy
// (fail-open/fail-closed) and the auth backoff constants are taken from
// ratelimit.DefaultTiers: the ADR classes the curve constants as remaining
// tuning work, and the outage policy is a security posture rather than a knob
// -- an operator who could flip the auth tier to fail-open would be
// configuring away the brute-force defense without it being obvious that is
// what they had done.
//
// A nil config yields the defaults, which is the right answer for an embedder
// who has not configured anything: the limits apply.
func tiersFromConfig(cfg *config.Config) ratelimit.Tiers {
	tiers := ratelimit.DefaultTiers()
	if cfg == nil {
		return tiers
	}

	ct := cfg.RateLimit.Tiers
	apply := func(dst *ratelimit.Tier, src config.Tier) {
		// A non-positive value is left at the default rather than applied.
		// Config validation already rejects those, so reaching here with one
		// means validation was bypassed, and the safe reading of a limit we
		// cannot understand is "keep the one we know is sane" -- never "no
		// limit", which is what a zero would mean downstream.
		if src.Requests > 0 {
			dst.Limit = int64(src.Requests)
		}
		if time.Duration(src.Window) > 0 {
			dst.Window = time.Duration(src.Window)
		}
	}
	apply(&tiers.Publish, ct.Publish)
	apply(&tiers.Management, ct.Management)
	apply(&tiers.Admin, ct.Admin)

	if ct.Auth.Requests > 0 {
		tiers.Auth.Limit = int64(ct.Auth.Requests)
	}
	if w := time.Duration(ct.Auth.Window); w > 0 {
		tiers.Auth.Window = w
	}
	return tiers
}

// newPublishLimiter builds the publish tier's limiter, or nil when rate
// limiting is disabled.
//
// A nil limiter is a supported state, not an error: ADR-0023 requires these
// limits be disableable so a deployment behind a trusted external limiter
// (proxy, CDN, WAF) does not enforce twice. rateLimitMiddleware treats nil as
// "not mounted" so the disabled path costs nothing per request.
func newPublishLimiter(cfg *config.Config, store counter.Store) (*ratelimit.Limiter, error) {
	if store == nil || (cfg != nil && !cfg.RateLimit.Enabled) {
		return nil, nil //nolint:nilnil // A nil limiter is the documented "disabled" state.
	}
	return ratelimit.NewLimiter(store, ratelimit.TierPublish, tiersFromConfig(cfg).Publish)
}

// newLimitStore builds the counter store backing the rate-limit tiers.
//
// Only the in-process store exists today. ADR-0023 anticipates a Redis/Valkey-
// style backend for multi-instance deployments, and config already accepts
// store: shared for it; until that adapter lands, a deployment that asks for it
// gets the memory store with a loud warning rather than a silent downgrade.
// Saying nothing would leave an operator believing their instances share
// counters when each is enforcing its own -- which multiplies every limit by
// the instance count.
func newLimitStore(cfg *config.Config, logger *slog.Logger) counter.Store {
	if cfg != nil && !cfg.RateLimit.Enabled {
		return nil
	}
	if cfg != nil && cfg.RateLimit.Store == "shared" && logger != nil {
		logger.LogAttrs(context.Background(), slog.LevelWarn,
			"rate limit: shared counter store not implemented; using in-process counters",
			slog.String("effect", "limits are enforced per instance, not across the deployment"))
	}
	// NewMemoryStore fails only on a nil clock, and the clock here is a
	// constant. The error is discarded explicitly rather than handled, because
	// a branch that cannot be reached is a branch that cannot be tested, and
	// untestable code has no place in a security control.
	store, _ := counter.NewMemoryStore(time.Now)
	return store
}

// rateLimitMiddleware enforces one per-IP tier.
//
// # Keyed by IP, never by identity
//
// The key is clientIP and nothing else. This matters for where it is mounted:
// the publish routes are DELIBERATELY unauthenticated (ADR-0019 -- public sets
// are open, and an AuthorizedKeysCommand fetches them with a bare curl), so a
// limiter that keyed on a credential would either have to require one or fall
// back to a single shared bucket for everyone. Limiting an anonymous caller by
// its source address is the only option that leaves public publishing working.
//
// # An unidentifiable caller is refused
//
// When clientIP cannot resolve an address, the request is refused rather than
// waved through, even on a fail-open tier. The alternative is an exemption
// available to exactly the callers whose origin we understand least, which an
// attacker would reach for first.
func rateLimitMiddleware(lim *ratelimit.Limiter, proxies trustedPeers, logger *slog.Logger) Middleware {
	return func(next http.Handler) http.Handler {
		if lim == nil {
			return next
		}
		if logger == nil {
			logger = slog.New(slog.DiscardHandler)
		}

		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := clientIP(r, proxies)
			if key == "" {
				logger.LogAttrs(r.Context(), slog.LevelWarn, "rate limit: unresolvable client address",
					slog.String("request_id", RequestIDFromContext(r.Context())))
				writeRateLimited(w, ratelimit.Decision{RetryAfter: lim.Tier().Window})
				return
			}

			decision, err := lim.Allow(r.Context(), key)
			if err != nil {
				// A limiter that has stopped limiting must be visible, so this
				// is logged at Error even when the tier's policy is to keep
				// serving. The client address is NOT logged: an access log is
				// retained and shipped far more widely than the request, and
				// this line would otherwise turn every 429 into a record of who
				// was where.
				logger.LogAttrs(r.Context(), slog.LevelError, "rate limit: counter store unavailable",
					slog.String("request_id", RequestIDFromContext(r.Context())),
					slog.Bool("serving", decision.Allowed),
					slog.String("error", err.Error()))
			}

			if !decision.Allowed {
				writeRateLimited(w, decision)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// writeRateLimited sends the 429 with a correct Retry-After.
//
// The header value is derived from the decision -- the actual remaining life of
// the caller's window, rounded up -- rather than being a constant. A constant
// is the easy bug here: it is present, it looks right in a header dump, and it
// is wrong for every request that is not the first in its window.
//
// The body carries no detail. Telling an unauthenticated caller its current
// count, its limit, or which tier it tripped hands an attacker a free
// calibration oracle for pacing a slower campaign under the threshold.
func writeRateLimited(w http.ResponseWriter, d ratelimit.Decision) {
	w.Header().Set(RetryAfterHeader, strconv.FormatInt(d.RetryAfterSeconds(), 10))
	writeJSON(w, http.StatusTooManyRequests, statusResponse{Status: "error"})
}
