package httpserver

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/auth"
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

// newManagementLimiter builds the management tier's limiter, or nil when rate
// limiting is disabled.
//
// It takes the same store as the publish tier rather than building its own.
// One store is what ADR-0023 describes ("the same store backs the auth
// revocation denylist"), and it is also what keeps the tiers honest: the
// Limiter namespaces its keys by tier name, so sharing the store cannot let one
// tier spend another's budget, while two stores would double the memory and
// give an operator two things to reason about where the ADR promises one.
//
// A nil limiter is the documented "disabled" state, exactly as for publish.
func newManagementLimiter(cfg *config.Config, store counter.Store) (*ratelimit.Limiter, error) {
	if store == nil || (cfg != nil && !cfg.RateLimit.Enabled) {
		return nil, nil //nolint:nilnil // A nil limiter is the documented "disabled" state.
	}
	return ratelimit.NewLimiter(store, ratelimit.TierManagement, tiersFromConfig(cfg).Management)
}

// newAdminLimiter builds the ADMIN tier's limiter, or nil when rate limiting is
// disabled.
//
// It shares the one counter store, as the publish and management tiers do, so
// the tier namespacing (ratelimit.TierAdmin) keeps its budget separate without
// a second store to reason about. A nil limiter is the documented "disabled"
// state, exactly as for the other fixed-window tiers.
//
// Unlike the AUTH tier this is an ordinary fixed-window Tier, not failure
// counting: the admin surface authenticates a signed bearer, so there is no
// guessable secret for backoff to defend. The tier fails CLOSED on a
// counter-store outage (DefaultTiers sets Admin.FailOpen false), which is the
// conservative answer for a privileged surface.
func newAdminLimiter(cfg *config.Config, store counter.Store) (*ratelimit.Limiter, error) {
	if store == nil || (cfg != nil && !cfg.RateLimit.Enabled) {
		return nil, nil //nolint:nilnil // A nil limiter is the documented "disabled" state.
	}
	return ratelimit.NewLimiter(store, ratelimit.TierAdmin, tiersFromConfig(cfg).Admin)
}

// adminRateLimit enforces the ADMIN tier on an admin route, keyed by the
// resolved administrator.
//
// # Why keyed by administrator, and why an empty key is not exempt
//
// ADR-0023 keys this tier per authenticated administrator, so one admin's
// automation cannot exhaust another's budget. The key is resolved through the
// same AdminIdentifier the handler authorizes with; a request that resolves to
// no administrator lands in one shared empty-id bucket. That bucket only ever
// holds requests the service is about to refuse as unauthorized anyway, and a
// separate real administrator keeps their own bucket, so the shared bucket
// throttles an anonymous flood without touching a legitimate caller -- the same
// "an unidentifiable caller is refused, never exempt" rule the other tiers take.
//
// # Mounted OUTSIDE the handler, before any work
//
// Unlike the management tier, admin routes do not pass through Guardian.Protect,
// so there is no verified credential to key on inside a ScopedHandler. The
// identity is resolved here from the AdminIdentifier and the limiter runs before
// the body is read, so a refused request costs nothing past the counter check.
//
// A nil limiter is the disabled state and the wrapper is a pass-through. The
// outage policy is read from the decision, never from the error, so the tier's
// configured FailOpen governs -- treating an error as deny would override it.
func adminRateLimit(lim *ratelimit.Limiter, id AdminIdentifier, logger *slog.Logger, next http.Handler) http.Handler {
	if lim == nil {
		return next
	}
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	if id == nil {
		id = denyAllAdminIdentifier{}
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := "admin:" + string(id.AdministratorID(r))
		decision, err := lim.Allow(r.Context(), key)
		if err != nil {
			// A limiter that has stopped limiting must be visible. The admin id
			// is NOT logged: an access log travels far more widely than the
			// request, and this line would otherwise record which administrator
			// acted when.
			level := slog.LevelError
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				level = slog.LevelDebug
			}
			logger.LogAttrs(r.Context(), level, "admin rate limit: counter store unavailable",
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

// managementRateLimit enforces the management tier on an already-authorized
// route.
//
// # Why this is a ScopedHandler decorator and not a Middleware
//
// ADR-0023 keys this tier PER CREDENTIAL, not per IP, and the credential does
// not exist until Guardian.Protect has verified the bearer token. An
// http.Handler middleware wrapped around Protect runs BEFORE that verification,
// so it could only ever key on the source address -- which is the keying the
// ADR explicitly rejects here, because an owner's automation legitimately
// shares one NAT with colleagues who would then throttle each other.
//
// The router's original seam comment said the tier would "wrap these
// registrations", which reads as an outer middleware. That reading is
// incompatible with per-credential keying, so the tier is mounted inside
// Protect instead; ADR-0023 decides this, not the comment.
//
// # Why the key is the credential id
//
// Authorization.CredentialID names the refresh credential the access token was
// minted from, which is the stable lineage: TokenID changes every time a client
// refreshes, so keying on it would hand a caller a budget reset for the cost of
// one refresh. The credential id is a non-guessable random identifier issued by
// this server and is unique across owners, so one owner's traffic can neither
// be attributed to nor exhaust another's -- the isolation comes from the
// identifier's uniqueness rather than from a composite key that would only
// restate it.
//
// # It cannot become an existence oracle
//
// The key is derived from the CALLER's verified credential and from nothing in
// the request path, so the counter a request lands in is identical whether the
// device or key it names exists, belongs to someone else, or was never created.
// The 429 body and headers are the same bytes in every case, and the check runs
// before the handler, so no storage has been consulted when it is written.
//
// # Cardinality is bounded by issued credentials
//
// Only requests that have already passed Protect reach this, so a key can only
// be a credential this server itself issued and has not revoked. An
// unauthenticated caller cannot mint key-space entries at all, which is a
// stronger bound than the publish tier's per-IP keying enjoys; combined with
// the store's fixed-window TTLs and sweeps, resident state is bounded by the
// credentials actually active within one window.
//
// # Outage behavior: fail CLOSED
//
// The decision comes from ratelimit.Tier.FailOpen, which DefaultTiers sets to
// false for this tier. Callers here are authenticated account holders receiving
// a clear 429 with Retry-After, and every mutating route on the surface lives
// behind it, so refusing during a counter-store outage is the conservative half
// of a read-available/write-refused degradation. That is why the branch below
// tests decision.Allowed and never the error: treating "error" as "deny" would
// silently override the tier's configured policy rather than apply it, and the
// same code would then be wrong the day a tier chooses to fail open.
func managementRateLimit(lim *ratelimit.Limiter, logger *slog.Logger) func(ScopedHandler) ScopedHandler {
	return func(next ScopedHandler) ScopedHandler {
		if lim == nil {
			return next
		}
		if logger == nil {
			logger = slog.New(slog.DiscardHandler)
		}

		return func(w http.ResponseWriter, r *http.Request, a *auth.Authorization) {
			key := string(a.CredentialID())
			if key == "" {
				// An Authorization always carries a credential id -- the signer
				// refuses to issue a token without one -- so this is
				// unreachable through Protect. It is a refusal rather than a
				// pass-through anyway: an unattributable caller must never be
				// the one caller exempt from the limit, which is the same rule
				// the per-IP middleware applies to an unresolvable address.
				logger.LogAttrs(r.Context(), slog.LevelWarn, "rate limit: authorization without a credential id",
					slog.String("request_id", RequestIDFromContext(r.Context())))
				writeRateLimited(w, ratelimit.Decision{RetryAfter: lim.Tier().Window})
				return
			}

			decision, err := lim.Allow(r.Context(), key)
			if err != nil {
				// Logged at Error even when the tier keeps serving, because a
				// limiter that has stopped limiting must be visible. Neither
				// the credential nor the owner is logged: an access log travels
				// far more widely than the request, and this line would
				// otherwise turn every 429 into a record of which account was
				// active when.
				//
				// A caller who hung up is the exception, and only when the
				// error IS that cancellation. Testing r.Context().Err()
				// instead would ask a different question -- "did the client
				// go away at some point" -- and a store outage that happens to
				// coincide with a disconnect would be filed at Debug. Under a
				// fail-closed tier that is worth being careful about: refusals
				// make clients disconnect, so the coincidence is correlated
				// with the outage rather than independent of it, and anyone
				// who can cause disconnects could otherwise mute the signal
				// that the limiter has stopped working.
				level := slog.LevelError
				if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
					level = slog.LevelDebug
				}
				logger.LogAttrs(r.Context(), level, "rate limit: counter store unavailable",
					slog.String("request_id", RequestIDFromContext(r.Context())),
					slog.Bool("serving", decision.Allowed),
					slog.String("error", err.Error()))
			}

			if !decision.Allowed {
				writeRateLimited(w, decision)
				return
			}
			next(w, r, a)
		}
	}
}

// newLimitStore builds the IN-PROCESS counter store backing the rate-limit
// tiers. It is the fallback used when the composition root did not inject one
// via WithCounterStore.
//
// The shared (Redis/Valkey with memory failover) store is built and injected by
// cmd/valletd, which owns its lifecycle (the connection pool and reprobe
// goroutine it must Close). Reaching this function with store: shared therefore
// means an embedder mounted NewHandler directly without wiring the shared store;
// it gets the in-process store with a loud warning rather than a silent
// downgrade, because saying nothing would leave an operator believing their
// instances share counters when each is enforcing its own -- which multiplies
// every limit by the instance count.
func newLimitStore(cfg *config.Config, logger *slog.Logger) counter.Store {
	if cfg != nil && !cfg.RateLimit.Enabled {
		return nil
	}
	if cfg != nil && cfg.RateLimit.Store == "shared" && logger != nil {
		logger.LogAttrs(context.Background(), slog.LevelWarn,
			"rate limit: shared counter store not wired into this handler; using in-process counters",
			slog.String("effect", "limits are enforced per instance, not across the deployment"))
	}
	// NewMemoryStore fails only on a nil clock, and the clock here is a
	// constant. The error is discarded explicitly rather than handled, because
	// a branch that cannot be reached is a branch that cannot be tested, and
	// untestable code has no place in a security control.
	store, _ := counter.NewMemoryStore(time.Now)
	return store
}

// authTierIP and authTierApprove are the two AUTH-tier key-space names. They
// derive from ratelimit.TierAuth so the operator's auth-tier configuration
// (limit, window) applies to both, while the distinct suffixes keep the IP-keyed
// credential-minting endpoints and the owner-keyed approval endpoint from
// spending each other's budget. They are constants for the same reason the tier
// names are: a typo would silently create a fresh, unmetered key space.
const (
	authTierIP      = ratelimit.TierAuth + "-ip"
	authTierApprove = ratelimit.TierAuth + "-approve"
)

// newAuthLimiter builds one AUTH-tier limiter (failure counting with backoff)
// under the given key-space name.
//
// # The AUTH tier has no disabled state
//
// The publish and management tiers return a nil limiter when rate limiting is
// switched off, and their callers treat that as "not mounted". The AUTH tier
// does not get that option: it is the ONLY brute-force defense standing in front
// of the credential-check endpoints, and ADR-0023 classes its posture as a
// security invariant rather than a knob -- tiersFromConfig already refuses to
// let an operator flip it fail-open for the same reason. So when no counter
// store is available (an embedder who disabled rate limiting, or one who mounted
// NewHandler without wiring the shared store) this falls back to an in-process
// store rather than returning nil. The failure count may then be per-instance
// rather than deployment-wide, but it is never simply absent, and a route that
// checks it can assume a non-nil limiter.
//
// The name is the key-space prefix, so two limiters built here with different
// names (one keyed by client IP for the un-guarded credential endpoints, one
// keyed by owner for approval) share the store without spending each other's
// budget, exactly as the tier constants do for the other tiers.
func newAuthLimiter(cfg *config.Config, store counter.Store, name string, logger *slog.Logger) (*ratelimit.AuthLimiter, error) {
	if store == nil {
		// NewMemoryStore fails only on a nil clock, which is a constant here.
		store, _ = counter.NewMemoryStore(time.Now)
		if logger != nil {
			logger.LogAttrs(context.Background(), slog.LevelWarn,
				"rate limit: auth tier using in-process counters; brute-force protection is per instance, not deployment-wide",
				slog.String("tier", name))
		}
	}
	return ratelimit.NewAuthLimiter(store, name, tiersFromConfig(cfg).Auth)
}

// authPrecheck runs the AUTH tier's read-only Check for key and reports whether
// the request may proceed to the credential check. On any denial it writes the
// 429 and returns false.
//
// # It fails CLOSED, in two directions
//
// An empty key -- clientIP could not resolve the caller's address -- is refused
// rather than waved through, so the one caller we cannot identify is never the
// one caller exempt from the limit. And AuthLimiter.Check already returns
// Allowed=false when the store will not answer, so a counter-store outage
// refuses logins too: unlike the publish tier this is the only defense against
// an unmetered guessing oracle, and serving one during an incident -- when an
// attacker is the likeliest reason the store is unhealthy -- is the failure this
// posture exists to prevent. The store error is logged (a limiter that has
// stopped limiting must be visible) but never changes the decision, which is
// read straight from Check.
func authPrecheck(w http.ResponseWriter, r *http.Request, lim *ratelimit.AuthLimiter, key string, logger *slog.Logger) bool {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	if key == "" {
		logger.LogAttrs(r.Context(), slog.LevelWarn, "auth rate limit: unresolvable client address",
			slog.String("request_id", RequestIDFromContext(r.Context())))
		writeRateLimited(w, ratelimit.Decision{RetryAfter: lim.Tier().Window})
		return false
	}
	decision, err := lim.Check(r.Context(), key)
	if err != nil {
		// The key is NOT logged: an access log travels far more widely than the
		// request, and naming the caller on every refusal would turn the log into
		// a record of who was active when.
		logger.LogAttrs(r.Context(), slog.LevelError, "auth rate limit: counter store unavailable",
			slog.String("request_id", RequestIDFromContext(r.Context())),
			slog.String("error", err.Error()))
	}
	if !decision.Allowed {
		writeRateLimited(w, decision)
		return false
	}
	return true
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
