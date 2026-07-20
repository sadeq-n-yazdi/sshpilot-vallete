package httpserver

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/config"
)

// trustedProxies reads the configured reverse-proxy trust list, tolerating a
// nil config: no config means no trusted proxy, which is the correct default
// for a directly-exposed listener.
func trustedProxies(cfg *config.Config) []string {
	if cfg == nil {
		return nil
	}
	return cfg.Server.TrustedProxies
}

// NewHandler builds the complete HTTP handler: the route table wrapped in the
// middleware chain.
//
// It is exported and listener-free so the whole request path can be exercised
// with httptest, and so cmd wiring can construct a handler without committing
// to a socket. A nil logger is replaced with a discarding one rather than
// panicking — losing logs must never be the reason a request fails.
//
// Routing uses the stdlib method-aware ServeMux patterns; no third-party
// router is pulled in for a handful of routes. (Those patterns arrived in Go
// 1.22, which is a note on the feature's history, not a compatibility floor:
// the module requires go 1.26 per go.mod, and CI builds on exactly that.)
//
// cfg supplies transport policy — which peers may be believed about the client
// scheme. It may be nil, which yields the strictest posture (HSTS only on
// connections this process terminated); that is the right default for an
// embedder who has not thought about proxy trust.
func NewHandler(cfg *config.Config, logger *slog.Logger, pinger Pinger, publisher Publisher) http.Handler {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}

	// A limiter that cannot be built is not a reason to refuse to serve: the
	// tiers are validated by config before startup, so a failure here means a
	// programming error rather than an operator one, and the honest response is
	// to serve without the tier and say so loudly. Failing startup instead
	// would convert a limiter bug into a total outage.
	publishLimiter, err := newPublishLimiter(cfg, newLimitStore(cfg, logger))
	if err != nil {
		logger.LogAttrs(context.Background(), slog.LevelError,
			"rate limit: publish tier not mounted", slog.String("error", err.Error()))
	}

	mux := http.NewServeMux()
	// Method-qualified patterns mean a POST to /healthz is answered with 405
	// by the mux itself; no handler-level method checking is needed.
	mux.Handle("GET /healthz", healthzHandler())
	mux.Handle("GET /readyz", readyzHandler(pinger, logger))

	// The publish routes. A "GET" pattern also matches HEAD, so one
	// registration serves both methods and they cannot drift apart.
	//
	// The wildcard patterns are registered alongside the literal health paths
	// without conflict: ServeMux prefers the more specific pattern, so
	// /healthz keeps reaching its own handler and is never treated as a
	// handle. Both publish routes share one handler; the absence of the {set}
	// segment is what selects the owner's default set.
	//
	// The publish tier is applied to the publish routes ONLY, not to the whole
	// mux. /healthz and /readyz must stay unlimited: they are polled by
	// orchestrators at a fixed cadence from a small set of addresses, so a
	// shared limit would let publish traffic starve the liveness probe and get
	// a healthy instance killed mid-incident -- the limiter causing the outage
	// it exists to prevent.
	//
	// It remains keyed purely by IP, so unauthenticated publishing keeps
	// working exactly as ADR-0019 requires.
	pub := chain(publishHandler(publisher, logger),
		rateLimitMiddleware(publishLimiter, newTrustedPeers(trustedProxies(cfg)), logger))
	mux.Handle("GET /{handle}", pub)
	mux.Handle("GET /{handle}/{set}", pub)

	// Outermost first: every response carries the transport policy, then every
	// request gets an ID, then is logged, then is protected from panics.
	//
	// hstsMiddleware is outermost so the header is set before any inner layer
	// can write — including the 500 that recoveryMiddleware writes for a
	// panicking handler, which would otherwise be the one response that escapes
	// without the policy.
	return chain(mux,
		hstsMiddleware(newHSTSPolicy(cfg)),
		requestIDMiddleware,
		loggingMiddleware(logger),
		recoveryMiddleware(logger),
	)
}
