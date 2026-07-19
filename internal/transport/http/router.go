package httpserver

import (
	"log/slog"
	"net/http"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/config"
)

// NewHandler builds the complete HTTP handler: the route table wrapped in the
// middleware chain.
//
// It is exported and listener-free so the whole request path can be exercised
// with httptest, and so cmd wiring can construct a handler without committing
// to a socket. A nil logger is replaced with a discarding one rather than
// panicking — losing logs must never be the reason a request fails.
//
// Routing uses the stdlib method-aware ServeMux patterns (Go 1.22+); no
// third-party router is pulled in for two health routes.
//
// cfg supplies transport policy — which peers may be believed about the client
// scheme. It may be nil, which yields the strictest posture (HSTS only on
// connections this process terminated); that is the right default for an
// embedder who has not thought about proxy trust.
func NewHandler(cfg *config.Config, logger *slog.Logger, pinger Pinger) http.Handler {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}

	mux := http.NewServeMux()
	// Method-qualified patterns mean a POST to /healthz is answered with 405
	// by the mux itself; no handler-level method checking is needed.
	mux.Handle("GET /healthz", healthzHandler())
	mux.Handle("GET /readyz", readyzHandler(pinger, logger))

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
