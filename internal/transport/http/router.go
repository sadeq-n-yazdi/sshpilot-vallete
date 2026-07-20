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
	// The self-served API contract (ADR-0021). These are registered
	// unconditionally and consult the exposure setting per request; when docs
	// are disabled every one of them answers with http.NotFound, which is the
	// identical response the mux itself gives an unregistered path. A scanner
	// therefore learns nothing from probing /docs on a locked-down deployment
	// — not even that the feature exists to be disabled.
	//
	// /docs/ is anchored with {$} so it matches that exact path and nothing
	// beneath it. The plain "GET /docs/" subtree form cannot be used: it
	// overlaps GET /{handle}/{set} with neither pattern more specific, which
	// the mux rejects at registration.
	docs := docsEnabled(cfg)
	mux.Handle("GET /docs", docsRedirectHandler(docs))
	mux.Handle("GET /docs/{$}", docsRootHandler(docs))
	// Fixed URLs for tooling that wants a deterministic path rather than a
	// negotiation. One route per representation, hard-coded: no path segment
	// selects the document, so there is nothing here to traverse.
	mux.Handle("GET /docs/spec/openapi.json", docsSpecHandler(docs, mediaJSON))
	mux.Handle("GET /docs/spec/openapi.yaml", docsSpecHandler(docs, mediaYAML))

	pub := publishHandler(publisher, logger)
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
