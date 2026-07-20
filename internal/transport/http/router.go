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
// opts carry the authenticated management surface. They are variadic rather
// than positional parameters because the management dependencies are optional
// to an embedder serving only the publish path, and because a nil-able
// parameter that MUST be supplied in production is a worse shape than an option
// whose absence has one loud, fail-closed meaning -- see managementGuardian.
func NewHandler(cfg *config.Config, logger *slog.Logger, pinger Pinger, publisher Publisher, opts ...HandlerOption) http.Handler {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}

	var o handlerOptions
	for _, opt := range opts {
		if opt != nil {
			opt(&o)
		}
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

	// The served helper installer (ADR-0013, ADR-0029). Registered
	// unconditionally and consulting the exposure setting per request: when
	// installs are disabled both routes answer with http.NotFound, which is the
	// identical response the mux itself gives an unregistered path, so probing
	// a locked-down deployment reveals nothing -- not even that the feature
	// exists to be turned off.
	//
	// Two hard-coded two-segment literals, one per artifact. There is
	// deliberately no /install/{name}: a path segment that selects the file
	// turns the one endpoint whose output operators execute into a traversal
	// surface. Being literals, they are strictly more specific than
	// GET /{handle}/{set} and register alongside it without conflict -- the
	// subtree form "GET /install/" would not, since a subtree pattern and a
	// two-wildcard pattern are incomparable and the mux panics on that pair.
	install := installEnabled(cfg)
	mux.Handle("GET /install/vallet-helper.sh", installScriptHandler(install))
	mux.Handle("GET /install/vallet-helper.sh.sha256", installDigestHandler(install))

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

	// The authenticated management surface.
	//
	// Every one of these goes through guardian.Protect, which is the only way
	// to obtain a handler that receives an *auth.Authorization, and therefore
	// the only way any of them can reach an owner at all. A route added here
	// without Protect would not compile against ScopedHandler, so "forgot to
	// protect it" is not a shape this table can take.
	//
	// They live under the "api" prefix, which ADR-0017 reserves as a routing
	// term precisely so it can never be claimed as a handle. That also keeps
	// them clear of the publish wildcards above, which match only one- and
	// two-segment GETs.
	//
	// The route-level access declarations are the scope boundary:
	// AccountAccess names no resource, so a device-bound token cannot reach the
	// account-wide list or the register endpoint; DeviceAccess names the device
	// from the path, so a device-bound token reaches only its own device. Both
	// are checked by auth.Guard before any handler runs and before any storage
	// is read.
	//
	// Rate limiting: ADR-0023 keys the management tier per credential rather
	// than per IP. The tiered limiter is I1 (PR #44) and is not on develop yet,
	// so the tier is deliberately not mounted here rather than vendored. This
	// is the seam: once #44 lands, the management tier wraps these three
	// registrations and nothing else about them changes.
	guardian := managementGuardian(o.authorizer, logger)
	mux.Handle("POST /api/v1/devices", guardian.Protect(AccountAccess, registerDeviceHandler(o.devices, logger)))
	mux.Handle("GET /api/v1/devices", guardian.Protect(AccountAccess, listDevicesHandler(o.devices, logger)))
	mux.Handle("DELETE /api/v1/devices/{deviceID}",
		guardian.Protect(DeviceAccess, revokeDeviceHandler(o.devices, logger)))

	// The public key routes all declare AccountAccess, including the one that
	// addresses a single key by id. That is not an oversight: auth.ResourceKind
	// has kinds for key sets and devices only, so there is no resource-bound
	// scope a key route could be checked against, and inventing an Access whose
	// kind the auth package does not recognize would be refused by
	// Access.validate rather than enforced. Declaring the account is the
	// conservative reading -- a resource-bound token cannot reach any of these,
	// and a read-only token cannot reach the two mutating ones, because the
	// Guardian derives Mutating from the method.
	mux.Handle("POST /api/v1/keys", guardian.Protect(AccountAccess, addKeyHandler(o.keys, logger)))
	mux.Handle("GET /api/v1/keys", guardian.Protect(AccountAccess, listKeysHandler(o.keys, logger)))
	mux.Handle("DELETE /api/v1/keys/{keyID}",
		guardian.Protect(AccountAccess, revokeKeyHandler(o.keys, logger)))

	// The key set routes split their access declarations, and the split is the
	// security decision on this block. Create and list address the account, so
	// they declare AccountAccess and a set-bound token cannot reach them --
	// a token scoped to one set must not be able to mint or enumerate others.
	// Rename and delete address one set, so they declare KeySetAccess, which
	// names the set from the path and lets auth.Guard confine a set-bound token
	// to the set it was issued for.
	//
	// This is deliberately NOT the all-AccountAccess shape the key routes above
	// use. Those have no choice: auth.ResourceKind has no kind for a key. Key
	// sets have auth.ResourceKeySet, so declaring the account here would widen
	// every set-bound token into an account-wide one.
	//
	// PATCH is the rename verb rather than PUT: the request carries the one
	// field it changes, and a PUT would imply the body replaces the resource --
	// inviting a later edit to accept visibility and is_default in it, which are
	// C4's decisions with their own authorization story.
	mux.Handle("POST /api/v1/keysets", guardian.Protect(AccountAccess, createKeySetHandler(o.keySets, logger)))
	mux.Handle("GET /api/v1/keysets", guardian.Protect(AccountAccess, listKeySetsHandler(o.keySets, logger)))
	mux.Handle("PATCH /api/v1/keysets/{keySetID}",
		guardian.Protect(KeySetAccess, renameKeySetHandler(o.keySets, logger)))
	mux.Handle("DELETE /api/v1/keysets/{keySetID}",
		guardian.Protect(KeySetAccess, deleteKeySetHandler(o.keySets, logger)))

	// The two C4 sub-resources split their access declarations for the same
	// reason, and the split is the security decision on this pair.
	//
	// Visibility declares KeySetAccess: the repository's Update is scoped to the
	// addressed row and touches nothing else, so a set-bound token performing it
	// changes only the set it was issued for -- the same blast radius rename has.
	//
	// Default declares AccountAccess even though its path names a set, and that
	// is deliberate. Designating a default also WRITES THE PREVIOUS DEFAULT'S
	// ROW: the repository clears is_default on it in the same transaction. A
	// set-bound token reaching this route would therefore mutate a set it was
	// never scoped to, and would repoint bare GET /{handle} -- account-wide
	// state that belongs to no single set. AccountAccess refuses a
	// resource-bound token before the handler runs, which is the conservative
	// reading and the same one DELETE /api/v1/keys/{keyID} takes.
	//
	// PUT rather than PATCH: each request carries the complete new state of the
	// one thing it addresses, and repeating it is idempotent.
	mux.Handle("PUT /api/v1/keysets/{keySetID}/default",
		guardian.Protect(AccountAccess, setDefaultKeySetHandler(o.keySets, logger)))
	mux.Handle("PUT /api/v1/keysets/{keySetID}/visibility",
		guardian.Protect(KeySetAccess, setVisibilityKeySetHandler(o.keySets, logger)))

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
