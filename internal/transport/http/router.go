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
	//
	// One counter store backs every tier, per ADR-0023. The limiters namespace
	// their own keys by tier name, so sharing it cannot let one tier spend
	// another's budget.
	//
	// The composition root injects the shared (Redis/Valkey with memory
	// failover) store via WithCounterStore; absent that, an in-process store is
	// built here, which is the single-node default and the embedder's.
	limitStore := o.counter
	if limitStore == nil {
		limitStore = newLimitStore(cfg, logger)
	}
	publishLimiter, err := newPublishLimiter(cfg, limitStore)
	if err != nil {
		logger.LogAttrs(context.Background(), slog.LevelError,
			"rate limit: publish tier not mounted", slog.String("error", err.Error()))
	}
	managementLimiter, err := newManagementLimiter(cfg, limitStore)
	if err != nil {
		logger.LogAttrs(context.Background(), slog.LevelError,
			"rate limit: management tier not mounted", slog.String("error", err.Error()))
	}
	adminLimiter, err := newAdminLimiter(cfg, limitStore)
	if err != nil {
		logger.LogAttrs(context.Background(), slog.LevelError,
			"rate limit: admin tier not mounted", slog.String("error", err.Error()))
	}
	// The AUTH tier's two limiters. Unlike the tiers above they have no disabled
	// state (newAuthLimiter falls back to in-process counters rather than nil):
	// they are the only brute-force defense on the credential-check endpoints, so
	// a build failure here leaves them nil and the handlers refuse (fail closed)
	// rather than serve an unmetered guessing oracle. The IP-keyed one guards the
	// un-guarded minting endpoints (redeem, exchange) and gates start/poll; the
	// owner-keyed one guards approval, where the ~40-bit user code must be bounded
	// independently of IP rotation (ADR-0032).
	authIPLimiter, err := newAuthLimiter(cfg, limitStore, authTierIP, logger)
	if err != nil {
		authIPLimiter = nil
		logger.LogAttrs(context.Background(), slog.LevelError,
			"rate limit: auth ip tier unavailable; credential-minting routes will refuse",
			slog.String("error", err.Error()))
	}
	authOwnerLimiter, err := newAuthLimiter(cfg, limitStore, authTierApprove, logger)
	if err != nil {
		authOwnerLimiter = nil
		logger.LogAttrs(context.Background(), slog.LevelError,
			"rate limit: auth owner tier unavailable; approval route will refuse",
			slog.String("error", err.Error()))
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
	// than per IP, so the tier is mounted INSIDE Protect -- mgmt decorates the
	// ScopedHandler, which is the first point at which a verified credential
	// exists. An outer middleware here could only key on the source address,
	// which is the keying the ADR rejects for this surface because an owner's
	// automation shares a NAT with colleagues who would then throttle each
	// other. See managementRateLimit.
	//
	// Every management route below is wrapped, and each wrap is its own call
	// site: dropping mgmt from any one of them fails that route's rate-limit
	// test rather than only the suite's first.
	//
	// The AUTH tier is now mounted: its routes have landed (the enrollment and
	// token-exchange surface below, ADR-0032). It is not a middleware -- the
	// AuthLimiter is failure-counting with backoff and must be driven by the
	// handler around the credential check so a correct credential does not climb
	// the same curve as a guess -- so it is threaded into those handlers rather
	// than wrapped here; see enrollment.go and token.go. The ADMIN tier remains
	// unmounted: no instance-administration authenticator exists yet to key it on.
	guardian := managementGuardian(o.authorizer, logger)
	mgmt := managementRateLimit(managementLimiter, logger)
	mux.Handle("POST /api/v1/devices", guardian.Protect(AccountAccess, mgmt(registerDeviceHandler(o.devices, logger))))
	mux.Handle("GET /api/v1/devices", guardian.Protect(AccountAccess, mgmt(listDevicesHandler(o.devices, logger))))
	mux.Handle("DELETE /api/v1/devices/{deviceID}",
		guardian.Protect(DeviceAccess, mgmt(revokeDeviceHandler(o.devices, logger))))

	// The enrollment and token-issuance surface (ADR-0032, modes 1 and 2).
	//
	// Three of these are deliberately UN-guarded: an unauthenticated client
	// starts a device grant, polls it, and redeems it, so they are plain handlers
	// that carry the AUTH tier keyed by client IP inside themselves. The proxy
	// trust list is the same one the publish tier uses, so an X-Forwarded-For is
	// believed only from a configured proxy. Redeem and exchange are the
	// credential-minting checks and carry the full failure-counting pattern;
	// start and poll only consult the shared IP lockout.
	proxies := newTrustedPeers(trustedProxies(cfg))
	mux.Handle("POST /api/v1/enroll/device", startDeviceGrantHandler(o.enrollment, authIPLimiter, proxies, logger))
	mux.Handle("POST /api/v1/enroll/poll", pollHandler(o.enrollment, authIPLimiter, proxies, logger))
	mux.Handle("POST /api/v1/enroll/redeem", redeemHandler(o.enrollment, authIPLimiter, proxies, logger))
	mux.Handle("POST /api/v1/token", exchangeHandler(o.tokens, authIPLimiter, proxies, nil, logger))

	// Mint and approve are owner actions, so they go through the Guardian (which
	// hands them the verified owner) and the management tier, exactly like the
	// device routes. Approve additionally carries the owner-keyed AUTH limiter for
	// the user-code oracle; mint verifies no guessable secret and needs none.
	// Both declare AccountAccess: enrollment is an account-wide act, so a
	// resource-bound token must not reach it.
	mux.Handle("POST /api/v1/enroll/mint",
		guardian.Protect(AccountAccess, mgmt(mintHandler(o.enrollment, logger))))
	mux.Handle("POST /api/v1/enroll/approve",
		guardian.Protect(AccountAccess, mgmt(approveHandler(o.enrollment, authOwnerLimiter, logger))))

	// The public key routes all declare AccountAccess, including the one that
	// addresses a single key by id. That is not an oversight: auth.ResourceKind
	// has kinds for key sets and devices only, so there is no resource-bound
	// scope a key route could be checked against, and inventing an Access whose
	// kind the auth package does not recognize would be refused by
	// Access.validate rather than enforced. Declaring the account is the
	// conservative reading -- a resource-bound token cannot reach any of these,
	// and a read-only token cannot reach the two mutating ones, because the
	// Guardian derives Mutating from the method.
	mux.Handle("POST /api/v1/keys", guardian.Protect(AccountAccess, mgmt(addKeyHandler(o.keys, logger))))
	mux.Handle("GET /api/v1/keys", guardian.Protect(AccountAccess, mgmt(listKeysHandler(o.keys, logger))))
	mux.Handle("DELETE /api/v1/keys/{keyID}",
		guardian.Protect(AccountAccess, mgmt(revokeKeyHandler(o.keys, logger))))

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
	mux.Handle("POST /api/v1/keysets", guardian.Protect(AccountAccess, mgmt(createKeySetHandler(o.keySets, logger))))
	mux.Handle("GET /api/v1/keysets", guardian.Protect(AccountAccess, mgmt(listKeySetsHandler(o.keySets, logger))))
	mux.Handle("PATCH /api/v1/keysets/{keySetID}",
		guardian.Protect(KeySetAccess, mgmt(renameKeySetHandler(o.keySets, logger))))
	mux.Handle("DELETE /api/v1/keysets/{keySetID}",
		guardian.Protect(KeySetAccess, mgmt(deleteKeySetHandler(o.keySets, logger))))

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
		guardian.Protect(AccountAccess, mgmt(setDefaultKeySetHandler(o.keySets, logger))))
	mux.Handle("PUT /api/v1/keysets/{keySetID}/visibility",
		guardian.Protect(KeySetAccess, mgmt(setVisibilityKeySetHandler(o.keySets, logger))))

	// The reserved-identifier list administration surface (ADR-0017, Fb4).
	//
	// These edit GLOBAL service policy -- which identifiers every owner may
	// claim -- so they are not owner-scoped and do NOT pass through the owner
	// Guardian above. Their authority is an administrator's, resolved by
	// adminID and enforced by the ListAdminService, which authorizes, audits,
	// and persists each edit before it takes effect.
	//
	// Mounted unconditionally, like the owner management routes, so the surface
	// is constant. With no AdminIdentifier wired they run behind
	// denyAllAdminIdentifier and refuse every edit; with no service wired they
	// answer 500. Both are the fail-closed directions, and neither depends on
	// how the process was configured being readable off the route table.
	//
	// The ADMIN rate-limit tier (ADR-0023) keys per authenticated administrator.
	// The reserved-identifier list routes below do not yet attach it; the owner
	// provisioning route does, since it is the first admin route wired to a real
	// AdminIdentifier (ADR-0033) and provisioning is the more consequential act
	// to bound. adminRateLimit resolves the same identity the handler authorizes
	// with, so the tier is keyed on the administrator rather than the source IP.
	adminID := o.adminIdentifier
	if adminID == nil {
		adminID = denyAllAdminIdentifier{}
	}
	mux.Handle("POST /api/v1/admin/reserved/allowlist", addAllowlistEntryHandler(o.listAdmin, adminID, logger))
	mux.Handle("DELETE /api/v1/admin/reserved/allowlist", removeAllowlistEntryHandler(o.listAdmin, adminID, logger))
	mux.Handle("POST /api/v1/admin/reserved/blocklist", addBlocklistTermHandler(o.listAdmin, adminID, logger))
	mux.Handle("DELETE /api/v1/admin/reserved/blocklist", removeBlocklistTermHandler(o.listAdmin, adminID, logger))

	// Admin-provisioned owner onboarding (ADR-0033, Phase-1 decision #14). Like
	// the list routes it is not owner-scoped and does not pass through the owner
	// Guardian; its authority is an administrator's, resolved by adminID and
	// re-checked (active status) by the OwnerOnboardingService before an owner is
	// created. Mounted unconditionally: with no service wired it answers 500,
	// with no AdminIdentifier every request is the empty administrator the
	// service refuses (403). The ADMIN rate-limit tier wraps it.
	mux.Handle("POST /api/v1/admin/owners",
		adminRateLimit(adminLimiter, adminID, logger, adminCreateOwnerHandler(o.ownerOnboarding, adminID, logger)))

	// Outermost first: every response carries the transport policy, then every
	// request gets an ID, then a span and a metric, then is logged, then is
	// protected from panics.
	//
	// telemetryMiddleware sits INSIDE requestIDMiddleware so the span can carry
	// the correlation ID, and OUTSIDE loggingMiddleware so the span covers the
	// whole handler. It never mounts a route; the scrape endpoint is a separate
	// listener (telemetry.MetricsServer), never a path on this mux.
	//
	// hstsMiddleware is outermost so the header is set before any inner layer
	// can write — including the 500 that recoveryMiddleware writes for a
	// panicking handler, which would otherwise be the one response that escapes
	// without the policy.
	return chain(mux,
		hstsMiddleware(newHSTSPolicy(cfg)),
		requestIDMiddleware,
		telemetryMiddleware(o.telemetry, o.telemetry.NewInstruments()),
		loggingMiddleware(logger),
		recoveryMiddleware(logger),
	)
}
