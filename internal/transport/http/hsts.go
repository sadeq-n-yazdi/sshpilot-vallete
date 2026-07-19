package httpserver

import (
	"net/http"
	"strings"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/config"
)

// StrictTransportSecurityHeader is the HSTS response header name (RFC 6797).
const StrictTransportSecurityHeader = "Strict-Transport-Security"

// hstsMaxAge is the HSTS max-age, in seconds: one year.
//
// One year is the value the major preload programs require and the value the
// web has converged on. The reasoning for a LONG max-age is that HSTS only
// protects a client that has already seen the header once — the window it
// closes is "user returns after the policy lapsed", so a short max-age reopens
// the very hole the header exists to close. A year is also long enough that the
// policy survives a client that visits the service only occasionally, which is
// the realistic pattern for an admin UI.
//
// The cost of a long max-age is the one an operator feels if they need to stop
// serving HTTPS on the name: browsers will refuse plaintext for up to a year and
// there is no way to reach those clients to tell them otherwise. That cost is
// accepted here because ADR-0015 makes HTTPS-only a permanent property of this
// service, not a phase — there is no future in which this server intends to
// serve plaintext on the same name, so the lock-in commits us to something we
// have already committed to.
const hstsMaxAge = 31536000

// hstsValue is the exact header value sent on every response.
//
// includeSubDomains is INCLUDED. Its blast radius is bounded to names beneath
// the host actually serving this response — a policy set by vallet.example.com
// governs *.vallet.example.com, not example.com or its other children — so it
// covers exactly the namespace this deployment already owns. Including it also
// closes a real attack: without it, an attacker who can spoof DNS for an
// unused sibling name (say assets.vallet.example.com) can serve plaintext there
// and set or read cookies scoped to the parent domain, working around the
// parent's HSTS. Operators who genuinely need a plaintext service under this
// host should give it a different parent, not weaken the transport policy here.
//
// preload is deliberately OMITTED, and this is the significant decision.
//
// The preload token is a request to be baked into browsers' compiled-in HSTS
// lists. Its effects are not ours to accept on the operator's behalf:
//
//   - It is effectively one-way. Removal requires a separate submission and then
//     rides browser release trains to users — months, with no way to expedite
//     for a broken deployment.
//   - It escapes this service. Preloading is submitted per registrable domain
//     and, with includeSubDomains, governs the operator's ENTIRE domain,
//     including hosts that have nothing to do with vallet and may legitimately
//     serve plaintext today.
//   - It cannot be undone by fixing the config. Every other setting in this
//     package stops applying when the operator changes it and restarts; a
//     preload entry persists in browsers that never contact this server again.
//
// A server binary that silently opted its operator's whole domain into that
// would be making an irreversible decision about infrastructure it does not own,
// on the strength of a default. Sending the token also does nothing on its own:
// preloading requires the operator to submit the domain deliberately. So the
// token is withheld, and an operator who wants preloading can pursue it as the
// explicit, informed choice it should be. Adding a config knob for it is
// reasonable future work; hardcoding it is not.
const hstsValue = "max-age=31536000; includeSubDomains"

// forwardedProtoHeader carries the client-side scheme from a reverse proxy.
//
// It is attacker-controlled on any directly-exposed listener. Nothing in this
// package may read it without first establishing, via trustedPeers, that the
// immediate peer is a configured proxy.
const forwardedProtoHeader = "X-Forwarded-Proto"

// hstsPolicy decides whether a given request arrived over secure transport.
//
// It is built once at startup from operator config so that the per-request path
// does no config parsing and no allocation.
type hstsPolicy struct {
	// upstreamTLS is true when the operator has declared that TLS is terminated
	// by a reverse proxy in front of this process (tls.mode: upstream). Only
	// then is a forwarded scheme header meaningful at all.
	upstreamTLS bool

	// proxies are the peers whose forwarded headers may be believed.
	proxies trustedPeers
}

// newHSTSPolicy derives the policy from config. A nil config yields the
// strictest posture: TLS must be terminated in this process, and no forwarded
// header is ever consulted.
func newHSTSPolicy(cfg *config.Config) hstsPolicy {
	if cfg == nil {
		return hstsPolicy{}
	}
	return hstsPolicy{
		upstreamTLS: cfg.TLS.Mode == "upstream",
		proxies:     newTrustedPeers(cfg.Server.TrustedProxies),
	}
}

// requestIsSecure reports whether r reached this server over TLS.
//
// Two ways to be secure, and no third:
//
//  1. r.TLS is set — TLS was terminated by this process. Unforgeable: it is
//     populated by net/http from the actual connection, not from any header.
//  2. The operator runs in upstream-termination mode, the immediate peer IS a
//     configured trusted proxy, and that proxy reports https.
//
// The ordering matters and is deliberate. The forwarded header is not consulted
// AT ALL unless both preconditions hold — it is not read and then overridden,
// not read and preferred-against, but never read. A header that is never read
// cannot be spoofed into meaning anything, and the alternative ("read it, but
// trust r.TLS more") still lets an attacker steer behavior in exactly the case
// where r.TLS is absent, which is the case this function exists to judge.
//
// This is the same trust rule that must govern X-Forwarded-For when rate
// limiting lands; see trustedPeers.
//
// The header value must be exactly "https" (case-insensitive). A comma-joined
// list such as "https, http" is REFUSED rather than parsed for its first
// element: a list means hops we have not vetted contributed to the value, and
// picking an element out of it would be trusting their assembly of it.
func (p hstsPolicy) requestIsSecure(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	if !p.upstreamTLS || p.proxies.empty() {
		return false
	}
	if !p.proxies.trusts(r.RemoteAddr) {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(r.Header.Get(forwardedProtoHeader)), "https")
}

// hstsMiddleware sets HSTS on responses to requests that arrived over TLS.
//
// Why this exists when the server has no plaintext listener at all: HSTS defends
// the step BEFORE the connection reaches this server. A browser told to visit
// http://vallet.example.com issues a cleartext request that an on-path attacker
// answers — this server never sees it, so refusing plaintext locally cannot
// prevent it. HSTS makes the client upgrade the scheme before any packet leaves,
// which is the only place that attack can be stopped. It additionally converts
// certificate warnings into hard failures, removing the click-through that
// undoes TLS entirely.
//
// The header is WITHHELD on a non-secure request. RFC 6797 §7.2 requires an
// HSTS host not to send the header over non-secure transport, and the reason is
// substantive rather than pedantic: a policy delivered in the clear is a policy
// an on-path attacker could have written, so honoring one would let an attacker
// deny service to a name for a year by injecting a max-age. Under ADR-0015 this
// process binds no plaintext listener, so on the shipped deployment r.TLS is
// always set and the check never fires — but NewHandler is exported and
// embeddable, and a guarantee this important should be stated by the code that
// makes it rather than inherited from how it happens to be mounted.
//
// The header is set on the way IN rather than after the handler runs, because
// headers must reach the map before anything is written; a handler that streams
// a body or panics mid-response would otherwise ship without the policy. Every
// secure response carries it, including errors and 404s, because an error page
// is exactly what a probing client hits first.
//
// Scope note: HSTS is a browser mechanism. vallet's publish clients (curl,
// AuthorizedKeysCommand) ignore it entirely, so this protects the admin/browser
// surface and nothing else — it is not a substitute for those clients being
// configured with https URLs. Emitting it in development is harmless: RFC 6797
// §8.1 requires user agents to IGNORE the header when the connection has any
// certificate error, so a self-signed dev instance cannot pin a developer's
// browser to localhost.
func hstsMiddleware(policy hstsPolicy) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if policy.requestIsSecure(r) {
				w.Header().Set(StrictTransportSecurityHeader, hstsValue)
			}
			next.ServeHTTP(w, r)
		})
	}
}
