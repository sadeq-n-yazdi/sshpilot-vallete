package httpserver

import "net/http"

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

// hstsMiddleware sets HSTS on every response.
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
// The header is set on the way IN rather than after the handler runs, because
// headers must reach the map before anything is written; a handler that streams
// a body or panics mid-response would otherwise ship without the policy. Setting
// it unconditionally also means error and 404 responses carry it, which matters
// because a redirect or error page is exactly what a probing client hits first.
//
// Scope note: HSTS is a browser mechanism. vallet's publish clients (curl,
// AuthorizedKeysCommand) ignore it entirely, so this protects the admin/browser
// surface and nothing else — it is not a substitute for those clients being
// configured with https URLs. Emitting it in development is harmless: RFC 6797
// §8.1 requires user agents to IGNORE the header when the connection has any
// certificate error, so a self-signed dev instance cannot pin a developer's
// browser to localhost.
func hstsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(StrictTransportSecurityHeader, hstsValue)
		next.ServeHTTP(w, r)
	})
}
