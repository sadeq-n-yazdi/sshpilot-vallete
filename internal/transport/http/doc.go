// Package httpserver is the HTTPS transport for the sshpilot-vallet backend:
// the router, the middleware chain, the health endpoints, and the TLS-only
// server that ties them together.
//
// # Why HTTPS only
//
// Vallet publishes and manages SSH public keys. A plaintext listener would let
// a network attacker substitute the key material a client is about to trust,
// which is the exact failure this service exists to prevent. There is therefore
// no plaintext listener and no opportunistic upgrade path: the server serves
// TLS or it does not serve at all, and TLS 1.2 is the floor (ADR-0022's
// tls.min_version can raise it but never lower it).
//
// # Shape
//
// The package separates "build a handler" from "bind a socket" so that almost
// everything is testable without a listener:
//
//   - [NewHandler] returns the fully wrapped [net/http.Handler] (routes plus
//     middleware) and is exercised with httptest.
//   - [New] builds a [Server] around that handler with hardened
//     [net/http.Server] timeouts and a [crypto/tls.Config]; only the final
//     ListenAndServe call touches the network.
//
// # Middleware order
//
// The chain is, outermost first: request ID, logging, panic recovery. The
// request ID is outermost because every later layer wants to name the request;
// logging sits outside recovery so that a panicking request is still logged
// with its final (500) status rather than disappearing.
//
// # Logging discipline
//
// The access log records method, route pattern, sanitized path, status,
// duration, and request ID — and nothing else. Query strings, headers, cookies,
// and bodies routinely carry tokens and are never logged; the log is treated as
// a lower-trust sink than the request itself.
package httpserver
