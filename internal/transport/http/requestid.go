package httpserver

import (
	"context"
	"crypto/rand"
)

// RequestIDHeader is the header carrying the correlation ID, both inbound
// (from a trusted proxy) and outbound (always set on the response).
const RequestIDHeader = "X-Request-Id"

// maxRequestIDLen bounds an accepted inbound ID. An unbounded ID would let a
// client inflate every log line for its requests; 128 is far above what any
// real tracing system emits.
const maxRequestIDLen = 128

// requestIDContextKey is the unexported context key type for the request ID.
// Using a private zero-size struct type (rather than a string) makes collision
// with another package's context value impossible.
type requestIDContextKey struct{}

// ContextWithRequestID returns a copy of ctx carrying id.
func ContextWithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestIDContextKey{}, id)
}

// RequestIDFromContext returns the request ID attached by the request-ID
// middleware, or "" when there is none. Callers must tolerate "": handlers
// invoked outside the chain (unit tests, internal calls) have no ID.
func RequestIDFromContext(ctx context.Context) string {
	id, _ := ctx.Value(requestIDContextKey{}).(string)
	return id
}

// safeRequestID reports whether an inbound request ID may be reused.
//
// The ID is echoed into the response header and into every log line for the
// request, which makes it attacker-controlled data flowing into two sinks that
// are parsed by other software. A strict allowlist — non-empty, bounded, and
// limited to [A-Za-z0-9._-] — removes the whole class of injection concerns
// (CR/LF header splitting, JSON/log-format confusion, control characters,
// terminal escapes) without needing to reason about each sink's escaping.
// Anything that does not match is discarded, not sanitized, so no unvalidated
// byte survives.
func safeRequestID(id string) bool {
	if id == "" || len(id) > maxRequestIDLen {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		switch {
		case c >= 'a' && c <= 'z',
			c >= 'A' && c <= 'Z',
			c >= '0' && c <= '9',
			c == '.', c == '_', c == '-':
		default:
			return false
		}
	}
	return true
}

// newRequestID returns a fresh, unguessable request ID.
//
// crypto/rand.Text yields 26 characters of base32 (~130 bits of entropy) drawn
// from [A-Z2-7], which is a subset of the charset safeRequestID accepts, so a
// generated ID always round-trips as a valid one. A CSPRNG is used rather than
// a counter or math/rand so that IDs leak nothing about request volume or
// ordering and cannot be predicted and pre-poisoned into logs.
func newRequestID() string {
	return rand.Text()
}
