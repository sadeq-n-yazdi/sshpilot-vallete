// Package logging provides the structured-logging layer for valletd (ADR-0025):
// JSON output, a configurable level that fails closed on a bad value, and a
// slog.Handler middleware that redacts secrets before they can be rendered.
//
// The redaction filter is deliberately NOT a courtesy for well-behaved callers.
// internal/secrets already makes a value that is *known* to be a secret safe by
// construction: Redacted and Ref render "[REDACTED]" through every fmt, json,
// yaml and slog path. That covers the disciplined call site. It cannot cover the
// call site that never knew the value was sensitive -- a raw DSN string, a
// bearer token pulled out of a header, a struct with a Password field -- and
// that is precisely where log leaks come from. RedactHandler is the backstop for
// those, and it is fail-closed: a value only survives if something about it was
// affirmatively declared loggable.
//
// # Residual limits
//
// A handler sees values, not the expressions that produced them, so anything
// flattened to a string BEFORE the record is built is past the point where key
// or type policy can act. Two shapes reach that state:
//
//   - a secret interpolated into the message, e.g.
//     log.Info(fmt.Sprintf("auth failed for %s", token));
//   - a struct holding a plain-string secret field, formatted with %v into a
//     string attribute under an allowlisted key.
//
// Both are inherent to any post-format redactor rather than gaps in this one,
// and both are already narrowed from the other side. A secret carried as
// secrets.Redacted or secrets.Ref renders "[REDACTED]" under every fmt verb, so
// the struct case is closed at the type for values the codebase knows are
// secret -- which is exactly the division of labor between these two packages.
// scrubURLCredentials additionally runs over the message and over every
// rendered string, so the highest-value instance of the first shape, a pasted
// connection string, is caught. What remains uncovered is a plain-string secret
// that was never given a secret type and never passed through an attribute; the
// answer to that is secrets.Redacted at the point the value is obtained, not a
// deeper handler.
package logging

import (
	"context"
	"log/slog"
	"strings"
)

// RedactedMarker is the single string every redaction path in this package
// emits. It matches the marker used by internal/secrets so that a log line
// reads identically whether the value was redacted by its own type or by this
// handler.
const RedactedMarker = "[REDACTED]"

// maxDepth bounds group recursion. slog.Value.Resolve already caps LogValuer
// chains, but a deeply nested group tree is still a way to burn CPU inside the
// logger, and anything past this depth is redacted rather than walked -- the
// bound fails closed, like every other branch here.
const maxDepth = 8

// Policy is the redaction engine: the allowlist plus the value rules applied
// to anything that passes it.
//
// It is exported because logs are not the only sink that carries attributes.
// Trace spans (ADR-0025) carry key/value pairs into a telemetry backend that is
// shipped, retained, and read at least as widely as a log stream, and a second
// redaction implementation for that sink would be a second policy — which means
// one of the two is wrong, and nobody finds out which until a value leaks
// through the weaker one. Every sink therefore calls Redact on THIS type, so
// there is exactly one allowlist and exactly one set of value rules in the
// process.
//
// Policy, in order of application:
//
//  1. Groups are recursed into, so nesting cannot be used to escape the filter.
//  2. A leaf attribute whose key is not in the allowlist is replaced wholesale
//     by RedactedMarker.
//  3. An allowlisted key's value must additionally be of a kind that can be
//     rendered safely; anything else is redacted (see leafValue).
//
// The zero value is not usable; construct with NewPolicy.
type Policy struct {
	allow map[string]struct{}
}

// NewPolicy builds the redaction policy from the default allowlist (see
// allowlist.go) plus any extra keys the caller declares.
//
// extraAllowed exists so that a package which emits its own vocabulary can
// widen the policy at the point it is wired up, rather than editing a central
// list from a distance. Widening is always an explicit, reviewable call.
func NewPolicy(extraAllowed ...string) *Policy {
	allow := make(map[string]struct{}, len(defaultAllowedKeys)+len(extraAllowed))
	for _, k := range defaultAllowedKeys {
		allow[k] = struct{}{}
	}
	for _, k := range extraAllowed {
		allow[strings.ToLower(strings.TrimSpace(k))] = struct{}{}
	}
	return &Policy{allow: allow}
}

// Redact applies the policy to one attribute, returning the value that may be
// rendered. It is the entry point every sink shares.
func (p *Policy) Redact(a slog.Attr) slog.Attr { return p.redact(a, 0) }

// RedactHandler is a slog.Handler middleware that filters every attribute
// through a Policy before passing the record to the next handler.
//
// The zero value is not usable; construct with NewRedactHandler.
type RedactHandler struct {
	next   slog.Handler
	policy *Policy
}

// Compile-time proof that the middleware satisfies the interface it wraps.
var _ slog.Handler = (*RedactHandler)(nil)

// NewRedactHandler wraps next with the default allowlist (see allowlist.go),
// plus any extra keys the caller declares.
func NewRedactHandler(next slog.Handler, extraAllowed ...string) *RedactHandler {
	return &RedactHandler{next: next, policy: NewPolicy(extraAllowed...)}
}

// Enabled delegates: level filtering is the wrapped handler's business.
func (h *RedactHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.next.Enabled(ctx, level)
}

// Handle redacts the record's attributes and its message, then forwards it.
//
// The message is scrubbed too. A log message is supposed to be a static string,
// but the realistic slip is fmt.Sprintf("connect to %s: %v", dsn, err) -- the
// attribute filter never sees that value because it was folded into the message
// before the handler ran. scrubURLCredentials is the one check that still
// applies at that point.
func (h *RedactHandler) Handle(ctx context.Context, r slog.Record) error {
	out := slog.NewRecord(r.Time, r.Level, scrubURLCredentials(r.Message), r.PC)
	r.Attrs(func(a slog.Attr) bool {
		out.AddAttrs(h.policy.Redact(a))
		return true
	})
	return h.next.Handle(ctx, out)
}

// WithAttrs redacts the preformatted attributes before handing them down, so a
// secret attached once to a logger cannot be replayed unfiltered on every
// subsequent record.
func (h *RedactHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	if len(attrs) == 0 {
		return h
	}
	redacted := make([]slog.Attr, 0, len(attrs))
	for _, a := range attrs {
		redacted = append(redacted, h.policy.Redact(a))
	}
	return &RedactHandler{next: h.next.WithAttrs(redacted), policy: h.policy}
}

// WithGroup opens a namespace on the wrapped handler.
//
// The group name is a namespace, not a value, so it needs no filtering; and the
// policy is applied per leaf key rather than per qualified path, so attributes
// added after this call are filtered exactly as they would be at the top level.
func (h *RedactHandler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	return &RedactHandler{next: h.next.WithGroup(name), policy: h.policy}
}

// redact applies the policy to one attribute, recursing through groups.
func (p *Policy) redact(a slog.Attr, depth int) slog.Attr {
	if depth >= maxDepth {
		return slog.String(a.Key, RedactedMarker)
	}

	// Resolve runs LogValuer FIRST, before any decision is taken. A type that
	// implements LogValuer -- secrets.Redacted does -- gets to redact itself,
	// and, more importantly, a LogValuer that expands into a group of secrets
	// cannot slip past by being opaque at the point the key is inspected.
	v := a.Value.Resolve()

	if v.Kind() == slog.KindGroup {
		subs := v.Group()
		out := make([]slog.Attr, 0, len(subs))
		for _, sub := range subs {
			out = append(out, p.redact(sub, depth+1))
		}
		return slog.Attr{Key: a.Key, Value: slog.GroupValue(out...)}
	}

	if !p.allowed(a.Key) {
		return slog.String(a.Key, RedactedMarker)
	}
	return slog.Attr{Key: a.Key, Value: leafValue(v)}
}

// allowed reports whether a key is declared loggable. Matching is
// case-insensitive so that "Authorization" and "authorization" cannot be
// different keys as far as the policy is concerned.
func (p *Policy) allowed(key string) bool {
	_, ok := p.allow[strings.ToLower(key)]
	return ok
}

// leafValue decides what an allowlisted key's value may render as.
//
// Passing the key check is not sufficient. An allowlist entry is a reviewer's
// statement that "a value under this name is safe to log", and that statement
// is only meaningful for values whose shape is known. slog.Any hands the JSON
// handler an arbitrary Go value, which it marshals field by field -- so an
// allowlisted key holding a struct with an unexported-from-review password
// field would print it. Structured values are therefore redacted unless they
// are an error.
//
// Errors are the deliberate exception, because an error's cause is the single
// most valuable thing in an operational log and refusing to render it would
// make the layer unusable. The risk is bounded from the other side: errors
// raised in this codebase carry secrets as secrets.Redacted or secrets.Ref,
// both of which render "[REDACTED]" from inside the error string, and any
// credential a third-party driver folds into a DSN is caught by
// scrubURLCredentials below.
func leafValue(v slog.Value) slog.Value {
	switch v.Kind() {
	case slog.KindString:
		return slog.StringValue(scrubURLCredentials(v.String()))
	case slog.KindBool, slog.KindInt64, slog.KindUint64, slog.KindFloat64,
		slog.KindDuration, slog.KindTime:
		// Structurally incapable of carrying key material or a token.
		return v
	}
	if err, ok := v.Any().(error); ok {
		return slog.StringValue(scrubURLCredentials(err.Error()))
	}
	return slog.StringValue(RedactedMarker)
}

// scrubURLCredentials removes the userinfo half of any URL-shaped substring
// that carries a password, rewriting "postgres://user:pw@host/db" as
// "postgres://[REDACTED]@host/db".
//
// This is the one content-based check in the package, and it is narrow on
// purpose. Connection strings are named explicitly as a thing that must never
// be logged, and they are the one secret that routinely arrives inside an
// otherwise legitimate value -- a driver's error text -- where no key-based
// policy can see it. The pattern "scheme://something:something@" is specific
// enough that it does not fire on the values this service exists to log: an SSH
// public key, a fingerprint, and a handle contain no such sequence.
//
// A userinfo with no ':' is left alone. A bare username is not a credential,
// and preserving it keeps the error actionable.
func scrubURLCredentials(s string) string {
	const sep = "://"
	var b strings.Builder
	rest, changed := s, false

	for {
		i := strings.Index(rest, sep)
		if i < 0 {
			break
		}
		authStart := i + len(sep)

		// Userinfo, if present, runs to '@' and may not cross into the path,
		// query, fragment, or surrounding prose.
		end := strings.IndexAny(rest[authStart:], "@/?# \t")
		if end < 0 || rest[authStart+end] != '@' {
			b.WriteString(rest[:authStart])
			rest = rest[authStart:]
			continue
		}

		if !strings.Contains(rest[authStart:authStart+end], ":") {
			b.WriteString(rest[:authStart+end+1])
			rest = rest[authStart+end+1:]
			continue
		}

		b.WriteString(rest[:authStart])
		b.WriteString(RedactedMarker)
		b.WriteByte('@')
		rest = rest[authStart+end+1:]
		changed = true
	}

	if !changed {
		return s
	}
	b.WriteString(rest)
	return b.String()
}
