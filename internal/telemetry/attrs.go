// Package telemetry provides the OpenTelemetry tracing and metrics layer for
// valletd (ADR-0025): spans exported over OTLP, metrics exposed both as a
// Prometheus scrape endpoint and over OTLP push, and a shared attribute policy
// that keeps secrets and unbounded values out of both.
//
// # Two different guards, deliberately not one
//
// Spans and metrics leak differently, so they are protected differently.
//
// A span attribute is free-form: it carries whatever key and value the code
// that started the span chose, and the failure mode is a future change that
// attaches a bearer token or a DSN to a span the way it might to a log line.
// That is the same failure the log allowlist exists to stop, so spans go
// through the SAME internal/logging.Policy -- not a copy of it. One allowlist,
// one set of value rules, one place to change them.
//
// A metric label is not free-form: the key set is fixed at compile time in
// instrument.go, so an allowlist over keys would guard nothing. The exposure
// there is the VALUE, because every distinct label value is a separate time
// series that lives in the scrape target's memory forever. A raw path or a raw
// method as a label is therefore both a disclosure (ADR-0010: credentials show
// up in URLs) and a denial of service a single client can drive. Metric label
// values are consequently bounded to closed sets by construction -- see
// NormalizeMethod and RouteLabel -- rather than filtered by name.
package telemetry

import (
	"log/slog"
	"net/http"

	"go.opentelemetry.io/otel/attribute"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/logging"
)

// RouteUnmatched is the route label used when no route matched the request.
//
// The tempting fallback -- label the series with the raw request path -- is the
// exact bug this constant exists to prevent, in both of its aspects. A 404
// sweep of random paths would mint one time series per probe, and each of those
// series names would be an attacker-chosen string recorded verbatim in the
// metrics store. A single constant makes the unmatched case one series.
const RouteUnmatched = "unmatched"

// MethodOther is the method label used for any method outside the known set.
const MethodOther = "OTHER"

// knownMethods is the closed set of methods that may appear as a label value.
//
// This bound is not cosmetic. net/http accepts any RFC 9110 token as a method
// and hands it to the handler unchanged, so "curl -X AAAA1", "-X AAAA2", ...
// against a single URL mints an unbounded number of label values without ever
// varying the path. Anything not on this list collapses to MethodOther, which
// caps the method dimension at len(knownMethods)+1 no matter what is sent.
var knownMethods = map[string]struct{}{
	http.MethodGet: {}, http.MethodHead: {}, http.MethodPost: {},
	http.MethodPut: {}, http.MethodPatch: {}, http.MethodDelete: {},
	http.MethodOptions: {}, http.MethodConnect: {}, http.MethodTrace: {},
}

// NormalizeMethod maps a request method onto the closed label set.
func NormalizeMethod(method string) string {
	if _, ok := knownMethods[method]; ok {
		return method
	}
	return MethodOther
}

// RouteLabel maps a matched ServeMux pattern onto a bounded label value.
//
// The pattern ("GET /{handle}") is a compile-time constant of the route table:
// there are as many possible values as there are registered routes, and no
// request can invent a new one. The raw path, by contrast, is entirely
// client-chosen. Passing the pattern through and collapsing the empty case is
// the whole mechanism that keeps metric cardinality a property of the code
// rather than of the traffic.
func RouteLabel(pattern string) string {
	if pattern == "" {
		return RouteUnmatched
	}
	return pattern
}

// SafeAttrs filters span attributes through the shared logging policy.
//
// Every attribute that reaches a span goes through here. The conversion to
// slog.Attr and back is deliberate: it routes the decision through
// logging.Policy.Redact rather than reimplementing the allowlist and the value
// rules, so a change to either one moves logs and spans together and they
// cannot drift into disagreeing about what is safe.
//
// Values whose slog kind has no attribute equivalent -- and any value the
// policy declines to render -- become the redaction marker, which is the same
// fail-closed direction the log path takes.
func SafeAttrs(policy *logging.Policy, attrs ...attribute.KeyValue) []attribute.KeyValue {
	if policy == nil {
		// No policy is not a reason to emit unfiltered attributes. A nil
		// policy means the caller was misconstructed, and the safe reading of
		// "I do not know what may be rendered" is "nothing may be".
		out := make([]attribute.KeyValue, 0, len(attrs))
		for _, kv := range attrs {
			out = append(out, attribute.String(string(kv.Key), logging.RedactedMarker))
		}
		return out
	}

	out := make([]attribute.KeyValue, 0, len(attrs))
	for _, kv := range attrs {
		out = append(out, safeAttr(policy, kv))
	}
	return out
}

// safeAttr applies the policy to one attribute.
func safeAttr(policy *logging.Policy, kv attribute.KeyValue) attribute.KeyValue {
	key := string(kv.Key)
	decided := policy.Redact(toSlog(key, kv.Value))
	return fromSlog(key, decided.Value)
}

// toSlog converts an OTel attribute value into the slog value the policy
// inspects. Composite kinds (the slice types) are handed over as an opaque Any,
// which leafValue redacts -- a slice of strings is exactly the shape that can
// smuggle a token past a scalar check.
func toSlog(key string, v attribute.Value) slog.Attr {
	switch v.Type() {
	case attribute.STRING:
		return slog.String(key, v.AsString())
	case attribute.BOOL:
		return slog.Bool(key, v.AsBool())
	case attribute.INT64:
		return slog.Int64(key, v.AsInt64())
	case attribute.FLOAT64:
		return slog.Float64(key, v.AsFloat64())
	default:
		return slog.Any(key, v.AsInterface())
	}
}

// fromSlog converts the policy's decision back into an OTel attribute. Any kind
// the policy did not reduce to a renderable scalar is stringified, which for a
// redacted value is the marker itself.
func fromSlog(key string, v slog.Value) attribute.KeyValue {
	switch v.Kind() {
	case slog.KindString:
		return attribute.String(key, v.String())
	case slog.KindBool:
		return attribute.Bool(key, v.Bool())
	case slog.KindInt64:
		return attribute.Int64(key, v.Int64())
	case slog.KindFloat64:
		return attribute.Float64(key, v.Float64())
	default:
		return attribute.String(key, v.String())
	}
}
