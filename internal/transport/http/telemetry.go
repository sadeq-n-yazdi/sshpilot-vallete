package httpserver

import (
	"net/http"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/telemetry"
)

// telemetryMiddleware opens a span per request and records the request metric.
//
// # Why the span is named after the request has been served
//
// The obvious span name -- the request target -- is forbidden here. ADR-0010
// keeps access credentials out of URLs precisely because URLs are recorded
// everywhere, and a span name is one of the most widely recorded strings there
// is; a raw path would also make the span-name dimension unbounded in any
// backend that aggregates on it. The safe name is the matched ROUTE PATTERN
// ("GET /{handle}"), which is a constant of the route table.
//
// The pattern is only known after the mux has matched, which happens INSIDE
// next.ServeHTTP. So the span starts under a placeholder name built from the
// normalized method, and is renamed once the pattern is known. This mirrors
// what loggingMiddleware already does with r.Pattern and is the standard OTel
// approach for a server span.
//
// Attributes go through telemetry.SafeAttrs, i.e. through the same
// internal/logging policy that filters the access log. The four recorded here
// are all allowlisted already and none is client-controlled, but they are
// filtered anyway rather than passed straight in: the filter is what makes the
// NEXT attribute somebody adds safe by default, and a call site that bypasses
// it for "obviously fine" values is how a bypass for a not-fine value gets
// added later by analogy.
func telemetryMiddleware(p *telemetry.Provider, instruments *telemetry.Instruments) Middleware {
	tracer := p.Tracer()
	policy := p.Policy()

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			method := telemetry.NormalizeMethod(r.Method)
			start := time.Now()

			ctx, span := tracer.Start(r.Context(), "HTTP "+method,
				trace.WithSpanKind(trace.SpanKindServer))
			defer span.End()

			// The downstream request is held in a variable rather than
			// built inline because ServeMux records the matched pattern ON
			// THE REQUEST IT IS GIVEN. WithContext returns a shallow copy, so
			// reading r.Pattern afterwards would always see the empty string
			// -- every span would be named "unmatched" and every metric would
			// land in one bucket, with nothing failing loudly to say so.
			inner := r.WithContext(ctx)
			rec := &statusRecorder{ResponseWriter: w}
			next.ServeHTTP(rec, inner)

			status := rec.status()
			route := telemetry.RouteLabel(inner.Pattern)
			span.SetName(route)
			span.SetAttributes(telemetry.SafeAttrs(policy,
				attribute.String("route", route),
				attribute.String("method", method),
				attribute.Int("status", status),
				// The correlation key: this is the same value the access log
				// records under the same name, so a log line and a trace can
				// be joined without either side carrying the other's ID.
				attribute.String("request_id", RequestIDFromContext(r.Context())),
			)...)

			// Recording happens after the response is complete and cannot
			// block on anything remote: the histogram is an in-memory
			// aggregation, read by the scrape endpoint or by the periodic OTLP
			// reader, both on their own goroutines.
			instruments.RecordRequest(ctx, inner.Pattern, r.Method, status, time.Since(start))
		})
	}
}
