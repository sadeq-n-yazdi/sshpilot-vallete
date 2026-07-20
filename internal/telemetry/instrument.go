package telemetry

import (
	"context"
	"log/slog"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// The metric and label catalog. ADR-0025 requires this to be a named, versioned
// artifact rather than whatever the code happens to emit, so it is one small
// block of constants with no dynamic construction anywhere near it.
//
// v1 catalog:
//
//	http.server.request.duration  histogram, seconds
//	  labels: route, method, status
//
// Every label value is drawn from a set fixed by the code:
//
//	route   one of the registered ServeMux patterns, or "unmatched"
//	method  one of nine HTTP methods, or "OTHER"
//	status  an HTTP status code
//
// The upper bound on series count is therefore routes x 10 x statuses, a
// three-digit number that no volume or shape of traffic can raise. Adding a
// label here is a decision about the memory of every Prometheus server that
// scrapes this service, which is why the list is short and why owner
// identifiers, handles, key-set names, fingerprints and request IDs are absent:
// they are unbounded, and they identify a tenant.
const (
	metricRequestDuration     = "http.server.request.duration"
	metricRequestDurationDesc = "Duration of HTTP server requests."

	labelRoute  = "route"
	labelMethod = "method"
	labelStatus = "status"

	// spanAttrRequestID correlates a span with the access-log line for the same
	// request. It is the one high-cardinality value recorded anywhere in this
	// package, and it is recorded ONLY as a span attribute, never as a metric
	// label: a span is a single record with a retention window, while a label
	// value is a permanent series.
	spanAttrRequestID = "request_id"
)

// Instruments are the process's metric instruments, created once at startup.
//
// A nil *Instruments is usable and records nothing, so the request path calls
// Record unconditionally.
type Instruments struct {
	requestDuration metric.Float64Histogram
}

// NewInstruments creates the instruments from the provider's meter.
//
// Instrument creation failing is logged and yields a recorder that does
// nothing; it is never fatal, for the same reason exporter construction is not.
func (p *Provider) NewInstruments() *Instruments {
	if p == nil {
		return nil
	}
	h, err := p.Meter().Float64Histogram(
		metricRequestDuration,
		metric.WithDescription(metricRequestDurationDesc),
		metric.WithUnit("s"),
	)
	if err != nil {
		p.logger.Error("telemetry: request duration instrument not created",
			slog.String("component", "telemetry"), slog.String("error", err.Error()))
		return nil
	}
	return &Instruments{requestDuration: h}
}

// RecordRequest records one completed request.
//
// The bounding of every label value happens HERE rather than at the call site,
// which is the point: a caller cannot pass a raw path or a raw method into a
// label even by mistake, because the raw values are normalized on the way in
// and the normalized ones are all this function will emit.
func (i *Instruments) RecordRequest(ctx context.Context, pattern, method string, status int, elapsed time.Duration) {
	if i == nil || i.requestDuration == nil {
		return
	}
	i.requestDuration.Record(ctx, elapsed.Seconds(), metric.WithAttributes(
		attribute.String(labelRoute, RouteLabel(pattern)),
		attribute.String(labelMethod, NormalizeMethod(method)),
		attribute.Int(labelStatus, status),
	))
}
