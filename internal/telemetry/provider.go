package telemetry

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	promexporter "go.opentelemetry.io/otel/exporters/prometheus"
	"go.opentelemetry.io/otel/metric"
	metricnoop "go.opentelemetry.io/otel/metric/noop"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
	tracenoop "go.opentelemetry.io/otel/trace/noop"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/config"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/logging"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/version"

	"github.com/prometheus/client_golang/prometheus"
)

// serviceName is the resource identity every exported span and metric carries.
const serviceName = "valletd"

// otlpExportTimeout bounds a single export attempt. It is short on purpose: an
// export is background work, and a backend that has stopped answering must cost
// bounded goroutine time rather than accumulating stuck exporters until the
// process runs out of memory.
const otlpExportTimeout = 10 * time.Second

// metricExportInterval is the OTLP metrics push period.
const metricExportInterval = 60 * time.Second

// shutdownTimeout bounds the whole telemetry drain, and each component within
// it, when the caller supplies no deadline of its own.
const shutdownTimeout = 5 * time.Second

// Provider holds the process's telemetry plumbing: the tracer used by the
// request path, the meter its instruments come from, the Prometheus registry a
// scrape endpoint reads, and the shutdown hooks that flush exporters.
//
// A nil *Provider is usable. Every method tolerates it and does nothing, so a
// caller that never enabled telemetry -- and a test that never wired it --
// takes the same code path as one that did, with no branch at the call site
// that could be forgotten.
type Provider struct {
	tracer   trace.Tracer
	meter    metric.Meter
	registry *prometheus.Registry
	policy   *logging.Policy
	shutdown []func(context.Context) error
	logger   *slog.Logger
}

// New builds the telemetry provider from operator config.
//
// It NEVER fails the process. Telemetry is diagnostic machinery; a backend that
// is unreachable, misconfigured, or temporarily gone is not a reason to stop
// serving the requests the telemetry exists to describe. Every exporter that
// cannot be constructed is logged at error level and omitted, and the returned
// Provider works with whatever remained -- degrading to a no-op tracer and a
// no-op meter if nothing could be built. This mirrors the rate limiter's stance
// in the router: a component that cannot be built is not a reason to refuse to
// serve.
//
// The span vocabulary is deliberately the same as the access log's -- route,
// method, status, request_id -- so it needs no widening of the shared allowlist
// and one grep finds every place a field is emitted. Any future span attribute
// that is not already allowlisted must be added to internal/logging's list in a
// reviewed diff, which is the moment the "is this safe to record?" question
// gets asked.
func New(cfg *config.Config, logger *slog.Logger) *Provider {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	p := &Provider{
		tracer: tracenoop.NewTracerProvider().Tracer(serviceName),
		meter:  metricnoop.NewMeterProvider().Meter(serviceName),
		policy: logging.NewPolicy(),
		logger: logger,
	}
	if cfg == nil {
		return p
	}

	// Resource attributes are NOT run through SafeAttrs, and that is a
	// deliberate exception rather than an omission. Both values are fixed at
	// compile time -- a constant and the build's version string -- so no
	// request, config value, or secret can reach them. Passing them through the
	// allowlist would only mean adding two OTel-namespaced keys to the log
	// policy, widening it for values that were never in danger. The policy
	// guards the attributes that carry runtime data; these carry none.
	res := resource.NewSchemaless(
		attribute.String("service.name", serviceName),
		attribute.String("service.version", version.String()),
	)

	p.initTraces(cfg, res)
	p.initMetrics(cfg, res)
	return p
}

// NewWithTracerProvider builds a Provider around a caller-supplied tracer
// provider, sharing the same redaction policy as New.
//
// It exists so a caller can observe or redirect spans -- a test that asserts
// what a span actually carries, or an embedder that already runs its own SDK
// pipeline -- without this package growing a second configuration path. It has
// no bearing on metrics or on the scrape endpoint: Registry() is nil, so
// NewMetricsServer builds nothing from it, and no exposure decision can be
// reached through this constructor.
func NewWithTracerProvider(tp trace.TracerProvider, logger *slog.Logger) *Provider {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	if tp == nil {
		tp = tracenoop.NewTracerProvider()
	}
	return &Provider{
		tracer: tp.Tracer(serviceName),
		meter:  metricnoop.NewMeterProvider().Meter(serviceName),
		policy: logging.NewPolicy(),
		logger: logger,
	}
}

// initTraces wires the OTLP trace exporter behind a BATCH span processor.
//
// Batching is a security and availability property here, not a throughput
// tweak. A simple span processor exports synchronously inside span.End(), which
// runs on the request goroutine -- so an OTLP endpoint that blackholes packets
// would add its full dial timeout to every single request, letting an
// unreachable telemetry backend become an outage of the service. The batch
// processor hands spans to a background worker and drops them when its queue
// fills, so the worst a dead backend can cost the request path is a queue
// insert.
func (p *Provider) initTraces(cfg *config.Config, res *resource.Resource) {
	if !cfg.Telemetry.Traces.Enabled || cfg.Telemetry.Traces.Endpoint == "" {
		return
	}

	// otlptracehttp does not dial here; the client connects lazily on the
	// first export, on the batch worker's goroutine. Startup therefore cannot
	// block on an unreachable collector.
	exp, err := otlptracehttp.New(context.Background(),
		otlptracehttp.WithEndpointURL(cfg.Telemetry.Traces.Endpoint),
		otlptracehttp.WithTimeout(otlpExportTimeout),
	)
	if err != nil {
		p.logger.Error("telemetry: trace exporter not started; tracing disabled",
			slog.String("component", "telemetry"), slog.String("error", err.Error()))
		return
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sdktrace.ParentBased(
			sdktrace.TraceIDRatioBased(clampRatio(cfg.Telemetry.Traces.SampleRatio)))),
		sdktrace.WithBatcher(exp,
			sdktrace.WithExportTimeout(otlpExportTimeout)),
	)
	p.tracer = tp.Tracer(serviceName)
	p.shutdown = append(p.shutdown, tp.Shutdown)
}

// clampRatio bounds a configured sampling ratio to [0,1]. Config validation
// already rejects anything outside that range; clamping here means a Provider
// built from an unvalidated config still cannot hand the SDK a nonsense value.
func clampRatio(r float64) float64 {
	switch {
	case r < 0:
		return 0
	case r > 1:
		return 1
	default:
		return r
	}
}

// initMetrics wires the metric readers: the Prometheus pull registry and the
// OTLP push reader, either, both, or neither.
//
// Both are off the request path by construction -- Prometheus collects when
// scraped, and the periodic reader exports on its own timer -- so neither can
// make a request slower, however sick the backend is.
func (p *Provider) initMetrics(cfg *config.Config, res *resource.Resource) {
	var readers []sdkmetric.Option

	if cfg.Telemetry.Metrics.Prometheus.Enabled {
		reg := prometheus.NewRegistry()
		exp, err := promexporter.New(promexporter.WithRegisterer(reg))
		if err != nil {
			p.logger.Error("telemetry: prometheus exporter not started",
				slog.String("component", "telemetry"), slog.String("error", err.Error()))
		} else {
			p.registry = reg
			readers = append(readers, sdkmetric.WithReader(exp))
		}
	}

	if cfg.Telemetry.Metrics.OTLP.Enabled && cfg.Telemetry.Metrics.OTLP.Endpoint != "" {
		exp, err := otlpmetrichttp.New(context.Background(),
			otlpmetrichttp.WithEndpointURL(cfg.Telemetry.Metrics.OTLP.Endpoint),
			otlpmetrichttp.WithTimeout(otlpExportTimeout),
		)
		if err != nil {
			p.logger.Error("telemetry: otlp metric exporter not started",
				slog.String("component", "telemetry"), slog.String("error", err.Error()))
		} else {
			readers = append(readers, sdkmetric.WithReader(sdkmetric.NewPeriodicReader(exp,
				sdkmetric.WithInterval(metricExportInterval),
				sdkmetric.WithTimeout(otlpExportTimeout))))
		}
	}

	if len(readers) == 0 {
		return
	}

	mp := sdkmetric.NewMeterProvider(append(readers, sdkmetric.WithResource(res))...)
	p.meter = mp.Meter(serviceName)
	p.shutdown = append(p.shutdown, mp.Shutdown)
}

// Tracer returns the tracer for the request path. It is never nil: a Provider
// with tracing disabled returns a no-op tracer, so callers start spans
// unconditionally and no call site needs an "if telemetry is on" branch that
// could be omitted.
func (p *Provider) Tracer() trace.Tracer {
	if p == nil {
		return tracenoop.NewTracerProvider().Tracer(serviceName)
	}
	return p.tracer
}

// Meter returns the meter instruments are created from, no-op when metrics are
// disabled.
func (p *Provider) Meter() metric.Meter {
	if p == nil {
		return metricnoop.NewMeterProvider().Meter(serviceName)
	}
	return p.meter
}

// Policy returns the shared redaction policy applied to span attributes.
func (p *Provider) Policy() *logging.Policy {
	if p == nil {
		return nil
	}
	return p.policy
}

// Registry returns the Prometheus registry to scrape, or nil when the
// Prometheus exporter is not enabled.
//
// It returns the process's own registry rather than prometheus.DefaultRegisterer
// on purpose: the default registry is global mutable state that any linked
// dependency can register into, so what /metrics exposes would be decided by
// the import graph instead of by this package. An explicit registry means the
// exposed series are exactly the ones built here.
func (p *Provider) Registry() *prometheus.Registry {
	if p == nil {
		return nil
	}
	return p.registry
}

// Shutdown flushes and stops every exporter, bounded by ctx.
//
// It is bounded rather than best-effort-forever because shutdown runs inside
// the process's drain window: an exporter still trying to reach a dead
// collector must not be able to outlast the deadline and turn a clean stop into
// a hung one. Errors are returned for logging, never for the exit code -- a
// backend that refused the final flush has lost some telemetry, which is not a
// failed shutdown.
func (p *Provider) Shutdown(ctx context.Context) error {
	if p == nil || len(p.shutdown) == 0 {
		return nil
	}
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, shutdownTimeout)
		defer cancel()
	}

	// Every shutdown runs, and every failure is kept. Returning only the first
	// would hide the rest behind whichever exporter happened to be registered
	// earliest, and these are the errors that say telemetry was lost on the way
	// out -- exactly what an operator reading a shutdown log needs all of.
	var errs []error
	for _, fn := range p.shutdown {
		if err := fn(ctx); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
