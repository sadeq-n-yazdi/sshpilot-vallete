package httpserver

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.opentelemetry.io/otel/attribute"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/config"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/logging"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/telemetry"
)

// recordingTelemetry returns a handler wired to a provider whose spans land in
// the returned recorder.
func recordingTelemetry(t *testing.T, cfg *config.Config) (http.Handler, *tracetest.SpanRecorder) {
	t.Helper()
	rec := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(rec))
	t.Cleanup(func() { _ = tp.Shutdown(t.Context()) })

	provider := telemetry.NewWithTracerProvider(tp, nil)
	h := NewHandler(cfg, nil, okPinger{}, stubPublisher{}, WithTelemetry(provider))
	return h, rec
}

// spanNames returns the names of every recorded span.
func spanNames(rec *tracetest.SpanRecorder) []string {
	ended := rec.Ended()
	out := make([]string, 0, len(ended))
	for _, s := range ended {
		out = append(out, s.Name())
	}
	return out
}

// TestSpanNamesUseRoutePatternsNeverRawPaths is the disclosure invariant for
// span names. ADR-0010 keeps credentials out of URLs because URLs are recorded
// everywhere; a span name is exactly such a record.
//
// The assertion is structural rather than a search for one planted string: no
// recorded span name may contain ANY segment the client chose. That holds for
// every request shape, including ones nobody thought to plant a token in.
func TestSpanNamesUseRoutePatternsNeverRawPaths(t *testing.T) {
	h, rec := recordingTelemetry(t, nil)

	const marker = "s3cr3t-value-from-the-url"
	requests := []string{
		"/" + marker,
		"/" + marker + "/" + marker,
		"/healthz",
		"/nope/" + marker + "/deep",
	}
	for _, target := range requests {
		req := httptest.NewRequest(http.MethodGet, target+"?token="+marker, nil)
		h.ServeHTTP(httptest.NewRecorder(), req)
	}

	names := spanNames(rec)
	if len(names) != len(requests) {
		t.Fatalf("recorded %d spans for %d requests: %v", len(names), len(requests), names)
	}
	for _, name := range names {
		if strings.Contains(name, marker) {
			t.Errorf("span name %q contains a client-supplied value; span names must be route patterns", name)
		}
		if !isRoutePatternOrUnmatched(name) {
			t.Errorf("span name %q is neither a registered route pattern nor %q",
				name, telemetry.RouteUnmatched)
		}
	}
}

// isRoutePatternOrUnmatched reports whether a span name is drawn from the
// closed set the route table can produce. A pattern always has the shape
// "METHOD /...", and the only other permitted value is the unmatched constant.
func isRoutePatternOrUnmatched(name string) bool {
	if name == telemetry.RouteUnmatched {
		return true
	}
	method, rest, ok := strings.Cut(name, " ")
	return ok && telemetry.NormalizeMethod(method) == method && strings.HasPrefix(rest, "/")
}

// TestSpanNameCardinalityCannotBeDrivenByRequests is the DoS invariant. It
// varies BOTH dimensions a client controls -- the path and the method -- because
// varying only the path leaves the method dimension untested, and net/http
// accepts any token as a method.
func TestSpanNameCardinalityCannotBeDrivenByRequests(t *testing.T) {
	h, rec := recordingTelemetry(t, nil)

	const n = 300
	for i := range n {
		// A distinct unmatched path AND a distinct client-invented method.
		req := httptest.NewRequest(fmt.Sprintf("XMETHOD%d", i), fmt.Sprintf("/no/such/route/%d", i), nil)
		h.ServeHTTP(httptest.NewRecorder(), req)
	}

	distinct := map[string]bool{}
	for _, name := range spanNames(rec) {
		distinct[name] = true
	}
	if len(distinct) != 1 {
		t.Fatalf("%d requests with distinct paths and distinct methods produced %d distinct span names: %v; "+
			"cardinality must be a property of the route table, not of the traffic", n, len(distinct), distinct)
	}
}

// TestSpanCarriesTheRequestIDForCorrelation pins the join between a trace and
// the access log: the span records the same request_id, under the same key, the
// log line uses.
func TestSpanCarriesTheRequestIDForCorrelation(t *testing.T) {
	h, rec := recordingTelemetry(t, nil)

	const id = "correlate-me-0123456789"
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req.Header.Set(RequestIDHeader, id)
	resp := httptest.NewRecorder()
	h.ServeHTTP(resp, req)

	if got := resp.Header().Get(RequestIDHeader); got != id {
		t.Fatalf("response request id = %q, want %q", got, id)
	}

	ended := rec.Ended()
	if len(ended) != 1 {
		t.Fatalf("recorded %d spans, want 1", len(ended))
	}
	if got := attrString(ended[0].Attributes(), "request_id"); got != id {
		t.Fatalf("span request_id = %q, want %q; a trace must be joinable to its log line", got, id)
	}
	if got := attrString(ended[0].Attributes(), "route"); got != "GET /healthz" {
		t.Fatalf("span route = %q, want the matched pattern", got)
	}
}

// TestSpanAttributesGoThroughTheSharedRedactionPolicy asserts the MECHANISM
// protecting spans, not the absence of one sample string.
//
// The middleware records four attributes, all of them allowlisted and none
// client-controlled, so a test that merely checked "no secret appears" would
// pass against a middleware that never filtered at all -- and would keep
// passing when somebody adds a fifth attribute holding a header value. Instead
// this drives the span attributes through the same call the middleware makes
// and asserts the policy decides: an unclassified key does not survive,
// whatever it holds.
func TestSpanAttributesGoThroughTheSharedRedactionPolicy(t *testing.T) {
	rec := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(rec))
	t.Cleanup(func() { _ = tp.Shutdown(t.Context()) })
	provider := telemetry.NewWithTracerProvider(tp, nil)

	_, span := provider.Tracer().Start(t.Context(), "GET /{handle}")
	span.SetAttributes(telemetry.SafeAttrs(provider.Policy(),
		attribute.String("authorization", "Bearer sk-live-000111222333"),
		attribute.String("db_url", "postgres://vallet:hunter2@db/vallet"),
		attribute.String("route", "GET /{handle}"),
	)...)
	span.End()

	attrs := rec.Ended()[0].Attributes()
	for _, key := range []string{"authorization", "db_url"} {
		if got := attrString(attrs, key); got != logging.RedactedMarker {
			t.Errorf("span attribute %q = %q, want %q: an unallowlisted key must not render its value",
				key, got, logging.RedactedMarker)
		}
	}
	if got := attrString(attrs, "route"); got != "GET /{handle}" {
		t.Errorf("allowlisted attribute route = %q; the policy must still let classified fields through", got)
	}
}

// TestHandlerNeverServesTheScrapeEndpoint is the exposure invariant at the
// router: the public handler has no /metrics route, whether or not telemetry is
// wired, and no config makes one appear.
func TestHandlerNeverServesTheScrapeEndpoint(t *testing.T) {
	cfg := config.Default()
	cfg.Telemetry.Metrics.Prometheus.Enabled = true
	cfg.Telemetry.Metrics.Prometheus.ListenAddr = "127.0.0.1:9090"

	provider := telemetry.New(&cfg, nil)
	t.Cleanup(func() { _ = provider.Shutdown(t.Context()) })

	for name, h := range map[string]http.Handler{
		"with telemetry": NewHandler(&cfg, nil, okPinger{}, stubPublisher{}, WithTelemetry(provider)),
		"no telemetry":   NewHandler(&cfg, nil, okPinger{}, stubPublisher{}),
	} {
		t.Run(name, func(t *testing.T) {
			for _, path := range []string{"/metrics", "/metrics/", "/debug/metrics"} {
				resp := httptest.NewRecorder()
				h.ServeHTTP(resp, httptest.NewRequest(http.MethodGet, path, nil))
				body, _ := io.ReadAll(resp.Result().Body)
				if strings.Contains(string(body), "http_server_request_duration") {
					t.Fatalf("the public handler served metrics at %s; the scrape endpoint "+
						"must exist only on its own listener", path)
				}
			}
		})
	}
}

// TestRequestsAreServedNormallyWithoutTelemetry checks the no-op path: a
// handler built with no provider still answers, so telemetry is never a
// prerequisite for serving.
func TestRequestsAreServedNormallyWithoutTelemetry(t *testing.T) {
	h := NewHandler(nil, nil, okPinger{}, stubPublisher{})
	resp := httptest.NewRecorder()
	h.ServeHTTP(resp, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if resp.Code != http.StatusOK {
		t.Fatalf("GET /healthz without telemetry = %d, want 200", resp.Code)
	}
}

func attrString(attrs []attribute.KeyValue, key string) string {
	for _, kv := range attrs {
		if string(kv.Key) == key {
			return kv.Value.AsString()
		}
	}
	return ""
}
