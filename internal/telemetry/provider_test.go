package telemetry

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/config"
)

// blackholeEndpoint returns the URL of a collector that accepts connections and
// then never answers.
//
// A CLOSED port is the wrong failure to test with, and this test learned that
// the hard way: connection-refused comes back in microseconds, so a synchronous
// exporter still looks fast and the mutation that puts export back on the
// request goroutine SURVIVED against it. The realistic outage -- a collector
// whose host is up but whose process is wedged, or a firewall that drops -- makes
// the export block until it times out. That is what this simulates: every
// connection is accepted and then held open in silence until the test ends.
func blackholeEndpoint(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		var held []net.Conn
		defer func() {
			for _, c := range held {
				_ = c.Close()
			}
		}()
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			// Accepted, never read from, never written to, never closed: the
			// client's export blocks on a response that never comes.
			held = append(held, conn)
		}
	}()

	return "http://" + ln.Addr().String()
}

func tracingConfig(endpoint string) *config.Config {
	cfg := config.Default()
	cfg.Telemetry.Traces.Enabled = true
	cfg.Telemetry.Traces.Endpoint = endpoint
	return &cfg
}

// TestUnreachableExporterDoesNotDelayTheRequestPath is the availability
// invariant: a telemetry backend that is not there must cost the request
// nothing.
//
// It asserts the property through the request path rather than by inspecting
// the SDK's configuration, because the property is what matters and the
// mechanism (a batch span processor, which hands spans to a background worker)
// is what makes it true. A simple span processor exports inside span.End(), on
// the request goroutine; wired that way this test fails on the bound below.
func TestUnreachableExporterDoesNotDelayTheRequestPath(t *testing.T) {
	p := New(tracingConfig(blackholeEndpoint(t)), nil)
	t.Cleanup(func() { _ = p.Shutdown(context.Background()) })

	tracer := p.Tracer()
	// Generous enough not to flake on a loaded CI box, far below the 10s export
	// timeout a single synchronous export burns against a silent collector.
	const budget = 2 * time.Second

	// The work runs on its own goroutine and the budget is enforced by a
	// select, not measured afterwards. A synchronous exporter blocks for the
	// full export timeout on EVERY span, so a loop that had to finish before
	// the assertion ran would take hours instead of failing.
	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 200 {
			_, span := tracer.Start(context.Background(), "GET /{handle}")
			span.End()
		}
	}()

	select {
	case <-done:
	case <-time.After(budget):
		t.Fatalf("200 spans against a collector that never answers exceeded %v; "+
			"export must not run on the goroutine that ends the span", budget)
	}
}

// TestShutdownWithAnUnreachableExporterDoesNotHang pins the drain bound: a
// collector that never answers must not keep the process alive past its
// deadline.
func TestShutdownWithAnUnreachableExporterDoesNotHang(t *testing.T) {
	p := New(tracingConfig(blackholeEndpoint(t)), nil)

	_, span := p.Tracer().Start(context.Background(), "GET /{handle}")
	span.End()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- p.Shutdown(ctx) }()

	select {
	case <-done:
		// Any result is acceptable: a flush that failed against a dead
		// collector is not a failed shutdown. Returning at all is the point.
	case <-time.After(10 * time.Second):
		t.Fatal("Shutdown did not return; a wedged exporter must not outlast the drain window")
	}
}

// TestShutdownIsIdempotentAndNilSafe covers the paths a cmd wrapper takes when
// telemetry was never configured.
func TestShutdownIsIdempotentAndNilSafe(t *testing.T) {
	var nilProvider *Provider
	if err := nilProvider.Shutdown(context.Background()); err != nil {
		t.Errorf("nil provider Shutdown: %v", err)
	}

	p := New(nil, nil)
	if err := p.Shutdown(context.Background()); err != nil {
		t.Errorf("provider with no exporters: %v", err)
	}
	if err := p.Shutdown(context.Background()); err != nil {
		t.Errorf("second Shutdown: %v", err)
	}
}

// TestNewNeverFailsOnABadExporterConfig is the fail-safe-not-closed direction:
// telemetry is diagnostic machinery and must never be the reason the service
// does not run. A Provider is always returned and always usable.
func TestNewNeverFailsOnABadExporterConfig(t *testing.T) {
	cfg := config.Default()
	cfg.Telemetry.Traces.Enabled = true
	cfg.Telemetry.Traces.Endpoint = "://not-a-url"
	cfg.Telemetry.Metrics.OTLP.Enabled = true
	cfg.Telemetry.Metrics.OTLP.Endpoint = "://also-not-a-url"

	p := New(&cfg, nil)
	t.Cleanup(func() { _ = p.Shutdown(context.Background()) })

	if p.Tracer() == nil || p.Meter() == nil {
		t.Fatal("New returned a provider that cannot be used")
	}
	_, span := p.Tracer().Start(context.Background(), "GET /{handle}")
	span.End()
	p.NewInstruments().RecordRequest(context.Background(), "GET /{handle}", "GET", 200, time.Millisecond)
}

// --- exposure model -------------------------------------------------------

// TestMetricsEndpointIsNotServedByDefault is the exposure invariant: on the
// shipped defaults, nothing serves a scrape endpoint anywhere.
func TestMetricsEndpointIsNotServedByDefault(t *testing.T) {
	cfg := config.Default()
	if cfg.Telemetry.Metrics.Prometheus.ListenAddr != "" {
		t.Fatalf("default scrape listen_addr is %q; the default must serve no endpoint",
			cfg.Telemetry.Metrics.Prometheus.ListenAddr)
	}

	p := New(&cfg, nil)
	t.Cleanup(func() { _ = p.Shutdown(context.Background()) })

	if srv := NewMetricsServer(&cfg, p, nil); srv != nil {
		t.Fatalf("default config built a scrape listener on %q; it must build none", srv.Addr())
	}
}

// TestMetricsServerRequiresAnExplicitAddress checks each precondition is
// load-bearing on its own: the endpoint appears only when everything needed to
// serve it was explicitly arranged.
func TestMetricsServerRequiresAnExplicitAddress(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*config.Config)
		wantNil bool
	}{
		{"defaults", func(*config.Config) {}, true},
		{"address but exporter disabled", func(c *config.Config) {
			c.Telemetry.Metrics.Prometheus.Enabled = false
			c.Telemetry.Metrics.Prometheus.ListenAddr = "127.0.0.1:0"
		}, true},
		{"enabled but no address", func(c *config.Config) {
			c.Telemetry.Metrics.Prometheus.Enabled = true
		}, true},
		{"enabled with an address", func(c *config.Config) {
			c.Telemetry.Metrics.Prometheus.Enabled = true
			c.Telemetry.Metrics.Prometheus.ListenAddr = "127.0.0.1:0"
		}, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.Default()
			tc.mutate(&cfg)
			p := New(&cfg, nil)
			t.Cleanup(func() { _ = p.Shutdown(context.Background()) })

			srv := NewMetricsServer(&cfg, p, nil)
			if (srv == nil) != tc.wantNil {
				t.Fatalf("NewMetricsServer nil=%v, want nil=%v", srv == nil, tc.wantNil)
			}
		})
	}
}

// TestMetricsListenerServesOnlyTheScrapePath checks the dedicated listener is
// not a second front door: it answers the scrape path and 404s everything else,
// including the API's own routes.
func TestMetricsListenerServesOnlyTheScrapePath(t *testing.T) {
	cfg := config.Default()
	cfg.Telemetry.Metrics.Prometheus.Enabled = true
	cfg.Telemetry.Metrics.Prometheus.ListenAddr = "127.0.0.1:0"

	p := New(&cfg, nil)
	t.Cleanup(func() { _ = p.Shutdown(context.Background()) })

	srv := NewMetricsServer(&cfg, p, nil)
	if srv == nil {
		t.Fatal("no scrape listener built")
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})

	base := "http://" + ln.Addr().String()
	if code, body := get(t, base+"/metrics"); code != http.StatusOK {
		t.Errorf("GET /metrics = %d, want 200 (body %.80q)", code, body)
	}
	for _, path := range []string{"/", "/healthz", "/readyz", "/docs", "/somehandle", "/debug/pprof/"} {
		if code, _ := get(t, base+path); code != http.StatusNotFound {
			t.Errorf("GET %s on the scrape listener = %d, want 404; this listener serves one route", path, code)
		}
	}
}

func get(t *testing.T, url string) (int, string) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("get %s: %v", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body)
}

// TestScrapeOutputCarriesNoTenantIdentifiers scrapes a real registry after
// recording requests and asserts the exposition contains none of the
// identifying, unbounded values ADR-0025 forbids as labels.
func TestScrapeOutputCarriesNoTenantIdentifiers(t *testing.T) {
	cfg := config.Default()
	cfg.Telemetry.Metrics.Prometheus.Enabled = true
	cfg.Telemetry.Metrics.Prometheus.ListenAddr = "127.0.0.1:0"

	p := New(&cfg, nil)
	t.Cleanup(func() { _ = p.Shutdown(context.Background()) })

	instruments := p.NewInstruments()
	instruments.RecordRequest(context.Background(), "GET /{handle}", "GET", 200, 5*time.Millisecond)
	// The values below are what a real request would carry alongside the
	// pattern; none of them is passed to RecordRequest, and this asserts none
	// of them can appear anyway.
	instruments.RecordRequest(context.Background(), "GET /{handle}/{set}", "GET", 404, time.Millisecond)

	srv := NewMetricsServer(&cfg, p, nil)
	if srv == nil {
		t.Fatal("no scrape listener built")
	}
	rec := httptest.NewRecorder()
	srv.httpSrv.Handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))

	body := rec.Body.String()
	if !strings.Contains(body, "http_server_request_duration") {
		t.Fatalf("scrape output does not contain the request metric:\n%s", body)
	}
	for _, forbidden := range []string{
		"owner", "handle=", "key_set", "fingerprint", "SHA256:", "token", "authorization",
	} {
		if strings.Contains(strings.ToLower(body), strings.ToLower(forbidden)) {
			t.Errorf("scrape output contains %q; owner identifiers, handles, key set names and "+
				"fingerprints must never be metric labels:\n%s", forbidden, body)
		}
	}
}

// TestMetricSeriesCardinalityIsBoundedByCode is the DoS invariant for metrics,
// asserted on the real exposition rather than on the normalizer in isolation.
//
// It drives BOTH client-controlled dimensions at once: a distinct invented
// method and a distinct raw path per iteration. A test that varied only the
// path would pass against an implementation that used the raw method as a
// label -- net/http accepts any RFC 9110 token, so "-X AAAA1", "-X AAAA2", ...
// mints one permanent time series per request without ever changing the URL.
func TestMetricSeriesCardinalityIsBoundedByCode(t *testing.T) {
	cfg := config.Default()
	cfg.Telemetry.Metrics.Prometheus.Enabled = true
	cfg.Telemetry.Metrics.Prometheus.ListenAddr = "127.0.0.1:0"

	p := New(&cfg, nil)
	t.Cleanup(func() { _ = p.Shutdown(context.Background()) })
	instruments := p.NewInstruments()

	const n = 2000
	for i := range n {
		// Pattern "" is what an unmatched request carries; the method is a
		// token a client invented. Both are the raw, attacker-chosen values.
		instruments.RecordRequest(context.Background(), "",
			"XMETHOD"+strconv.Itoa(i), 404, time.Millisecond)
	}

	families, err := p.Registry().Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	series := 0
	for _, f := range families {
		series += len(f.GetMetric())
	}
	// One route x one method bucket x one status. The exact number matters
	// less than that it is a small constant and not a function of n.
	if series > 4 {
		t.Fatalf("%d requests with distinct methods and no matched route produced %d time series; "+
			"label values must come from closed sets, not from the request", n, series)
	}
}
