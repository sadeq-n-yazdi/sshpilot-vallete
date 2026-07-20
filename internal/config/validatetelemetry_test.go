package config

import (
	"strings"
	"testing"
)

// validTelemetryBase returns a config that passes Validate, so a telemetry test
// can change one field and know the resulting error is about that field.
func validTelemetryBase() Config {
	c := Default()
	c.Server.Environment = "development"
	c.TLS.Mode = "self_signed"
	return c
}

func telemetryErrors(t *testing.T, c Config) map[string]string {
	t.Helper()
	err := c.Validate()
	if err == nil {
		return nil
	}
	errs, ok := err.(ValidationErrors)
	if !ok {
		t.Fatalf("Validate returned %T, want ValidationErrors", err)
	}
	out := map[string]string{}
	for _, e := range errs {
		out[e.Field] = e.Msg
	}
	return out
}

// TestMetricsExposureIsFailClosedByDefault pins the default posture at the
// config layer: the shipped defaults name no scrape address, so no endpoint can
// be served, and the defaults are valid.
func TestMetricsExposureIsFailClosedByDefault(t *testing.T) {
	c := validTelemetryBase()
	if c.Telemetry.Metrics.Prometheus.ListenAddr != "" {
		t.Fatalf("default scrape listen_addr = %q, want empty (not served)",
			c.Telemetry.Metrics.Prometheus.ListenAddr)
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("defaults must validate: %v", err)
	}
}

// TestScrapeAddressMayNotCollideWithTheAPIListener is the exposure invariant at
// the config layer. Sharing the socket is exactly the unauthenticated public
// exposure the separate listener exists to prevent, and an operator reaches it
// by pasting one address into two fields.
func TestScrapeAddressMayNotCollideWithTheAPIListener(t *testing.T) {
	c := validTelemetryBase()
	c.Server.ListenAddr = "0.0.0.0:8443"
	c.Telemetry.Metrics.Prometheus.ListenAddr = "0.0.0.0:8443"

	errs := telemetryErrors(t, c)
	if _, ok := errs["telemetry.metrics.prometheus.listen_addr"]; !ok {
		t.Fatalf("a scrape address equal to server.listen_addr was accepted; errors: %v", errs)
	}
}

// TestScrapeAddressAndPathAreWellFormed keeps a misconfigured endpoint from
// starting as a listener that silently answers nothing.
func TestScrapeAddressAndPathAreWellFormed(t *testing.T) {
	tests := []struct {
		name  string
		addr  string
		path  string
		field string
	}{
		{"address without a port", "127.0.0.1", "/metrics", "telemetry.metrics.prometheus.listen_addr"},
		{"relative path", "127.0.0.1:9090", "metrics", "telemetry.metrics.prometheus.path"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := validTelemetryBase()
			c.Telemetry.Metrics.Prometheus.ListenAddr = tc.addr
			c.Telemetry.Metrics.Prometheus.Path = tc.path
			if _, ok := telemetryErrors(t, c)[tc.field]; !ok {
				t.Fatalf("%s was accepted, want an error on %s", tc.name, tc.field)
			}
		})
	}
}

// TestExportEndpointsMayNotEmbedCredentials keeps a secret out of a plain
// config field. An endpoint with userinfo puts a password into a value that is
// echoed by diagnostics and visible in a process listing.
func TestExportEndpointsMayNotEmbedCredentials(t *testing.T) {
	const withCreds = "https://collector:hunter2@otel.example.com/v1/traces"

	t.Run("traces", func(t *testing.T) {
		c := validTelemetryBase()
		c.Telemetry.Traces.Enabled = true
		c.Telemetry.Traces.Endpoint = withCreds
		assertRejectedWithoutEchoingTheSecret(t, c, "telemetry.traces.endpoint")
	})

	t.Run("otlp metrics", func(t *testing.T) {
		c := validTelemetryBase()
		c.Telemetry.Metrics.OTLP.Enabled = true
		c.Telemetry.Metrics.OTLP.Endpoint = withCreds
		assertRejectedWithoutEchoingTheSecret(t, c, "telemetry.metrics.otlp.endpoint")
	})
}

// assertRejectedWithoutEchoingTheSecret checks both halves: the config is
// refused, AND the refusal does not itself print the password it refused.
func assertRejectedWithoutEchoingTheSecret(t *testing.T, c Config, field string) {
	t.Helper()
	errs := telemetryErrors(t, c)
	msg, ok := errs[field]
	if !ok {
		t.Fatalf("an endpoint with embedded credentials was accepted; errors: %v", errs)
	}
	if strings.Contains(msg, "hunter2") {
		t.Fatalf("the validation error echoed the password: %q", msg)
	}
}

// TestSampleRatioIsBounded keeps a nonsense sampling ratio from reaching the
// SDK, where it would silently mean something the operator did not ask for.
func TestSampleRatioIsBounded(t *testing.T) {
	for _, ratio := range []float64{-0.1, 1.5} {
		c := validTelemetryBase()
		c.Telemetry.Traces.SampleRatio = ratio
		if _, ok := telemetryErrors(t, c)["telemetry.traces.sample_ratio"]; !ok {
			t.Errorf("sample_ratio %v was accepted", ratio)
		}
	}
	for _, ratio := range []float64{0, 0.5, 1} {
		c := validTelemetryBase()
		c.Telemetry.Traces.SampleRatio = ratio
		if err := c.Validate(); err != nil {
			t.Errorf("sample_ratio %v rejected: %v", ratio, err)
		}
	}
}
