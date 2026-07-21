package httpserver

import (
	"context"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/config"
)

// startHealthServer binds the health server on a port-0 loopback listener and
// returns its base URL, serving in the background until the test ends.
func startHealthServer(t *testing.T, pinger Pinger) string {
	t.Helper()
	cfg := config.Default()
	// A concrete address is required only so NewHealthServer builds a server; the
	// actual bind happens on the port-0 listener below, so the value is unused for
	// listening and simply must be non-empty.
	cfg.Server.HealthListenAddr = "127.0.0.1:0"
	h := NewHealthServer(&cfg, nil, pinger)
	if h == nil {
		t.Fatal("NewHealthServer returned nil for a configured address")
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = h.Serve(ln) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = h.Shutdown(ctx)
	})
	return "http://" + ln.Addr().String()
}

func getStatus(t *testing.T, url string) int {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do %s: %v", url, err)
	}
	defer func() { _, _ = io.Copy(io.Discard, resp.Body); _ = resp.Body.Close() }()
	return resp.StatusCode
}

// TestHealthServerServesOnlyHealthAndReadiness pins the surface of the plaintext
// probe listener: /healthz and /readyz answer, and NOTHING else does. The
// publish and management paths that exist on the real API mux must be 404 here,
// so an operator cannot reach an unauthenticated management or key surface by
// probing the health socket.
func TestHealthServerServesOnlyHealthAndReadiness(t *testing.T) {
	base := startHealthServer(t, okPinger{})

	if code := getStatus(t, base+"/healthz"); code != http.StatusOK {
		t.Errorf("/healthz: got %d, want 200", code)
	}
	if code := getStatus(t, base+"/readyz"); code != http.StatusOK {
		t.Errorf("/readyz: got %d, want 200", code)
	}

	// Every one of these is a live route on the real API mux (see router.go). On
	// the health listener each must be unrouted -- a 404 from the mux itself.
	for _, path := range []string{
		"/alice",                           // publish default set
		"/alice/prod",                      // publish named set
		"/api/v1/keys",                     // management
		"/api/v1/keysets",                  // management
		"/api/v1/admin/reserved/allowlist", // admin list
		"/docs",                            // docs
		"/install/vallet-helper.sh",        // installer
		"/metrics",                         // scrape
	} {
		if code := getStatus(t, base+path); code != http.StatusNotFound {
			t.Errorf("%s: got %d, want 404 (surface must be health-only)", path, code)
		}
	}
}

// TestHealthServerReadinessReflectsPinger proves /readyz is the real readiness
// check, not a stub: a failing dependency drives it to 503, the same fail-closed
// meaning it carries on the HTTPS listener.
func TestHealthServerReadinessReflectsPinger(t *testing.T) {
	base := startHealthServer(t, errPinger{err: context.DeadlineExceeded})

	if code := getStatus(t, base+"/healthz"); code != http.StatusOK {
		t.Errorf("/healthz should stay 200 regardless of dependencies, got %d", code)
	}
	if code := getStatus(t, base+"/readyz"); code != http.StatusServiceUnavailable {
		t.Errorf("/readyz with a down dependency: got %d, want 503", code)
	}
}

// TestNewHealthServerNilWhenUnconfigured pins the fail-closed default: with no
// health address the listener does not exist, and its nil value is a safe no-op
// through every method (this is what serve() relies on).
func TestNewHealthServerNilWhenUnconfigured(t *testing.T) {
	cfg := config.Default()
	if h := NewHealthServer(&cfg, nil, okPinger{}); h != nil {
		t.Fatal("NewHealthServer should return nil when no health address is set")
	}
	if NewHealthServer(nil, nil, okPinger{}) != nil {
		t.Fatal("NewHealthServer(nil cfg) should return nil")
	}

	var h *HealthServer
	if got := h.Addr(); got != "" {
		t.Errorf("nil HealthServer Addr: got %q, want empty", got)
	}
	if err := h.ListenAndServe(); err != nil {
		t.Errorf("nil HealthServer ListenAndServe: got %v, want nil", err)
	}
	if err := h.Shutdown(context.Background()); err != nil {
		t.Errorf("nil HealthServer Shutdown: got %v, want nil", err)
	}
}
