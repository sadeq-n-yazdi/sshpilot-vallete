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

// startUpstreamServer binds the plaintext upstream server on a port-0 loopback
// listener with the given trusted-proxy list and returns its base URL. The
// client's peer address on this listener is 127.0.0.1, so a test lists (or
// omits) that address to make the immediate peer trusted (or not).
func startUpstreamServer(t *testing.T, trustedProxies []string) string {
	t.Helper()
	cfg := config.Default()
	cfg.TLS.Mode = "upstream"
	cfg.Server.TrustedProxies = trustedProxies

	s, err := NewUpstreamServer(&cfg, nil, nil, stubPublisher{})
	if err != nil {
		t.Fatalf("NewUpstreamServer: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = s.Serve(ln) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = s.Shutdown(ctx)
	})
	return "http://" + ln.Addr().String()
}

// doWithProto issues GET url, optionally setting X-Forwarded-Proto, and returns
// the status code.
func doWithProto(t *testing.T, url, proto string) int {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if proto != "" {
		req.Header.Set("X-Forwarded-Proto", proto)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do %s: %v", url, err)
	}
	defer func() { _, _ = io.Copy(io.Discard, resp.Body); _ = resp.Body.Close() }()
	return resp.StatusCode
}

// TestUpstreamListenerEnforcesTrustedProxyAndProto is the core fence for the
// plaintext upstream listener (ADR-0015, Decision 31): a request is served only
// when it arrives from a configured trusted proxy AND carries
// X-Forwarded-Proto: https. Every other shape is refused, so a plaintext request
// that bypassed the proxy -- or a proxy that did not assert https -- cannot be
// served as if the client's connection were encrypted.
func TestUpstreamListenerEnforcesTrustedProxyAndProto(t *testing.T) {
	t.Run("trusted proxy with https is served", func(t *testing.T) {
		base := startUpstreamServer(t, []string{"127.0.0.1", "::1"})
		if code := doWithProto(t, base+"/healthz", "https"); code != http.StatusOK {
			t.Errorf("trusted peer + https: got %d, want 200", code)
		}
	})

	t.Run("missing forwarded proto is refused", func(t *testing.T) {
		base := startUpstreamServer(t, []string{"127.0.0.1", "::1"})
		if code := doWithProto(t, base+"/healthz", ""); code != http.StatusBadRequest {
			t.Errorf("trusted peer, no proto header: got %d, want 400", code)
		}
	})

	t.Run("forwarded proto http is refused", func(t *testing.T) {
		base := startUpstreamServer(t, []string{"127.0.0.1", "::1"})
		if code := doWithProto(t, base+"/healthz", "http"); code != http.StatusBadRequest {
			t.Errorf("trusted peer, proto http: got %d, want 400", code)
		}
	})

	t.Run("untrusted peer is refused even with https", func(t *testing.T) {
		// The client's peer is 127.0.0.1, which is NOT in this list, so the
		// forwarded header carries no authority no matter what it says.
		base := startUpstreamServer(t, []string{"10.0.0.1"})
		if code := doWithProto(t, base+"/healthz", "https"); code != http.StatusBadRequest {
			t.Errorf("untrusted peer + https: got %d, want 400", code)
		}
	})

	t.Run("publish path is gated too", func(t *testing.T) {
		// The gate is uniform: even an ordinary publish GET is refused without a
		// trusted https hop, so nothing on the API is reachable in the clear.
		base := startUpstreamServer(t, []string{"10.0.0.1"})
		if code := doWithProto(t, base+"/alice", "https"); code != http.StatusBadRequest {
			t.Errorf("untrusted peer on publish path: got %d, want 400", code)
		}
	})
}

// TestNewUpstreamServerRefusesNilPublisher pins the fail-closed constructor: a
// server that cannot answer the publish endpoint must never bind a port, exactly
// as Server.New requires.
func TestNewUpstreamServerRefusesNilPublisher(t *testing.T) {
	cfg := config.Default()
	cfg.TLS.Mode = "upstream"
	if _, err := NewUpstreamServer(&cfg, nil, nil, nil); err == nil {
		t.Fatal("expected NewUpstreamServer to refuse a nil publisher")
	}
}
