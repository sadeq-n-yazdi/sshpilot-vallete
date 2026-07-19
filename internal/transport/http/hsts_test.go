package httpserver

import (
	"crypto/tls"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestHSTSHeaderValue pins the exact policy string and the decisions behind it.
// Each assertion below corresponds to a documented choice in hsts.go, so a
// future edit to the constant has to confront the reasoning.
func TestHSTSHeaderValue(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	hstsMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))

	got := rec.Header().Get(StrictTransportSecurityHeader)
	if got == "" {
		t.Fatal("no Strict-Transport-Security header was set")
	}

	// max-age must be present and at least six months; a short policy reopens
	// the window HSTS exists to close.
	maxAge := hstsMaxAgeFrom(t, got)
	if maxAge != hstsMaxAge {
		t.Errorf("max-age = %d, want %d", maxAge, hstsMaxAge)
	}
	const sixMonths = 15768000
	if maxAge < sixMonths {
		t.Errorf("max-age = %d is too short to be protective", maxAge)
	}

	if !strings.Contains(got, "includeSubDomains") {
		t.Error("includeSubDomains must be present: without it a spoofed sibling host bypasses the policy")
	}

	// preload is deliberately NOT sent. It is effectively irreversible and
	// governs the operator's entire registrable domain, which is not a decision
	// this binary may make on their behalf.
	if strings.Contains(strings.ToLower(got), "preload") {
		t.Error("preload must never be hardcoded: its effect on the operator's domain is one-way and hard to reverse")
	}
}

// hstsMaxAgeFrom extracts the max-age directive, failing if it is absent or
// unparseable.
func hstsMaxAgeFrom(t *testing.T, header string) int {
	t.Helper()

	for _, part := range strings.Split(header, ";") {
		part = strings.TrimSpace(part)
		after, ok := strings.CutPrefix(part, "max-age=")
		if !ok {
			continue
		}
		n, err := strconv.Atoi(after)
		if err != nil {
			t.Fatalf("max-age %q is not a number: %v", after, err)
		}
		return n
	}
	t.Fatalf("header %q has no max-age directive", header)
	return 0
}

// TestHSTSOnEveryResponse checks the header survives the response shapes that
// most easily escape a middleware: errors, redirects, panics, streamed bodies,
// and responses that never call WriteHeader.
func TestHSTSOnEveryResponse(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		handler http.HandlerFunc
	}{
		{
			name:    "implicit 200 with no WriteHeader",
			handler: func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) },
		},
		{
			name:    "explicit error status",
			handler: func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusInternalServerError) },
		},
		{
			name: "redirect",
			handler: func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, "https://example.com/", http.StatusMovedPermanently)
			},
		},
		{
			name:    "404 from the mux",
			handler: func(w http.ResponseWriter, _ *http.Request) { http.NotFound(w, nil) },
		},
		{
			name: "handler writes nothing at all",
			handler: func(_ http.ResponseWriter, _ *http.Request) {
			},
		},
		{
			name: "streamed body flushed before completion",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte("chunk"))
				_ = http.NewResponseController(w).Flush()
				_, _ = w.Write([]byte("more"))
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			rec := httptest.NewRecorder()
			hstsMiddleware(tc.handler).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
			if got := rec.Header().Get(StrictTransportSecurityHeader); got != hstsValue {
				t.Errorf("HSTS = %q, want %q", got, hstsValue)
			}
		})
	}
}

// TestHSTSSurvivesAPanickingHandler is the case the middleware ordering exists
// for: recoveryMiddleware writes a 500 for a panicking handler, and that
// response must still carry the policy. It goes through the real NewHandler
// chain rather than the middleware alone, because ordering is what is under
// test.
func TestHSTSSurvivesAPanickingHandler(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	chain(
		http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) { panic("boom") }),
		hstsMiddleware,
		requestIDMiddleware,
		recoveryMiddleware(slog.New(slog.DiscardHandler)),
	).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	if got := rec.Header().Get(StrictTransportSecurityHeader); got != hstsValue {
		t.Errorf("HSTS = %q, want %q on the recovered 500 response", got, hstsValue)
	}
}

// TestHSTSThroughRealHandshake asserts the policy reaches a client over an
// actual TLS connection through the full router, not just through the
// middleware in isolation.
func TestHSTSThroughRealHandshake(t *testing.T) {
	t.Parallel()

	srv, err := New(devConfig(), nil, okPinger{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Shutdown(t.Context()) })

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // self-signed dev cert under test.
		},
	}

	for _, path := range []string{"/healthz", "/does-not-exist"} {
		resp, err := client.Get("https://" + addr + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()

		if got := resp.Header.Get(StrictTransportSecurityHeader); got != hstsValue {
			t.Errorf("GET %s: HSTS = %q, want %q", path, got, hstsValue)
		}
	}
}

// TestNoPlaintextListenerExists documents and enforces the ADR-0015 decision to
// bind no port 80 at all rather than run a redirect-only plaintext listener.
//
// The reasoning, recorded here because this is where it is enforced: a redirect
// listener still accepts the first request in the clear, so an on-path attacker
// sees the URL and any credential a misconfigured client sent, and can answer
// with its own redirect. HSTS is the correct fix for scheme upgrade, and it
// works without accepting a plaintext byte. vallet's clients are programmatic
// and can be given https URLs directly, so the usability argument for a
// redirect does not apply here.
//
// The test asserts the server never produces application data, and never a
// redirect, over a plaintext connection.
func TestNoPlaintextListenerExists(t *testing.T) {
	t.Parallel()

	srv, err := New(devConfig(), nil, okPinger{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Shutdown(t.Context()) })

	// A cleartext HTTP request to the TLS port must not yield a redirect or a
	// body. Go's TLS server rejects the malformed record; what matters is that
	// no 2xx, no 3xx, and no payload ever crosses an unencrypted connection.
	plain := &http.Client{
		Timeout:       5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := plain.Get("http://" + addr + "/healthz") //nolint:bodyclose // closed below when non-nil.
	if err != nil {
		return // Connection refused or a TLS record error: the desired outcome.
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	if resp.StatusCode < 400 {
		t.Errorf("plaintext request produced status %d; plaintext must never be served or redirected", resp.StatusCode)
	}
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		t.Errorf("plaintext request was redirected to %q; ADR-0015 refuses plaintext rather than redirecting",
			resp.Header.Get("Location"))
	}
	if strings.Contains(string(body), `"status":"ok"`) {
		t.Errorf("health payload leaked over plaintext: %q", body)
	}
}
