package httpserver

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/version"
)

// okPinger is a healthy readiness dependency.
type okPinger struct{}

func (okPinger) PingContext(context.Context) error { return nil }

// errPinger is a dependency that always fails, standing in for a down database.
type errPinger struct{ err error }

func (p errPinger) PingContext(context.Context) error { return p.err }

// blockingPinger never answers on its own; it returns only when the caller's
// deadline fires, which is exactly how a wedged database behaves.
type blockingPinger struct{}

func (blockingPinger) PingContext(ctx context.Context) error {
	<-ctx.Done()
	return ctx.Err()
}

func TestHealthzIsLivenessOnly(t *testing.T) {
	t.Parallel()

	// A broken dependency must NOT affect liveness: restarting the process
	// would not fix a database outage.
	logger, _ := newTestLogger()
	h := NewHandler(logger, errPinger{err: errors.New("database down")})

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 even with a failing dependency", rec.Code)
	}

	var body statusResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("body is not JSON: %v (%q)", err, rec.Body.String())
	}
	if body.Status != "ok" {
		t.Errorf("status = %q, want %q", body.Status, "ok")
	}
	if body.Version != version.String() {
		t.Errorf("version = %q, want %q", body.Version, version.String())
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("Content-Type = %q, want JSON", ct)
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", cc)
	}
	if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Error("X-Content-Type-Options: nosniff is missing")
	}
}

func TestReadyzReflectsDependencyHealth(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		pinger     Pinger
		wantStatus int
		wantBody   string
	}{
		{name: "healthy", pinger: okPinger{}, wantStatus: http.StatusOK, wantBody: "ready"},
		{
			name:       "ping fails",
			pinger:     errPinger{err: errors.New("connection refused")},
			wantStatus: http.StatusServiceUnavailable,
			wantBody:   "unavailable",
		},
		{
			name:       "ping times out",
			pinger:     blockingPinger{},
			wantStatus: http.StatusServiceUnavailable,
			wantBody:   "unavailable",
		},
		{
			name:       "no pinger configured",
			pinger:     nil,
			wantStatus: http.StatusServiceUnavailable,
			wantBody:   "unavailable",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			logger, _ := newTestLogger()
			// A pre-canceled context makes the timeout case terminate at once
			// instead of waiting out readyPingTimeout, with no flakiness.
			ctx := t.Context()
			if _, blocking := tc.pinger.(blockingPinger); blocking {
				canceled, cancel := context.WithCancel(ctx)
				cancel()
				ctx = canceled
			}

			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/readyz", nil).WithContext(ctx)
			NewHandler(logger, tc.pinger).ServeHTTP(rec, req)

			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d", rec.Code, tc.wantStatus)
			}

			var body statusResponse
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("body is not JSON: %v (%q)", err, rec.Body.String())
			}
			if body.Status != tc.wantBody {
				t.Errorf("status = %q, want %q", body.Status, tc.wantBody)
			}
		})
	}
}

func TestReadyzDoesNotDiscloseTheFailureReason(t *testing.T) {
	t.Parallel()

	const detail = "dial tcp 10.0.0.7:5432: connection refused"
	logger, buf := newTestLogger()

	rec := httptest.NewRecorder()
	NewHandler(logger, errPinger{err: errors.New(detail)}).
		ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))

	if strings.Contains(rec.Body.String(), detail) {
		t.Errorf("readiness response disclosed the failure reason: %q", rec.Body.String())
	}
	if !strings.Contains(buf.String(), detail) {
		t.Errorf("the failure reason should still be logged:\n%s", buf.String())
	}
}

func TestRoutesRejectWrongMethodAndUnknownPaths(t *testing.T) {
	t.Parallel()

	logger, _ := newTestLogger()
	h := NewHandler(logger, okPinger{})

	tests := []struct {
		name       string
		method     string
		path       string
		wantStatus int
	}{
		{name: "post healthz", method: http.MethodPost, path: "/healthz", wantStatus: http.StatusMethodNotAllowed},
		{name: "post readyz", method: http.MethodPost, path: "/readyz", wantStatus: http.StatusMethodNotAllowed},
		// Publish routes are a later track; nothing beyond health is mounted.
		{name: "unknown handle route", method: http.MethodGet, path: "/someone", wantStatus: http.StatusNotFound},
		{name: "root", method: http.MethodGet, path: "/", wantStatus: http.StatusNotFound},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(tc.method, tc.path, nil))
			if rec.Code != tc.wantStatus {
				t.Errorf("%s %s = %d, want %d", tc.method, tc.path, rec.Code, tc.wantStatus)
			}
		})
	}
}

func TestNewHandlerToleratesNilLogger(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	NewHandler(nil, okPinger{}).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}
