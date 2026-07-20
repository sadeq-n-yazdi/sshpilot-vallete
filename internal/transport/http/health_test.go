package httpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
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
	h := NewHandler(nil, logger, errPinger{err: errors.New("database down")}, stubPublisher{})

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
			NewHandler(nil, logger, tc.pinger, stubPublisher{}).ServeHTTP(rec, req)

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
	NewHandler(nil, logger, errPinger{err: errors.New(detail)}, stubPublisher{}).
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
	h := NewHandler(nil, logger, okPinger{}, stubPublisher{})

	tests := []struct {
		name       string
		method     string
		path       string
		wantStatus int
	}{
		{name: "post healthz", method: http.MethodPost, path: "/healthz", wantStatus: http.StatusMethodNotAllowed},
		{name: "post readyz", method: http.MethodPost, path: "/readyz", wantStatus: http.StatusMethodNotAllowed},
		// The publish routes accept only GET (and the HEAD that GET implies);
		// a write to a read-only endpoint is refused by the mux itself.
		{name: "post handle", method: http.MethodPost, path: "/someone", wantStatus: http.StatusMethodNotAllowed},
		{name: "post handle set", method: http.MethodPost, path: "/someone/work", wantStatus: http.StatusMethodNotAllowed},
		// The root is not a handle: a wildcard segment never matches empty, so
		// "/" stays unrouted rather than resolving to some default account.
		{name: "root", method: http.MethodGet, path: "/", wantStatus: http.StatusNotFound},
		// Nothing is mounted below a set, so a third segment is not a route.
		{name: "too many segments", method: http.MethodGet, path: "/someone/work/extra", wantStatus: http.StatusNotFound},
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
	NewHandler(nil, nil, okPinger{}, stubPublisher{}).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

// TestReadyzLogsClientCancellationBelowWarn separates "this instance cannot
// reach its database" from "the probe hung up". Both still answer 503 — the
// instance genuinely did not confirm readiness — but only the former is an
// operator-actionable fault. A load balancer with a tight probe timeout would
// otherwise emit a steady stream of Warn lines and train readers to ignore the
// message that signals a real outage.
func TestReadyzLogsClientCancellationBelowWarn(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // the client is gone before the ping is attempted

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil).WithContext(ctx)
	rec := httptest.NewRecorder()
	readyzHandler(errPinger{err: context.Canceled}, logger)(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503: readiness was still not confirmed", rec.Code)
	}

	var entry struct {
		Level string `json:"level"`
		Msg   string `json:"msg"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &entry); err != nil {
		t.Fatalf("decode log entry %q: %v", buf.String(), err)
	}
	if entry.Level == slog.LevelWarn.String() || entry.Level == slog.LevelError.String() {
		t.Fatalf("client cancellation logged at %s; must not alert operators", entry.Level)
	}
	if entry.Msg == "readiness check failed" {
		t.Fatal("client cancellation must not reuse the genuine-failure message")
	}
}

// TestReadyzStillWarnsOnRealDependencyFailure guards the other direction: the
// cancellation carve-out must not downgrade an actual database outage.
func TestReadyzStillWarnsOnRealDependencyFailure(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rec := httptest.NewRecorder()
	readyzHandler(errPinger{err: errors.New("connection refused")}, logger)(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
	if !strings.Contains(buf.String(), slog.LevelWarn.String()) {
		t.Fatalf("real dependency failure must stay at Warn, got %s", buf.String())
	}
}
