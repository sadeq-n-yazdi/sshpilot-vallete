package httpserver

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// newTestLogger returns a JSON logger writing into a buffer, so tests can
// assert on exactly what would be persisted.
func newTestLogger() (*slog.Logger, *bytes.Buffer) {
	var buf bytes.Buffer
	return slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})), &buf
}

func TestRequestIDMiddleware(t *testing.T) {
	t.Parallel()

	const unsafeMarker = "evil"
	tests := []struct {
		name    string
		inbound string
		reused  bool
	}{
		{name: "absent generates", inbound: "", reused: false},
		{name: "safe value reused", inbound: "trace-abc_123.4", reused: true},
		{name: "crlf injection rejected", inbound: "evil\r\nX-Injected: 1", reused: false},
		{name: "space rejected", inbound: "evil value", reused: false},
		{name: "control char rejected", inbound: "evil\x00id", reused: false},
		{name: "json breaker rejected", inbound: `evil","leak":"`, reused: false},
		{name: "over long rejected", inbound: unsafeMarker + strings.Repeat("a", maxRequestIDLen), reused: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var fromCtx string
			h := requestIDMiddleware(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				fromCtx = RequestIDFromContext(r.Context())
			}))

			req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
			if tc.inbound != "" {
				req.Header.Set(RequestIDHeader, tc.inbound)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			got := rec.Header().Get(RequestIDHeader)
			if got == "" {
				t.Fatal("response is missing a request ID header")
			}
			if got != fromCtx {
				t.Errorf("context ID %q does not match header %q", fromCtx, got)
			}
			if !safeRequestID(got) {
				t.Errorf("emitted ID %q is not in the safe charset", got)
			}

			if tc.reused {
				if got != tc.inbound {
					t.Errorf("safe inbound ID not reused: got %q, want %q", got, tc.inbound)
				}
				return
			}
			// The unsafe value must not survive anywhere.
			if got == tc.inbound {
				t.Fatalf("unsafe inbound ID %q was echoed back", tc.inbound)
			}
			if tc.inbound != "" && strings.Contains(got, unsafeMarker) {
				t.Errorf("emitted ID %q retains part of the rejected input", got)
			}
			if _, ok := rec.Header()["X-Injected"]; ok {
				t.Error("header injection succeeded via X-Request-Id")
			}
		})
	}
}

func TestRequestIDFromContextAbsent(t *testing.T) {
	t.Parallel()

	if got := RequestIDFromContext(t.Context()); got != "" {
		t.Errorf("got %q, want empty string for a context with no request ID", got)
	}
}

func TestNewRequestIDIsUniqueAndSafe(t *testing.T) {
	t.Parallel()

	seen := make(map[string]bool, 128)
	for range 128 {
		id := newRequestID()
		if !safeRequestID(id) {
			t.Fatalf("generated ID %q is not in the safe charset", id)
		}
		if seen[id] {
			t.Fatalf("generated ID %q repeated", id)
		}
		seen[id] = true
	}
}

func TestLoggingMiddlewareOmitsQueryString(t *testing.T) {
	t.Parallel()

	const secret = "s3cr3t-token-value"
	logger, buf := newTestLogger()

	h := chain(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
		_, _ = w.Write([]byte("hi"))
	}), requestIDMiddleware, loggingMiddleware(logger))

	req := httptest.NewRequest(http.MethodGet, "/publish?token="+secret, nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	req.Header.Set("Cookie", "session="+secret)
	h.ServeHTTP(httptest.NewRecorder(), req)

	out := buf.String()
	if strings.Contains(out, secret) {
		t.Fatalf("access log leaked a sensitive value:\n%s", out)
	}
	for _, banned := range []string{"token=", "Authorization", "Bearer", "Cookie", "session="} {
		if strings.Contains(out, banned) {
			t.Errorf("access log contains %q:\n%s", banned, out)
		}
	}

	var rec map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &rec); err != nil {
		t.Fatalf("log record is not valid JSON: %v", err)
	}
	if rec["msg"] != "http request" {
		t.Errorf("msg = %v, want %q", rec["msg"], "http request")
	}
	if rec["method"] != http.MethodGet {
		t.Errorf("method = %v, want GET", rec["method"])
	}
	if rec["path"] != "/publish" {
		t.Errorf("path = %v, want /publish (query stripped)", rec["path"])
	}
	if rec["status"] != float64(http.StatusTeapot) {
		t.Errorf("status = %v, want %d", rec["status"], http.StatusTeapot)
	}
	if id, _ := rec["request_id"].(string); !safeRequestID(id) {
		t.Errorf("request_id = %v, want a safe generated ID", rec["request_id"])
	}
	for _, key := range []string{"duration", "bytes"} {
		if _, ok := rec[key]; !ok {
			t.Errorf("log record is missing %q", key)
		}
	}
}

func TestLoggingMiddlewareRecordsRoutePattern(t *testing.T) {
	t.Parallel()

	logger, buf := newTestLogger()
	h := NewHandler(nil, logger, okPinger{}, stubPublisher{})

	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/healthz", nil))

	if got := buf.String(); !strings.Contains(got, `"route":"GET /healthz"`) {
		t.Errorf("log is missing the matched route pattern:\n%s", got)
	}
}

func TestLoggingMiddlewareSanitizesPath(t *testing.T) {
	t.Parallel()

	logger, buf := newTestLogger()
	h := chain(http.NotFoundHandler(), loggingMiddleware(logger))

	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.URL.Path = "/a\nb\x1b[31m" + strings.Repeat("z", maxLoggedPathLen)
	h.ServeHTTP(httptest.NewRecorder(), req)

	var rec map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(buf.String())), &rec); err != nil {
		t.Fatalf("log record is not valid JSON: %v", err)
	}
	path, _ := rec["path"].(string)
	if len(path) > maxLoggedPathLen {
		t.Errorf("logged path length %d exceeds the %d cap", len(path), maxLoggedPathLen)
	}
	for _, bad := range []string{"\n", "\x1b"} {
		if strings.Contains(path, bad) {
			t.Errorf("logged path retains control character %q: %q", bad, path)
		}
	}
}

func TestLoggingMiddlewareDefaultsToImplicit200(t *testing.T) {
	t.Parallel()

	logger, buf := newTestLogger()
	h := chain(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {}), loggingMiddleware(logger))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))

	if got := buf.String(); !strings.Contains(got, `"status":200`) {
		t.Errorf("a handler that writes nothing should log 200:\n%s", got)
	}
}

func TestStatusRecorderKeepsFirstStatus(t *testing.T) {
	t.Parallel()

	inner := httptest.NewRecorder()
	rec := &statusRecorder{ResponseWriter: inner}
	rec.WriteHeader(http.StatusCreated)
	rec.WriteHeader(http.StatusInternalServerError)
	if _, err := rec.Write([]byte("body")); err != nil {
		t.Fatalf("write: %v", err)
	}

	if rec.status() != http.StatusCreated {
		t.Errorf("status = %d, want %d", rec.status(), http.StatusCreated)
	}
	if rec.bytes != 4 {
		t.Errorf("bytes = %d, want 4", rec.bytes)
	}
	if rec.Unwrap() != inner {
		t.Error("Unwrap did not return the wrapped ResponseWriter")
	}
}

func TestRecoveryMiddlewareReturns500WithoutLeaking(t *testing.T) {
	t.Parallel()

	logger, buf := newTestLogger()
	const internal = "internal-detail-do-not-leak"

	h := chain(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		panic(internal)
	}), requestIDMiddleware, loggingMiddleware(logger), recoveryMiddleware(logger))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/boom", nil))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}

	body := rec.Body.String()
	if strings.Contains(body, internal) {
		t.Errorf("response body leaked the panic value: %q", body)
	}
	for _, leak := range []string{"goroutine", "httpserver.", ".go:", "runtime"} {
		if strings.Contains(body, leak) {
			t.Errorf("response body leaks internals (%q): %q", leak, body)
		}
	}

	var resp statusResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("body is not the generic JSON envelope: %v (%q)", err, body)
	}
	if resp.Status != "error" {
		t.Errorf("status field = %q, want %q", resp.Status, "error")
	}

	// The detail belongs in the log, correlated by request ID.
	logged := buf.String()
	if !strings.Contains(logged, internal) {
		t.Errorf("panic value was not logged:\n%s", logged)
	}
	if !strings.Contains(logged, rec.Header().Get(RequestIDHeader)) {
		t.Errorf("panic log is missing the request ID:\n%s", logged)
	}
	if !strings.Contains(logged, `"status":500`) {
		t.Errorf("access log did not record the 500 status:\n%s", logged)
	}
}

func TestRecoveryMiddlewareKeepsServerUsable(t *testing.T) {
	t.Parallel()

	logger, _ := newTestLogger()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /boom", func(_ http.ResponseWriter, _ *http.Request) { panic("boom") })
	mux.HandleFunc("GET /fine", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("fine"))
	})
	h := chain(mux, requestIDMiddleware, loggingMiddleware(logger), recoveryMiddleware(logger))

	boom := httptest.NewRecorder()
	h.ServeHTTP(boom, httptest.NewRequest(http.MethodGet, "/boom", nil))
	if boom.Code != http.StatusInternalServerError {
		t.Fatalf("panicking route status = %d, want 500", boom.Code)
	}

	after := httptest.NewRecorder()
	h.ServeHTTP(after, httptest.NewRequest(http.MethodGet, "/fine", nil))
	if after.Code != http.StatusOK {
		t.Errorf("handler after a panic returned %d, want 200", after.Code)
	}
	if after.Body.String() != "fine" {
		t.Errorf("body = %q, want %q", after.Body.String(), "fine")
	}
}

func TestRecoveryMiddlewareRepanicsAbortHandler(t *testing.T) {
	t.Parallel()

	logger, buf := newTestLogger()
	h := recoveryMiddleware(logger)(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		panic(http.ErrAbortHandler)
	}))

	defer func() {
		p := recover()
		if p == nil {
			t.Fatal("http.ErrAbortHandler was swallowed; it must be re-panicked")
		}
		if p != http.ErrAbortHandler { //nolint:errorlint // panicked by value.
			t.Fatalf("re-panicked with %v, want http.ErrAbortHandler", p)
		}
		if strings.Contains(buf.String(), "panic recovered") {
			t.Error("a deliberate abort must not be logged as a recovered panic")
		}
	}()

	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/abort", nil))
}

func TestRecoveryMiddlewareAfterResponseStarted(t *testing.T) {
	t.Parallel()

	logger, _ := newTestLogger()
	h := chain(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("partial"))
		panic("too late")
	}), loggingMiddleware(logger), recoveryMiddleware(logger))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/late", nil))

	// The status line is already on the wire; it cannot be rewritten to 500.
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want the already-sent 200", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "too late") {
		t.Errorf("panic value leaked into the body: %q", rec.Body.String())
	}
}

func TestChainAppliesOutermostFirst(t *testing.T) {
	t.Parallel()

	var order []string
	mark := func(name string) Middleware {
		return func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				order = append(order, name)
				next.ServeHTTP(w, r)
			})
		}
	}

	h := chain(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		order = append(order, "handler")
	}), mark("first"), mark("second"), mark("third"))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))

	want := []string{"first", "second", "third", "handler"}
	if strings.Join(order, ",") != strings.Join(want, ",") {
		t.Errorf("order = %v, want %v", order, want)
	}
}

// TestRecoveryStandaloneDoesNotCorruptStartedResponse covers the case that the
// old statusRecorder type assertion got wrong: recoveryMiddleware used on its
// own, with no loggingMiddleware above it. The assertion failed there, so a
// panic raised after the handler had already written left recovery believing
// nothing had been sent, and it appended a 500 body to a 200 response.
func TestRecoveryStandaloneDoesNotCorruptStartedResponse(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))

	h := recoveryMiddleware(logger)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte(`{"status":"ok"}`)); err != nil {
			t.Errorf("write: %v", err)
		}
		panic("after headers")
	}))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d (status line was already sent)", rec.Code, http.StatusOK)
	}
	if body := rec.Body.String(); body != `{"status":"ok"}` {
		t.Fatalf("body = %q, want the original response with nothing appended", body)
	}
	if !strings.Contains(buf.String(), "panic recovered") {
		t.Fatal("panic should still be logged")
	}
}

// TestRecoveryStandaloneWritesFiveHundredBeforeAnySend is the other half: with
// nothing yet sent, recovery must still produce a 500 when used standalone.
func TestRecoveryStandaloneWritesFiveHundredBeforeAnySend(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(&bytes.Buffer{}, nil))
	h := recoveryMiddleware(logger)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("before headers")
	}))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", nil))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "before headers") {
		t.Fatal("panic value must never reach the client")
	}
}

func TestSanitizeLogPathReturnsCleanInputUnchanged(t *testing.T) {
	for _, p := range []string{"", "/", "/alice/default", "/a/b?c=d", "/naïve/路径"} {
		if got := sanitizeLogPath(p); got != p {
			t.Errorf("sanitizeLogPath(%q) = %q, want it returned unchanged", p, got)
		}
	}
}

func TestSanitizeLogPathStillReplacesControlBytes(t *testing.T) {
	got := sanitizeLogPath("/a\r\nX-Injected: 1\x00\x7f/b")
	for _, bad := range []string{"\r", "\n", "\x00", "\x7f"} {
		if strings.Contains(got, bad) {
			t.Fatalf("sanitized path %q still contains %q", got, bad)
		}
	}
	// Multi-byte runes must survive the byte-level scan intact.
	if got := sanitizeLogPath("/naïve\n"); !strings.Contains(got, "naïve") {
		t.Fatalf("multi-byte rune corrupted: %q", got)
	}
}
