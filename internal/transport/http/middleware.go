package httpserver

import (
	"log/slog"
	"net/http"
	"time"
)

// Middleware wraps a handler with cross-cutting behavior.
type Middleware func(http.Handler) http.Handler

// chain composes middleware around h. The first element of mw is the OUTERMOST
// layer — it sees the request first and the response last — so a call reads in
// the same order the request travels:
//
//	chain(mux, requestIDMiddleware, loggingMiddleware(log), recoveryMiddleware(log))
//
// It is built back-to-front precisely so callers can write it front-to-back.
func chain(h http.Handler, mw ...Middleware) http.Handler {
	for i := len(mw) - 1; i >= 0; i-- {
		h = mw[i](h)
	}
	return h
}

// maxLoggedPathLen bounds the path recorded in the access log, so a very long
// URL cannot be used to bloat log storage.
const maxLoggedPathLen = 256

// statusRecorder observes the response status and byte count without buffering
// the body. WriteHeader may legitimately never be called (an implicit 200), so
// the zero value reports 200 only once something has actually been written or
// the handler has returned normally; see status.
type statusRecorder struct {
	http.ResponseWriter
	code    int
	written bool
	bytes   int64
}

func (r *statusRecorder) WriteHeader(code int) {
	if r.written {
		// Duplicate WriteHeader: net/http already ignores it and logs a
		// warning. Keep the first status, which is the one on the wire.
		return
	}
	r.code = code
	r.written = true
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	if !r.written {
		// An implicit 200 from the first Write, mirroring net/http.
		r.code = http.StatusOK
		r.written = true
	}
	n, err := r.ResponseWriter.Write(b)
	r.bytes += int64(n)
	return n, err
}

// Unwrap exposes the underlying writer to http.ResponseController so that
// wrapping does not silently disable flushing, hijacking, or deadline control.
func (r *statusRecorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }

// status returns the status to report. A handler that returns without writing
// anything still produces a 200 on the wire.
func (r *statusRecorder) status() int {
	if !r.written {
		return http.StatusOK
	}
	return r.code
}

// requestIDMiddleware attaches a correlation ID to the request context and the
// response header.
//
// An inbound X-Request-Id is reused only when it passes safeRequestID;
// otherwise it is DISCARDED and a fresh random ID takes its place. The rejected
// value is never stored, logged, or echoed — it is attacker-controlled input,
// and the only safe treatment of an untrusted identifier is to replace it.
func requestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get(RequestIDHeader)
		if !safeRequestID(id) {
			id = newRequestID()
		}
		w.Header().Set(RequestIDHeader, id)
		next.ServeHTTP(w, r.WithContext(ContextWithRequestID(r.Context(), id)))
	})
}

// loggingMiddleware emits one structured access-log record per request.
//
// The recorded fields are deliberately minimal: method, matched route pattern,
// sanitized path, status, duration, and request ID. The query string, headers,
// cookies, and body are NEVER recorded — publish and management requests carry
// bearer tokens and key material, and an access log is copied, shipped, and
// retained far more widely than the request itself.
func loggingMiddleware(logger *slog.Logger) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			rec := &statusRecorder{ResponseWriter: w}

			// Deferred so the record is written even when an inner layer
			// panics: recovery sits inside this middleware and converts the
			// panic to a 500, but a re-panicked http.ErrAbortHandler unwinds
			// through here and must still be accounted for.
			defer func() {
				attrs := []slog.Attr{
					slog.String("method", r.Method),
					slog.String("path", sanitizeLogPath(r.URL.Path)),
					slog.Int("status", rec.status()),
					slog.Int64("bytes", rec.bytes),
					slog.Duration("duration", time.Since(start)),
					slog.String("request_id", RequestIDFromContext(r.Context())),
				}
				// Pattern is populated by ServeMux once a route matches; it is
				// the low-cardinality label ("GET /healthz") worth aggregating
				// on, and unlike the path it is never client-controlled.
				if r.Pattern != "" {
					attrs = append(attrs, slog.String("route", r.Pattern))
				}
				logger.LogAttrs(r.Context(), slog.LevelInfo, "http request", attrs...)
			}()

			next.ServeHTTP(rec, r)
		})
	}
}

// sanitizeLogPath bounds and de-fangs a request path before logging.
//
// The path is client-controlled and may contain control characters, newlines,
// or terminal escape sequences. A JSON handler would escape these, but the log
// format is operator-configurable (ADR-0025 allows text), so the value is made
// safe at the source instead of relying on the sink.
func sanitizeLogPath(p string) string {
	if len(p) > maxLoggedPathLen {
		p = p[:maxLoggedPathLen]
	}
	out := []byte(p)
	for i := 0; i < len(out); i++ {
		if out[i] < 0x20 || out[i] == 0x7f {
			out[i] = '?'
		}
	}
	return string(out)
}

// recoveryMiddleware turns a panicking handler into a 500 without killing the
// process, so one bad request cannot take the server down.
//
// Two invariants:
//
//   - http.ErrAbortHandler is re-panicked. It is net/http's documented signal
//     that a handler is deliberately abandoning the connection; swallowing it
//     would convert an intentional abort into a bogus 500.
//   - The client gets a generic body. Panic values and stack traces name
//     internal paths, types, and sometimes argument values, so they go to the
//     log (where they are needed) and never to the wire.
func recoveryMiddleware(logger *slog.Logger) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rec, ok := w.(*statusRecorder)
			defer func() {
				p := recover()
				if p == nil {
					return
				}
				if p == http.ErrAbortHandler { //nolint:errorlint // sentinel is panicked by value, not wrapped.
					panic(p)
				}

				logger.LogAttrs(r.Context(), slog.LevelError, "panic recovered",
					slog.String("request_id", RequestIDFromContext(r.Context())),
					slog.String("method", r.Method),
					slog.String("path", sanitizeLogPath(r.URL.Path)),
					slog.Any("panic", p),
				)

				// Only write a response if nothing has been sent yet; once the
				// status line is out, the best we can do is end the response.
				if ok && rec.written {
					return
				}
				writeJSON(w, http.StatusInternalServerError, statusResponse{Status: "error"})
			}()

			next.ServeHTTP(w, r)
		})
	}
}
