package httpserver

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/version"
)

// Pinger is the minimal readiness dependency: anything that can be round-
// tripped under a deadline. *database/sql.DB satisfies it as-is.
//
// It is declared here, at the point of use, rather than imported from the
// storage layer, so the transport never depends on a concrete database
// package and readiness stays trivially fakeable in tests.
type Pinger interface {
	PingContext(ctx context.Context) error
}

// readyPingTimeout bounds the readiness dependency check.
//
// Readiness is polled frequently by orchestrators, and a check that can block
// on a wedged database would pile up goroutines and stall the very signal that
// is supposed to report the problem. A short deadline turns "hung" into "not
// ready", which is the answer the caller actually needs.
const readyPingTimeout = 2 * time.Second

// statusResponse is the small JSON body shared by the health endpoints. It
// carries no diagnostics: an unauthenticated probe endpoint must not disclose
// which dependency failed or why, since that maps the deployment for an
// attacker. The detail goes to the log instead.
type statusResponse struct {
	Status  string `json:"status"`
	Version string `json:"version,omitempty"`
}

// healthzHandler answers liveness.
//
// It reports on the process and nothing else: if this handler runs, the
// process is alive and should not be restarted. It deliberately performs NO
// dependency checks — wiring the database into liveness would make an
// orchestrator kill healthy servers during a database blip, turning a
// recoverable outage into a restart storm. Dependencies belong in readiness.
func healthzHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, statusResponse{Status: "ok", Version: version.String()})
	}
}

// readyzHandler answers readiness, reflecting database health.
//
// It FAILS CLOSED: 200 is returned only when the pinger answers without error
// inside readyPingTimeout. A missing pinger, a ping error, and a timeout all
// produce 503, so a server that cannot serve real traffic is removed from the
// load balancer rather than silently accepting requests it will fail.
func readyzHandler(p Pinger, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if p == nil {
			logger.LogAttrs(r.Context(), slog.LevelError, "readiness check misconfigured",
				slog.String("request_id", RequestIDFromContext(r.Context())),
				slog.String("error", ErrNilPinger.Error()),
			)
			writeJSON(w, http.StatusServiceUnavailable, statusResponse{Status: "unavailable"})
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), readyPingTimeout)
		defer cancel()

		if err := p.PingContext(ctx); err != nil {
			// The reason is logged, never returned: the client learns only
			// that the instance is not ready.
			//
			// A probe that hangs up mid-check is not a fault of this instance,
			// so it must not be logged at the level operators alert on. Left at
			// Warn, a load balancer with a tight probe timeout would emit a
			// steady stream of false failures and train readers to ignore the
			// message that signals a genuinely unreachable database.
			level, msg := slog.LevelWarn, "readiness check failed"
			if r.Context().Err() != nil {
				level, msg = slog.LevelDebug, "readiness check canceled by client"
			}
			logger.LogAttrs(r.Context(), level, msg,
				slog.String("request_id", RequestIDFromContext(r.Context())),
				slog.String("error", err.Error()),
			)
			writeJSON(w, http.StatusServiceUnavailable, statusResponse{Status: "unavailable"})
			return
		}

		writeJSON(w, http.StatusOK, statusResponse{Status: "ready", Version: version.String()})
	}
}

// writeJSON writes a small JSON document with the given status.
//
// Encoding errors are ignored on purpose: by the time encoding fails the status
// line is already on the wire and there is no way to signal a different result
// to the client, so the only options are to ignore it or to corrupt the
// response further. Bodies here are fixed-shape structs that cannot fail to
// marshal in practice.
func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	// Health responses reflect a point in time; a cached 200 would let a probe
	// keep passing after the instance went unhealthy.
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
