package httpserver

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/config"
)

// Health-probe listener timeouts. A probe is a well-behaved local client that
// issues one small GET, so these mirror the scrape listener's tight bounds
// rather than the public server's: the socket exists to answer liveness and
// readiness and must never become a way to hold connections open.
const (
	healthReadHeaderTimeout = 5 * time.Second
	healthReadTimeout       = 10 * time.Second
	healthWriteTimeout      = 10 * time.Second
	healthIdleTimeout       = 60 * time.Second
	healthMaxHeaderBytes    = 16 << 10
)

// HealthServer serves ONLY /healthz and /readyz on its OWN plaintext listener
// (ADR-0015, Decision 43).
//
// It exists because a server certificate that public clients do not trust — a
// Cloudflare Origin CA certificate, or the ephemeral self-signed one — makes a
// direct TLS probe fail the handshake, so an orchestrator that dials the pod or
// instance IP cannot health-check the HTTPS listener at all. This gives probes a
// plaintext path that completes.
//
// The security control is the same separation MetricsServer relies on: this is a
// distinct type with a distinct socket and a fresh mux carrying exactly two
// routes. There is deliberately no function that mounts the publish or
// management surface here, so no future change can reach an insecure arrangement
// by passing a flag — it would have to be written on purpose. The bind address
// is fenced to loopback/private by config validation (validatePrivateBindAddr),
// so the unauthenticated endpoint cannot be exposed to the internet by leaving a
// field blank.
//
// A nil *HealthServer is usable: every method is a no-op, which is the shape a
// deployment with no configured health address takes.
type HealthServer struct {
	httpSrv *http.Server
	addr    string
	logger  *slog.Logger
}

// NewHealthServer builds the health-probe listener, or returns nil when no
// health address was configured.
//
// nil — meaning "no such listener exists" — is the fail-closed default: the
// endpoint appears only when an operator explicitly named a (loopback/private)
// address for it. The pinger backs /readyz exactly as it does on the HTTPS
// server: readiness is not forked here, it reflects the same dependency check,
// so a probe on this listener and a probe on the main one agree.
func NewHealthServer(cfg *config.Config, logger *slog.Logger, pinger Pinger) *HealthServer {
	if cfg == nil || cfg.Server.HealthListenAddr == "" {
		return nil
	}
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}

	// A fresh mux serving exactly two routes. Everything else here is a 404 from
	// the mux itself: no publish, no management, no docs, no metrics. The
	// method-qualified patterns also mean a POST is answered 405 by the mux, so
	// no handler-level method checking is needed and the surface stays exactly
	// these two liveness/readiness reads.
	mux := http.NewServeMux()
	mux.Handle("GET /healthz", healthzHandler())
	mux.Handle("GET /readyz", readyzHandler(pinger, logger))

	addr := cfg.Server.HealthListenAddr
	return &HealthServer{
		addr:   addr,
		logger: logger,
		httpSrv: &http.Server{
			Addr:              addr,
			Handler:           mux,
			ReadHeaderTimeout: healthReadHeaderTimeout,
			ReadTimeout:       healthReadTimeout,
			WriteTimeout:      healthWriteTimeout,
			IdleTimeout:       healthIdleTimeout,
			MaxHeaderBytes:    healthMaxHeaderBytes,
			ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelWarn),
		},
	}
}

// Addr returns the configured health address, or "" when nothing is served.
func (h *HealthServer) Addr() string {
	if h == nil {
		return ""
	}
	return h.addr
}

// ListenAndServe binds the health address and serves until shutdown. It returns
// nil on a clean shutdown so a caller can treat any non-nil return as a real
// failure.
func (h *HealthServer) ListenAndServe() error {
	if h == nil {
		return nil
	}
	ln, err := net.Listen("tcp", h.addr)
	if err != nil {
		return err
	}
	return h.Serve(ln)
}

// Serve serves on an already-bound listener, so tests can bind port 0 and learn
// the real address without racing the goroutine that starts serving.
func (h *HealthServer) Serve(ln net.Listener) error {
	if h == nil {
		return nil
	}
	h.logger.Info("health probe endpoint listening (plaintext, loopback/private)",
		slog.String("component", "health"), slog.String("addr", ln.Addr().String()))
	if err := h.httpSrv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// Shutdown stops the health listener within ctx.
func (h *HealthServer) Shutdown(ctx context.Context) error {
	if h == nil {
		return nil
	}
	if err := h.httpSrv.Shutdown(ctx); err != nil {
		_ = h.httpSrv.Close()
		return err
	}
	return nil
}
