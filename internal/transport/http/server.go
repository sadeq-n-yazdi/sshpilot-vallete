package httpserver

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/config"
)

// Server timeouts. Every one of these exists to stop a slow or idle peer from
// holding a connection (and its goroutine and file descriptor) indefinitely.
const (
	// readHeaderTimeout is the single most important one: without it a
	// Slowloris client can trickle request headers forever and exhaust the
	// server with a handful of connections.
	readHeaderTimeout = 10 * time.Second

	// readTimeout bounds the whole request, headers plus body.
	readTimeout = 30 * time.Second

	// writeTimeout bounds response writing, capping how long a slow reader can
	// pin a handler goroutine.
	writeTimeout = 30 * time.Second

	// idleTimeout closes kept-alive connections that go quiet.
	idleTimeout = 120 * time.Second

	// maxHeaderBytes caps header memory per connection. The endpoints here take
	// no large headers, so 64 KiB is generous and well under the 1 MiB default.
	maxHeaderBytes = 64 << 10
)

// Server is the HTTPS listener for the vallet API.
//
// It is HTTPS-only by construction: the only serve method performs a TLS
// handshake, and no plaintext listener exists anywhere in this package. There
// is intentionally no HTTP-to-HTTPS redirect listener — a redirect still
// accepts the first request in the clear, and every vallet client is
// programmatic and can be configured with an https URL directly, so the safest
// plaintext port is a closed one.
type Server struct {
	httpSrv *http.Server
	logger  *slog.Logger
	addr    string
}

// New builds a Server from operator config, a logger, and the readiness
// dependency.
//
// It fails closed: any TLS problem (unsupported mode, bad min version,
// self-signed in production without the explicit override, unreadable key
// files) is returned here, at startup, rather than surfacing later as a failed
// handshake on a server the operator believes is healthy.
//
// The pinger may be nil, in which case readiness reports 503 forever; that is
// the honest answer for a server with no database. The publisher may NOT be
// nil: serving the publish endpoint is the whole point of the process, and a
// server that cannot answer it should never bind a port.
func New(cfg *config.Config, logger *slog.Logger, pinger Pinger, publisher Publisher) (*Server, error) {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	if publisher == nil {
		return nil, ErrNilPublisher
	}

	tlsCfg, err := buildTLSConfig(cfg, time.Now)
	if err != nil {
		return nil, err
	}

	warnIfSelfSigned(cfg, logger)

	return &Server{
		logger: logger,
		addr:   cfg.Server.ListenAddr,
		httpSrv: &http.Server{
			Addr:              cfg.Server.ListenAddr,
			Handler:           NewHandler(cfg, logger, pinger, publisher),
			TLSConfig:         tlsCfg,
			ReadHeaderTimeout: readHeaderTimeout,
			ReadTimeout:       readTimeout,
			WriteTimeout:      writeTimeout,
			IdleTimeout:       idleTimeout,
			MaxHeaderBytes:    maxHeaderBytes,
			ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelWarn),
		},
	}, nil
}

// warnIfSelfSigned emits the loud warning ADR-0015's ephemeral-mode guardrails
// require whenever the self-signed mode is active.
//
// Clients of a self-signed instance cannot distinguish this server from an
// interceptor, so the operator must be told at every startup rather than only
// when they go looking. The warning is louder still when the mode was reached in
// production via the explicit override, because that is the configuration most
// likely to be an accident someone has to notice and undo.
//
// The audit event the ADR also calls for is NOT emitted here: the audit sink is
// not wired into this constructor, and reaching for it would drag an unrelated
// dependency into the transport layer. It is deliberately left to the track that
// wires auditing into startup.
func warnIfSelfSigned(cfg *config.Config, logger *slog.Logger) {
	if cfg == nil || cfg.TLS.Mode != "self_signed" {
		return
	}
	logger.Warn("serving an ephemeral self-signed certificate; clients cannot authenticate this server",
		slog.String("tls_mode", "self_signed"),
		slog.String("environment", cfg.Server.Environment),
		slog.Duration("validity", selfSignedValidity),
		slog.Bool("production_override", isProduction(cfg) && cfg.TLS.AllowSelfSignedInProduction),
	)
}

// Handler returns the wrapped handler. Exposed for tests and for embedding the
// API in another server; it carries the full middleware chain.
func (s *Server) Handler() http.Handler { return s.httpSrv.Handler }

// TLSConfig returns the negotiated TLS settings, for assertions and for
// operators logging the effective posture at startup.
func (s *Server) TLSConfig() *tls.Config { return s.httpSrv.TLSConfig }

// Addr returns the configured listen address.
func (s *Server) Addr() string { return s.addr }

// ListenAndServe binds the configured address and serves HTTPS until the
// server is shut down.
//
// It returns nil on a clean shutdown (http.ErrServerClosed is the expected
// terminal condition, not a failure) so callers can treat any non-nil return as
// fatal. Certificates come from the TLS config built in New, so the empty
// strings passed to ServeTLS are correct, not an oversight.
func (s *Server) ListenAndServe() error {
	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return err
	}
	return s.Serve(ln)
}

// Serve serves HTTPS on an already-bound listener. Splitting this out from
// ListenAndServe lets tests bind port 0 and know the real address before
// traffic starts, with no sleep-and-hope.
func (s *Server) Serve(ln net.Listener) error {
	s.logger.Info("https server listening", slog.String("addr", ln.Addr().String()))
	if err := s.httpSrv.ServeTLS(ln, "", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// Shutdown stops accepting connections and waits for in-flight requests to
// finish, bounded by ctx. When ctx expires the remaining connections are closed
// hard: a drain that never ends is a hung deploy, so the deadline wins.
func (s *Server) Shutdown(ctx context.Context) error {
	err := s.httpSrv.Shutdown(ctx)
	if err != nil {
		// Force-close whatever is left so the process can exit.
		_ = s.httpSrv.Close()
		return err
	}
	return nil
}
