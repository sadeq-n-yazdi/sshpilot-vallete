package httpserver

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/config"
)

// UpstreamServer is the PLAINTEXT application listener used when TLS is
// terminated by an upstream proxy (ADR-0015, Decision 31, tls.mode: upstream).
//
// It is a deliberate, tightly-fenced exception to the package's HTTPS-only rule.
// In upstream mode the process holds no certificate -- the proxy terminates TLS
// and forwards plaintext HTTP -- so there is no HTTPS listener to bind, and this
// is the app's only socket. Every guardrail below is load-bearing:
//
//   - It exists ONLY in upstream mode. The composition root builds this type
//     instead of *Server for that one mode; it is never constructed otherwise, so
//     no TLS-terminating deployment can bind a plaintext socket.
//   - It binds a loopback/private address, fenced by config validation
//     (validatePrivateBindAddr), so the plaintext socket sits behind the proxy
//     and is never reachable directly from the internet.
//   - Every request passes through requireSecureTransport BEFORE the handler:
//     unless it arrives from a configured trusted proxy carrying
//     X-Forwarded-Proto: https, it is refused. A plaintext request that bypassed
//     the proxy therefore cannot be served as if it were secure.
//
// Keeping it a separate type from *Server is itself a control: *Server's only
// serve method is ServeTLS, so no bug in the HTTPS type can ever emit plaintext;
// the plaintext path lives only here.
type UpstreamServer struct {
	httpSrv *http.Server
	logger  *slog.Logger
	addr    string
}

// NewUpstreamServer builds the plaintext upstream listener carrying the full API
// handler behind the require-secure-transport gate.
//
// It fails closed: the publisher may NOT be nil (serving the publish endpoint is
// the whole point of the process), matching Server.New. The handler is the
// IDENTICAL one *Server serves -- same NewHandler, same options -- so upstream
// mode does not quietly serve a reduced surface; the only difference is the
// plaintext socket and the outer secure-transport gate.
func NewUpstreamServer(cfg *config.Config, logger *slog.Logger, pinger Pinger, publisher Publisher, opts ...HandlerOption) (*UpstreamServer, error) {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	if publisher == nil {
		return nil, ErrNilPublisher
	}

	// requireSecureTransport is OUTERMOST, wrapping the fully-chained handler, so
	// a non-secure request is refused before any handler work, logging, or
	// telemetry runs -- there is nothing to observe about a request that must not
	// be served.
	handler := requireSecureTransport(newHSTSPolicy(cfg), logger)(NewHandler(cfg, logger, pinger, publisher, opts...))

	addr := cfg.TLS.Upstream.ListenAddr
	return &UpstreamServer{
		logger: logger,
		addr:   addr,
		httpSrv: &http.Server{
			Addr:              addr,
			Handler:           handler,
			ReadHeaderTimeout: readHeaderTimeout,
			ReadTimeout:       readTimeout,
			WriteTimeout:      writeTimeout,
			IdleTimeout:       idleTimeout,
			MaxHeaderBytes:    maxHeaderBytes,
			ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelWarn),
		},
	}, nil
}

// Addr returns the configured plaintext listen address.
func (s *UpstreamServer) Addr() string {
	if s == nil {
		return ""
	}
	return s.addr
}

// ListenAndServe binds the plaintext address and serves until shutdown. It
// returns nil on a clean shutdown so a caller can treat any non-nil return as
// fatal.
func (s *UpstreamServer) ListenAndServe() error {
	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return err
	}
	return s.Serve(ln)
}

// Serve serves plaintext HTTP on an already-bound listener, so tests can bind
// port 0 and know the real address before traffic starts.
func (s *UpstreamServer) Serve(ln net.Listener) error {
	s.logger.Warn("plaintext upstream listener started; it terminates NO TLS and trusts X-Forwarded-Proto only from configured proxies -- keep it on a private interface behind the proxy",
		slog.String("component", "upstream"), slog.String("addr", ln.Addr().String()))
	if err := s.httpSrv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// Shutdown stops accepting connections and drains in-flight requests within ctx,
// force-closing whatever remains when ctx expires.
func (s *UpstreamServer) Shutdown(ctx context.Context) error {
	if err := s.httpSrv.Shutdown(ctx); err != nil {
		_ = s.httpSrv.Close()
		return err
	}
	return nil
}

// requireSecureTransport refuses any request that did not arrive over secure
// transport, for the plaintext upstream listener.
//
// "Secure" is decided by the SAME rule the HSTS layer uses -- hstsPolicy.
// requestIsSecure -- so there is one definition of a trusted forwarded scheme in
// this package, not two. On this plaintext socket r.TLS is always nil, so that
// rule reduces to exactly: the immediate peer is a configured trusted proxy AND
// it forwarded X-Forwarded-Proto: https. A request that bypassed the proxy, or a
// proxy that did not assert https, is refused -- it must never be served as
// though the client's original connection were encrypted.
//
// This gate is applied UNIFORMLY, including to /healthz and /readyz: a direct
// plaintext probe of this socket is refused like anything else. That is
// deliberate and is why the separate loopback health listener (Decision 43)
// exists -- an orchestrator probes there, not here.
//
// tls.upstream.require_forwarded_proto is documented as always-on for this
// listener: the forwarded-scheme check is the fence, and it is not made
// disable-able here (see ADR-0015). The refusal carries no detail, so a probing
// client learns only that its request was rejected.
func requireSecureTransport(policy hstsPolicy, logger *slog.Logger) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !policy.requestIsSecure(r) {
				logger.LogAttrs(r.Context(), slog.LevelWarn,
					"refused a request that did not arrive over a trusted https proxy",
					slog.String("component", "upstream"),
					slog.String("remote_addr", r.RemoteAddr),
				)
				http.Error(w, "https required", http.StatusBadRequest)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
