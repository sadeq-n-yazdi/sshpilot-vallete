package telemetry

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/config"
)

// Scrape listener timeouts. A scraper is a well-behaved local client, so these
// are tighter than the public server's; the listener exists to answer one small
// GET and must never become a way to hold connections open.
const (
	scrapeReadHeaderTimeout = 5 * time.Second
	scrapeReadTimeout       = 10 * time.Second
	scrapeWriteTimeout      = 30 * time.Second
	scrapeIdleTimeout       = 60 * time.Second
	scrapeMaxHeaderBytes    = 16 << 10
)

// MetricsServer serves the Prometheus scrape endpoint on its OWN listener.
//
// It is a separate type with a separate socket rather than a route on the API
// mux, and that separation is the security control (see config.PrometheusConfig
// for the full reasoning). There is deliberately no function anywhere in this
// codebase that mounts the scrape handler on the public router, so the insecure
// arrangement is not something a future change can reach by passing a flag --
// it would have to be written on purpose.
//
// A nil *MetricsServer is usable: every method is a no-op, which is the shape a
// deployment with no configured scrape address takes.
type MetricsServer struct {
	httpSrv *http.Server
	addr    string
	logger  *slog.Logger
}

// NewMetricsServer builds the scrape listener, or returns nil when metrics are
// not to be served.
//
// nil is returned -- meaning "no endpoint exists" -- whenever any of the three
// preconditions is missing: the Prometheus exporter is disabled, no listen
// address was configured, or no registry was built. That is the fail-closed
// composition: the endpoint appears only when everything needed to serve it was
// explicitly arranged, and any gap yields no listener rather than a listener
// serving something unexpected.
func NewMetricsServer(cfg *config.Config, p *Provider, logger *slog.Logger) *MetricsServer {
	if cfg == nil || p == nil {
		return nil
	}
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	prom := cfg.Telemetry.Metrics.Prometheus
	if !prom.Enabled || prom.ListenAddr == "" {
		return nil
	}
	reg := p.Registry()
	if reg == nil {
		return nil
	}

	path := prom.Path
	if path == "" {
		path = "/metrics"
	}

	// A fresh mux serving exactly one route. Everything else on this listener
	// is a 404 from the mux itself: no health endpoint, no docs, no publish
	// routes, no pprof. A scrape listener that also exposed the API would
	// reintroduce, on a port chosen for its laxer network exposure, precisely
	// the surface the separate listener exists to keep off it.
	mux := http.NewServeMux()
	mux.Handle("GET "+path, promhttp.HandlerFor(reg, promhttp.HandlerOpts{
		// Registry errors are logged rather than written into the scrape
		// response: an error string can name internal state, and the scraper
		// has no use for it.
		ErrorHandling: promhttp.ContinueOnError,
		ErrorLog:      slog.NewLogLogger(logger.Handler(), slog.LevelWarn),
	}))

	return &MetricsServer{
		addr:   prom.ListenAddr,
		logger: logger,
		httpSrv: &http.Server{
			Addr:              prom.ListenAddr,
			Handler:           mux,
			ReadHeaderTimeout: scrapeReadHeaderTimeout,
			ReadTimeout:       scrapeReadTimeout,
			WriteTimeout:      scrapeWriteTimeout,
			IdleTimeout:       scrapeIdleTimeout,
			MaxHeaderBytes:    scrapeMaxHeaderBytes,
			ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelWarn),
		},
	}
}

// Addr returns the configured scrape address, or "" when nothing is served.
func (m *MetricsServer) Addr() string {
	if m == nil {
		return ""
	}
	return m.addr
}

// ListenAndServe binds the scrape address and serves until shutdown.
//
// It returns nil on a clean shutdown so a caller can treat any non-nil return
// as a real failure.
func (m *MetricsServer) ListenAndServe() error {
	if m == nil {
		return nil
	}
	ln, err := net.Listen("tcp", m.addr)
	if err != nil {
		return err
	}
	return m.Serve(ln)
}

// Serve serves on an already-bound listener, so tests can bind port 0 and learn
// the real address without racing the goroutine that starts serving.
func (m *MetricsServer) Serve(ln net.Listener) error {
	if m == nil {
		return nil
	}
	// The address is logged so an operator can see, in the startup output,
	// exactly where an unauthenticated endpoint was opened. Silence here would
	// make the one thing worth reviewing invisible.
	m.logger.Warn("metrics scrape endpoint listening; it is UNAUTHENTICATED, restrict access to this address",
		slog.String("component", "telemetry"), slog.String("addr", ln.Addr().String()))
	if err := m.httpSrv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// Shutdown stops the scrape listener within ctx.
func (m *MetricsServer) Shutdown(ctx context.Context) error {
	if m == nil {
		return nil
	}
	if err := m.httpSrv.Shutdown(ctx); err != nil {
		_ = m.httpSrv.Close()
		return err
	}
	return nil
}
