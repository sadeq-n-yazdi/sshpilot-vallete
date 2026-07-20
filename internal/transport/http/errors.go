package httpserver

import "errors"

// Sentinel errors returned during server construction. They are all
// construction-time (startup) failures: the process fails closed and exits
// rather than serving with a weaker transport than the operator asked for.
var (
	// ErrTLSModeUnsupported is returned when config selects a tls.mode that
	// this transport cannot serve yet. Modes are validated by the config
	// package, so reaching this means a valid-but-unimplemented mode (acme,
	// cloudflare_origin, csr, upstream) was selected; failing closed is
	// correct because the alternative is silently serving a weaker cert.
	ErrTLSModeUnsupported = errors.New("httpserver: tls mode unsupported")

	// ErrSelfSignedInProduction is returned when tls.mode is self_signed while
	// server.environment is production and tls.allow_self_signed_in_production
	// is not set. A self-signed certificate gives clients no way to
	// distinguish the real server from an interceptor, so production requires
	// an explicit, deliberate opt-in.
	ErrSelfSignedInProduction = errors.New("httpserver: self-signed certificate refused in production")

	// ErrTLSMinVersion is returned for a tls.min_version that is unknown or
	// below the TLS 1.2 floor. Downgrading below 1.2 is never honored.
	ErrTLSMinVersion = errors.New("httpserver: unsupported tls min version")

	// ErrNilPinger is returned when a readiness pinger is required but absent.
	ErrNilPinger = errors.New("httpserver: nil readiness pinger")
)
