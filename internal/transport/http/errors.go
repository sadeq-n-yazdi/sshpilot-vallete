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

	// ErrTLSCertificateInvalid is returned when operator-supplied certificate
	// material cannot be used: unreadable, malformed PEM, or a private key that
	// does not match the certificate's public key.
	//
	// It deliberately wraps rather than replaces the underlying crypto/tls
	// error, so the operator learns which file and which defect, but the error
	// text is built only from the certificate side of the pair — a key-parsing
	// failure must never quote the bytes it choked on.
	ErrTLSCertificateInvalid = errors.New("httpserver: invalid tls certificate material")

	// ErrTLSCertificateExpired is returned when operator-supplied certificate
	// material is outside its validity window (expired, or not yet valid).
	//
	// ADR-0015 §4 requires failing closed on expiry: a server that starts with
	// an expired certificate would present it to every client, and the only
	// alternatives to refusing are serving material clients must reject or
	// falling back to plaintext. Both are worse than not starting, because a
	// process that will not start is visible to the operator immediately.
	ErrTLSCertificateExpired = errors.New("httpserver: tls certificate outside its validity window")

	// ErrTLSCertificateUnavailable is returned when a CertProvider could not
	// supply a certificate for a handshake.
	//
	// Unlike its neighbors this one is NOT construction-time: it surfaces from
	// the tls.Config.GetCertificate callback, so it aborts a single handshake
	// rather than startup. That is the point — ADR-0015 §4 requires the listener
	// to stop serving when certificate material goes bad while the process runs,
	// and refusing each handshake is how a provider failure becomes a refusal
	// instead of a downgrade to a self-signed or plaintext fallback.
	ErrTLSCertificateUnavailable = errors.New("httpserver: no tls certificate available")

	// ErrTLSCSRPending is returned in csr mode when no signed certificate has
	// been installed yet.
	//
	// It is a distinct sentinel because on a first run it is the EXPECTED
	// state, not a misconfiguration: the provider has just written a CSR and
	// the operator's next step is to get it signed. The server still refuses to
	// start — ADR-0015 permits no plaintext or self-signed fallback while
	// waiting — but the operator needs to tell "do the round trip" apart from
	// "your path is wrong".
	ErrTLSCSRPending = errors.New("httpserver: awaiting an externally signed certificate")

	// ErrTLSKeyPermissions is returned when a private key file is readable or
	// writable by group or other.
	//
	// Failing closed is the only defensible response: a key at 0644 may already
	// have been copied by any local account, so it must be treated as
	// compromised. Silently tightening the mode would serve with suspect
	// material and hide that the exposure ever happened.
	ErrTLSKeyPermissions = errors.New("httpserver: tls private key has unsafe file permissions")

	// ErrNilPinger is returned when a readiness pinger is required but absent.
	ErrNilPinger = errors.New("httpserver: nil readiness pinger")

	// ErrNilPublisher is returned when the publish service is absent. Unlike
	// the pinger, which may legitimately be nil on a database-less server, the
	// publisher is the reason this process exists: New rejects a nil one at
	// startup so a misconfigured deployment fails loudly instead of serving
	// 500s that look like an outage, or 404s that look like empty accounts.
	ErrNilPublisher = errors.New("httpserver: nil publish service")

	// ErrNilAuthorizer is returned when a Guardian is constructed without an
	// Authorizer. Like the nil publisher this is refused at startup rather than
	// tolerated, and for a sharper reason: a Guardian without an Authorizer
	// would mount routes that look protected in the route table and serve every
	// request unauthorized. A control that is wired up, reads as enforced, and
	// enforces nothing is the one failure mode this whole layer exists to
	// prevent.
	ErrNilAuthorizer = errors.New("httpserver: nil authorizer")

	// ErrNilDeviceService is logged when a device management route is reached
	// with no service behind it. Unlike the sentinels above it is not a
	// startup refusal: the management routes are mounted unconditionally so
	// that they always exist and always refuse, and a missing service is
	// therefore a 500 on the route rather than a process that will not start.
	ErrNilDeviceService = errors.New("httpserver: nil device service")
)
