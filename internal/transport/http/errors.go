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

	// ErrACMEAccount is returned when the ACME account cannot be established:
	// the directory is unreachable, or the CA refuses to register the account
	// key. It is a startup failure, because an unregistered account can issue
	// nothing and finding that out at first-handshake time is finding out too
	// late.
	ErrACMEAccount = errors.New("httpserver: acme account unavailable")

	// ErrACMETermsNotAccepted is returned when acme mode is selected without
	// tls.acme.accept_tos.
	//
	// RFC 8555 has the client assert agreement to the CA's terms. Asserting it
	// because an operator picked a mode would be making a commitment on their
	// behalf, so registration is refused instead. Config validation catches
	// this first; the provider re-checks so there is no second path to
	// registering under terms nobody accepted.
	ErrACMETermsNotAccepted = errors.New("httpserver: acme terms of service not accepted")

	// ErrACMEIssuance is returned when no ACME certificate is available for a
	// handshake — not issued yet, the order failed, or the challenge path was
	// asked for a name with no pending validation.
	//
	// Like ErrTLSCertificateUnavailable this is mostly a per-handshake failure
	// rather than a startup one, and that is the fail-closed posture, not a
	// gap: TLS-ALPN-01 cannot produce a certificate before the listener is up,
	// so the server accepts connections and REFUSES them until it holds a real
	// certificate. It never substitutes a self-signed one, which would leave
	// monitoring showing a healthy service that authenticates nothing.
	ErrACMEIssuance = errors.New("httpserver: acme certificate unavailable")

	// ErrOriginCACredential is returned when the Cloudflare Origin CA
	// credential cannot be obtained from the secret provider.
	//
	// It is a startup failure. The credential is the only way this mode can
	// obtain a certificate, so a deployment that cannot read it will never
	// serve anything, and discovering that at first-handshake time is
	// discovering it too late. The error names the config FIELD and the
	// reference's scheme; the secret provider's own errors are built to name
	// the reference and never the value, so nothing here can carry the key.
	ErrOriginCACredential = errors.New("httpserver: cloudflare origin ca credential unavailable")

	// ErrOriginCAIssuance is returned when Cloudflare's Origin CA API does not
	// yield a usable certificate: the request failed, the API rejected it, or
	// the response was malformed.
	//
	// Every one of those is a refusal rather than a degraded mode. There is no
	// stand-in certificate to fall back to, and an origin serving a self-signed
	// certificate behind Cloudflare would be an origin whose traffic Cloudflare
	// refuses anyway — so failing closed loses nothing and hides nothing.
	ErrOriginCAIssuance = errors.New("httpserver: cloudflare origin ca certificate unavailable")

	// ErrOriginCADirectClient is returned when a peer that is not a configured
	// trusted proxy asks for the origin certificate.
	//
	// This is the enforcement half of the misconfiguration gate described on
	// config.CloudflareOriginConfig. An Origin CA certificate is trusted only
	// by the Cloudflare edge, so a handshake from anywhere else means the
	// origin is reachable directly — the exact topology in which this mode is
	// unsafe. The certificate is withheld rather than presented: a direct
	// client that receives it learns the origin's real certificate and is
	// invited to bypass Cloudflare by disabling verification, which is how the
	// MITM protection ADR-0015 exists to provide gets turned off in practice.
	ErrOriginCADirectClient = errors.New("httpserver: origin certificate withheld from a non-proxy peer")

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

	// ErrNilPublicKeyService is logged when a public key management route is
	// reached with no service behind it. Like ErrNilDeviceService it is a 500
	// on the route rather than a startup refusal, because the management routes
	// are mounted unconditionally so that they always exist and always refuse.
	ErrNilPublicKeyService = errors.New("httpserver: nil public key service")

	// ErrNilKeySetService is logged when a key set management route is reached
	// with no service behind it. Like the two above it is a 500 on the route
	// rather than a startup refusal, because the management routes are mounted
	// unconditionally so that they always exist and always refuse.
	ErrNilKeySetService = errors.New("httpserver: nil key set service")
)
