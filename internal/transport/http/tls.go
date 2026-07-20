package httpserver

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/config"
)

// buildTLSConfig assembles the server's TLS configuration from operator config,
// failing closed on anything it cannot serve safely.
//
// The certificate SOURCE is a [CertProvider]; the certificate POLICY (minimum
// version, cipher allowlist, ALPN) is set here and applies to whatever any
// provider returns. Adding a provider therefore cannot weaken the negotiated
// connection — that separation is the point of the seam.
//
// Only two modes are implemented in this track: self_signed (development
// bring-up) and manual (operator-supplied files). ACME, Cloudflare origin, CSR
// and upstream termination are later tracks and return [ErrTLSModeUnsupported]
// rather than silently degrading to a weaker certificate.
//
// The now argument is the validity clock, a function rather than an instant
// because certificates are re-checked on every handshake and may be renewed
// while the process runs. Production passes time.Now; tests pass a clock they
// control.
//
// Startup behavior: the provider is asked for a certificate once, here, so that
// an operator whose material is missing, mismatched or expired learns at startup
// rather than from the first client's failed handshake. That check is NOT the
// only one — the same guard runs again on every handshake, which is what closes
// the gap E1 documented, where a certificate expiring mid-process kept being
// served until restart.
func buildTLSConfig(cfg *config.Config, now func() time.Time) (*tls.Config, error) {
	minVersion, err := parseMinVersion(cfg.TLS.MinVersion)
	if err != nil {
		return nil, err
	}

	provider, err := newCertProvider(cfg, now)
	if err != nil {
		return nil, err
	}

	guard := newCertGuard(provider, now)
	if _, err := guard.GetCertificate(nil); err != nil {
		return nil, err
	}

	return &tls.Config{
		MinVersion: minVersion,
		// GetCertificate, with Certificates left NIL. Every certificate this
		// server presents is therefore produced by a provider and validated by
		// the guard on the way out; populating Certificates as well would create
		// a second, unvalidated path that crypto/tls would fall back to.
		GetCertificate: guard.GetCertificate,
		CipherSuites:   tls12CipherSuites(),
		// CurvePreferences is deliberately LEFT UNSET.
		//
		// The obvious "hardening" here is to pin a list such as
		// {X25519, CurveP256, CurveP384}. That was tried and rejected: as of Go
		// 1.24 the default set leads with X25519MLKEM768, the post-quantum
		// hybrid key exchange, and pinning any explicit list that omits it
		// silently REMOVES it. Verified by handshake: with preferences unset the
		// negotiated curve is X25519MLKEM768; with {X25519, P256, P384} pinned it
		// drops to plain X25519. Since published keys are long-lived and a
		// harvest-now-decrypt-later adversary is exactly the threat the hybrid
		// addresses, the "hardened" list is strictly weaker than the default.
		//
		// Leaving this nil also means the curve set tracks the Go team's
		// judgement across upgrades rather than freezing today's opinion into
		// the binary. Every curve Go enables by default already provides forward
		// secrecy, which is the property this field could otherwise protect.
		//
		// HTTP/1.1 and h2 only; advertising the set explicitly stops
		// negotiation of anything the handler stack has not been reviewed for.
		NextProtos: []string{"h2", "http/1.1"},
	}, nil
}

// newCertProvider selects the certificate provider for the configured mode.
//
// The default branch refuses. Config validation already restricts tls.mode to a
// known set, so an unimplemented-but-valid mode lands here — and the only two
// alternatives to refusing would be serving a self-signed certificate the
// operator did not ask for, or no TLS at all. Both are the silent downgrade
// ADR-0015 exists to prevent.
func newCertProvider(cfg *config.Config, now func() time.Time) (CertProvider, error) {
	switch cfg.TLS.Mode {
	case "self_signed":
		return newSelfSignedProvider(cfg, now)
	case "manual":
		return newManualProvider(cfg.TLS.Manual.CertFile, cfg.TLS.Manual.KeyFile)
	case "csr":
		return newCSRProvider(cfg)
	default:
		return nil, fmt.Errorf("%w: %q", ErrTLSModeUnsupported, cfg.TLS.Mode)
	}
}

// tls12CipherSuites is the allowlist of TLS 1.2 cipher suites the server will
// negotiate. TLS 1.3 suites are NOT listed because crypto/tls does not allow
// them to be configured — all three (AES-128-GCM, AES-256-GCM,
// ChaCha20-Poly1305) are AEAD with forward secrecy, so there is nothing to
// exclude and an allowlist could only be wrong later.
//
// Two properties are required of every entry, and every exclusion follows from
// one of them:
//
//   - AEAD only. Each suite here is GCM or ChaCha20-Poly1305. All CBC suites are
//     excluded: the TLS 1.2 MAC-then-encrypt CBC construction is the source of
//     the Lucky13 family of padding-oracle attacks, and the constant-time
//     countermeasures are notoriously fragile. RC4 (broken keystream biases) and
//     3DES (64-bit block, Sweet32) are excluded for the same reason — they are
//     not AEAD and are independently broken.
//   - Forward secrecy required. Every entry is ECDHE. The static-RSA
//     TLS_RSA_WITH_AES_*_GCM_* suites are AEAD and would pass the first test,
//     but they derive the session key from the server's long-term RSA key, so
//     one future key compromise retroactively decrypts every recorded session.
//     They are excluded deliberately, not by oversight.
//
// Both ECDSA and RSA signature variants are listed so the allowlist does not
// constrain what certificate an operator may install; the ECDSA entries also
// carry Ed25519 certificates, which TLS 1.2 signs through the ECDSA suites.
//
// The order of this slice is NOT a preference order. Since Go 1.17 the server
// ignores the ordering of CipherSuites and applies its own preference logic
// (which accounts for hardware AES support); this list controls MEMBERSHIP
// only, and is written grouped by key exchange for readability.
func tls12CipherSuites() []uint16 {
	return []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
	}
}

// manualProvider serves an operator-supplied certificate and key.
//
// This is the operator-provided mode of ADR-0015 §2: the operator owns renewal.
// The files are read ONCE, at startup — there is deliberately no on-disk watch,
// so replacing them requires a restart — but the resulting certificate is still
// re-validated by the guard on every handshake. That matters for the expiry
// rule: ADR-0015 §4 applies fail-closed-on-expiry to the operator-owned modes
// too, and a long-running process holding a certificate that expires underneath
// it must stop serving rather than present it.
type manualProvider struct {
	cert tls.Certificate
}

// newManualProvider loads and structurally checks the operator's PEM files.
//
// Loading is separated from validity checking on purpose. Everything that can
// only be decided from the FILES (are they present, is the PEM well-formed, does
// the key match the certificate) is decided here, once, at startup, because
// re-reading two files on every handshake would be a needless I/O path in the
// connection hot loop. Everything that depends on the CLOCK is left to the
// guard, because it changes while the process runs.
//
// Note on secret handling: the private key reaches this process only inside
// tls.Certificate.PrivateKey, as a crypto.PrivateKey. It is never read into a
// string, never formatted, and never logged. The error below is built from the
// crypto/tls message and file paths — a path is not a secret, but key bytes are,
// so nothing here ever quotes file contents.
func newManualProvider(certFile, keyFile string) (*manualProvider, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		// %w on the crypto/tls error preserves "failed to find any PEM data",
		// "private key does not match public key", and the os path errors,
		// which are what an operator needs to fix the problem. None of them
		// echo key material.
		return nil, fmt.Errorf("%w: %w", ErrTLSCertificateInvalid, err)
	}

	// Leaf is populated by LoadX509KeyPair as of Go 1.23, but GODEBUG
	// x509keypairleaf=0 can restore the old nil-Leaf behavior, so it is
	// re-parsed rather than trusted. The guard re-parses from DER regardless;
	// this keeps the field consistent for anything else that reads it.
	if cert.Leaf == nil && len(cert.Certificate) > 0 {
		leaf, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return nil, fmt.Errorf("%w: parse leaf of %s: %w", ErrTLSCertificateInvalid, certFile, err)
		}
		cert.Leaf = leaf
	}

	return &manualProvider{cert: cert}, nil
}

// Name identifies the mode for diagnostics.
func (p *manualProvider) Name() string { return "manual" }

// GetCertificate returns the operator's certificate. The same material is
// returned for every handshake — renewal in this mode means an operator
// replacing the files and restarting — but the guard still re-checks its
// validity window each time, so expiry stops the listener without a restart.
func (p *manualProvider) GetCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return &p.cert, nil
}

// parseMinVersion maps the configured tls.min_version onto a crypto/tls
// constant. TLS 1.2 is a hard floor: 1.0 and 1.1 are deprecated and broken, and
// an operator typo must not be allowed to quietly downgrade the transport, so
// anything below the floor (or unrecognized) is an error rather than a clamp.
func parseMinVersion(v string) (uint16, error) {
	switch v {
	case "", "1.2":
		return tls.VersionTLS12, nil
	case "1.3":
		return tls.VersionTLS13, nil
	default:
		return 0, fmt.Errorf("%w: %q (want 1.2 or 1.3)", ErrTLSMinVersion, v)
	}
}
