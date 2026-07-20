package httpserver

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/config"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/secrets"
)

// buildTLSConfig assembles the server's TLS configuration from operator config,
// failing closed on anything it cannot serve safely.
//
// The certificate SOURCE is a [CertProvider]; the certificate POLICY (minimum
// version, cipher allowlist, ALPN) is set here and applies to whatever any
// provider returns. Adding a provider therefore cannot weaken the negotiated
// connection — that separation is the point of the seam.
//
// Implemented modes: self_signed (development bring-up), manual
// (operator-supplied files), csr (external signing), acme with the TLS-ALPN-01
// solver, and cloudflare_origin. The ACME DNS-01 solver and upstream
// termination are later tracks and return [ErrTLSModeUnsupported] rather than
// silently degrading to a weaker certificate.
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
func buildTLSConfig(ctx context.Context, cfg *config.Config, now func() time.Time) (*tls.Config, io.Closer, error) {
	minVersion, err := parseMinVersion(cfg.TLS.MinVersion)
	if err != nil {
		return nil, nil, err
	}

	provider, err := newCertProvider(ctx, cfg, now)
	if err != nil {
		return nil, nil, err
	}

	guard := newCertGuard(provider, now)

	// The startup probe is SKIPPED for a provider that proves control in band,
	// and only for one. This is not leniency: TLS-ALPN-01 has the CA connect to
	// this very listener, so requiring a certificate before the listener exists
	// would make the mode impossible to bootstrap. Fail-closed is preserved by
	// the per-handshake guard, which refuses every ordinary handshake until a
	// real certificate exists. Every other mode keeps the strict startup check,
	// so an operator with missing, mismatched or expired material still learns
	// at startup rather than from a client.
	challengeProtos := challengeALPNProtos(provider)
	if startupProbeRequired(provider) {
		if _, err := guard.GetCertificate(nil); err != nil {
			return nil, nil, err
		}
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
		//
		// A challenge protocol is appended ONLY when the installed provider
		// answers one. In every other mode the listener has no "acme-tls/1" to
		// offer at all, so it cannot be negotiated even by a client that asks.
		NextProtos: append([]string{"h2", "http/1.1"}, challengeProtos...),
	}, guard, nil
}

// inBandChallengeSolver is implemented by a provider that proves control of its
// names during the TLS handshake itself.
//
// Two consequences follow from that one property, which is why they share an
// interface rather than being two flags: such a provider needs its challenge
// ALPN protocol advertised by the listener, and it cannot be asked for a
// certificate before the listener is up.
//
// Today only the ACME TLS-ALPN-01 provider implements it. DNS-01 will not — it
// proves control out of band — and so will keep the strict startup probe.
type inBandChallengeSolver interface {
	// challengeALPNProtos returns the ALPN protocol names on which the provider
	// serves challenge certificates.
	challengeALPNProtos() []string
}

// challengeALPNProtos returns the challenge protocols a provider needs
// advertised, or nil for the providers that need none.
func challengeALPNProtos(provider CertProvider) []string {
	if s, ok := provider.(inBandChallengeSolver); ok {
		return s.challengeALPNProtos()
	}
	return nil
}

// startupProbeRequired reports whether a provider must produce a certificate
// before the server is allowed to start.
//
// It is true for every provider EXCEPT one that solves its challenge in band,
// because such a provider cannot be issued a certificate until the listener the
// probe would precede is already accepting connections. Keeping the rule in one
// named predicate is what makes the exemption auditable: it can be tested
// directly, and it cannot be widened for one mode without widening it visibly.
func startupProbeRequired(provider CertProvider) bool {
	return len(challengeALPNProtos(provider)) == 0
}

// newCertProvider selects the certificate provider for the configured mode.
//
// The default branch refuses. Config validation already restricts tls.mode to a
// known set, so an unimplemented-but-valid mode lands here — and the only two
// alternatives to refusing would be serving a self-signed certificate the
// operator did not ask for, or no TLS at all. Both are the silent downgrade
// ADR-0015 exists to prevent.
//
// Every case returns through [asCertProvider]. That is not decoration: each
// constructor returns a CONCRETE pointer type, and `return newXProvider(...)`
// would convert a nil pointer into a non-nil CertProvider interface holding a
// typed nil. A caller that checked `provider != nil` instead of the error would
// then proceed with a provider that is nil underneath. Every caller today
// checks the error first, so this is not reachable now — asCertProvider makes it
// unreachable by construction rather than by caller discipline, on a seam whose
// failure mode is serving without the certificate policy it exists to enforce.
func newCertProvider(ctx context.Context, cfg *config.Config, now func() time.Time) (CertProvider, error) {
	switch cfg.TLS.Mode {
	case "self_signed":
		return asCertProvider(newSelfSignedProvider(cfg, now))
	case "manual":
		return asCertProvider(newManualProvider(cfg.TLS.Manual.CertFile, cfg.TLS.Manual.KeyFile))
	case "csr":
		return asCertProvider(newCSRProvider(cfg))
	case "acme":
		return newACMEProviderForSolver(ctx, cfg, now)
	case "cloudflare_origin":
		// This case arrived on develop after the asCertProvider guard was
		// written, and newOriginCAProvider returns a concrete
		// *originCAProvider, so an unwrapped return here would reintroduce the
		// exact typed nil this change exists to remove. Every case in this
		// switch returns through asCertProvider; that is the invariant, and a
		// new mode that quietly skips it is the failure this comment prevents.
		return asCertProvider(newOriginCAProvider(ctx, cfg, now, builtinSecretResolver(cfg)))
	default:
		return nil, fmt.Errorf("%w: %q", ErrTLSModeUnsupported, cfg.TLS.Mode)
	}
}

// asCertProvider lifts a concrete provider constructor's (*T, error) result into
// (CertProvider, error) without ever producing a typed-nil interface.
//
// The type parameter is constrained to CertProvider, so this cannot be used to
// smuggle a non-provider through; on error the returned interface is the
// UNTYPED nil literal, which is the only value for which `provider == nil` is
// true. Returning p directly on the error path would satisfy the compiler and
// silently defeat the whole point.
func asCertProvider[T CertProvider](p T, err error) (CertProvider, error) {
	if err != nil {
		return nil, err
	}
	return p, nil
}

// secretResolver resolves a config secret reference to its value.
//
// It is a function type rather than the concrete *secrets.Resolver so that a
// test can supply a missing or failing credential without standing up an
// environment or a file, which is what makes the credential-missing failure
// path testable at all.
type secretResolver func(ctx context.Context, ref secrets.Ref) (secrets.Redacted, error)

// builtinSecretResolver returns the resolver used in production: the built-in
// env and file providers from ADR-0022.
//
// The file provider's permission posture is derived from the environment, which
// is the split the secrets package documents — it never imports config, so the
// config layer makes this call. Production REFUSES a world-readable secret
// file, because a credential any local account can read must be treated as
// already copied; development warns instead, so a contributor is not blocked by
// a checkout's permissions.
//
// A resolver is built here, at the point of use, rather than threaded down from
// main because this is currently the only production consumer of a secret
// reference. When a second one appears, hoisting construction into bootstrap
// and passing it in is the right move; doing it now would add a parameter to
// Server.New that nothing else needs.
func builtinSecretResolver(cfg *config.Config) secretResolver {
	permMode := secrets.PermError
	if cfg.Server.Environment != "production" {
		permMode = secrets.PermWarn
	}
	return func(ctx context.Context, ref secrets.Ref) (secrets.Redacted, error) {
		resolver, err := secrets.NewResolver(secrets.Builtin(secrets.FileOptions{PermMode: permMode})...)
		if err != nil {
			return "", err
		}
		return resolver.Resolve(ctx, ref)
	}
}

// newACMEProviderForSolver dispatches on the configured ACME solver.
//
// dns_01 is a valid configuration that this track does not implement, so it
// refuses rather than silently solving with TLS-ALPN-01 instead. Answering a
// challenge the operator did not select would issue through a path they may
// have deliberately ruled out — for example a deployment whose port 443 is not
// reachable from the CA — and would do it silently.
func newACMEProviderForSolver(ctx context.Context, cfg *config.Config, now func() time.Time) (CertProvider, error) {
	switch cfg.TLS.ACME.Solver {
	case "tls_alpn_01":
		// asCertProvider for the same reason as in newCertProvider: this is the
		// TRUE source of the acme mode's interface value, so fixing the
		// passthrough above without fixing it here would leave the hazard.
		return asCertProvider(newACMEProvider(ctx, cfg, now))
	default:
		return nil, fmt.Errorf("%w: acme solver %q", ErrTLSModeUnsupported, cfg.TLS.ACME.Solver)
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
