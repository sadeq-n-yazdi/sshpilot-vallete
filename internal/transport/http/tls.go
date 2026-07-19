package httpserver

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/config"
)

// selfSignedValidity is how long a development certificate is accepted.
//
// It is deliberately short. The key never leaves memory and is regenerated on
// every start, so a long validity buys nothing; a short one bounds the damage
// if a developer pins or copies the certificate somewhere it does not belong.
const selfSignedValidity = 24 * time.Hour

// buildTLSConfig assembles the server's TLS configuration from operator config,
// failing closed on anything it cannot serve safely.
//
// Only two of the configured modes are implemented in this track: self_signed
// (development bring-up) and manual (operator-supplied files). ACME, Cloudflare
// origin, CSR, and upstream termination are later tracks and return
// [ErrTLSModeUnsupported] rather than silently degrading to a weaker
// certificate.
//
// The now argument is the validity clock for certificate checks. It is a
// parameter rather than a call to time.Now so that expiry behavior is
// deterministically testable; production passes the real clock.

func buildTLSConfig(cfg *config.Config, now time.Time) (*tls.Config, error) {
	minVersion, err := parseMinVersion(cfg.TLS.MinVersion)
	if err != nil {
		return nil, err
	}

	var cert tls.Certificate
	switch cfg.TLS.Mode {
	case "self_signed":
		cert, err = selfSignedCertificate(cfg, now)
	case "manual":
		cert, err = tls.LoadX509KeyPair(cfg.TLS.Manual.CertFile, cfg.TLS.Manual.KeyFile)
		if err != nil {
			err = fmt.Errorf("httpserver: load tls keypair: %w", err)
		}
	default:
		err = fmt.Errorf("%w: %q", ErrTLSModeUnsupported, cfg.TLS.Mode)
	}
	if err != nil {
		return nil, err
	}

	return &tls.Config{
		MinVersion:   minVersion,
		Certificates: []tls.Certificate{cert},
		CipherSuites: tls12CipherSuites(),
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

// selfSignedCertificate returns an ephemeral development certificate, refusing
// to produce one in production without an explicit opt-in.
//
// A self-signed certificate offers no way for a client to tell this server from
// an interceptor, which defeats the point of serving TLS at all. Development
// bring-up still needs *some* certificate, so it is allowed there — but
// production must set tls.allow_self_signed_in_production, making the weakened
// posture a recorded, deliberate decision rather than an accident of a copied
// config file.
func selfSignedCertificate(cfg *config.Config, now time.Time) (tls.Certificate, error) {
	if cfg.Server.Environment == "production" && !cfg.TLS.AllowSelfSignedInProduction {
		return tls.Certificate{}, fmt.Errorf(
			"%w: set tls.allow_self_signed_in_production to override", ErrSelfSignedInProduction)
	}
	return newSelfSignedCert(certHosts(cfg), now)
}

// certHosts returns the names the development certificate should cover: the
// configured domain and SANs, defaulting to loopback when neither is set.
func certHosts(cfg *config.Config) []string {
	hosts := make([]string, 0, len(cfg.TLS.SANs)+1)
	if cfg.TLS.Domain != "" {
		hosts = append(hosts, cfg.TLS.Domain)
	}
	hosts = append(hosts, cfg.TLS.SANs...)
	if len(hosts) == 0 {
		hosts = []string{"localhost", "127.0.0.1", "::1"}
	}
	return hosts
}

// newSelfSignedCert generates an in-memory ed25519 self-signed certificate.
//
// ed25519 is used for speed and for having no parameter choices to get wrong.
// The key is never written to disk: it exists for the lifetime of the process
// only, so there is no key file to leak, and every restart invalidates whatever
// the previous run issued.
func newSelfSignedCert(hosts []string, now time.Time) (tls.Certificate, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("httpserver: generate key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("httpserver: generate serial: %w", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{Organization: []string{"sshpilot-vallet development"}},
		NotBefore:    now.Add(-time.Minute), // tolerate small clock skew
		NotAfter:     now.Add(selfSignedValidity),
		// An end-entity certificate, NOT a CA: it is self-issued only because
		// there is no issuer to ask. Setting IsCA/KeyUsageCertSign would mean
		// that a developer who added this cert to a trust store granted it the
		// power to vouch for arbitrary other names, so the capability is
		// withheld even though the key is ephemeral and in-memory.
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
			continue
		}
		tmpl.DNSNames = append(tmpl.DNSNames, h)
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("httpserver: create certificate: %w", err)
	}

	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("httpserver: parse certificate: %w", err)
	}

	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  priv,
		Leaf:        leaf,
	}, nil
}
