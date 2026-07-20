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
	"sync"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/config"
)

// selfSignedValidity is the hard ceiling on an ephemeral certificate's lifetime.
//
// ADR-0015 ("Guardrails for the ephemeral self-signed mode") fixes this at at
// most ~6 hours and states the reason: the ceiling is low ON PURPOSE so the mode
// cannot quietly become a steady-state production posture. It is a constant and
// not a config knob for the same reason — an operator who could raise it to a
// year would have turned the dev-only escape hatch into a permanent one.
//
// E1 shipped 24h here, which exceeded the ADR ceiling; this is the correction.
const selfSignedValidity = 6 * time.Hour

// selfSignedRenewBefore is how long before expiry a new certificate is minted.
//
// Renewal exists even for this provider because the certificate is short-lived
// by design: a process running longer than selfSignedValidity would otherwise
// hit the guard's expiry check and stop serving. Regenerating is lazy — on the
// next handshake, no background goroutine — which keeps the provider free of any
// lifecycle to manage while still exercising the interface's ability to return
// DIFFERENT material over the process lifetime.
const selfSignedRenewBefore = 30 * time.Minute

// environmentDevelopment is the ONLY environment value that permits a
// self-signed certificate without an explicit production override.
//
// It is matched exactly and positively. See isProduction.
const environmentDevelopment = "development"

// isProduction decides whether this instance must be treated as production.
//
// The test is deliberately inverted: an instance is production unless it says,
// exactly, that it is development. Everything else — "", "prod", "Production",
// "staging", a typo, a config file that never set the key, a zero-valued
// config.Config constructed in code — is production and refuses.
//
// Written the obvious way round (`Environment == "production"`) it is
// DEFAULT-ALLOW: every unrecognized or missing value falls through to "not
// production" and quietly permits a self-signed certificate. That is the precise
// failure this project cannot have, because the config that most plausibly
// reaches a real deployment with a bad environment string is one an operator
// copied and edited, and the punishment for a typo would be a server presenting
// a certificate no client can authenticate.
//
// This check is intentionally independent of config.Validate, which already
// restricts the field to production|development. buildTLSConfig accepts a
// *config.Config that no one has proven was validated, so the security decision
// is re-derived here rather than inherited. A nil config is production too.
func isProduction(cfg *config.Config) bool {
	if cfg == nil {
		return true
	}
	return cfg.Server.Environment != environmentDevelopment
}

// selfSignedProvider serves an ephemeral, in-memory, self-signed certificate.
//
// This is ADR-0015 §2's development / install-bootstrap mode: it exists so the
// HTTPS-only invariant holds before a real certificate is available, never as a
// fallback when another provider fails. The key is generated on demand and never
// touches disk, so there is no key file to leak and every restart invalidates
// whatever the previous run issued.
//
// Safe for concurrent use: crypto/tls calls GetCertificate from every connection
// goroutine, and the lazy regeneration below is a read-modify-write of shared
// state that must not race.
type selfSignedProvider struct {
	hosts []string
	now   func() time.Time

	mu   sync.Mutex
	cert *tls.Certificate
}

// newSelfSignedProvider builds the provider, refusing outright in production.
//
// The refusal happens HERE, at construction, rather than at the first handshake:
// a process that may not use this mode must fail to start, visibly, instead of
// binding a port and then refusing every connection in a way that looks like a
// network fault.
//
// tls.allow_self_signed_in_production is the ADR's "separate, explicit
// override". It is a positive opt-in an operator must write down; note that it
// cannot be reached by ACCIDENT the way the environment check could, because its
// zero value is false and no typo can turn it true.
func newSelfSignedProvider(cfg *config.Config, now func() time.Time) (*selfSignedProvider, error) {
	if isProduction(cfg) && !allowsSelfSignedInProduction(cfg) {
		return nil, fmt.Errorf(
			"%w: environment %q is treated as production; set tls.allow_self_signed_in_production to override",
			ErrSelfSignedInProduction, environmentOf(cfg))
	}
	return &selfSignedProvider{hosts: certHosts(cfg), now: now}, nil
}

// allowsSelfSignedInProduction reports the explicit operator override.
func allowsSelfSignedInProduction(cfg *config.Config) bool {
	return cfg != nil && cfg.TLS.AllowSelfSignedInProduction
}

// environmentOf returns the configured environment for diagnostics. It is
// operator-supplied config, not a secret, so quoting it in an error is what
// lets an operator see the typo that caused the refusal.
func environmentOf(cfg *config.Config) string {
	if cfg == nil {
		return ""
	}
	return cfg.Server.Environment
}

// Name identifies the mode. It is a constant: nothing derived from certificate
// or key material ever appears in a provider name.
func (p *selfSignedProvider) Name() string { return "self_signed" }

// GetCertificate returns the current ephemeral certificate, minting a new one
// when the old one is missing or close to expiry.
//
// The renewal threshold is checked against the leaf's real NotAfter, so this
// provider genuinely returns different material over the process lifetime —
// which is the property the CertProvider interface exists to support and the
// one a startup-only Load() could not have.
//
// The hello is unused: a self-signed certificate covers the configured hosts
// regardless of SNI, and refusing unknown SNI here would only convert a
// certificate warning the developer already expects into an opaque handshake
// failure.
func (p *selfSignedProvider) GetCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	now := p.now()
	if p.cert != nil && p.cert.Leaf != nil && now.Before(p.cert.Leaf.NotAfter.Add(-selfSignedRenewBefore)) {
		return p.cert, nil
	}

	cert, err := newSelfSignedCert(p.hosts, now)
	if err != nil {
		// Fail rather than keep serving the old certificate. Returning the
		// stale one on a generation failure would be exactly the silent
		// downgrade the guard is built to prevent, and generation failing at
		// all means the process is in no state to be trusted.
		return nil, err
	}
	p.cert = &cert
	return p.cert, nil
}

// certHosts returns the names the ephemeral certificate should cover: the
// configured domain and SANs, defaulting to loopback when neither is set.
func certHosts(cfg *config.Config) []string {
	if cfg == nil {
		return []string{"localhost", "127.0.0.1", "::1"}
	}
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
// The key exists for the lifetime of the process only and is never written
// anywhere.
//
// Note on error handling: ed25519.GenerateKey and rand.Int draw from
// crypto/rand, whose Read cannot fail as of Go 1.24 — it terminates the process
// instead of returning an error. The error returns are still checked because the
// functions declare them and ignoring a declared error is worse practice than a
// branch that does not fire; but no attempt is made to build recovery logic
// around a condition that cannot be reached.
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
