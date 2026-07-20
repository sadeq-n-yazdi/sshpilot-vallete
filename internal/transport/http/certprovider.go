package httpserver

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"time"
)

// CertProvider is the source of the server's TLS certificate.
//
// Every certificate-provisioning mode of ADR-0015 §2 is one implementation:
// ephemeral self-signed and operator-provided ship here, CSR and upstream
// termination follow, and ACME (TLS-ALPN-01 and DNS-01), Cloudflare Origin CA
// and the DNS-provider tail plug in later without changing this interface.
//
// # Why this shape
//
// The signature is deliberately [tls.Config.GetCertificate]'s. A provider is
// asked for a certificate PER HANDSHAKE, not once at startup, and that is the
// whole reason the interface exists:
//
//   - Renewal. An ACME certificate is replaced while the process runs. A
//     one-shot Load() would pin the startup certificate for the process
//     lifetime and force a restart to pick up a renewal — for a 90-day cert on
//     a ~30-day renewal cadence that is a guaranteed outage.
//   - Fail closed on expiry (ADR-0015 §4). tls.go documents this as E1's known
//     gap: its expiry check is a STARTUP check, so a certificate that expires
//     while running keeps being served. Only a per-handshake callback can
//     refuse at the moment the certificate goes invalid, and that comment names
//     this callback as the intended hook.
//   - Name-dependent selection. The hello carries SNI, which TLS-ALPN-01 and
//     multi-SAN deployments need. Discarding it now would be a breaking change
//     later.
//
// Providers that need background work (an ACME renewal loop) additionally
// implement [io.Closer]; see [certGuard.Close]. That is kept OFF this interface
// so the many providers with nothing to tear down are not forced to carry an
// empty method.
//
// # Contract for implementations
//
// Return a usable certificate or an error. NEVER return a certificate the
// implementation knows to be bad, and never substitute a weaker one on failure:
// an error here makes the handshake fail, which is the required outcome, while a
// silent downgrade is the outcome ADR-0015 exists to prevent.
//
// Implementations must not log, format, or otherwise emit private key material.
// The returned key stays inside tls.Certificate.PrivateKey as a crypto.Signer.
type CertProvider interface {
	// Name identifies the mode for operator-facing diagnostics. It is a
	// constant like "self_signed" — never anything derived from key material.
	Name() string

	// GetCertificate returns the certificate to present for this handshake.
	// It must be safe for concurrent use: crypto/tls calls it from every
	// connection goroutine.
	GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error)
}

// certGuard is the single validation gate between every CertProvider and
// crypto/tls.
//
// A provider is not trusted because it is registered. Whatever a provider
// returns — including the ones in this repository — is re-checked here before
// it can be presented to a client, because "the provider is correct" is exactly
// the assumption a compromised, buggy or misconfigured provider violates. There
// is one gate rather than a check inside each provider so that a future provider
// cannot forget to have one.
//
// The guard is installed as tls.Config.GetCertificate with tls.Config
// Certificates left nil, so there is no second path by which an unvalidated
// certificate could reach a handshake.
type certGuard struct {
	provider CertProvider

	// now is the validity clock, injected so expiry behavior is deterministic
	// in tests. Production passes time.Now.
	now func() time.Time
}

// newCertGuard wraps a provider in the validation gate.
func newCertGuard(provider CertProvider, now func() time.Time) *certGuard {
	return &certGuard{provider: provider, now: now}
}

// GetCertificate is the tls.Config.GetCertificate callback.
//
// Fail-closed is the entire contract: every path that does not produce a
// validated certificate returns an error, and an error from this callback aborts
// the handshake. There is deliberately NO fallback — not to a self-signed
// certificate, not to a previously good one, not to plaintext. A client that
// cannot be served securely is not served at all, which is the posture ADR-0015
// chose over serving something weaker.
func (g *certGuard) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	cert, err := g.provider.GetCertificate(hello)
	if err != nil {
		// The provider name is included because with several modes an operator
		// needs to know which one failed. The underlying error is wrapped, not
		// re-worded, so ACME/DNS diagnostics survive; no provider is permitted
		// to put key material in an error, per the interface contract.
		return nil, fmt.Errorf("%w: %s provider: %w", ErrTLSCertificateUnavailable, g.provider.Name(), err)
	}
	if cert == nil {
		// A nil certificate with a nil error is a provider bug. Treated as a
		// failure rather than passed on, because returning (nil, nil) from
		// GetCertificate makes crypto/tls fall back to tls.Config.Certificates
		// — which would be an unvalidated path around this guard if that field
		// were ever non-empty.
		return nil, fmt.Errorf("%w: %s provider returned no certificate",
			ErrTLSCertificateUnavailable, g.provider.Name())
	}
	if err := validateCertificate(cert, g.now()); err != nil {
		return nil, fmt.Errorf("%s provider: %w", g.provider.Name(), err)
	}
	return cert, nil
}

// Close releases provider resources when the provider has any.
//
// The type assertion is how optional background work (an ACME renewal loop)
// is supported without putting a lifecycle on every provider. A provider with
// nothing to close needs no method and no no-op.
func (g *certGuard) Close() error {
	if c, ok := g.provider.(interface{ Close() error }); ok {
		return c.Close()
	}
	return nil
}

// validateCertificate rejects any certificate that must not be presented.
//
// Three independent defects, each of which would otherwise be served happily by
// crypto/tls:
//
//  1. No certificate at all -> ErrTLSCertificateInvalid.
//  2. The private key does not match the leaf's public key ->
//     ErrTLSCertificateInvalid. crypto/tls does NOT check this at handshake
//     time when the certificate comes from GetCertificate; a mismatch surfaces
//     as an opaque signature failure to the client, or, worse, as a certificate
//     presented with a key the operator did not intend.
//  3. The leaf is outside its validity window -> ErrTLSCertificateExpired.
//     This is the per-handshake enforcement of ADR-0015 §4's fail-closed-on-
//     expiry rule that E1 could only do at startup.
//
// The leaf is ALWAYS re-parsed from the DER in Certificate[0] and the
// caller-supplied Leaf field is ignored for validation. This is not redundancy:
// tls.Certificate.Leaf is an ordinary struct field a provider sets, so a
// provider could present an expired DER chain alongside a Leaf pointing at
// something valid. Clients verify the DER, so the DER is what must be checked.
//
// Validity is checked on the leaf only; intermediates belong to the issuing CA
// and are the client's business to verify against its own trust store, so
// failing closed on one an operator cannot fix would be failing closed on
// someone else's clock. This matches manualCertificate's reasoning.
func validateCertificate(cert *tls.Certificate, now time.Time) error {
	if len(cert.Certificate) == 0 {
		return fmt.Errorf("%w: certificate chain is empty", ErrTLSCertificateInvalid)
	}

	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return fmt.Errorf("%w: parse leaf: %w", ErrTLSCertificateInvalid, err)
	}

	if err := checkKeyMatchesLeaf(cert.PrivateKey, leaf); err != nil {
		return err
	}

	// Both ends of the window are enforced. A not-yet-valid certificate is as
	// unservable as an expired one — clients reject both — and it is the usual
	// symptom of a skewed clock, so it is refused rather than waved through.
	if now.Before(leaf.NotBefore) {
		return fmt.Errorf("%w: not valid before %s",
			ErrTLSCertificateExpired, leaf.NotBefore.UTC().Format(time.RFC3339))
	}
	if now.After(leaf.NotAfter) {
		return fmt.Errorf("%w: expired at %s",
			ErrTLSCertificateExpired, leaf.NotAfter.UTC().Format(time.RFC3339))
	}

	return nil
}

// checkKeyMatchesLeaf verifies that the private key really is the leaf's key.
//
// The comparison is done on PUBLIC keys, via the Equal method every standard
// key type implements (crypto.PublicKey's documented contract since Go 1.15).
// The alternative the brief allows — re-encoding to PEM and calling
// tls.X509KeyPair — would serialize the PRIVATE key into a byte slice purely to
// perform a comparison, creating exactly the kind of plaintext key copy that
// must not exist in this process. Comparing public keys reaches the same
// conclusion without ever marshaling a secret.
//
// Anything that is not a crypto.Signer, or whose public key does not expose
// Equal, is REFUSED rather than allowed through unchecked. An unrecognized key
// type means the match cannot be established, and an unestablished match must
// deny — the same fail-closed rule trustedPeers.trusts follows.
func checkKeyMatchesLeaf(key crypto.PrivateKey, leaf *x509.Certificate) error {
	if key == nil {
		return fmt.Errorf("%w: certificate has no private key", ErrTLSCertificateInvalid)
	}

	signer, ok := key.(crypto.Signer)
	if !ok {
		// %T names the TYPE only. It never renders the value, so no key bytes
		// can reach the error string.
		return fmt.Errorf("%w: private key of type %T cannot sign", ErrTLSCertificateInvalid, key)
	}

	pub, ok := signer.Public().(interface{ Equal(crypto.PublicKey) bool })
	if !ok {
		return fmt.Errorf("%w: private key of type %T cannot be compared to the certificate",
			ErrTLSCertificateInvalid, key)
	}

	if !pub.Equal(leaf.PublicKey) {
		return fmt.Errorf("%w: private key does not match the certificate", ErrTLSCertificateInvalid)
	}
	return nil
}
