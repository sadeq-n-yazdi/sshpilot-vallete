package httpserver

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/acme"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/config"
)

// idPeACMEIdentifier is the OID of the critical extension RFC 8737 requires in
// a TLS-ALPN-01 challenge certificate.
//
// It is redeclared here rather than imported because the acme package keeps it
// unexported. That is deliberate for these tests: the presence of THIS
// extension is what makes a certificate a challenge certificate, so the tests
// identify one by the property the CA actually looks for, not by which variable
// the implementation happened to return.
var idPeACMEIdentifier = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 31}

// hasACMEIdentifier reports whether a certificate is a TLS-ALPN-01 challenge
// certificate, by re-parsing the leaf from DER and looking for the extension.
//
// Re-parsing from DER is the point. A test that trusted tls.Certificate.Leaf,
// or that compared pointers against the certificate the test itself installed,
// would pass even if the provider returned the wrong material, because it would
// be asserting on bookkeeping instead of on the bytes a client receives.
func hasACMEIdentifier(t *testing.T, cert *tls.Certificate) bool {
	t.Helper()

	if cert == nil || len(cert.Certificate) == 0 {
		t.Fatal("certificate has no DER chain")
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	for _, ext := range leaf.Extensions {
		if ext.Id.Equal(idPeACMEIdentifier) {
			return true
		}
	}
	return false
}

// mustTestAccountKey returns an account key for building challenge
// certificates. acme.Client derives the key authorization from this key's
// public part, so a real one is required even with no CA involved.
func mustTestAccountKey(t *testing.T) crypto.Signer {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate account key: %v", err)
	}
	return key
}

// acmeTestProvider builds a provider with no CA behind it.
//
// Every invariant in this file is a property of the provider's own logic —
// which certificate it hands to which handshake, what it refuses, what it
// persists — so none of them needs an ACME server. Constructing directly also
// keeps the tests from depending on network reachability, which is what makes
// them able to assert fail-closed behavior deterministically.
func acmeTestProvider(t *testing.T, now time.Time) *acmeProvider {
	t.Helper()

	return &acmeProvider{
		domains:   []string{"vallet.example.com"},
		cacheDir:  t.TempDir(),
		now:       staticClock(now),
		challenge: make(map[string]*tls.Certificate),
		stop:      func() {},
		done:      make(chan struct{}),
	}
}

// TestACMEChallengeCertIsolatedFromOrdinaryTraffic is the central security test
// of this provider.
//
// A TLS-ALPN-01 challenge certificate is self-signed and authenticates nothing.
// Handing one to an ordinary client would give them a certificate that does not
// identify this service, while the connection still looks successful — so the
// two certificates must never be confused in either direction.
//
// The assertion is on the acmeIdentifier EXTENSION, re-parsed from DER, not on
// "some certificate was returned". That distinction is the whole test: a
// provider that returned the challenge certificate to everyone would satisfy a
// did-I-get-a-certificate check on every one of these cases.
func TestACMEChallengeCertIsolatedFromOrdinaryTraffic(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	p := acmeTestProvider(t, now)

	// A real issued certificate for ordinary traffic, and a real challenge
	// certificate built by the acme package itself for the challenge path.
	real := mustSelfSigned(t, now)
	p.setCurrent(real)

	client := &acme.Client{Key: mustTestAccountKey(t)}
	challenge, err := client.TLSALPN01ChallengeCert("test-token", "vallet.example.com")
	if err != nil {
		t.Fatalf("TLSALPN01ChallengeCert: %v", err)
	}
	p.setChallengeCert("vallet.example.com", &challenge)

	tests := []struct {
		name  string
		alpn  []string
		want  bool // want the acmeIdentifier extension
		about string
	}{
		{
			name:  "acme-tls/1 alone gets the challenge certificate",
			alpn:  []string{acme.ALPNProto},
			want:  true,
			about: "this is the CA validating; it must get the challenge answer",
		},
		{
			name:  "h2 gets the real certificate",
			alpn:  []string{"h2"},
			want:  false,
			about: "ordinary browser/client traffic",
		},
		{
			name:  "http/1.1 gets the real certificate",
			alpn:  []string{"http/1.1"},
			want:  false,
			about: "ordinary curl / AuthorizedKeysCommand traffic",
		},
		{
			name:  "no ALPN gets the real certificate",
			alpn:  nil,
			want:  false,
			about: "a client that offers no ALPN at all",
		},
		{
			name: "acme-tls/1 alongside h2 gets the real certificate",
			alpn: []string{acme.ALPNProto, "h2"},
			want: false,
			about: "the evasion this guards against: RFC 8737 requires a CA to " +
				"offer acme-tls/1 ALONE, so a client listing it next to a real " +
				"protocol is not validating and must not be handed the challenge",
		},
		{
			name:  "h2 ahead of acme-tls/1 gets the real certificate",
			alpn:  []string{"h2", acme.ALPNProto},
			want:  false,
			about: "the same evasion with the order reversed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := p.GetCertificate(&tls.ClientHelloInfo{
				ServerName:      "vallet.example.com",
				SupportedProtos: tt.alpn,
			})
			if err != nil {
				t.Fatalf("GetCertificate(%v): %v (%s)", tt.alpn, err, tt.about)
			}

			if isChallenge := hasACMEIdentifier(t, got); isChallenge != tt.want {
				t.Errorf("ALPN %v: got challenge certificate = %v, want %v (%s)",
					tt.alpn, isChallenge, tt.want, tt.about)
			}
		})
	}
}

// TestACMEChallengeCertNeverBecomesTheServiceCertificate proves the challenge
// certificate cannot be installed as the certificate ordinary clients get.
//
// The isolation test above shows the two paths return different material while
// both exist. This one removes the real certificate entirely, which is the
// state a first run is in while its order is being validated: with only a
// challenge certificate in hand, ordinary traffic must be REFUSED rather than
// served the one certificate that happens to be available.
func TestACMEChallengeCertNeverBecomesTheServiceCertificate(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	p := acmeTestProvider(t, now)

	client := &acme.Client{Key: mustTestAccountKey(t)}
	challenge, err := client.TLSALPN01ChallengeCert("test-token", "vallet.example.com")
	if err != nil {
		t.Fatalf("TLSALPN01ChallengeCert: %v", err)
	}
	p.setChallengeCert("vallet.example.com", &challenge)

	got, err := p.GetCertificate(&tls.ClientHelloInfo{
		ServerName:      "vallet.example.com",
		SupportedProtos: []string{"h2"},
	})
	if err == nil {
		t.Fatalf("ordinary handshake was served a certificate while only a challenge existed "+
			"(challenge certificate = %v)", hasACMEIdentifier(t, got))
	}
	if !errors.Is(err, ErrACMEIssuance) {
		t.Errorf("error = %v, want ErrACMEIssuance", err)
	}
}

// TestACMEChallengeWithdrawnAfterUse proves a challenge answer stops being
// reachable once its order settles.
func TestACMEChallengeWithdrawnAfterUse(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	p := acmeTestProvider(t, now)

	client := &acme.Client{Key: mustTestAccountKey(t)}
	challenge, err := client.TLSALPN01ChallengeCert("test-token", "vallet.example.com")
	if err != nil {
		t.Fatalf("TLSALPN01ChallengeCert: %v", err)
	}

	p.setChallengeCert("vallet.example.com", &challenge)
	if _, err := p.challengeCert("vallet.example.com"); err != nil {
		t.Fatalf("challenge should be answerable while pending: %v", err)
	}

	p.clearChallenge("vallet.example.com")
	if _, err := p.challengeCert("vallet.example.com"); err == nil {
		t.Error("challenge certificate still served after the order settled")
	}
}

// TestACMEChallengePathRefusesUnknownNames proves the challenge path does not
// fall back to the real certificate for a name it has no pending order for.
//
// Falling back would put the service certificate on a path anyone can reach by
// asking for acme-tls/1, and would not satisfy a CA anyway.
func TestACMEChallengePathRefusesUnknownNames(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	p := acmeTestProvider(t, now)
	p.setCurrent(mustSelfSigned(t, now))

	got, err := p.GetCertificate(&tls.ClientHelloInfo{
		ServerName:      "attacker.example.net",
		SupportedProtos: []string{acme.ALPNProto},
	})
	if err == nil {
		t.Fatalf("challenge path served a certificate for a name with no pending order "+
			"(challenge certificate = %v)", hasACMEIdentifier(t, got))
	}
	if !errors.Is(err, ErrACMEIssuance) {
		t.Errorf("error = %v, want ErrACMEIssuance", err)
	}
}

// TestACMEIssuanceFailureRefusesToServe proves the fail-closed posture: when no
// certificate has been issued, handshakes are refused and nothing weaker is
// substituted.
//
// The check is not merely that an error came back. It also asserts that no
// certificate accompanies it, because a silent downgrade to a self-signed
// certificate is the specific outcome this rule exists to prevent — it would
// leave monitoring showing a healthy service that authenticates nothing.
func TestACMEIssuanceFailureRefusesToServe(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	p := acmeTestProvider(t, now)

	cert, err := p.GetCertificate(&tls.ClientHelloInfo{
		ServerName:      "vallet.example.com",
		SupportedProtos: []string{"h2"},
	})
	if err == nil {
		t.Fatal("GetCertificate succeeded with no issued certificate; must fail closed")
	}
	if cert != nil {
		t.Errorf("a certificate was returned alongside the error: downgrade, not refusal")
	}
	if !errors.Is(err, ErrACMEIssuance) {
		t.Errorf("error = %v, want ErrACMEIssuance", err)
	}

	// The same refusal must survive the guard, since the guard is what the TLS
	// stack actually calls.
	guard := newCertGuard(p, staticClock(now))
	if _, err := guard.GetCertificate(&tls.ClientHelloInfo{SupportedProtos: []string{"h2"}}); err == nil {
		t.Error("guard served a certificate when the provider had none")
	}
}

// TestACMERenewalReplacesCertificateWithoutRestart proves the property that
// motivated the per-handshake CertProvider interface in the first place.
//
// The same provider instance — never reconstructed, no listener rebind, no
// process restart — must serve the new certificate on the next handshake after
// a renewal. The two certificates are distinguished by their DER bytes, so a
// provider that pinned the first one cannot pass by returning something
// superficially similar.
func TestACMERenewalReplacesCertificateWithoutRestart(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	p := acmeTestProvider(t, now)

	first := mustSelfSigned(t, now)
	p.setCurrent(first)

	hello := &tls.ClientHelloInfo{ServerName: "localhost", SupportedProtos: []string{"h2"}}

	before, err := p.GetCertificate(hello)
	if err != nil {
		t.Fatalf("GetCertificate before renewal: %v", err)
	}
	if !bytesEqual(before.Certificate[0], first.Certificate[0]) {
		t.Fatal("provider did not serve the certificate it was given")
	}

	// Renewal: a genuinely different certificate replaces the old one.
	second := mustSelfSigned(t, now.Add(time.Hour))
	if bytesEqual(first.Certificate[0], second.Certificate[0]) {
		t.Fatal("test setup produced two identical certificates; it cannot detect a swap")
	}
	p.setCurrent(second)

	after, err := p.GetCertificate(hello)
	if err != nil {
		t.Fatalf("GetCertificate after renewal: %v", err)
	}
	if !bytesEqual(after.Certificate[0], second.Certificate[0]) {
		t.Error("handshake still served the OLD certificate after renewal; " +
			"renewal requires a restart, which the CertProvider interface exists to avoid")
	}
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestACMENeedsRenewalThreshold pins the renew-ahead rule of ADR-0015 §4: at
// most two-thirds of the lifetime may have elapsed before renewal starts.
func TestACMENeedsRenewalThreshold(t *testing.T) {
	t.Parallel()

	notBefore := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	leaf := &x509.Certificate{NotBefore: notBefore, NotAfter: notBefore.Add(90 * 24 * time.Hour)}

	tests := []struct {
		name string
		at   time.Time
		want bool
	}{
		{"fresh", notBefore.Add(time.Hour), false},
		{"halfway", notBefore.Add(45 * 24 * time.Hour), false},
		{"just inside the window", notBefore.Add(59 * 24 * time.Hour), false},
		{"30 days left", notBefore.Add(61 * 24 * time.Hour), true},
		{"expired", notBefore.Add(91 * 24 * time.Hour), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := acmeNeedsRenewal(leaf, tt.at); got != tt.want {
				t.Errorf("acmeNeedsRenewal at %v = %v, want %v", tt.at, got, tt.want)
			}
		})
	}
}

// TestACMEBackoffGrowsAndIsCapped pins the retry policy. A backoff that stayed
// flat, or that reset on every failure, would be the hot retry loop that turns
// a transient CA failure into a week-long rate-limit lockout.
func TestACMEBackoffGrowsAndIsCapped(t *testing.T) {
	t.Parallel()

	// First failure must wait at least the floor, never retry immediately.
	first := nextACMEBackoff(0)
	if first < acmeBackoffMin {
		t.Errorf("first backoff = %v, want at least %v", first, acmeBackoffMin)
	}

	// Growth: each step must exceed the previous one's nominal value.
	second := nextACMEBackoff(first)
	if second <= first {
		t.Errorf("backoff did not grow: %v then %v", first, second)
	}

	// Ceiling: even from an absurd starting point the delay stays bounded, so a
	// long outage does not turn into an effectively infinite wait. The jitter
	// adds up to a quarter on top of the cap.
	capped := nextACMEBackoff(30 * 24 * time.Hour)
	if capped > acmeBackoffMax+acmeBackoffMax/4 {
		t.Errorf("backoff = %v, want at most %v plus jitter", capped, acmeBackoffMax)
	}
}

// TestACMEAccountKeyCustody proves the account key is held to the same rules as
// the CSR mode's key: created 0600, and a key other accounts can read is
// refused rather than used.
func TestACMEAccountKeyCustody(t *testing.T) {
	t.Parallel()

	t.Run("created 0600", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "account.key")

		if _, err := loadOrCreateKey(path); err != nil {
			t.Fatalf("loadOrCreateKey: %v", err)
		}

		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat: %v", err)
		}
		if got := info.Mode().Perm(); got != keyFileMode {
			t.Errorf("account key mode = %#o, want %#o", got, keyFileMode)
		}
	})

	for _, mode := range []os.FileMode{0o640, 0o604, 0o644, 0o660, 0o666} {
		t.Run("refuses mode "+mode.String(), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "account.key")

			if _, err := loadOrCreateKey(path); err != nil {
				t.Fatalf("seed key: %v", err)
			}
			if err := os.Chmod(path, mode); err != nil {
				t.Fatalf("chmod: %v", err)
			}

			_, err := loadOrCreateKey(path)
			if !errors.Is(err, ErrTLSKeyPermissions) {
				t.Errorf("mode %#o: error = %v, want ErrTLSKeyPermissions", mode, err)
			}
		})
	}
}

// TestACMEProviderRefusesWithoutTOS proves the provider will not register an
// account while asserting agreement to terms the operator never accepted, even
// if config validation is bypassed.
func TestACMEProviderRefusesWithoutTOS(t *testing.T) {
	t.Parallel()

	cfg := acmeTestConfig(t)
	cfg.TLS.ACME.AcceptTOS = false

	// The directory URL points nowhere reachable, so if the TOS check were
	// removed this would fail with a network error instead — which is why the
	// assertion is on the specific sentinel, not merely on "an error".
	_, err := newACMEProvider(t.Context(), cfg, time.Now)
	if !errors.Is(err, ErrACMETermsNotAccepted) {
		t.Errorf("error = %v, want ErrACMETermsNotAccepted", err)
	}
}

// TestACMEProviderFailsClosedOnUnreachableDirectory proves an unreachable CA is
// a startup failure, not a server that comes up serving something else.
func TestACMEProviderFailsClosedOnUnreachableDirectory(t *testing.T) {
	t.Parallel()

	cfg := acmeTestConfig(t)

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	p, err := newACMEProvider(ctx, cfg, time.Now)
	if err == nil {
		_ = p.Close()
		t.Fatal("provider constructed against an unreachable directory; must fail closed")
	}
	if !errors.Is(err, ErrACMEAccount) {
		t.Errorf("error = %v, want ErrACMEAccount", err)
	}
}

// acmeTestConfig returns an acme-mode config pointing at an unroutable
// directory. 127.0.0.1 with a closed port refuses immediately, so a test that
// expects failure gets it without waiting on a timeout.
func acmeTestConfig(t *testing.T) *config.Config {
	t.Helper()

	dir := t.TempDir()
	cfg := devConfig()
	cfg.TLS.Mode = "acme"
	cfg.TLS.Domain = "vallet.example.com"
	cfg.TLS.ACME.Solver = "tls_alpn_01"
	cfg.TLS.ACME.DirectoryURL = "https://127.0.0.1:1/directory"
	cfg.TLS.ACME.AccountKeyFile = filepath.Join(dir, "account.key")
	cfg.TLS.ACME.CacheDir = filepath.Join(dir, "cache")
	cfg.TLS.ACME.AcceptTOS = true
	return cfg
}

// TestACMECacheCustody proves the cached certificate key gets the same custody
// as every other private key here: written 0600, and refused on reload if
// another account can read it.
func TestACMECacheCustody(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	p := acmeTestProvider(t, now)

	cert := mustSelfSigned(t, now)
	if err := p.storeCachedCert(cert); err != nil {
		t.Fatalf("storeCachedCert: %v", err)
	}

	keyPath := filepath.Join(p.cacheDir, acmeKeyFile)
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("stat cached key: %v", err)
	}
	if got := info.Mode().Perm(); got != keyFileMode {
		t.Errorf("cached key mode = %#o, want %#o", got, keyFileMode)
	}

	// A round trip must produce the same certificate, so the cache genuinely
	// avoids re-issuance rather than silently failing and re-ordering.
	loaded, err := p.loadCachedCert()
	if err != nil {
		t.Fatalf("loadCachedCert: %v", err)
	}
	if !bytesEqual(loaded.Certificate[0], cert.Certificate[0]) {
		t.Error("cached certificate did not round-trip")
	}

	if err := os.Chmod(keyPath, 0o644); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	if _, err := p.loadCachedCert(); !errors.Is(err, ErrTLSKeyPermissions) {
		t.Errorf("world-readable cached key: error = %v, want ErrTLSKeyPermissions", err)
	}
}

// TestACMECacheRejectsExpiredCertificate proves a stale cache is not adopted.
// Serving a cached certificate that expired while the process was down would be
// exactly the "last-good expired cert" ADR-0015 §4 rejects.
func TestACMECacheRejectsExpiredCertificate(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	p := acmeTestProvider(t, now)

	if err := p.storeCachedCert(mustSelfSigned(t, now)); err != nil {
		t.Fatalf("storeCachedCert: %v", err)
	}

	// Re-read far in the future, past the self-signed certificate's ceiling.
	stale := acmeTestProvider(t, now.Add(365*24*time.Hour))
	stale.cacheDir = p.cacheDir

	if _, err := stale.loadCachedCert(); !errors.Is(err, ErrTLSCertificateExpired) {
		t.Errorf("expired cache: error = %v, want ErrTLSCertificateExpired", err)
	}
}

// TestACMEIssuedCertificatesGoThroughTheGuard proves a CA-issued certificate
// gets no more trust than an operator-supplied one.
//
// The provider is loaded with a certificate that is structurally fine but
// outside its validity window — the shape of a certificate a misbehaving or
// compromised CA could return — and the guard must refuse it on the handshake
// path rather than pass it through because "the CA issued it".
func TestACMEIssuedCertificatesGoThroughTheGuard(t *testing.T) {
	t.Parallel()

	issuedAt := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	p := acmeTestProvider(t, issuedAt)
	p.setCurrent(mustSelfSigned(t, issuedAt))

	// The handshake happens long after the certificate stopped being valid.
	guard := newCertGuard(p, staticClock(issuedAt.Add(365*24*time.Hour)))

	_, err := guard.GetCertificate(&tls.ClientHelloInfo{SupportedProtos: []string{"h2"}})
	if !errors.Is(err, ErrTLSCertificateExpired) {
		t.Errorf("error = %v, want ErrTLSCertificateExpired: an ACME certificate must be "+
			"re-validated per handshake like every other provider's", err)
	}
}

// TestACMEProviderName pins the mode name. It must be a constant, never
// anything derived from the domain or key material.
func TestACMEProviderName(t *testing.T) {
	t.Parallel()

	p := acmeTestProvider(t, time.Now())
	if got := p.Name(); got != "acme_tls_alpn_01" {
		t.Errorf("Name() = %q", got)
	}
	if strings.Contains(p.Name(), "example.com") {
		t.Error("provider name leaks the configured domain")
	}
}

// TestACMERenewalLoopDrivesIssuance tests the MECHANISM that keeps a
// certificate fresh, not the artifact it produces.
//
// Every other test in this file reaches issuance directly — setCurrent, or
// obtain against Pebble — so all of them still pass if renewalLoop never calls
// issuance at all. That mutant survives an artifact-shaped test suite, and its
// consequence is a server that issues once and then silently rides the
// certificate to expiry, at which point it refuses every handshake. Failing
// closed makes it an outage rather than a downgrade, but an outage nobody can
// see coming is still the thing renewal exists to prevent.
//
// So these cases assert on the issuance CALL: that the loop makes one when a
// certificate is needed, makes none when the current one is fresh, and does not
// retry hot after a failure.
func TestACMERenewalLoopDrivesIssuance(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name string
		// seed installs the provider's starting certificate, if any.
		seed      func(p *acmeProvider)
		issueErr  error
		wantCalls int
		reason    string
	}{
		{
			name:      "no certificate yet",
			seed:      func(*acmeProvider) {},
			wantCalls: 1,
			reason:    "the loop must obtain the first certificate; nothing else will",
		},
		{
			name:      "current certificate is fresh",
			seed:      func(p *acmeProvider) { p.setCurrent(mustSelfSigned(t, now)) },
			wantCalls: 0,
			reason:    "reissuing a fresh certificate burns CA rate limit for nothing",
		},
		{
			name:      "issuance keeps failing",
			seed:      func(*acmeProvider) {},
			issueErr:  errors.New("order failed"),
			wantCalls: 1,
			reason: "a failed attempt must back off on the timer, not retry in a hot " +
				"loop that would hammer the CA into a rate-limit ban",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			p := acmeTestProvider(t, now)
			tc.seed(p)

			var mu sync.Mutex
			calls := 0
			called := make(chan struct{}, 1)

			p.issue = func(context.Context) error {
				mu.Lock()
				calls++
				mu.Unlock()
				select {
				case called <- struct{}{}:
				default:
				}
				return tc.issueErr
			}

			ctx, cancel := context.WithCancel(t.Context())
			go p.renewalLoop(ctx)

			if tc.wantCalls > 0 {
				select {
				case <-called:
				case <-time.After(5 * time.Second):
					cancel()
					<-p.done
					t.Fatalf("renewalLoop never called issuance: %s", tc.reason)
				}
			}

			// Settle: long enough that a hot retry loop, or a loop that reissues a
			// fresh certificate, would run up a call count far above wantCalls.
			// The real waits here are acmeBackoffMin (1m) and
			// acmeRenewCheckInterval (1h), so a correct loop makes no further
			// call in this window.
			time.Sleep(200 * time.Millisecond)
			cancel()
			<-p.done

			mu.Lock()
			got := calls
			mu.Unlock()

			if got != tc.wantCalls {
				t.Errorf("issuance called %d times, want %d: %s", got, tc.wantCalls, tc.reason)
			}
		})
	}
}

// TestNeedsIssuanceTreatsAnEmptyChainAsNeedingIssuance pins the empty-chain
// guard in needsIssuance.
//
// The guard is depth: validateCertificate runs on every path that reaches
// setCurrent and rejects an empty chain, so a live provider cannot hold one.
// That makes this test the only thing standing behind the guard, which is
// exactly why it is worth writing — without it the guard reads as dead code and
// the next reader deletes it.
//
// The failure it prevents is not a wrong answer but an index panic on the
// renewal goroutine. A panic there ends issuance for the life of the process,
// and once the held certificate expires the listener stops serving with it, so
// an unservable certificate would take the service down rather than be
// replaced.
func TestNeedsIssuanceTreatsAnEmptyChainAsNeedingIssuance(t *testing.T) {
	t.Parallel()

	p := acmeTestProvider(t, time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC))

	// Set directly rather than through setCurrent: the point is to reach
	// needsIssuance with a state its callers are supposed to make impossible.
	p.current = &tls.Certificate{Certificate: nil}

	if !p.needsIssuance() {
		t.Fatal("needsIssuance() = false for a certificate with an empty chain, want true")
	}

	// A zero-length non-nil chain is the same condition by a different route,
	// and indexes just as fatally.
	p.current = &tls.Certificate{Certificate: [][]byte{}}

	if !p.needsIssuance() {
		t.Fatal("needsIssuance() = false for a zero-length chain, want true")
	}
}
