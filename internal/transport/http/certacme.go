package httpserver

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/crypto/acme"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/config"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/secrets"
)

// acmeChallengeType is the RFC 8737 challenge this provider answers. DNS-01 is
// a separate track; HTTP-01 is refused by ADR-0015 because it needs a port-80
// listener the HTTPS-only posture forbids.
const acmeChallengeType = "tls-alpn-01"

const (
	// acmeCertFile and acmeKeyFile are the cached certificate and its key,
	// inside the operator's cache directory.
	acmeCertFile = "certificate.pem"
	acmeKeyFile  = "certificate.key"

	// acmeCacheDirMode is the mode the cache directory is created with. 0700,
	// not 0755: it holds a private key, so no other account may even list it.
	acmeCacheDirMode fs.FileMode = 0o700

	// acmeRenewFraction is the share of a certificate's total lifetime that
	// must remain before renewal is attempted. ADR-0015 §4 asks for "~1/3 of
	// remaining lifetime / ~30 days for 90-day certs"; a third of the lifetime
	// is exactly 30 days on Let's Encrypt's 90-day certificates and scales
	// correctly for a CA with a different lifetime.
	acmeRenewFraction = 3

	// acmeRenewCheckInterval is how often the renewal loop re-examines the
	// certificate. Hourly is far more often than a ~30-day window needs, which
	// is the point: it costs one clock comparison and no network traffic (an
	// in-window certificate triggers no ACME request at all), while keeping the
	// reaction time short if the clock jumps or a cert is replaced underneath.
	acmeRenewCheckInterval = time.Hour

	// acmeBackoffMin, acmeBackoffMax and acmeBackoffFactor bound retries after
	// a failed issuance.
	//
	// The failure mode being defended against is a hot retry loop against a CA
	// whose rate limits are counted over a rolling WEEK — a lockout is measured
	// in days, so retrying fast makes an outage longer, never shorter. The
	// backoff is exponential from one minute with a six-hour ceiling, and it is
	// driven by a TIMER rather than by handshakes, so a flood of client
	// connections cannot convert itself into a flood of ACME orders.
	acmeBackoffMin    = time.Minute
	acmeBackoffMax    = 6 * time.Hour
	acmeBackoffFactor = 2
)

// acmeProvider implements ADR-0015 §2's automatic ACME mode with the
// TLS-ALPN-01 solver.
//
// # Why issuance is deferred to serving
//
// TLS-ALPN-01 proves control of a name by having the CA open a TLS connection
// to this server's public :443 and negotiate the "acme-tls/1" ALPN protocol.
// That is only answerable once the listener is accepting connections, so a
// certificate CANNOT exist at construction time on a first run. The provider
// therefore registers its account at startup (which is checkable offline) and
// issues on demand once serving, rather than pretending it can do both at once.
//
// This is not a relaxation of the fail-closed rule. Until a certificate exists,
// every ordinary handshake is REFUSED — see [acmeProvider.GetCertificate]. The
// server comes up, answers the CA's validation, and starts serving real traffic
// only when it has a real certificate. It never serves a weaker one meanwhile.
//
// # Rate-limit posture
//
// Three controls, because Let's Encrypt lockouts last a week:
//
//   - A valid cached certificate is reused across restarts, so a crash loop
//     issues nothing.
//   - Issuance is single-flighted; concurrent handshakes cannot each start an
//     order.
//   - Failures back off exponentially on a timer, never per handshake.
type acmeProvider struct {
	client   *acme.Client
	domains  []string
	cacheDir string
	now      func() time.Time

	// mu guards the certificate and challenge state read on the handshake path.
	// An RWMutex because GetCertificate is called from every connection
	// goroutine and almost always only reads.
	mu sync.RWMutex
	// current is the issued certificate, nil until one exists.
	current *tls.Certificate
	// challenge maps an identifier (the SNI the CA will send) to the
	// short-lived certificate that answers its validation. Entries exist only
	// while an order is in flight and are removed as soon as it settles.
	challenge map[string]*tls.Certificate

	// issueMu single-flights issuance. It is separate from mu because an order
	// takes network round trips, and holding the handshake lock for that would
	// stall every connection.
	issueMu sync.Mutex

	// stop cancels in-flight ACME work and terminates the renewal loop; done is
	// closed when that loop has exited, so Close can wait for it and leave no
	// goroutine behind.
	stop context.CancelFunc
	done chan struct{}

	// issue performs one issuance attempt. It is always p.obtain in production
	// and exists only so a test can drive renewalLoop's trigger and backoff
	// wiring without a CA: asserting that a certificate eventually appears
	// proves the artifact, not that the LOOP is what produced it, and a loop
	// that never fires would leave the process serving nothing after expiry.
	issue func(context.Context) error
}

// Compile-time proof that the provider satisfies both contracts it relies on:
// the ordinary provider interface, and the in-band-challenge marker that makes
// buildTLSConfig advertise "acme-tls/1" and skip the startup probe.
var (
	_ CertProvider          = (*acmeProvider)(nil)
	_ inBandChallengeSolver = (*acmeProvider)(nil)
)

// newACMEProvider prepares the ACME account and starts the renewal loop.
//
// Everything that can be decided WITHOUT the listener being up is decided here,
// so an operator with a bad key path, an unreachable directory or an
// unaccepted TOS finds out at startup: the account key is loaded or created
// under the custody rules, the directory is discovered, and the account is
// registered. Only the part that genuinely requires a live listener — proving
// control of the name — is deferred.
func newACMEProvider(ctx context.Context, cfg *config.Config, now func() time.Time) (*acmeProvider, error) {
	a := cfg.TLS.ACME

	if !a.AcceptTOS {
		// Defense in depth: config validation already refuses this. Registering
		// while asserting agreement the operator never gave is not something a
		// second code path should be able to reach.
		return nil, fmt.Errorf("%w: tls.acme.accept_tos is not set", ErrACMETermsNotAccepted)
	}

	key, err := loadOrCreateKey(a.AccountKeyFile)
	if err != nil {
		return nil, err
	}

	if err := os.MkdirAll(a.CacheDir, acmeCacheDirMode); err != nil {
		return nil, fmt.Errorf("%w: create cache dir %s: %w", ErrACMEIssuance, a.CacheDir, err)
	}

	client := &acme.Client{
		Key:          key,
		DirectoryURL: a.DirectoryURL,
		UserAgent:    "sshpilot-vallet",
	}

	return newACMEProviderWithClient(ctx, client, cfg, now)
}

// newACMEProviderWithClient registers the account and starts the provider
// around an already-built ACME client.
//
// Splitting this out lets a test drive the whole flow against a local ACME
// server whose API certificate is not publicly trusted, by supplying a client
// with its own HTTP transport. Production always reaches it through
// newACMEProvider, so the client the server uses is still built from operator
// config alone and no code path can widen the trust the process extends to a
// CA.
func newACMEProviderWithClient(
	ctx context.Context, client *acme.Client, cfg *config.Config, now func() time.Time,
) (*acmeProvider, error) {
	a := cfg.TLS.ACME

	if err := registerACMEAccount(ctx, client, a.ContactEmail); err != nil {
		return nil, err
	}

	runCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	p := &acmeProvider{
		client:    client,
		domains:   certHosts(cfg),
		cacheDir:  a.CacheDir,
		now:       now,
		challenge: make(map[string]*tls.Certificate),
		stop:      cancel,
		done:      make(chan struct{}),
	}

	// A cached certificate that is still usable is adopted, and no ACME request
	// is made. This is what stops a restart loop from becoming an issuance
	// loop. A cache that is absent, unreadable, unsafe or expired is simply not
	// adopted — it is never a startup failure, because the correct response is
	// to issue a new certificate, not to refuse to run.
	if cert, err := p.loadCachedCert(); err == nil {
		p.current = cert
	}

	p.issue = p.obtain
	go p.renewalLoop(runCtx)
	return p, nil
}

// Name identifies the mode for diagnostics. It is a constant, never derived
// from the domain or any key material.
func (p *acmeProvider) Name() string { return "acme_tls_alpn_01" }

// challengeALPNProtos declares the ALPN protocol the CA uses to validate.
//
// Returning it here rather than hard-coding "acme-tls/1" into the TLS policy is
// deliberate: the protocol is advertised ONLY when a provider that answers it
// is actually installed, so every other mode's listener has no acme-tls/1 to
// offer at all.
func (p *acmeProvider) challengeALPNProtos() []string { return []string{acme.ALPNProto} }

// GetCertificate serves either the challenge certificate or the real one, and
// never confuses the two.
//
// The split is the security boundary of this file. A challenge certificate is
// self-signed, carries the critical acmeIdentifier extension, and authenticates
// NOTHING — presenting one to an ordinary client would hand them a certificate
// that does not identify this service. So it is returned only when the hello is
// unambiguously a validation attempt, and the real certificate is never
// returned on that path either.
//
// A nil hello (the startup probe) is treated as ordinary traffic, so it reports
// whether a real certificate exists rather than being satisfied by a challenge.
func (p *acmeProvider) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if isACMEChallengeHello(hello) {
		return p.challengeCert(hello.ServerName)
	}

	p.mu.RLock()
	cert := p.current
	p.mu.RUnlock()

	if cert == nil {
		// Fail closed. On a first run this is the expected state between the
		// listener opening and the first order completing, and it is still a
		// refusal: there is deliberately no self-signed stand-in, because a
		// server that quietly serves an unauthenticated certificate looks
		// healthy to monitoring while giving clients nothing to trust.
		return nil, fmt.Errorf("%w: no certificate issued yet", ErrACMEIssuance)
	}
	return cert, nil
}

// isACMEChallengeHello reports whether a ClientHello is an ACME validation
// attempt.
//
// The test is deliberately strict: the client must offer EXACTLY the acme-tls/1
// protocol and nothing else. RFC 8737 §3 requires a validating CA to send only
// that protocol, so nothing legitimate is excluded, and the strictness is what
// stops an ordinary client from being handed a challenge certificate by listing
// acme-tls/1 alongside h2 in its ALPN set.
func isACMEChallengeHello(hello *tls.ClientHelloInfo) bool {
	return hello != nil &&
		len(hello.SupportedProtos) == 1 &&
		hello.SupportedProtos[0] == acme.ALPNProto
}

// challengeCert returns the pending challenge certificate for an identifier.
//
// An unknown name is an error rather than a fallback to the real certificate.
// Serving the real certificate over acme-tls/1 would let anyone who asks for
// that protocol fetch it outside the intended path, and it would not satisfy
// the CA anyway.
func (p *acmeProvider) challengeCert(name string) (*tls.Certificate, error) {
	p.mu.RLock()
	cert, ok := p.challenge[name]
	p.mu.RUnlock()

	if !ok {
		// %q on an SNI value: a hostname the client just sent in cleartext is
		// not a secret. No token or key authorization is ever named here.
		return nil, fmt.Errorf("%w: no challenge pending for %q", ErrACMEIssuance, name)
	}
	return cert, nil
}

// setChallengeCert publishes the answer for one identifier, and clearChallenge
// withdraws it.
//
// Withdrawal is not housekeeping. The challenge certificate stops being needed
// the moment the authorization settles, and leaving it installed would keep an
// unauthenticating certificate reachable on the acme-tls/1 path for no reason.
func (p *acmeProvider) setChallengeCert(name string, cert *tls.Certificate) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.challenge[name] = cert
}

func (p *acmeProvider) clearChallenge(name string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.challenge, name)
}

// setCurrent installs a newly issued certificate for subsequent handshakes.
//
// This is the whole of "renewal without a restart": handshakes read this field
// through GetCertificate on every connection, so replacing it takes effect on
// the very next handshake, with no listener rebind and no process restart.
func (p *acmeProvider) setCurrent(cert *tls.Certificate) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.current = cert
}

// Close stops the renewal loop and waits for it to exit.
//
// The wait is what makes the provider safe to construct in a test: a goroutine
// still running after the test's temp directory is removed is both a leak and a
// race detector finding.
func (p *acmeProvider) Close() error {
	p.stop()
	<-p.done
	return nil
}

// registerACMEAccount ensures the account key is known to the CA.
//
// An already-registered key is the normal case on every restart after the
// first, and the CA reports it as ErrAccountAlreadyExists; that is a success,
// not a failure, so it is explicitly tolerated. Any other error fails startup,
// because an unregistered account cannot issue anything and discovering that at
// first-handshake time would be discovering it too late.
func registerACMEAccount(ctx context.Context, client *acme.Client, contactEmail string) error {
	acct := &acme.Account{}
	if contactEmail != "" {
		acct.Contact = []string{"mailto:" + contactEmail}
	}

	// acme.AcceptTOS is passed only because config validation and
	// newACMEProvider have both already established that the operator set
	// accept_tos.
	if _, err := client.Register(ctx, acct, acme.AcceptTOS); err != nil {
		if errors.Is(err, acme.ErrAccountAlreadyExists) {
			return nil
		}
		// The acme error carries the CA's problem document (type, detail,
		// status). Those describe the fault, never key material — the account
		// key is only ever used to SIGN requests and is not part of any
		// response.
		return fmt.Errorf("%w: register account: %w", ErrACMEAccount, err)
	}
	return nil
}

// obtain runs one full ACME order for the configured identifiers.
//
// Single-flighted by issueMu: two handshakes, or a handshake and the renewal
// loop, cannot open two orders for the same names. Duplicate orders are the
// fastest route to a rate-limit lockout.
func (p *acmeProvider) obtain(ctx context.Context) error {
	p.issueMu.Lock()
	defer p.issueMu.Unlock()

	order, err := p.client.AuthorizeOrder(ctx, acme.DomainIDs(p.domains...))
	if err != nil {
		return fmt.Errorf("%w: authorize order: %w", ErrACMEIssuance, err)
	}

	for _, authzURL := range order.AuthzURLs {
		if err := p.solveAuthorization(ctx, authzURL); err != nil {
			return err
		}
	}

	// The order URI is captured before the wait. The order object a CA returns
	// from a poll carries its URI only in a Location header, and not every CA
	// sets one, so the value from the original order is the reliable handle —
	// and it is needed again if issuance has to be re-polled below.
	orderURI := order.URI

	order, err = p.client.WaitOrder(ctx, orderURI)
	if err != nil {
		return fmt.Errorf("%w: wait order: %w", ErrACMEIssuance, err)
	}

	cert, err := p.finalize(ctx, orderURI, order)
	if err != nil {
		return err
	}

	// The certificate the CA returned is validated BEFORE it is cached or
	// served. A CA-issued certificate gets no more trust than an
	// operator-supplied one: this is the same check certGuard applies per
	// handshake, run here so a certificate that could never be served is not
	// written to disk to be re-adopted on the next restart.
	if err := validateCertificate(cert, p.now()); err != nil {
		return fmt.Errorf("%w: issued certificate rejected: %w", ErrACMEIssuance, err)
	}

	if err := p.storeCachedCert(cert); err != nil {
		return err
	}
	p.setCurrent(cert)
	return nil
}

// solveAuthorization answers one identifier's TLS-ALPN-01 challenge.
func (p *acmeProvider) solveAuthorization(ctx context.Context, authzURL string) error {
	authz, err := p.client.GetAuthorization(ctx, authzURL)
	if err != nil {
		return fmt.Errorf("%w: get authorization: %w", ErrACMEIssuance, err)
	}
	// An authorization the CA still considers valid needs no new proof. Reusing
	// it is not a shortcut around validation — the CA decides — and re-proving
	// control it already accepted only spends rate-limit budget.
	if authz.Status == acme.StatusValid {
		return nil
	}

	chal := findACMEChallenge(authz, acmeChallengeType)
	if chal == nil {
		return fmt.Errorf("%w: no %s challenge offered for %q",
			ErrACMEIssuance, acmeChallengeType, authz.Identifier.Value)
	}

	// TLSALPN01ChallengeCert derives the key authorization from the challenge
	// token and the ACCOUNT KEY's public part, and embeds only its SHA-256
	// digest in a critical extension. The token and the key authorization stay
	// inside this certificate; neither is logged or returned in any error.
	cert, err := p.client.TLSALPN01ChallengeCert(chal.Token, authz.Identifier.Value)
	if err != nil {
		return fmt.Errorf("%w: build challenge certificate: %w", ErrACMEIssuance, err)
	}

	p.setChallengeCert(authz.Identifier.Value, &cert)
	// Withdrawn on every exit path, including the error ones: a challenge
	// certificate left installed after a failed order would stay answerable on
	// the acme-tls/1 path indefinitely.
	defer p.clearChallenge(authz.Identifier.Value)

	if _, err := p.client.Accept(ctx, chal); err != nil {
		return fmt.Errorf("%w: accept challenge: %w", ErrACMEIssuance, err)
	}
	if _, err := p.client.WaitAuthorization(ctx, authzURL); err != nil {
		return fmt.Errorf("%w: authorization failed: %w", ErrACMEIssuance, err)
	}
	return nil
}

// findACMEChallenge picks the challenge of the requested type, or nil.
func findACMEChallenge(authz *acme.Authorization, typ string) *acme.Challenge {
	for _, c := range authz.Challenges {
		if c.Type == typ {
			return c
		}
	}
	return nil
}

// finalize generates the certificate key, submits the CSR, and returns the
// issued chain paired with its key.
//
// A FRESH key is generated for every issuance rather than reusing the previous
// certificate's. Renewal is then a full key rotation, so a compromise of one
// certificate's key does not extend across renewals, and the key never has to
// outlive the certificate it belongs to.
func (p *acmeProvider) finalize(ctx context.Context, orderURI string, order *acme.Order) (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("%w: generate certificate key: %w", ErrACMEIssuance, err)
	}

	tmpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: p.domains[0]}}
	for _, h := range p.domains {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
			continue
		}
		tmpl.DNSNames = append(tmpl.DNSNames, h)
	}

	csr, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		return nil, fmt.Errorf("%w: create csr: %w", ErrACMEIssuance, err)
	}

	// bundle=true asks for the issuer chain alongside the leaf, which clients
	// need to build a path to a trusted root.
	der, _, err := p.client.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	if err != nil {
		// A CA that answers finalize with "processing" and no Location header
		// leaves the acme package with no URI to poll, so it fails here even
		// though issuance is under way. The order URI captured earlier is the
		// recovery: poll that, then fetch the certificate the CA issued.
		//
		// This is a retry of the WAIT, never of the finalize request — the CSR
		// is not resubmitted, so it cannot turn one order into two against the
		// CA's rate limits. A genuinely failed finalize still fails, because
		// the order goes to "invalid" and the poll surfaces that.
		der, err = p.awaitIssuedCert(ctx, orderURI)
		if err != nil {
			return nil, fmt.Errorf("%w: finalize order: %w", ErrACMEIssuance, err)
		}
	}

	// The key stays a crypto.Signer from generation onward. It is serialized
	// exactly once, by storeCachedCert, on its way to a 0600 file.
	return &tls.Certificate{Certificate: der, PrivateKey: key}, nil
}

// awaitIssuedCert polls an order to completion and downloads its certificate.
//
// It exists only for the recovery path in finalize, where the acme package lost
// the order URI. Nothing here submits anything: it waits and then fetches, so
// it consumes no additional issuance budget.
func (p *acmeProvider) awaitIssuedCert(ctx context.Context, orderURI string) ([][]byte, error) {
	order, err := p.client.WaitOrder(ctx, orderURI)
	if err != nil {
		return nil, fmt.Errorf("wait for issuance: %w", err)
	}
	if order.CertURL == "" {
		return nil, errors.New("order completed without a certificate url")
	}

	der, err := p.client.FetchCert(ctx, order.CertURL, true)
	if err != nil {
		return nil, fmt.Errorf("fetch certificate: %w", err)
	}
	return der, nil
}

// loadCachedCert reads a previously issued certificate and key from the cache.
//
// The key file's permissions are checked with the same rule the CSR mode
// applies: a key readable by group or other may already have been copied, so it
// is refused rather than used. Refusing here means the next issuance replaces
// it, which is the safe outcome — the compromised key is never served.
func (p *acmeProvider) loadCachedCert() (*tls.Certificate, error) {
	keyPath := filepath.Join(p.cacheDir, acmeKeyFile)

	key, err := loadExistingKey(keyPath)
	if err != nil {
		return nil, err
	}

	chain, err := loadCertChain(filepath.Join(p.cacheDir, acmeCertFile))
	if err != nil {
		return nil, err
	}

	cert := &tls.Certificate{Certificate: chain, PrivateKey: key}

	// Validated before adoption, so a cached certificate that has expired since
	// the process last ran is not served for even one handshake — the renewal
	// loop replaces it instead.
	if err := validateCertificate(cert, p.now()); err != nil {
		return nil, err
	}
	return cert, nil
}

// storeCachedCert persists the issued certificate and key.
//
// Both go through atomicWriteFile, which creates at 0600 and renames into
// place, so the key is never briefly world-readable and no reader ever sees a
// half-written file. The key is written 0600; the certificate is written 0600
// as well, matching ADR-0015 §3's "cert and key are stored as files with 0600".
func (p *acmeProvider) storeCachedCert(cert *tls.Certificate) error {
	der, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		return fmt.Errorf("%w: marshal certificate key: %w", ErrACMEIssuance, err)
	}

	// Wrapped in secrets.Redacted for the one crossing into serialized form, so
	// that anything which later formats the value it came from yields the
	// redaction marker instead of the key. Plaintext is taken only at the
	// moment it is handed to the writer.
	encoded := secrets.NewRedacted(string(pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: der,
	})))
	if err := atomicWriteFile(filepath.Join(p.cacheDir, acmeKeyFile), []byte(encoded.Reveal()), keyFileMode); err != nil {
		return fmt.Errorf("%w: write certificate key: %w", ErrACMEIssuance, err)
	}

	var chain []byte
	for _, block := range cert.Certificate {
		chain = append(chain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: block})...)
	}
	if err := atomicWriteFile(filepath.Join(p.cacheDir, acmeCertFile), chain, keyFileMode); err != nil {
		return fmt.Errorf("%w: write certificate: %w", ErrACMEIssuance, err)
	}
	return nil
}

// renewalLoop obtains the first certificate and keeps it fresh.
//
// It runs on a TIMER, never on the handshake path. That is the rate-limit
// property that matters most: no volume of client connections — including a
// deliberate flood — can increase the number of ACME orders this server makes.
func (p *acmeProvider) renewalLoop(ctx context.Context) {
	defer close(p.done)

	backoff := time.Duration(0)
	timer := time.NewTimer(0)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}

		wait := acmeRenewCheckInterval
		if p.needsIssuance() {
			if err := p.issue(ctx); err != nil {
				// The error is deliberately NOT logged here: it can carry the
				// CA's problem document, and the logging track owns redaction.
				// It is surfaced instead by every ordinary handshake being
				// refused, which is both louder and impossible to miss.
				backoff = nextACMEBackoff(backoff)
				wait = backoff
			} else {
				backoff = 0
			}
		}

		timer.Reset(wait)
	}
}

// needsIssuance reports whether a certificate must be obtained or renewed.
func (p *acmeProvider) needsIssuance() bool {
	p.mu.RLock()
	cert := p.current
	p.mu.RUnlock()

	// The empty-chain half of this guard is depth, not a hole being closed.
	// Every path that reaches setCurrent runs validateCertificate first, and
	// that rejects an empty chain, so p.current cannot hold one today. But that
	// is a derived argument: it stops holding the moment someone adds a fourth
	// way to set p.current, and what it would cost here is an index panic on
	// the renewal goroutine -- which takes down issuance for the life of the
	// process and, once the certificate expires, the listener with it. Two
	// lines locally is cheaper than a guarantee that lives in another file.
	//
	// Reading it as "needs issuance" is also the correct answer on its own
	// terms: a certificate with no chain is one that cannot be served.
	if cert == nil || len(cert.Certificate) == 0 {
		return true
	}
	// Re-parsed from DER rather than trusting cert.Leaf, for the same reason
	// certGuard does: Leaf is an ordinary field that could disagree with the
	// bytes clients actually verify.
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return true
	}
	return acmeNeedsRenewal(leaf, p.now())
}

// acmeNeedsRenewal reports whether less than a third of a certificate's
// lifetime remains, per ADR-0015 §4's renew-ahead rule.
func acmeNeedsRenewal(leaf *x509.Certificate, now time.Time) bool {
	lifetime := leaf.NotAfter.Sub(leaf.NotBefore)
	return now.After(leaf.NotAfter.Add(-lifetime / acmeRenewFraction))
}

// nextACMEBackoff advances the retry delay after a failed issuance.
//
// Exponential with a ceiling, plus jitter of up to a quarter of the delay. The
// jitter matters for the same reason it does in any retry loop, and more so
// here: many instances of this server restarted together by an orchestrator
// would otherwise retry against the CA in lockstep, turning a shared outage
// into a synchronized burst against a rate limiter.
func nextACMEBackoff(current time.Duration) time.Duration {
	next := current * acmeBackoffFactor
	if next < acmeBackoffMin {
		next = acmeBackoffMin
	}
	if next > acmeBackoffMax {
		next = acmeBackoffMax
	}

	// crypto/rand, not math/rand: this process has no non-cryptographic RNG
	// seeded anywhere, and a jitter draw is far too cheap to justify adding one.
	spread, err := rand.Int(rand.Reader, big.NewInt(int64(next/4)))
	if err != nil {
		return next
	}
	return next + time.Duration(spread.Int64())
}

// loadExistingKey reads a private key that must already exist.
//
// It differs from loadOrCreateKey in refusing to create one: a missing cached
// certificate key means there is nothing cached, which is a normal first-run
// state, and silently generating a key with no certificate to match it would
// leave a file that looks like state but pairs with nothing.
func loadExistingKey(path string) (crypto.Signer, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // operator-configured cache path.
	if err != nil {
		return nil, fmt.Errorf("%w: read cached key: %w", ErrACMEIssuance, err)
	}
	return parseKey(path, raw)
}
