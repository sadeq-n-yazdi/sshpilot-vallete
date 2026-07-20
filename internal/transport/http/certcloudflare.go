package httpserver

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/config"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/secrets"
)

const (
	// originCAEndpoint is Cloudflare's Origin CA issuance endpoint. It is a
	// constant, not config: pointing this mode at an arbitrary host would let a
	// configuration change redirect a CSR — and the resulting certificate — to
	// a third party, and there is no legitimate second endpoint to support.
	originCAEndpoint = "https://api.cloudflare.com/client/v4/certificates"

	// originCARequestType selects the signature algorithm Cloudflare puts on
	// the certificate. "origin-ecc" matches the P-256 key generated below;
	// "origin-rsa" would produce a certificate whose public key does not match
	// our key at all, which certGuard would (correctly) refuse to serve.
	originCARequestType = "origin-ecc"

	// originCAKeyPrefix is the fixed prefix of a Cloudflare Origin CA Key. The
	// credential is dispatched on it — see originCAAuthHeader.
	originCAKeyPrefix = "v1.0-"

	// originCACertFile and originCAKeyFile are the cached certificate and its
	// key inside the operator's cache directory.
	originCACertFile = "origin.pem"
	originCAKeyFile  = "origin.key"

	// originCACacheDirMode is 0700, not 0755: the directory holds a private
	// key, so no other local account may even list it.
	originCACacheDirMode fs.FileMode = 0o700

	// originCARequestTimeout bounds a single API call, so an unresponsive
	// endpoint cannot wedge the renewal goroutine forever.
	originCARequestTimeout = 30 * time.Second

	// originCAMaxResponseBytes caps how much of a response is read. The
	// expected body is a few kilobytes; the cap stops a hostile or broken
	// endpoint from turning a certificate request into unbounded memory
	// growth in a long-lived server process.
	originCAMaxResponseBytes = 1 << 20

	// originCARenewCheckInterval is how often the renewal loop re-examines the
	// certificate. Hourly costs one clock comparison and no network traffic —
	// an in-window certificate triggers no API request at all.
	originCARenewCheckInterval = time.Hour
)

// originCAProvider implements ADR-0015 §2's Cloudflare Origin CA mode.
//
// # What this certificate is, and is not
//
// Cloudflare's Origin CA signs with a private root that ONLY the Cloudflare
// edge trusts. It is not in any public trust store. A browser, curl, or Go
// client connecting straight to this origin rejects it. That is not a defect to
// work around — it is the definition of the product, and it is what makes this
// mode correct for exactly one topology (origin behind the Cloudflare proxy)
// and a trap for every other.
//
// # The trap, and why the provider enforces rather than warns
//
// If the origin is reachable directly, the operator sees "certificate signed by
// unknown authority" from every direct client. The fix they reach for is to
// disable verification. That single step removes the MITM protection on the
// key-publish path — an attacker who can alter published keys gets
// unauthorized SSH access, which is the threat ADR-0015 exists to counter. A
// comment in a config file does not survive contact with an operator debugging
// an outage at 2am, so the constraint is enforced in two places instead:
//
//   - At startup, config validation refuses the mode unless
//     server.trusted_proxies names the Cloudflare edge ranges. The process
//     cannot prove from the inside that it is unreachable from the internet,
//     so it does not guess; it requires the operator to DECLARE the topology.
//   - At every handshake, [originCAProvider.GetCertificate] withholds the
//     certificate from any peer outside that list. The declaration is
//     therefore load-bearing rather than advisory, and a directly-reachable
//     origin fails closed on the first direct connection instead of quietly
//     teaching its users to skip verification.
//
// # Key custody
//
// The private key is generated in this process and NEVER leaves it except as a
// 0600 file in the cache directory, written through atomicWriteFile so it is
// never briefly world-readable. Only a CSR — public key and subject, both of
// which appear in the issued certificate — is sent to Cloudflare. Cloudflare
// never sees, holds, or could disclose this key.
//
// # Rate-limit posture
//
// Same three controls as the ACME provider, for the same reason: a valid cached
// certificate is reused across restarts so a crash loop issues nothing;
// issuance is single-flighted; and failures back off on a timer, never per
// handshake, so no volume of client connections can become API requests.
type originCAProvider struct {
	doer     httpDoer
	token    secrets.Redacted
	hosts    []string
	cacheDir string
	validity int
	now      func() time.Time

	// peers is the trusted-proxy allowlist the handshake check enforces. It is
	// captured at construction from server.trusted_proxies, which config
	// validation has already guaranteed is non-empty for this mode.
	peers trustedPeers

	// mu guards current, which is read on the handshake path by every
	// connection goroutine and written only by the renewal loop.
	mu      sync.RWMutex
	current *tls.Certificate

	// issueMu single-flights issuance so concurrent triggers cannot each start
	// an order. It is separate from mu because an order takes network round
	// trips and holding the handshake lock across them would stall connections.
	issueMu sync.Mutex

	// stop cancels in-flight work and terminates the renewal loop; done is
	// closed when that loop has exited, so Close can wait and leave no
	// goroutine behind.
	stop context.CancelFunc
	done chan struct{}

	// issue performs one issuance attempt. It is always p.obtain in production
	// and exists so a test can drive the loop's trigger and backoff wiring
	// without reaching Cloudflare, exactly as acmeProvider.issue does.
	issue func(context.Context) error
}

// httpDoer is the seam through which every Cloudflare API call is made.
//
// It exists so the failure paths that matter — an API rejection, a malformed
// response, a transport error — can be exercised deterministically. A control
// that can only be tested against the live API is a control that is never
// tested for the case it exists to catch, and the cases here (refusing a
// malformed certificate, refusing an unsuccessful response) are precisely the
// ones no live API will produce on demand.
type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// originCAProvider serves ordinary traffic only, so it is deliberately NOT an
// inBandChallengeSolver: it advertises no challenge ALPN protocol and keeps the
// strict startup probe, which is what makes a deployment with a broken
// credential fail at startup rather than at the first handshake.
var _ CertProvider = (*originCAProvider)(nil)

// originCAResponse is Cloudflare's API envelope.
//
// Only the fields this provider acts on are decoded. Success is read from the
// explicit "success" boolean AND from the certificate actually parsing — see
// obtain — because an envelope that says success while carrying nothing usable
// must not be treated as an issuance.
type originCAResponse struct {
	Success bool `json:"success"`
	Errors  []struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"errors"`
	Result struct {
		Certificate string `json:"certificate"`
		ExpiresOn   string `json:"expires_on"`
	} `json:"result"`
}

// newOriginCAProvider builds the provider from operator config.
//
// The credential is resolved through the secret provider (ADR-0015 §3, ADR-0022)
// rather than read from config, and it is held as a [secrets.Redacted] so that
// any code which later formats this struct yields the redaction marker instead
// of the key.
func newOriginCAProvider(
	ctx context.Context, cfg *config.Config, now func() time.Time, resolve secretResolver,
) (*originCAProvider, error) {
	o := cfg.TLS.CloudflareOrigin

	token, err := resolve(ctx, o.APITokenRef)
	if err != nil {
		// The resolver's errors name the reference, never the value. The field
		// name is prefixed so an operator with several *_ref settings knows
		// which one to fix.
		return nil, fmt.Errorf("%w: tls.cloudflare_origin.api_token_ref: %w", ErrOriginCACredential, err)
	}
	if token.Reveal() == "" {
		// Defense in depth: the env and file providers both reject an empty
		// value already. An empty credential would produce an unauthenticated
		// request, and Cloudflare's rejection of it is a worse place to learn
		// this than startup.
		return nil, fmt.Errorf("%w: tls.cloudflare_origin.api_token_ref resolved to an empty value", ErrOriginCACredential)
	}

	if err := os.MkdirAll(o.CacheDir, originCACacheDirMode); err != nil {
		return nil, fmt.Errorf("%w: create cache dir %s: %w", ErrOriginCAIssuance, o.CacheDir, err)
	}

	return newOriginCAProviderWithClient(ctx, cfg, now, token, &http.Client{Timeout: originCARequestTimeout})
}

// newOriginCAProviderWithClient starts the provider around an already-resolved
// credential and HTTP client.
//
// Splitting this out lets a test drive the whole flow against an httptest
// server. Production always reaches it through newOriginCAProvider, so the
// endpoint the server talks to is still the compiled-in constant and no code
// path can point issuance at a different host.
func newOriginCAProviderWithClient(
	ctx context.Context, cfg *config.Config, now func() time.Time, token secrets.Redacted, doer httpDoer,
) (*originCAProvider, error) {
	o := cfg.TLS.CloudflareOrigin

	peers := newTrustedPeers(cfg.Server.TrustedProxies)
	if peers.empty() {
		// Defense in depth: config validation already refuses this mode with an
		// empty list. Without the list there is nothing to enforce the
		// behind-the-proxy topology against, and the provider would hand the
		// origin certificate to anyone who connected — the misconfiguration
		// this mode has to fail closed on. A second code path must not be able
		// to reach that state.
		return nil, fmt.Errorf("%w: server.trusted_proxies is empty, so no peer can be recognized as the Cloudflare edge",
			ErrOriginCADirectClient)
	}

	runCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	p := &originCAProvider{
		doer:     doer,
		token:    token,
		hosts:    certHosts(cfg),
		cacheDir: o.CacheDir,
		validity: o.ValidityDays,
		now:      now,
		peers:    peers,
		stop:     cancel,
		done:     make(chan struct{}),
	}

	// A cached certificate that is still usable is adopted and no API request
	// is made; this is what stops a restart loop from becoming an issuance
	// loop. A cache that is absent, unreadable, unsafely permissioned or
	// expired is simply not adopted — never a startup failure, because the
	// correct response is to issue a new certificate, not to refuse to run.
	if cert, err := p.loadCachedCert(); err == nil {
		p.current = cert
	}

	// Unlike ACME, issuance here needs no live listener — Cloudflare's API is
	// an outbound call — so the first certificate is obtained synchronously.
	// That keeps the startup probe meaningful: an operator with a bad
	// credential, an unreachable API or a hostname outside their zone finds out
	// at startup instead of from a client's failed handshake.
	if p.current == nil {
		if err := p.obtain(runCtx); err != nil {
			cancel()
			return nil, err
		}
	}

	p.issue = p.obtain
	go p.renewalLoop(runCtx)
	return p, nil
}

// Name identifies the mode for diagnostics. It is a constant, never derived
// from the domain, the credential, or any key material.
func (p *originCAProvider) Name() string { return "cloudflare_origin" }

// GetCertificate returns the origin certificate, but only to a peer that is
// allowed to have it.
//
// The peer check is the security boundary of this file, not a convenience. See
// the type comment: this certificate is meaningful only to the Cloudflare edge,
// so a handshake from anywhere else means the origin is directly reachable, and
// serving it there is what starts the chain ending in disabled verification.
//
// A nil hello is the startup probe from buildTLSConfig — an internal caller,
// not a client — and is treated as ordinary traffic so that it reports whether a
// real certificate exists. A non-nil hello with no connection is refused rather
// than allowed: the peer cannot be established, and an unestablished peer must
// deny, the same rule checkKeyMatchesLeaf and trustedPeers.trusts already
// follow.
func (p *originCAProvider) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if hello != nil {
		if hello.Conn == nil {
			return nil, fmt.Errorf("%w: peer address unavailable", ErrOriginCADirectClient)
		}
		if remote := hello.Conn.RemoteAddr(); remote == nil || !p.peers.trusts(remote.String()) {
			// The peer address is NOT quoted. It is attacker-controlled input
			// on a path that runs before any request logging or rate limiting,
			// so an internet-wide origin scan must not be able to write chosen
			// bytes into this server's error paths.
			return nil, fmt.Errorf("%w: connection did not arrive through a configured trusted proxy",
				ErrOriginCADirectClient)
		}
	}

	p.mu.RLock()
	cert := p.current
	p.mu.RUnlock()

	if cert == nil {
		// Fail closed. There is deliberately no self-signed stand-in: a client
		// that cannot be served securely is not served at all.
		return nil, fmt.Errorf("%w: no certificate has been issued", ErrOriginCAIssuance)
	}
	return cert, nil
}

// Close stops the renewal loop and waits for it to exit.
func (p *originCAProvider) Close() error {
	p.stop()
	<-p.done
	return nil
}

// setCurrent installs a newly issued certificate for subsequent handshakes.
func (p *originCAProvider) setCurrent(cert *tls.Certificate) {
	p.mu.Lock()
	p.current = cert
	p.mu.Unlock()
}

// obtain generates a fresh key, has Cloudflare sign a CSR for it, and installs
// the result.
//
// A NEW key is generated on every issuance rather than reusing the cached one.
// Renewal is the only moment at which this deployment's key material is ever
// replaced, so reusing the key would mean a key that lives for as long as the
// deployment does — and the whole reason ValidityDays defaults to a year rather
// than Cloudflare's 15 is to make that replacement actually happen.
func (p *originCAProvider) obtain(ctx context.Context) error {
	p.issueMu.Lock()
	defer p.issueMu.Unlock()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("%w: generate origin key: %w", ErrOriginCAIssuance, err)
	}

	csr, err := p.buildCSR(key)
	if err != nil {
		return err
	}

	chain, err := p.requestCertificate(ctx, csr)
	if err != nil {
		return err
	}

	cert := &tls.Certificate{Certificate: chain, PrivateKey: key}

	// Validated BEFORE it is cached or served. certGuard would catch a bad
	// certificate on the way out anyway, but catching it here means a
	// certificate that does not match the key we generated is never written to
	// disk, so a restart cannot adopt it.
	if err := validateCertificate(cert, p.now()); err != nil {
		return fmt.Errorf("%w: issued certificate is unusable: %w", ErrOriginCAIssuance, err)
	}

	if err := p.storeCachedCert(cert); err != nil {
		return err
	}

	p.setCurrent(cert)
	return nil
}

// buildCSR builds the certificate signing request Cloudflare will sign.
//
// The CSR carries the public key and the subject only. The private key is not
// serialized here and never crosses the network.
func (p *originCAProvider) buildCSR(key crypto.Signer) ([]byte, error) {
	tmpl := &x509.CertificateRequest{}
	if len(p.hosts) > 0 {
		tmpl.Subject = pkix.Name{CommonName: p.hosts[0]}
	}
	for _, h := range p.hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
			continue
		}
		tmpl.DNSNames = append(tmpl.DNSNames, h)
	}

	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		return nil, fmt.Errorf("%w: create csr: %w", ErrOriginCAIssuance, err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), nil
}

// requestCertificate performs the Origin CA API call and returns the issued
// chain as DER blocks.
//
// Every non-success path returns an error and no certificate. There is no
// partial acceptance: an HTTP error, an envelope with success=false, a body
// that is not JSON, and a result containing no parseable CERTIFICATE block are
// all "no certificate was issued", which is the only safe reading of each.
func (p *originCAProvider) requestCertificate(ctx context.Context, csr []byte) ([][]byte, error) {
	body, err := json.Marshal(map[string]any{
		"csr":                string(csr),
		"hostnames":          p.hosts,
		"request_type":       originCARequestType,
		"requested_validity": p.validity,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: encode request: %w", ErrOriginCAIssuance, err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, originCAEndpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("%w: build request: %w", ErrOriginCAIssuance, err)
	}
	req.Header.Set("Content-Type", "application/json")
	name, value := originCAAuthHeader(p.token)
	req.Header.Set(name, value)

	resp, err := p.doer.Do(req)
	if err != nil {
		// The transport error is wrapped, not re-worded, so DNS and TLS
		// diagnostics survive. It cannot carry the credential: the credential
		// only ever appears in a header value, which net/http does not echo
		// into transport errors.
		return nil, fmt.Errorf("%w: request failed: %w", ErrOriginCAIssuance, err)
	}
	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, originCAMaxResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("%w: read response: %w", ErrOriginCAIssuance, err)
	}

	var decoded originCAResponse
	if err := json.Unmarshal(raw, &decoded); err != nil {
		// The body is NOT included. A non-JSON response is most likely a proxy
		// or captive-portal error page, and echoing an arbitrary remote body
		// into this server's errors is how unrelated content ends up in logs.
		// The status code is the actionable part and is safe.
		return nil, fmt.Errorf("%w: malformed response (status %d)", ErrOriginCAIssuance, resp.StatusCode)
	}

	if resp.StatusCode != http.StatusOK || !decoded.Success {
		return nil, fmt.Errorf("%w: api rejected the request (status %d): %s",
			ErrOriginCAIssuance, resp.StatusCode, originCAErrorSummary(decoded, p.token))
	}

	chain := parseCertChainPEM([]byte(decoded.Result.Certificate))
	if len(chain) == 0 {
		// success=true with nothing usable in it. Treated as a failure rather
		// than trusted, because the envelope is the API's claim and the
		// certificate is the evidence; only the evidence can be served.
		return nil, fmt.Errorf("%w: response contained no certificate", ErrOriginCAIssuance)
	}
	return chain, nil
}

// originCAAuthHeader selects the authentication header for the credential.
//
// Cloudflare's Origin CA endpoint accepts two different credentials, and they
// are NOT sent the same way:
//
//   - An Origin CA Key — the dedicated credential from the dashboard, whose
//     value always begins "v1.0-" — goes in X-Auth-User-Service-Key.
//   - A scoped API token goes in Authorization: Bearer.
//
// Sending either one in the other's header simply fails to authenticate, so the
// shape of the value is the only signal available and it is an unambiguous one.
// Dispatching on the prefix is a comparison against a constant; it neither logs
// nor returns any part of the credential.
func originCAAuthHeader(token secrets.Redacted) (name, value string) {
	raw := token.Reveal()
	if strings.HasPrefix(raw, originCAKeyPrefix) {
		return "X-Auth-User-Service-Key", raw
	}
	return "Authorization", "Bearer " + raw
}

// originCAErrorSummary renders the API's own error list for the operator, with
// the credential scrubbed out of it.
//
// Cloudflare's error messages describe the request — a hostname outside the
// zone, an invalid validity, an unauthenticated key — and are exactly what an
// operator needs, so they are surfaced rather than swallowed. But the message
// is REMOTE-CONTROLLED text, and an endpoint that echoes the rejected
// credential back in its own error (a plausible thing for an API, a proxy, or a
// hostile impostor to do) would otherwise round-trip the key straight into this
// server's error paths and from there into logs.
//
// So the credential is replaced wherever it appears before the message is
// returned, and the whole thing is truncated because its length is
// remote-controlled too. Scrubbing rather than dropping the message keeps the
// diagnostic while making the leak structurally impossible: the value cannot
// survive this function no matter what the endpoint sends.
func originCAErrorSummary(resp originCAResponse, token secrets.Redacted) string {
	if len(resp.Errors) == 0 {
		return "no error detail provided"
	}
	var b strings.Builder
	for i, e := range resp.Errors {
		if i > 0 {
			b.WriteString("; ")
		}
		fmt.Fprintf(&b, "%d %s", e.Code, e.Message)
	}

	s := b.String()
	// The empty check is not decorative: replacing the empty string would
	// splice the marker between every character of the message.
	if raw := token.Reveal(); raw != "" {
		s = strings.ReplaceAll(s, raw, "[REDACTED]")
	}

	const maxSummary = 512
	if len(s) > maxSummary {
		return s[:maxSummary] + "..."
	}
	return s
}

// parseCertChainPEM decodes every CERTIFICATE block in a PEM bundle to DER.
//
// Non-certificate blocks are skipped rather than treated as an error: the point
// is to extract exactly the certificates, and a bundle carrying anything else
// should contribute nothing rather than abort the parse.
func parseCertChainPEM(raw []byte) [][]byte {
	var chain [][]byte
	for rest := raw; ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return chain
		}
		if block.Type == "CERTIFICATE" {
			chain = append(chain, block.Bytes)
		}
	}
}

// loadCachedCert reads a previously issued certificate and key from the cache.
//
// The key file's permissions are checked by parseKey with the same rule the CSR
// and ACME modes apply: a key readable by group or other may already have been
// copied, so it is refused rather than used. Refusing here means the next
// issuance replaces it, so the suspect key is never served.
func (p *originCAProvider) loadCachedCert() (*tls.Certificate, error) {
	key, err := loadExistingKey(filepath.Join(p.cacheDir, originCAKeyFile))
	if err != nil {
		return nil, err
	}

	chain, err := loadCertChain(filepath.Join(p.cacheDir, originCACertFile))
	if err != nil {
		return nil, err
	}

	cert := &tls.Certificate{Certificate: chain, PrivateKey: key}

	// Validated before adoption, so a cached certificate that expired since the
	// process last ran is not served for even one handshake — the renewal loop
	// replaces it instead.
	if err := validateCertificate(cert, p.now()); err != nil {
		return nil, err
	}
	return cert, nil
}

// storeCachedCert persists the issued certificate and key.
//
// Both go through atomicWriteFile, which creates at 0600 and renames into
// place, so the key is never briefly world-readable and no reader sees a
// half-written file. Both are written 0600, matching ADR-0015 §3.
func (p *originCAProvider) storeCachedCert(cert *tls.Certificate) error {
	der, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		return fmt.Errorf("%w: marshal origin key: %w", ErrOriginCAIssuance, err)
	}

	// Wrapped in secrets.Redacted for the one crossing into serialized form, so
	// anything which later formats the value it came from yields the redaction
	// marker instead of the key. Plaintext is taken only at the moment it is
	// handed to the writer.
	encoded := secrets.NewRedacted(string(pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: der,
	})))
	if err := atomicWriteFile(filepath.Join(p.cacheDir, originCAKeyFile), []byte(encoded.Reveal()), keyFileMode); err != nil {
		return fmt.Errorf("%w: write origin key: %w", ErrOriginCAIssuance, err)
	}

	var chain []byte
	for _, block := range cert.Certificate {
		chain = append(chain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: block})...)
	}
	if err := atomicWriteFile(filepath.Join(p.cacheDir, originCACertFile), chain, keyFileMode); err != nil {
		return fmt.Errorf("%w: write origin certificate: %w", ErrOriginCAIssuance, err)
	}
	return nil
}

// renewalLoop keeps the certificate fresh.
//
// It runs on a TIMER, never on the handshake path — the rate-limit property
// that matters most: no volume of client connections, including a deliberate
// flood, can increase the number of API requests this server makes.
//
// The renewal threshold and the retry backoff are shared with the ACME provider
// rather than reimplemented. They are ADR-0015 §4's rules, not ACME's — renew
// when less than a third of the lifetime remains, retry with exponential
// backoff and jitter — and having one implementation means the two modes cannot
// drift into disagreeing about what the ADR says.
func (p *originCAProvider) renewalLoop(ctx context.Context) {
	defer close(p.done)

	backoff := time.Duration(0)
	timer := time.NewTimer(originCARenewCheckInterval)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}

		wait := originCARenewCheckInterval
		if p.needsIssuance() {
			if err := p.issue(ctx); err != nil {
				// Deliberately NOT logged here: the error can carry the API's
				// message, and the logging track owns redaction. It is
				// surfaced instead by handshakes being refused once the
				// certificate lapses, which is impossible to miss.
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
func (p *originCAProvider) needsIssuance() bool {
	p.mu.RLock()
	cert := p.current
	p.mu.RUnlock()

	// An empty chain reads as "needs issuance" on its own terms — a certificate
	// with no chain cannot be served — and guards the index below against a
	// future fourth way of setting p.current, where the cost would be a panic
	// on the renewal goroutine that takes issuance down for the process.
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
