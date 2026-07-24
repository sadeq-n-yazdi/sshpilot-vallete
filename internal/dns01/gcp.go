package dns01

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/safetext"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/secrets"
)

const (
	// gcpDNSAPIBase is the Cloud DNS v1 API root. It is a constant rather than
	// configurable, for the same reason every other provider's base is: a
	// settable endpoint is a way to point the highest-privilege credential this
	// process holds at an attacker's server.
	gcpDNSAPIBase = "https://dns.googleapis.com/dns/v1"

	// gcpTokenEndpoint is Google's OAuth 2.0 token endpoint, where the signed JWT
	// assertion is exchanged for a bearer access token. It is a constant, and the
	// service account key's own token_uri is deliberately IGNORED: trusting a URL
	// carried inside the credential would let a typo or a tampered key steer the
	// signed assertion — and the credential it authenticates — at another host.
	// The assertion's audience is bound to this same constant.
	gcpTokenEndpoint = "https://oauth2.googleapis.com/token"

	// gcpDNSScope is the OAuth scope requested for the access token: read/write on
	// Cloud DNS resource record sets and changes, and nothing else.
	gcpDNSScope = "https://www.googleapis.com/auth/ndev.clouddns.readwrite"

	// gcpGrantType is the JWT-bearer grant RFC 7523 defines for service-account
	// authentication.
	gcpGrantType = "urn:ietf:params:oauth:grant-type:jwt-bearer"

	// gcpChallengeTTL is the TTL on the challenge record. Low on purpose: the
	// record is deleted minutes later, and a long TTL would keep resolvers serving
	// a challenge answer after the authorization it belonged to is gone.
	gcpChallengeTTL = 60

	// gcpJWTLifetime bounds the assertion's validity window. Short because the
	// assertion is used once, immediately, to obtain the access token.
	gcpJWTLifetime = 10 * time.Minute

	// gcpHTTPTimeout bounds one API call.
	gcpHTTPTimeout = 30 * time.Second

	// gcpMaxBody caps how much of a response is read. A response body is
	// attacker-influenced input; without a cap a hostile or broken endpoint could
	// stream until the process runs out of memory.
	gcpMaxBody = 1 << 20
)

// ErrGCPAPI is returned when the Google Cloud DNS API (or the token exchange)
// refuses a request or answers unusably. It never carries the service account
// key — see [gcpProvider].
var ErrGCPAPI = errors.New("dns01: gcp api")

// ErrGCPAmbiguousZone is returned when more than one managed zone matches the
// name being validated.
//
// Like Route 53's equivalent, it is a separate error because it is a
// configuration fault with a specific remedy, and because the alternative —
// picking one — is the failure this provider most needs to avoid. A project may
// legitimately hold two public managed zones for the same DNS name; only the one
// the registrar's delegation points at is real. Writing the challenge record
// into the other one succeeds at the API level and is never seen by the CA, so
// issuance fails later at the propagation gate with a message about DNS rather
// than about the project. Refusing here names the real problem.
var ErrGCPAmbiguousZone = errors.New("dns01: gcp ambiguous managed zone")

// gcpProvider creates and removes the challenge TXT record through Google Cloud
// DNS, authenticating with a service account JSON key.
//
// # Credential custody
//
// The seam hands a provider ONE [secrets.Redacted]; for GCP it is the whole
// service account JSON key, which CONTAINS the RSA private key. It is unwrapped
// in exactly ONE place, [parseServiceAccount], which is called from the
// constructor (to fail a malformed key at startup) and from
// [gcpProvider.accessToken] (to sign the JWT assertion). The parsed private key
// is never stored — only projectID, which is not a secret, is kept — mirroring
// Route 53's rule that the split halves are re-derived at the point of use
// rather than held. Consequences, mirroring the other providers:
//
//   - This struct implements [fmt.Formatter], so no formatting of it can print
//     the key. That method is required, not decorative: secrets.Redacted's own
//     redaction is bypassed by fmt when the value sits in an UNEXPORTED struct
//     field, because fmt renders such fields by raw reflection and never calls
//     their String, Format or GoString methods.
//   - The type holds no logger and no telemetry handle, so there is no local
//     call site that could emit it.
//   - Errors are built from the record name and the API's own fault. The token
//     exchange's request body carries the signed assertion, and neither the
//     request nor the JSON key is ever rendered into an error.
//
// # Why cleanup re-reads the rrset instead of capturing an ID
//
// Cloud DNS has no per-record identifier: a record is a ResourceRecordSet keyed
// by (name, type) holding a SET of values, exactly like Route 53. A change is
// submitted as deletions plus additions, and a deletion must carry the rrset's
// exact current contents. A single ACME order legitimately puts two TXT values
// at one name — a certificate covering both "example.com" and "*.example.com"
// publishes both challenges at "_acme-challenge.example.com" with different
// digests ([ChallengeRecordName] strips the wildcard prefix because RFC 8555
// says so). So Present reads the current rrset and writes back the union, and
// cleanup reads the current rrset and writes back the difference — deleting the
// rrset outright only when the value it created was the last one in it. The
// scoping guarantee rests on SET SUBTRACTION against an unforgeable value (the
// base64url SHA-256 digest of a key authorization computed from this process's
// account key), so cleanup removes the exact value this process published and
// leaves every other value in place. It cannot remove a record it did not
// create, including an operator's own TXT record at the same name.
//
// The read-modify-write is not atomic. Within this process the solver serializes
// challenges, so the race needs a second writer to the same name in the same
// zone — another ACME client, or a second instance of this program validating
// the same domain concurrently.
type gcpProvider struct {
	credential secrets.Redacted
	projectID  string
	client     *http.Client

	// now is injectable so the JWT iat/exp are deterministic in tests. It is not
	// configurable at runtime.
	now func() time.Time
}

var _ Provider = (*gcpProvider)(nil)

// gcpServiceAccount is the parsed form of the service account JSON key. It holds
// the unwrapped private key and is never stored on the provider; it is produced
// at the point of use and discarded.
type gcpServiceAccount struct {
	projectID   string
	clientEmail string
	privateKey  *rsa.PrivateKey
}

// parseServiceAccount is the ONLY place in the file that reveals the service
// account key. It parses the JSON, decodes the PEM private key and asserts it is
// RSA. Every error is generic: the input is (or contains) the private key, so
// neither the raw JSON nor the underlying json/pem/x509 error — which can echo
// input bytes — is ever wrapped into a returned error.
func parseServiceAccount(credential secrets.Redacted) (gcpServiceAccount, error) {
	var key struct {
		ProjectID   string `json:"project_id"`
		ClientEmail string `json:"client_email"`
		PrivateKey  string `json:"private_key"`
	}
	if err := json.Unmarshal([]byte(credential.Reveal()), &key); err != nil {
		return gcpServiceAccount{}, fmt.Errorf("%w: malformed service account json", ErrGCPAPI)
	}
	if key.ProjectID == "" || key.ClientEmail == "" || key.PrivateKey == "" {
		return gcpServiceAccount{}, fmt.Errorf(
			"%w: service account json missing project_id, client_email or private_key", ErrGCPAPI)
	}
	if !validGCPProjectID(key.ProjectID) {
		// The project id lands in a request path, so a value that is not the shape
		// Google documents is refused rather than interpolated. It comes from the
		// operator's own credential, so this is defense in depth, not a trust
		// boundary.
		return gcpServiceAccount{}, fmt.Errorf("%w: malformed project_id in service account json", ErrGCPAPI)
	}

	block, _ := pem.Decode([]byte(key.PrivateKey))
	if block == nil {
		return gcpServiceAccount{}, fmt.Errorf("%w: service account private_key is not valid pem", ErrGCPAPI)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return gcpServiceAccount{}, fmt.Errorf("%w: service account private_key is not a valid pkcs8 key", ErrGCPAPI)
	}
	rsaKey, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return gcpServiceAccount{}, fmt.Errorf("%w: service account private_key is not an rsa key", ErrGCPAPI)
	}
	return gcpServiceAccount{projectID: key.ProjectID, clientEmail: key.ClientEmail, privateKey: rsaKey}, nil
}

// NewGCP builds the provider from the credential set.
//
// The service account JSON is parsed once here so a malformed key fails at
// startup, where the operator sees it, rather than at the first renewal months
// later. The parsed private key is deliberately NOT stored — only the check runs
// here and the non-secret project id is kept; the key is re-derived at the
// single unwrap site (accessToken) when it is needed to sign.
//
// A nil client gets a bounded default; the parameter exists so a test can supply
// a transport pointed at a local fake and so an operator's proxy settings can be
// honored later.
func NewGCP(creds Credentials, client *http.Client) (Provider, error) {
	// One value authenticates GCP (the JSON key); an empty or multi-value set
	// yields ok=false and is refused rather than guessed at. Fail closed.
	credential, ok := creds.Single()
	if !ok {
		return nil, fmt.Errorf("%w: no service account credential", ErrGCPAPI)
	}
	// A whitespace-only credential is refused as firmly as an empty one, and
	// without unwrapping it here so this file keeps a single plaintext-unwrap
	// site. A blank value would otherwise reach parseServiceAccount as an empty
	// JSON document.
	if credential.IsBlank() {
		return nil, fmt.Errorf("%w: blank service account key (empty or whitespace only)", ErrGCPAPI)
	}
	sa, err := parseServiceAccount(credential)
	if err != nil {
		return nil, err
	}
	if client == nil {
		client = &http.Client{
			Timeout: gcpHTTPTimeout,
			// Redirects are REFUSED rather than followed. Following one would send a
			// request carrying the access token to whatever host the response named;
			// net/http strips Authorization across origins, but a same-origin
			// redirect to an unexpected path would still be followed, and no
			// legitimate Cloud DNS or token call redirects.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}
	return &gcpProvider{credential: credential, projectID: sa.projectID, client: client, now: time.Now}, nil
}

// Name identifies the provider. It is a constant, never derived from the
// credential.
func (p *gcpProvider) Name() string { return "gcp" }

// Format renders the provider as a constant under every fmt verb, so no
// formatting of this value can print the service account key.
//
// See the type comment: this is load-bearing. Without it, "%+v" of this struct
// prints the JSON key — including the RSA private key — in full, because fmt
// walks unexported fields by reflection and never calls their redaction methods.
// "%#v" routes through Formatter too when the operand implements it.
func (p *gcpProvider) Format(f fmt.State, _ rune) {
	_, _ = io.WriteString(f, "dns01.gcpProvider{credential:[REDACTED]}")
}

// Present publishes the challenge value and returns the cleanup that withdraws
// exactly that value.
func (p *gcpProvider) Present(ctx context.Context, rec Record) (CleanupFunc, error) {
	token, err := p.accessToken(ctx)
	if err != nil {
		return nil, err
	}
	zone, err := p.managedZone(ctx, token, rec.Name)
	if err != nil {
		return nil, err
	}

	fqdn := rec.Name + "."
	existing, ttl, err := p.currentTXT(ctx, token, zone, fqdn)
	if err != nil {
		return nil, err
	}

	values := existing
	if !slices.Contains(values, rec.Value) {
		values = append(slices.Clone(existing), rec.Value)
	}
	if ttl <= 0 {
		ttl = gcpChallengeTTL
	}

	// The cleanup is built BEFORE the write and returned even when the write
	// reports failure, because a failed write can still have applied: a response
	// lost to a timeout or a reset connection leaves the change committed at
	// Google with nothing here knowing it. Returning nil in that case leaks a
	// standing _acme-challenge TXT value that no code path can withdraw — the
	// seam's contract in dns01.go is explicit that a cleanup MUST come back
	// whenever anything may have been created, including when Present goes on to
	// fail, and the solver registers it on exactly that path.
	//
	// Returning it early is safe because the closure captures only the zone, the
	// fqdn and the value — all known before the call — and nothing from the
	// response. And returning it when the write genuinely never applied is
	// harmless: the closure's first act is a read, and finding its value absent it
	// returns success without submitting any change.
	cleanup := p.removeValue(zone, fqdn, rec.Value)

	if err := p.changeRecords(ctx, token, zone, fqdn, ttl, existing, values); err != nil {
		return cleanup, fmt.Errorf("%w: publish txt value for %q: %w", ErrGCPAPI, rec.Name, err)
	}
	return cleanup, nil
}

// removeValue returns the cleanup closure for one published value.
//
// The zone, the fqdn and the exact value are CAPTURED. The closure re-reads the
// rrset because Cloud DNS's change submits the whole set, but it only ever
// subtracts the one captured value — no input to it can widen that, and it can
// never remove a value this process did not publish. It fetches its own access
// token because it runs on paths where the token obtained during Present has
// expired or was never taken.
func (p *gcpProvider) removeValue(zone gcpZone, fqdn, value string) CleanupFunc {
	return func(ctx context.Context) error {
		token, err := p.accessToken(ctx)
		if err != nil {
			return err
		}
		existing, ttl, err := p.currentTXT(ctx, token, zone, fqdn)
		if err != nil {
			return fmt.Errorf("%w: read txt record for cleanup: %w", ErrGCPAPI, err)
		}
		if !slices.Contains(existing, value) {
			// Already gone is success. Cleanup runs on retry and shutdown paths, so
			// it must be idempotent, and the zone is already in the state this call
			// wanted to reach. This is also the path a cleanup returned from a
			// genuinely failed publish takes.
			return nil
		}
		if ttl <= 0 {
			ttl = gcpChallengeTTL
		}
		remaining := slices.DeleteFunc(slices.Clone(existing), func(v string) bool { return v == value })
		if err := p.changeRecords(ctx, token, zone, fqdn, ttl, existing, remaining); err != nil {
			return fmt.Errorf("%w: remove txt value: %w", ErrGCPAPI, err)
		}
		return nil
	}
}

// gcpZone is a managed zone's identifier and DNS name, as returned by
// managedZones.list.
type gcpZone struct {
	name    string // the zone's resource id, used in request paths
	dnsName string // the zone's DNS suffix, e.g. "example.com."
}

// managedZone finds the single public managed zone that should hold the record.
//
// Candidate suffixes are tried most-specific-first, exactly as the other
// providers do, so a delegated "eu.example.com" wins over its parent
// "example.com" — writing to the parent would put the record in a zone that is
// not authoritative for the name.
//
//   - PRIVATE zones are discarded. A private zone is visible only inside its
//     associated networks; the CA queries the public internet. A challenge
//     record written into a private zone is accepted and never seen.
//   - More than one surviving match REFUSES, for the same reason Route 53's
//     equivalent does: only the zone the registrar delegates to is real, and
//     picking the first would be a coin flip resolved silently.
func (p *gcpProvider) managedZone(ctx context.Context, token, recordName string) (gcpZone, error) {
	name := strings.TrimSuffix(recordName, ".")

	for range maxZoneLabels {
		idx := strings.IndexByte(name, '.')
		if idx < 0 {
			break
		}
		name = name[idx+1:]
		if !strings.Contains(name, ".") {
			// A single label is a TLD; no project hosts a zone there and querying it
			// only spends an API call.
			break
		}
		if !validDomainName(name) {
			// A candidate that is not a plain domain name is not placed into a query.
			// The candidate is derived from the record name, which comes from the
			// certificate request, so this is the check that stops a crafted
			// identifier from steering a credentialed request.
			return gcpZone{}, fmt.Errorf("%w: malformed zone candidate for %q", ErrGCPAPI, recordName)
		}

		matches, err := p.publicZonesNamed(ctx, token, name)
		if err != nil {
			return gcpZone{}, err
		}
		switch len(matches) {
		case 0:
			continue
		case 1:
			return matches[0], nil
		default:
			return gcpZone{}, fmt.Errorf("%w: %d public managed zones for %q; "+
				"remove the duplicate or the challenge record may be written to the zone the registrar does not delegate to",
				ErrGCPAmbiguousZone, len(matches), name)
		}
	}
	return gcpZone{}, fmt.Errorf("%w: no public managed zone found for %q", ErrGCPAPI, recordName)
}

// publicZonesNamed returns the public managed zones whose dnsName is exactly
// dnsName. The dnsName filter is passed to the API AND re-checked here, and the
// zone id the API returns is validated before it can reach a request path.
func (p *gcpProvider) publicZonesNamed(ctx context.Context, token, dnsName string) ([]gcpZone, error) {
	query := url.Values{"dnsName": {dnsName + "."}}.Encode()
	path := "/projects/" + p.projectID + "/managedZones?" + query

	var out gcpManagedZonesListResponse
	if err := p.do(ctx, token, http.MethodGet, path, nil, &out); err != nil {
		return nil, fmt.Errorf("%w: look up managed zone %q: %w", ErrGCPAPI, dnsName, err)
	}

	var zones []gcpZone
	for _, z := range out.ManagedZones {
		if !strings.EqualFold(strings.TrimSuffix(z.DNSName, "."), dnsName) {
			continue
		}
		// Cloud DNS reports visibility as "public" or "private"; anything other
		// than an explicit "public" is treated as not-public and discarded, so a
		// missing or unknown value fails closed rather than being published where
		// the CA cannot see it.
		if !strings.EqualFold(z.Visibility, "public") {
			continue
		}
		if !validGCPZoneName(z.Name) {
			// A zone id that is not the shape Google documents is not interpolated
			// into a request path. The id reaches a URL, so this stops a hostile or
			// confused response from steering a credentialed request at another
			// resource.
			return nil, fmt.Errorf("%w: malformed managed zone id in response", ErrGCPAPI)
		}
		zones = append(zones, gcpZone{name: z.Name, dnsName: z.DNSName})
	}
	return zones, nil
}

// currentTXT returns the TXT values currently published at fqdn and their TTL.
// A missing record set is the normal state before the first challenge and
// reports as an empty slice.
func (p *gcpProvider) currentTXT(ctx context.Context, token string, zone gcpZone, fqdn string) ([]string, int, error) {
	query := url.Values{"name": {fqdn}, "type": {"TXT"}}.Encode()
	path := "/projects/" + p.projectID + "/managedZones/" + zone.name + "/rrsets?" + query

	var out gcpResourceRecordSetsListResponse
	if err := p.do(ctx, token, http.MethodGet, path, nil, &out); err != nil {
		return nil, 0, fmt.Errorf("%w: list txt records for %q: %w", ErrGCPAPI, fqdn, err)
	}
	for _, rrset := range out.RRSets {
		if !strings.EqualFold(rrset.Name, fqdn) || rrset.Type != "TXT" {
			continue
		}
		values := make([]string, 0, len(rrset.Rrdatas))
		for _, rr := range rrset.Rrdatas {
			values = append(values, unquoteTXT(rr))
		}
		return values, rrset.TTL, nil
	}
	return nil, 0, nil
}

// changeRecords submits one changes.create with the deletion of the existing
// rrset (when there was one) and the addition of the desired rrset (when it is
// non-empty). A change carrying only a deletion removes the set outright.
//
// It deliberately does NOT wait for the change to reach status "done". The seam
// forbids a provider-side propagation wait: the solver polls the zone's
// authoritative nameservers once, for every provider, which is a strictly
// stronger signal than any "change applied" flag Google could return.
func (p *gcpProvider) changeRecords(ctx context.Context, token string, zone gcpZone, fqdn string, ttl int, existing, desired []string) error {
	var change gcpChange
	if len(existing) > 0 {
		change.Deletions = []gcpRRSet{{Name: fqdn, Type: "TXT", TTL: ttl, Rrdatas: quoteTXTAll(existing)}}
	}
	if len(desired) > 0 {
		change.Additions = []gcpRRSet{{Name: fqdn, Type: "TXT", TTL: ttl, Rrdatas: quoteTXTAll(desired)}}
	}
	if len(change.Deletions) == 0 && len(change.Additions) == 0 {
		// Nothing to do: there was no set and none is wanted. Not an error.
		return nil
	}

	body, err := json.Marshal(change)
	if err != nil {
		return fmt.Errorf("encode change: %w", err)
	}
	path := "/projects/" + p.projectID + "/managedZones/" + zone.name + "/changes"
	return p.do(ctx, token, http.MethodPost, path, body, nil)
}

// quoteTXTAll renders each value as Cloud DNS stores TXT rrdata: a quoted
// string. It reuses the package's route53 quoting so there is one decision about
// how a TXT value is escaped.
func quoteTXTAll(values []string) []string {
	out := make([]string, len(values))
	for i, v := range values {
		out[i] = quoteTXT(v)
	}
	return out
}

// accessToken builds and signs a JWT assertion from the service account key and
// exchanges it for a bearer access token.
//
// This calls the single reveal site, [parseServiceAccount], to obtain the RSA
// key; the returned access token is an ordinary string from the token response,
// not a wrapped secret, so threading it into an Authorization header downstream
// is not a second unwrap of the credential.
func (p *gcpProvider) accessToken(ctx context.Context) (string, error) {
	sa, err := parseServiceAccount(p.credential)
	if err != nil {
		return "", err
	}

	now := p.now()
	claims := gcpJWTClaims{
		Issuer:   sa.clientEmail,
		Scope:    gcpDNSScope,
		Audience: gcpTokenEndpoint,
		IssuedAt: now.Unix(),
		Expiry:   now.Add(gcpJWTLifetime).Unix(),
	}
	assertion, err := signJWT(claims, sa.privateKey)
	if err != nil {
		// signJWT builds its error from the signing failure only; the key material
		// is never rendered.
		return "", fmt.Errorf("%w: sign token assertion: %w", ErrGCPAPI, err)
	}

	form := url.Values{"grant_type": {gcpGrantType}, "assertion": {assertion}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, gcpTokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("%w: build token request: %w", ErrGCPAPI, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		// The transport error is wrapped as-is. url.Error renders the request URL,
		// which is the constant token endpoint and carries no credential; the signed
		// assertion travels in the body.
		return "", fmt.Errorf("%w: token request failed: %w", ErrGCPAPI, err)
	}
	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, gcpMaxBody))
	if err != nil {
		return "", fmt.Errorf("%w: read token response: %w", ErrGCPAPI, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", gcpTokenError(resp.StatusCode, raw)
	}
	var tok gcpTokenResponse
	if err := json.Unmarshal(raw, &tok); err != nil {
		// The body is NOT quoted into the error: an unparseable response from
		// something impersonating the endpoint is attacker-controlled text.
		return "", fmt.Errorf("%w: unparseable token response (http %d)", ErrGCPAPI, resp.StatusCode)
	}
	if tok.AccessToken == "" {
		// A success without a token leaves nothing to authenticate with. Refused
		// loudly rather than proceeding to send "Bearer " and learn nothing until
		// the first API call is rejected.
		return "", fmt.Errorf("%w: token response carried no access_token (http %d)", ErrGCPAPI, resp.StatusCode)
	}
	return tok.AccessToken, nil
}

// signJWT builds the RS256-signed assertion. The header and claims are
// base64url-encoded without padding (as JWT requires), and the signature is over
// the SHA-256 hash of "header.claims".
func signJWT(claims gcpJWTClaims, key *rsa.PrivateKey) (string, error) {
	header, err := json.Marshal(gcpJWTHeader{Algorithm: "RS256", Type: "JWT"})
	if err != nil {
		return "", fmt.Errorf("encode jwt header: %w", err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("encode jwt claims: %w", err)
	}
	signingInput := base64.RawURLEncoding.EncodeToString(header) + "." +
		base64.RawURLEncoding.EncodeToString(payload)

	digest := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		return "", fmt.Errorf("rsa sign: %w", err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// do performs one authenticated Cloud DNS API call and decodes its result. The
// access token it writes into the Authorization header is the string returned by
// accessToken, never the service account key.
func (p *gcpProvider) do(ctx context.Context, token, method, path string, body []byte, out any) error {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, gcpDNSAPIBase+path, reader)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		// The transport error is wrapped as-is. url.Error renders the request URL,
		// which carries no credential: the token travels in a header, and the path
		// holds only the project, zone and record name.
		return fmt.Errorf("request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, gcpMaxBody))
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return gcpAPIError(resp.StatusCode, raw)
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		// The body is NOT quoted into the error. An unparseable response from
		// something impersonating the API is attacker-controlled text, and echoing
		// it into logs is how log injection starts. The status code is the
		// diagnostic.
		return fmt.Errorf("unparseable response (http %d)", resp.StatusCode)
	}
	return nil
}

// gcpAPIError renders the Cloud DNS API's own error, using only its structured
// message. The message is bounded through [safetext.Bound] because it is remote
// input; a fixed byte cut could split a multi-byte rune and leave invalid UTF-8
// for the log encoder downstream to mangle. No credential is spliced into it.
func gcpAPIError(status int, raw []byte) error {
	var env gcpErrorResponse
	if err := json.Unmarshal(raw, &env); err != nil || env.Error.Message == "" {
		return fmt.Errorf("request rejected (http %d)", status)
	}
	msg := safetext.Bound(env.Error.Message, maxAPIMessageBytes)
	return fmt.Errorf("request rejected (http %d): %s", status, msg)
}

// gcpTokenError renders the OAuth token endpoint's error. It uses only the
// structured "error" / "error_description" fields, bounded, and never the raw
// body. The signed assertion is never echoed by the endpoint and nothing here
// would put it there.
func gcpTokenError(status int, raw []byte) error {
	var env gcpTokenErrorResponse
	if err := json.Unmarshal(raw, &env); err != nil || (env.Error == "" && env.Description == "") {
		return fmt.Errorf("%w: token request rejected (http %d)", ErrGCPAPI, status)
	}
	detail := env.Error
	if env.Description != "" {
		detail = env.Error + ": " + env.Description
	}
	msg := safetext.Bound(detail, maxAPIMessageBytes)
	return fmt.Errorf("%w: token request rejected (http %d): %s", ErrGCPAPI, status, msg)
}

// validGCPProjectID reports whether id is the shape Google documents for a
// project id: 6-30 chars, lowercase letter first, then lowercase letters,
// digits or hyphens. It exists to keep the credential-supplied project id from
// escaping into a URL path as anything else.
func validGCPProjectID(id string) bool {
	if len(id) < 6 || len(id) > 30 {
		return false
	}
	for i := range len(id) {
		c := id[i]
		switch {
		case c >= 'a' && c <= 'z':
		case i > 0 && (c >= '0' && c <= '9' || c == '-'):
		default:
			return false
		}
	}
	return true
}

// validGCPZoneName reports whether name is the shape Cloud DNS documents for a
// managed zone id: 1-63 chars, lowercase letter first, then lowercase letters,
// digits or hyphens. It keeps a response value from escaping into a URL path.
func validGCPZoneName(name string) bool {
	if name == "" || len(name) > 63 {
		return false
	}
	for i := range len(name) {
		c := name[i]
		switch {
		case c >= 'a' && c <= 'z':
		case i > 0 && (c >= '0' && c <= '9' || c == '-'):
		default:
			return false
		}
	}
	return true
}

// The JSON shapes below are the subset of the Cloud DNS v1 and OAuth token APIs
// this provider uses. Only the fields actually read or written are declared;
// encoding/json ignores the rest.

type gcpJWTHeader struct {
	Algorithm string `json:"alg"`
	Type      string `json:"typ"`
}

type gcpJWTClaims struct {
	Issuer   string `json:"iss"`
	Scope    string `json:"scope"`
	Audience string `json:"aud"`
	IssuedAt int64  `json:"iat"`
	Expiry   int64  `json:"exp"`
}

type gcpTokenResponse struct {
	AccessToken string `json:"access_token"`
}

type gcpTokenErrorResponse struct {
	Error       string `json:"error"`
	Description string `json:"error_description"`
}

type gcpManagedZonesListResponse struct {
	ManagedZones []struct {
		Name       string `json:"name"`
		DNSName    string `json:"dnsName"`
		Visibility string `json:"visibility"`
	} `json:"managedZones"`
}

type gcpResourceRecordSetsListResponse struct {
	RRSets []gcpRRSet `json:"rrsets"`
}

type gcpRRSet struct {
	Name    string   `json:"name"`
	Type    string   `json:"type"`
	TTL     int      `json:"ttl"`
	Rrdatas []string `json:"rrdatas"`
}

type gcpChange struct {
	Additions []gcpRRSet `json:"additions,omitempty"`
	Deletions []gcpRRSet `json:"deletions,omitempty"`
}

type gcpErrorResponse struct {
	Error struct {
		Message string `json:"message"`
	} `json:"error"`
}
