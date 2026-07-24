package dns01

import (
	"bytes"
	"context"
	"encoding/json"
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

// The wire protocol below is the GoDaddy Domains v1 API, addressed by
// (name, type): a request path names one record type at one record name within
// a domain, and the body is the SET of values held there. The endpoints, the
// "sso-key" auth scheme and the 600s TTL floor are confirmed against the vendor
// reference and the go-acme/lego provider:
//
//	https://developer.godaddy.com/doc/endpoint/domains
const (
	// godaddyAPIBase is the v1 API root. It is a constant rather than
	// configurable, for the same reason Cloudflare's, Route 53's, Gandi's and
	// the others' are: a settable endpoint is a way to point the
	// highest-privilege credential this process holds at an attacker's server.
	godaddyAPIBase = "https://api.godaddy.com/v1"

	// godaddyChallengeTTL is the TTL on a challenge record this provider
	// creates.
	//
	// Unlike the 60s some providers use, this is 600: GoDaddy rejects a TTL
	// below 600, so a lower value is not "more aggressive cleanup", it is a
	// request the API refuses. It is still the floor rather than a large value,
	// because the record is deleted minutes later and a long TTL would keep
	// resolvers serving a challenge answer after the authorization it belonged
	// to is gone.
	godaddyChallengeTTL = 600

	// godaddyHTTPTimeout bounds one API call.
	godaddyHTTPTimeout = 30 * time.Second

	// godaddyMaxBody caps how much of a response is read. A response body is
	// attacker-influenced input; without a cap a hostile or broken endpoint
	// could stream until the process runs out of memory.
	godaddyMaxBody = 1 << 20
)

// ErrGoDaddyAPI is returned when the GoDaddy API refuses a request or answers
// unusably. It never carries the credential — see [godaddyProvider].
var ErrGoDaddyAPI = errors.New("dns01: godaddy api")

// godaddyProvider creates and removes the challenge TXT record through the
// GoDaddy Domains v1 API.
//
// # Credential custody
//
// GoDaddy authenticates with an API key AND an API secret, presented together
// as "Authorization: sso-key <KEY>:<SECRET>". The seam hands a provider ONE
// [secrets.Redacted], so — exactly as Route 53 does for its access-key pair —
// the two values are held as one colon-packed "KEY:SECRET" string and split
// after unwrapping. The whole packed string is held redacted rather than only
// the secret half: keeping the pair together means there is exactly one unwrap
// site to audit, in [godaddyProvider.do], immediately before it is written into
// the Authorization header. That the auth scheme itself joins the two halves
// with a colon is also the evidence the colon-pack is unambiguous: a GoDaddy
// key or secret containing a colon could not travel in this header at all.
//
// Consequences, mirroring the other providers:
//
//   - This struct implements [fmt.Formatter], so no formatting of it can print
//     the credential. That method is required, not decorative:
//     secrets.Redacted's own redaction is bypassed by fmt when the value sits
//     in an UNEXPORTED struct field, because fmt renders such fields by raw
//     reflection and never calls their String, Format or GoString methods.
//   - The type holds no logger and no telemetry handle, so there is no local
//     call site that could emit it.
//   - Errors are built from the record name and GoDaddy's own status and
//     message. The request is never rendered into an error, because a rendered
//     *http.Request includes its Authorization header.
//
// # Why cleanup re-reads the record set instead of capturing an ID or deleting by name
//
// This is the security heart of the provider, and it is where GoDaddy's model
// diverges from the by-ID providers. GoDaddy has no per-record identifier: a
// record is addressed by (name, type) and one such address holds a SET of
// values. The obvious cleanup — DELETE the whole (name, TXT) set — is WRONG for
// this seam: a single ACME order legitimately puts two TXT values at one name,
// because a certificate covering both "example.com" and "*.example.com"
// publishes both challenges at "_acme-challenge.example.com" with different
// digests ([ChallengeRecordName] strips the wildcard prefix precisely because
// RFC 8555 says so). Deleting the set would revoke the sibling challenge still
// in flight, and would also destroy any operator TXT value that happens to
// share the name.
//
// So Present reads the current set and PUTs back the union, and cleanup reads
// the current set and PUTs back the difference — issuing a DELETE of the whole
// (name, TXT) set only when the value it published was the SOLE value. The
// scoping guarantee rests on SET SUBTRACTION against an unforgeable value: the
// challenge value is the base64url SHA-256 digest of a key authorization
// computed from this process's ACCOUNT KEY, so no other party's value can equal
// it. Cleanup therefore removes the exact value this process published and
// leaves every other value byte for byte, so it cannot remove a record it did
// not create.
//
// The read-modify-write is not atomic. Within this process the solver
// serializes challenges, so the race needs a second writer to the same name in
// the same zone — another ACME client, or a second instance of this program
// validating the same domain concurrently. That is called out rather than
// papered over: GoDaddy's PUT is an unconditional replace with no
// compare-and-set to close it.
//
// # Propagation
//
// Present does not wait for the record to be served. The seam forbids a
// provider-side wait: the solver polls the zone's authoritative nameservers
// once, for every provider, which is a strictly stronger signal than any
// "change applied" flag a vendor could return.
type godaddyProvider struct {
	credential secrets.Redacted
	client     *http.Client
}

var _ Provider = (*godaddyProvider)(nil)

// NewGoDaddy builds the provider from the credential set.
//
// GoDaddy needs two values. The named form supplies them as api_key and
// api_secret; the single form supplies them colon-packed as "KEY:SECRET". Both
// are normalized to the packed shape by godaddyCredential, so the provider
// keeps exactly one stored value and one unwrap site (do), which is the custody
// model the type comment describes.
//
// A nil client gets a bounded default; the parameter exists so a test can
// supply a transport pointed at a local fake and so an operator's proxy
// settings can be honored later.
func NewGoDaddy(creds Credentials, client *http.Client) (Provider, error) {
	credential, err := godaddyCredential(creds)
	if err != nil {
		return nil, err
	}
	// Parsed once at construction so a malformed or blank credential fails at
	// startup, where the operator sees it, rather than at the first renewal
	// months later. The parsed halves are deliberately NOT stored — only the
	// check runs here; the split happens again at request time inside the
	// single unwrap site.
	if _, _, err := splitGoDaddyCredential(credential); err != nil {
		return nil, err
	}
	if client == nil {
		client = &http.Client{
			Timeout: godaddyHTTPTimeout,
			// Redirects are REFUSED rather than followed. Following one would
			// send a request carrying the zone-editing credential to whatever
			// host the response named; net/http strips Authorization across
			// origins, but a same-origin redirect to an unexpected path would
			// still be followed, and no legitimate GoDaddy call redirects.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}
	return &godaddyProvider{credential: credential, client: client}, nil
}

// godaddyCredential normalizes the credential set into the single packed
// "KEY:SECRET" form the provider stores and splits at request time.
//
// Precedence is explicit rather than a fall-through, because a lenient fallback
// here would be a security bug, exactly as it would for Route 53:
//
//   - Both named halves present -> use them, packed with a colon through
//     secrets.Join so the one downstream unwrap site (splitGoDaddyCredential in
//     do) is unchanged and this file keeps no Reveal of its own. GoDaddy keys
//     and secrets do not contain a colon — the "sso-key KEY:SECRET" header
//     format could not carry one — so the repack is unambiguous.
//   - Exactly one named half present -> REFUSE. The missing half cannot be
//     inferred, and colon-splitting a lone api_key would tear an operator value
//     into the wrong parts. The error names neither half.
//   - Neither named half -> fall back to the single packed reference via
//     Single(). An empty set yields ok=false and is refused.
func godaddyCredential(creds Credentials) (secrets.Redacted, error) {
	key, keyOK := creds.Get("api_key")
	secret, secretOK := creds.Get("api_secret")

	switch {
	case keyOK && secretOK:
		return secrets.Join(":", key, secret), nil
	case keyOK != secretOK:
		return "", fmt.Errorf(
			"%w: named credentials need both api_key and api_secret", ErrGoDaddyAPI)
	default:
		packed, ok := creds.Single()
		if !ok {
			return "", fmt.Errorf("%w: no credential supplied", ErrGoDaddyAPI)
		}
		return packed, nil
	}
}

// splitGoDaddyCredential parses the packed credential.
//
// The parse is strict — exactly two non-empty halves — and its error names
// neither half. A lenient parse here would be a security bug rather than a
// convenience: a credential accidentally supplied as just a secret, or with a
// stray newline from a file-backed secret provider, would otherwise be sent
// with silently and fail as an opaque 401 from GoDaddy. A whitespace-only half
// is blank and is refused, which is what keeps "   :   " from building a
// provider at startup.
func splitGoDaddyCredential(credential secrets.Redacted) (key, secret string, err error) {
	raw := strings.TrimSpace(credential.Reveal())
	key, secret, found := strings.Cut(raw, ":")
	if !found || strings.TrimSpace(key) == "" || strings.TrimSpace(secret) == "" {
		return "", "", fmt.Errorf(
			"%w: credential must be %q with both halves non-empty", ErrGoDaddyAPI, "KEY:SECRET")
	}
	return strings.TrimSpace(key), strings.TrimSpace(secret), nil
}

// Name identifies the provider. It is a constant, never derived from the
// credential.
func (p *godaddyProvider) Name() string { return "godaddy" }

// Format renders the provider as a constant under every fmt verb, so no
// formatting of this value can print the credential.
//
// See the type comment: this is load-bearing. Without it, "%+v" of this struct
// prints the packed key and secret in full, because fmt walks unexported fields
// by reflection and never calls their redaction methods. "%#v" routes through
// Formatter too when the operand implements it.
func (p *godaddyProvider) Format(f fmt.State, _ rune) {
	_, _ = io.WriteString(f, "dns01.godaddyProvider{credential:[REDACTED]}")
}

// Present publishes the challenge value and returns the cleanup that withdraws
// exactly that value.
func (p *godaddyProvider) Present(ctx context.Context, rec Record) (CleanupFunc, error) {
	domain, err := p.domainFor(ctx, rec.Name)
	if err != nil {
		return nil, err
	}
	relative, err := godaddyRecordName(rec.Name, domain)
	if err != nil {
		return nil, err
	}

	existing, ttl, err := p.currentTXT(ctx, domain, relative)
	if err != nil {
		return nil, err
	}

	// Merge into the set rather than replacing it: an operator TXT value at this
	// name, or a sibling wildcard challenge, must survive a create. Kept values
	// are carried BYTE FOR BYTE as the API returned them; only this process's
	// own value is added, in the bare form [Record] documents.
	values := existing
	if !slices.Contains(existing, rec.Value) {
		values = append(slices.Clone(existing), rec.Value)
	}
	if ttl < godaddyChallengeTTL {
		// An existing set's own TTL is preserved when it already meets the
		// floor, so merging a challenge into an operator's record does not
		// silently rewrite that record's TTL. Only when there was no record —
		// ttl zero — or a value below the floor does the challenge TTL apply.
		ttl = godaddyChallengeTTL
	}

	// The cleanup is built BEFORE the write and returned even when the write
	// reports failure, because a failed write can still have applied: a response
	// lost to a timeout or a reset connection leaves the set replaced at GoDaddy
	// with nothing here knowing it. Returning nil in that case leaks a standing
	// _acme-challenge TXT value that no code path can withdraw — the seam's
	// contract in dns01.go is explicit that a cleanup MUST come back whenever
	// anything may have been created, including when Present goes on to fail,
	// and the solver registers it on exactly that path.
	//
	// Returning it early is safe because the closure captures only the domain,
	// the relative name and the value — all known before the call — and nothing
	// from the response. And returning it when the write genuinely never applied
	// is harmless: the closure's first act is a read, and finding its value
	// absent it returns success without issuing any destructive request.
	cleanup := p.removeValue(domain, relative, rec.Value)

	if err := p.putTXT(ctx, domain, relative, ttl, values); err != nil {
		return cleanup, fmt.Errorf("%w: publish txt value for %q: %w", ErrGoDaddyAPI, rec.Name, err)
	}
	return cleanup, nil
}

// removeValue returns the cleanup closure for one published value.
//
// The domain, the relative name and the exact value are CAPTURED. The closure
// re-reads the set because GoDaddy's write is a whole-set replace, but it only
// ever subtracts the one captured value — no input to it can widen that, and it
// can never remove a value this process did not publish.
func (p *godaddyProvider) removeValue(domain, relative, value string) CleanupFunc {
	return func(ctx context.Context) error {
		existing, ttl, err := p.currentTXT(ctx, domain, relative)
		if err != nil {
			return fmt.Errorf("%w: read txt record for cleanup: %w", ErrGoDaddyAPI, err)
		}
		if !slices.Contains(existing, value) {
			// Already gone is success. Cleanup runs on retry and shutdown paths,
			// so it must be idempotent, and the zone is already in the state
			// this call wanted to reach. This is also the path a cleanup
			// returned from a genuinely failed publish takes: our value is
			// absent, so nothing is written or deleted and no destructive
			// request is issued.
			return nil
		}

		// Every OTHER value is carried byte for byte; only ours is dropped. If it
		// was the sole value, the whole (name, TXT) set goes, because a PUT with
		// an empty value list is not how GoDaddy empties a record.
		remaining := slices.DeleteFunc(slices.Clone(existing), func(v string) bool { return v == value })
		if len(remaining) == 0 {
			if err := p.deleteTXT(ctx, domain, relative); err != nil {
				return fmt.Errorf("%w: delete txt record: %w", ErrGoDaddyAPI, err)
			}
			return nil
		}
		if ttl < godaddyChallengeTTL {
			ttl = godaddyChallengeTTL
		}
		if err := p.putTXT(ctx, domain, relative, ttl, remaining); err != nil {
			return fmt.Errorf("%w: remove txt value: %w", ErrGoDaddyAPI, err)
		}
		return nil
	}
}

// currentTXT returns the values and TTL of the TXT record set at relative, or
// an empty slice when no such record exists.
//
// GoDaddy answers a missing record set with 200 and an EMPTY ARRAY rather than
// a 404, so the empty case is the empty slice either way; a 404 is tolerated
// too, so a future change in that behavior does not turn "nothing here yet" into
// a hard failure. The GET addresses one exact (name, type) path, so unlike Route
// 53's start-at listing there is no adjacent record to filter out; the values
// are taken as returned.
func (p *godaddyProvider) currentTXT(ctx context.Context, domain, relative string) ([]string, int, error) {
	var out []godaddyRecord
	err := p.do(ctx, http.MethodGet, godaddyRecordPath(domain, relative), nil, &out)
	if errors.Is(err, errGoDaddyNotFound) {
		return nil, 0, nil
	}
	if err != nil {
		return nil, 0, fmt.Errorf("%w: read txt record for %q: %w", ErrGoDaddyAPI, relative, err)
	}
	values := make([]string, 0, len(out))
	ttl := 0
	for _, r := range out {
		values = append(values, r.Data)
		if ttl == 0 {
			// The set shares one name; GoDaddy carries a TTL per record but they
			// are equal in practice. The first is taken to decide whether the
			// existing TTL already meets the floor on a merge.
			ttl = r.TTL
		}
	}
	return values, ttl, nil
}

// putTXT creates or replaces the TXT record set at relative with exactly
// values.
//
// A PUT to the typed (name, TXT) path creates the set when it is absent and
// replaces it when it is present, so one call covers both the first challenge
// and a merge into an existing set — there is no separate create path to keep in
// step. The record name and type live in the URL, so the body carries only the
// data and TTL of each value.
func (p *godaddyProvider) putTXT(ctx context.Context, domain, relative string, ttl int, values []string) error {
	records := make([]godaddyRecord, 0, len(values))
	for _, v := range values {
		records = append(records, godaddyRecord{Data: v, TTL: ttl})
	}
	body, err := json.Marshal(records)
	if err != nil {
		return fmt.Errorf("encode records: %w", err)
	}
	return p.do(ctx, http.MethodPut, godaddyRecordPath(domain, relative), body, nil)
}

// deleteTXT removes the whole TXT record set at relative. It is called ONLY when
// the value this process published was the last one in the set; the
// value-scoping decision lives in [godaddyProvider.removeValue], never here.
//
// A 404 is treated as success: cleanup is idempotent, and a set already gone is
// the state this call wanted to reach.
func (p *godaddyProvider) deleteTXT(ctx context.Context, domain, relative string) error {
	err := p.do(ctx, http.MethodDelete, godaddyRecordPath(domain, relative), nil, nil)
	if err == nil || errors.Is(err, errGoDaddyNotFound) {
		return nil
	}
	return err
}

// godaddyRecordPath builds the typed (name, TXT) record path. Both segments are
// escaped: the domain has been validated as a plain domain name by
// [godaddyProvider.domainFor] and the relative name is the challenge label, but
// escaping keeps a stray byte in either from splitting the path rather than
// trusting the shape.
func godaddyRecordPath(domain, relative string) string {
	return "/domains/" + url.PathEscape(domain) + "/records/TXT/" + url.PathEscape(relative)
}

// domainFor finds the GoDaddy domain that holds the record name.
//
// Candidate suffixes are tried most-specific-first, exactly as the other
// providers do, so a delegated "eu.example.com" wins over its parent
// "example.com" — writing to the parent would put the record in a zone that is
// not authoritative for the name.
//
// GET /domains/{domain} answers 200 for a domain in the account and 404 for one
// that is not, so ONLY a 404 means "try the parent". Every other failure — a
// rejected credential (401), a credential not entitled to the DNS API or to this
// domain (403), a 5xx — is surfaced, never swallowed as a miss: treating a 403
// as "try the parent" would turn a bad or under-privileged credential into a
// misleading "no domain found" after walking the whole name. A domain name is
// the API's own path key, so there is no ambiguity to resolve as with Route
// 53's duplicate hosted zones; the only failure is that none of the candidates
// is in the account, which REFUSES loudly rather than guessing.
func (p *godaddyProvider) domainFor(ctx context.Context, recordName string) (string, error) {
	name := strings.TrimSuffix(recordName, ".")

	for range maxZoneLabels {
		idx := strings.IndexByte(name, '.')
		if idx < 0 {
			break
		}
		name = name[idx+1:]
		if !strings.Contains(name, ".") {
			// A single label is a TLD; no account holds a domain there and
			// querying it only spends an API call.
			break
		}
		if !validDomainName(name) {
			// A candidate that is not a plain domain name is not interpolated
			// into a request path. The candidate is derived from the record
			// name, which comes from the certificate request, so this is the
			// check that stops a crafted identifier from steering a credentialed
			// request at another API resource.
			return "", fmt.Errorf("%w: malformed domain candidate for %q", ErrGoDaddyAPI, recordName)
		}

		var out godaddyDomainResponse
		err := p.do(ctx, http.MethodGet, "/domains/"+url.PathEscape(name), nil, &out)
		if errors.Is(err, errGoDaddyNotFound) {
			continue
		}
		if err != nil {
			return "", fmt.Errorf("%w: look up domain %q: %w", ErrGoDaddyAPI, name, err)
		}
		// The response's own name is confirmed to be the one asked for rather
		// than trusted, so a redirected or impersonated answer cannot substitute
		// a different domain for the one this lookup resolved.
		if !strings.EqualFold(strings.TrimSuffix(out.Domain, "."), name) {
			return "", fmt.Errorf("%w: domain lookup for %q answered for a different domain", ErrGoDaddyAPI, name)
		}
		return name, nil
	}
	return "", fmt.Errorf("%w: no domain found for %q", ErrGoDaddyAPI, recordName)
}

// godaddyRecordName converts the fully qualified record name into the form
// GoDaddy stores, which is relative to the domain.
//
// The label-boundary split is shared with the DigitalOcean and Gandi providers
// — the rule is the same and another copy is another thing to get wrong — and
// GoDaddy's apex encoding is "@", the same as theirs, so no translation is
// needed. The apex is unreachable for an ACME challenge, whose name always
// carries the _acme-challenge label, but the split is checked rather than
// assumed so a name that does not sit inside the resolved domain is refused
// rather than written.
func godaddyRecordName(fqdn, domain string) (string, error) {
	relative, err := relativeRecordName(fqdn, domain)
	if err != nil {
		// Rewrapped so the error names GoDaddy rather than the provider whose
		// file the shared helper happens to live in.
		return "", fmt.Errorf("%w: record %q is not inside domain %q", ErrGoDaddyAPI, fqdn, domain)
	}
	return relative, nil
}

// errGoDaddyNotFound marks a 404, so the domain walk can treat a miss as "try
// the parent", a missing record reads as empty, and a delete of an
// already-removed record is done.
var errGoDaddyNotFound = errors.New("resource not found")

// do performs one API call and decodes its result.
//
// This is the ONLY function in the file that reveals the credential, and it does
// so straight into a request header that is never logged, never stored, and
// never rendered into an error.
func (p *godaddyProvider) do(ctx context.Context, method, path string, body []byte, out any) error {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, godaddyAPIBase+path, reader)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}

	key, secret, err := splitGoDaddyCredential(p.credential)
	if err != nil {
		return err
	}
	// The halves are already trimmed by splitGoDaddyCredential, so no control
	// character from a file-backed secret reaches the header value; a newline in
	// a header value is a header-injection shape net/http rejects, and trimming
	// keeps the common file-with-trailing-newline case working either way.
	req.Header.Set("Authorization", "sso-key "+key+":"+secret)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		// The transport error is wrapped as-is. url.Error renders the request
		// URL, which carries no credential: the key and secret travel in a
		// header, and the path holds only a domain and a record name.
		return fmt.Errorf("request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, godaddyMaxBody))
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode == http.StatusNotFound {
		return errGoDaddyNotFound
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return godaddyError(resp.StatusCode, raw)
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		// The body is NOT quoted into the error. An unparseable response from
		// something impersonating the API is attacker-controlled text, and
		// echoing it into logs is how log injection starts. The status code is
		// the diagnostic.
		return fmt.Errorf("unparseable response (http %d)", resp.StatusCode)
	}
	return nil
}

// godaddyError renders the API's own error, using only its structured code and
// message.
//
// The message is bounded because it is remote input, treated as a bounded
// diagnostic rather than as trusted text. GoDaddy never echoes the credential in
// an error, and nothing here would put it there if it did.
//
// The bound goes through [safetext.Bound] rather than a slice expression: a
// fixed byte cut can land inside a multi-byte rune and leave invalid UTF-8 for
// the log encoder downstream to mangle. No credential is spliced into this
// message before the cut, so there is no scrub whose ordering against the
// truncation matters here.
func godaddyError(status int, raw []byte) error {
	var env godaddyErrorResponse
	if err := json.Unmarshal(raw, &env); err != nil || env.Message == "" {
		return fmt.Errorf("request rejected (http %d)", status)
	}
	msg := safetext.Bound(env.Message, maxAPIMessageBytes)
	if env.Code != "" {
		return fmt.Errorf("request rejected (http %d, code %s): %s", status, env.Code, msg)
	}
	return fmt.Errorf("request rejected (http %d): %s", status, msg)
}

// The JSON shapes below are the subset of the Domains v1 API this provider uses.
// Only the fields actually read or written are declared; encoding/json ignores
// the rest.

// godaddyRecord is one DNS record. It is both an element of the GET result and
// of the PUT body: the record name and type travel in the URL, so only the data
// and TTL are carried here.
type godaddyRecord struct {
	Data string `json:"data"`
	TTL  int    `json:"ttl"`
}

type godaddyDomainResponse struct {
	Domain string `json:"domain"`
}

type godaddyErrorResponse struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}
