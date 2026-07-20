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
	"strconv"
	"strings"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/safetext"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/secrets"
)

const (
	// digitalOceanAPIBase is the v2 API root. It is a constant rather than
	// configurable, for the same reason Cloudflare's and Route 53's are: a
	// settable endpoint is a way to point the highest-privilege credential this
	// process holds at an attacker's server.
	digitalOceanAPIBase = "https://api.digitalocean.com/v2"

	// digitalOceanChallengeTTL is the TTL on the challenge record. DigitalOcean's
	// minimum is 30s; low is what we want, because the record is deleted minutes
	// later and a long TTL would keep resolvers serving a challenge answer after
	// the authorization it belonged to is gone.
	digitalOceanChallengeTTL = 60

	// digitalOceanHTTPTimeout bounds one API call.
	digitalOceanHTTPTimeout = 30 * time.Second

	// digitalOceanMaxBody caps how much of a response is read. A response body is
	// attacker-influenced input; without a cap a hostile or broken endpoint could
	// stream until the process runs out of memory.
	digitalOceanMaxBody = 1 << 20

	// digitalOceanListPerPage bounds one page of a record listing. The listing is
	// filtered to one name and type, so the challenge set is one or two records;
	// this only ensures a single request suffices.
	digitalOceanListPerPage = 200
)

// ErrDigitalOceanAPI is returned when the DigitalOcean API refuses a request or
// answers unusably. It never carries the API token — see [digitalOceanProvider].
var ErrDigitalOceanAPI = errors.New("dns01: digitalocean api")

// digitalOceanProvider creates and removes the challenge TXT record through
// DigitalOcean's v2 API.
//
// # Token custody
//
// DigitalOcean authenticates with a single bearer token, which fits the seam's
// one-credential shape directly — no packing, unlike Route 53. The token is held
// as a [secrets.Redacted] and is unwrapped in exactly ONE place,
// [digitalOceanProvider.do], directly into the Authorization header of an
// outbound request. Consequences, mirroring the other two providers:
//
//   - This struct implements [fmt.Formatter], so no formatting of it can print
//     the token. That method is required, not decorative: secrets.Redacted's own
//     redaction is bypassed by fmt when the value sits in an UNEXPORTED struct
//     field, because fmt renders such fields by raw reflection and never calls
//     their String, Format or GoString methods.
//   - The type holds no logger and no telemetry handle, so there is no local
//     call site that could emit it.
//   - Errors are built from the record name and DigitalOcean's own status and
//     message. The request is never rendered into an error, because a rendered
//     *http.Request includes its Authorization header.
//
// # Why cleanup resolves the record by VALUE rather than capturing the create ID
//
// DigitalOcean has per-record integer IDs, so Cloudflare's capture-the-ID shape
// is available and was the starting point. It is not what this provider does,
// for one reason: the seam requires a usable cleanup back even when Present goes
// on to FAIL (see [Provider]), and on the create path the only failure that
// matters is the one where no ID came back. A create whose response is lost to a
// timeout or a reset connection leaves the record standing at DigitalOcean with
// this process holding no ID for it. A cleanup that can only delete a captured
// ID is therefore nil exactly when it is needed, which is the leaked standing
// _acme-challenge record the contract exists to prevent.
//
// So the closure captures the domain, the record name and the VALUE — all known
// before the write — and resolves the ID at cleanup time by listing the TXT
// records at that name and matching on the exact value. Deletion is still by ID;
// only the ID's discovery moved. The scoping guarantee is unchanged and rests on
// the value being unforgeable: it is the base64url SHA-256 digest of a key
// authorization computed from this process's ACCOUNT KEY, so no other party's
// record can carry it. Cleanup therefore removes the exact value this process
// published and cannot remove a record it did not create — including an
// operator's own TXT record at the same name, and including the OTHER challenge
// of a wildcard order, which sits at the same name with a different digest.
//
// # Propagation
//
// Present does not wait for the record to be served. DigitalOcean exposes no
// change-status endpoint to be tempted by, and the seam forbids a provider-side
// wait regardless: the solver polls the zone's authoritative nameservers once,
// for every provider, which is a strictly stronger signal than any "change
// applied" flag the vendor could return.
type digitalOceanProvider struct {
	token  secrets.Redacted
	client *http.Client
}

var _ Provider = (*digitalOceanProvider)(nil)

// NewDigitalOcean builds the provider. A nil client gets a bounded default; the
// parameter exists so a test can supply a transport pointed at a local fake and
// so an operator's proxy settings can be honored later.
func NewDigitalOcean(token secrets.Redacted, client *http.Client) (Provider, error) {
	// The emptiness check compares the WRAPPED value against "" rather than
	// revealing it, exactly as the Cloudflare constructor does, so this file
	// keeps a single plaintext-unwrap site. Refused at construction, where the
	// operator sees it, rather than at the first renewal months later.
	if token == "" {
		return nil, fmt.Errorf("%w: empty api token", ErrDigitalOceanAPI)
	}
	if client == nil {
		client = &http.Client{
			Timeout: digitalOceanHTTPTimeout,
			// Redirects are REFUSED rather than followed. Following one would send
			// a request carrying the zone-editing token to whatever host the
			// response named; net/http strips Authorization across origins, but a
			// same-origin redirect to an unexpected path would still be followed,
			// and no legitimate DigitalOcean API call redirects.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}
	return &digitalOceanProvider{token: token, client: client}, nil
}

// Name identifies the provider. It is a constant, never derived from the token.
func (p *digitalOceanProvider) Name() string { return "digitalocean" }

// Format renders the provider as a constant under every fmt verb, so no
// formatting of this value can print the token.
//
// See the type comment: this is load-bearing. Without it, "%+v" of this struct
// prints the bearer token in full, because fmt walks unexported fields by
// reflection and never calls their redaction methods. "%#v" routes through
// Formatter too when the operand implements it.
func (p *digitalOceanProvider) Format(f fmt.State, _ rune) {
	_, _ = io.WriteString(f, "dns01.digitalOceanProvider{token:[REDACTED]}")
}

// Present publishes the challenge value and returns the cleanup that withdraws
// exactly that value.
func (p *digitalOceanProvider) Present(ctx context.Context, rec Record) (CleanupFunc, error) {
	domain, err := p.domainFor(ctx, rec.Name)
	if err != nil {
		return nil, err
	}
	relative, err := relativeRecordName(rec.Name, domain)
	if err != nil {
		return nil, err
	}

	body, err := json.Marshal(map[string]any{
		"type": "TXT",
		// The name is RELATIVE to the domain. DigitalOcean treats an unsuffixed
		// name as a subdomain prefix, so sending the FQDN here would create
		// "_acme-challenge.example.com.example.com" — a record the API accepts,
		// that reaches the zone, and that no CA ever queries. See
		// [relativeRecordName].
		"name": relative,
		// TXT content is "data" on this API, not Cloudflare's "content".
		"data": rec.Value,
		"ttl":  digitalOceanChallengeTTL,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: encode record: %w", ErrDigitalOceanAPI, err)
	}

	// The cleanup is built BEFORE the write and returned even when the write
	// reports failure, because a failed write can still have applied: a response
	// lost to a timeout or a reset connection leaves the record created at
	// DigitalOcean with nothing here knowing its ID. Returning nil in that case
	// leaks a standing _acme-challenge TXT record that no code path can withdraw
	// — the seam's contract in dns01.go is explicit that a cleanup MUST come back
	// whenever anything may have been created, including when Present goes on to
	// fail, and the solver registers it on exactly that path.
	//
	// Returning it early is safe because the closure captures only the domain,
	// the relative name and the value — all known before the call — and nothing
	// from the response. And returning it when the write genuinely never applied
	// is harmless: the closure's first act is a read, and finding its value
	// absent it returns success without issuing any delete. So the pessimistic
	// case costs one GET and cannot disturb a concurrent challenge at the same
	// name.
	cleanup := p.removeValue(domain, relative, rec.Name, rec.Value)

	if err := p.do(ctx, http.MethodPost, "/domains/"+url.PathEscape(domain)+"/records", body, nil); err != nil {
		return cleanup, fmt.Errorf("%w: create txt record for %q: %w", ErrDigitalOceanAPI, rec.Name, err)
	}
	return cleanup, nil
}

// removeValue returns the cleanup closure for one published value.
//
// The domain, the relative record name and the exact value are CAPTURED. The
// closure lists the TXT records at that one name and deletes only the record
// whose data equals the captured value — no input to it can widen that, and it
// can never remove a value this process did not publish.
func (p *digitalOceanProvider) removeValue(domain, relative, fqdn, value string) CleanupFunc {
	return func(ctx context.Context) error {
		id, found, err := p.findRecord(ctx, domain, relative, fqdn, value)
		if err != nil {
			return fmt.Errorf("%w: find txt record for cleanup: %w", ErrDigitalOceanAPI, err)
		}
		if !found {
			// Already gone is success. Cleanup runs on retry and shutdown paths,
			// so it must be idempotent, and the zone is already in the state this
			// call wanted to reach. This is also the path a cleanup returned from
			// a genuinely failed publish takes: nothing was created, so nothing is
			// deleted and no destructive request is issued.
			return nil
		}

		path := "/domains/" + url.PathEscape(domain) + "/records/" + strconv.FormatInt(id, 10)
		err = p.do(ctx, http.MethodDelete, path, nil, nil)
		if err == nil || errors.Is(err, errDigitalOceanNotFound) {
			return nil
		}
		return fmt.Errorf("%w: delete txt record: %w", ErrDigitalOceanAPI, err)
	}
}

// findRecord returns the ID of the TXT record at relative whose data is value.
//
// Every element of the match is re-checked in code rather than delegated to the
// API's filter. The name filter is a query parameter on a remote service: if it
// were ignored, mishandled, or answered by something impersonating the API, an
// unchecked caller would delete whatever record happened to come back first. The
// three checks below — name, type, and exact value — are what make this a lookup
// for one specific published value rather than a name-to-records primitive.
func (p *digitalOceanProvider) findRecord(ctx context.Context, domain, relative, fqdn, value string) (int64, bool, error) {
	// DigitalOcean's name filter requires the FULLY QUALIFIED record name, while
	// the records it returns carry the RELATIVE one. Both forms are therefore in
	// play here, and they are not interchangeable.
	query := fmt.Sprintf("?type=TXT&name=%s&per_page=%d", url.QueryEscape(fqdn), digitalOceanListPerPage)
	var out digitalOceanRecordsResponse
	if err := p.do(ctx, http.MethodGet, "/domains/"+url.PathEscape(domain)+"/records"+query, nil, &out); err != nil {
		if errors.Is(err, errDigitalOceanNotFound) {
			// The domain or the record set is gone entirely; nothing to remove.
			return 0, false, nil
		}
		return 0, false, fmt.Errorf("list txt records for %q: %w", fqdn, err)
	}

	for _, r := range out.DomainRecords {
		if !strings.EqualFold(r.Type, "TXT") {
			continue
		}
		if !strings.EqualFold(strings.TrimSuffix(r.Name, "."), relative) {
			continue
		}
		if r.Data != value {
			// The value check is what keeps a wildcard order's two challenges
			// apart: both sit at this exact name with different digests, and
			// removing the wrong one would revoke a challenge still in flight.
			continue
		}
		if r.ID <= 0 {
			return 0, false, fmt.Errorf("record at %q has no usable id", fqdn)
		}
		return r.ID, true, nil
	}
	return 0, false, nil
}

// domainFor finds the DigitalOcean domain that holds the record name.
//
// Candidate suffixes are tried most-specific-first, exactly as the Cloudflare
// and Route 53 providers do, so a delegated "eu.example.com" wins over its
// parent "example.com" — writing to the parent would put the record in a zone
// that is not authoritative for the name.
//
// Unlike Route 53 there is no ambiguity to resolve. A DigitalOcean domain name
// is the API's own path key, so GET /v2/domains/{name} answers with exactly one
// domain or 404; an account cannot hold two domains with the same name for this
// to have to choose between. What CAN happen is that none of the candidates is
// in the account, and that REFUSES loudly rather than guessing: the alternative
// is writing the challenge into some other domain, which succeeds at the API
// level and is never seen by the CA, so issuance fails ten minutes later at the
// propagation gate with a message about DNS rather than about the account.
func (p *digitalOceanProvider) domainFor(ctx context.Context, recordName string) (string, error) {
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
			// into a request path. The candidate is derived from the record name,
			// which comes from the certificate request, so this is the check that
			// stops a crafted identifier from steering a credentialed request at
			// another API resource.
			return "", fmt.Errorf("%w: malformed domain candidate for %q", ErrDigitalOceanAPI, recordName)
		}

		var out digitalOceanDomainResponse
		err := p.do(ctx, http.MethodGet, "/domains/"+url.PathEscape(name), nil, &out)
		if errors.Is(err, errDigitalOceanNotFound) {
			continue
		}
		if err != nil {
			return "", fmt.Errorf("%w: look up domain %q: %w", ErrDigitalOceanAPI, name, err)
		}
		// The response's own name is confirmed to be the one asked for rather
		// than trusted, so a redirected or impersonated answer cannot substitute
		// a different domain for the one this lookup resolved.
		if !strings.EqualFold(strings.TrimSuffix(out.Domain.Name, "."), name) {
			return "", fmt.Errorf("%w: domain lookup for %q answered for a different domain", ErrDigitalOceanAPI, name)
		}
		return name, nil
	}
	return "", fmt.Errorf("%w: no domain found for %q", ErrDigitalOceanAPI, recordName)
}

// relativeRecordName converts the fully qualified record name into the form
// DigitalOcean stores, which is relative to the domain.
//
// Getting this wrong is silent: DigitalOcean accepts an unsuffixed name as a
// subdomain prefix, so passing the FQDN through would create the record at
// "_acme-challenge.example.com.example.com", the API would report success, and
// the CA would query a name that does not exist. The split is therefore checked
// rather than assumed — a name that is not inside the domain is a bug in the
// domain selection above, and it fails here instead of writing somewhere
// unintended.
func relativeRecordName(fqdn, domain string) (string, error) {
	name := strings.TrimSuffix(fqdn, ".")
	domain = strings.TrimSuffix(domain, ".")

	if strings.EqualFold(name, domain) {
		// The apex. Not reachable for an ACME challenge, whose name always
		// carries the _acme-challenge label, but the encoding is DigitalOcean's
		// and is spelled out rather than left to produce an empty name.
		return "@", nil
	}
	if len(name) <= len(domain)+1 || !strings.EqualFold(name[len(name)-len(domain):], domain) ||
		name[len(name)-len(domain)-1] != '.' {
		return "", fmt.Errorf("%w: record %q is not inside domain %q", ErrDigitalOceanAPI, fqdn, domain)
	}
	return name[:len(name)-len(domain)-1], nil
}

// validDomainName reports whether name is a plain dotted domain name. It exists
// to keep a value derived from a certificate request from escaping into a URL
// path as anything other than a domain.
func validDomainName(name string) bool {
	if name == "" || len(name) > 253 {
		return false
	}
	for i := range len(name) {
		c := name[i]
		ok := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			c == '-' || c == '.' || c == '_'
		if !ok {
			return false
		}
	}
	return true
}

// errDigitalOceanNotFound marks a 404, so cleanup can treat an already-removed
// record as done and the domain walk can treat a miss as "try the parent".
var errDigitalOceanNotFound = errors.New("resource not found")

// do performs one API call and decodes its result.
//
// This is the ONLY function in the file that reveals the token, and it does so
// straight into a request header that is never logged, never stored, and never
// rendered into an error.
func (p *digitalOceanProvider) do(ctx context.Context, method, path string, body []byte, out any) error {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, digitalOceanAPIBase+path, reader)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	// Trimmed at the point of use: a file-backed secret provider commonly yields
	// a trailing newline, and a newline in a header VALUE is a header-injection
	// shape. net/http rejects it rather than sending it, so the failure would be
	// safe but opaque; trimming here makes the common case work and keeps the
	// control characters out of the request either way.
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(p.token.Reveal()))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		// The transport error is wrapped as-is. url.Error renders the request
		// URL, which carries no credential: the token travels in a header, and
		// the path holds only a domain and a record name.
		return fmt.Errorf("request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, digitalOceanMaxBody))
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode == http.StatusNotFound {
		return errDigitalOceanNotFound
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return digitalOceanError(resp.StatusCode, raw)
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

// digitalOceanError renders the API's own error, using only its structured id
// and message.
//
// The message is truncated because it is remote input, treated as a bounded
// diagnostic rather than as trusted text. DigitalOcean never echoes the bearer
// token in an error, and nothing here would put it there if it did.
//
// The bound goes through [safetext.Bound] rather than a slice expression. A
// fixed BYTE cut can land in the middle of a multi-byte UTF-8 sequence and
// leave a fragment that is not valid UTF-8, which the JSON log encoder
// downstream then mangles. No credential is spliced into this message before
// the cut, so there is no scrub whose ordering against the truncation matters
// here.
func digitalOceanError(status int, raw []byte) error {
	var env digitalOceanErrorResponse
	if err := json.Unmarshal(raw, &env); err != nil || env.ID == "" {
		return fmt.Errorf("request rejected (http %d)", status)
	}
	msg := safetext.Bound(env.Message, maxAPIMessageBytes)
	return fmt.Errorf("request rejected (http %d, id %s): %s", status, env.ID, msg)
}

// The JSON shapes below are the subset of the v2 API this provider uses. Only
// the fields actually read are declared; encoding/json ignores the rest.

type digitalOceanDomainResponse struct {
	Domain struct {
		Name string `json:"name"`
	} `json:"domain"`
}

type digitalOceanRecordsResponse struct {
	DomainRecords []struct {
		ID   int64  `json:"id"`
		Type string `json:"type"`
		Name string `json:"name"`
		Data string `json:"data"`
	} `json:"domain_records"`
}

type digitalOceanErrorResponse struct {
	ID      string `json:"id"`
	Message string `json:"message"`
}
