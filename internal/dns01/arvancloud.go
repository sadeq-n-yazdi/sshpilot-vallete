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
	"strings"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/safetext"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/secrets"
)

// ArvanCloud DNS API reference (CDN 4.0), confirmed against the official docs:
//
//   - Endpoints/host: https://docs.arvancloud.ir/en/developer-tools/api/api-usage
//   - DNS record shape: https://docs.arvancloud.ir/en/cdn/dns-records/adding-records
//
// A TXT record's type is the lowercase string "txt", its name is stored
// RELATIVE to the domain, and its content sits in a nested value object,
// {"value":{"text":"..."}}. Record IDs are opaque UUID strings, not integers.
const (
	// arvanCloudAPIBase is the CDN 4.0 API root. It is a constant rather than
	// configurable, for the same reason Cloudflare's, Route 53's and
	// DigitalOcean's are: a settable endpoint is a way to point the
	// highest-privilege credential this process holds at an attacker's server.
	arvanCloudAPIBase = "https://napi.arvancloud.ir/cdn/4.0"

	// arvanCloudChallengeTTL is the TTL on the challenge record. ArvanCloud
	// rejects a TXT record with a TTL below 600s, so a lower value would be a
	// silent create failure at renewal time; 600 is still short for a record
	// deleted minutes later, and a longer TTL would keep resolvers serving a
	// challenge answer after the authorization it belonged to is gone.
	arvanCloudChallengeTTL = 600

	// arvanCloudHTTPTimeout bounds one API call.
	arvanCloudHTTPTimeout = 30 * time.Second

	// arvanCloudMaxBody caps how much of a response is read. A response body is
	// attacker-influenced input; without a cap a hostile or broken endpoint
	// could stream until the process runs out of memory.
	arvanCloudMaxBody = 1 << 20

	// arvanCloudListPerPage bounds one page of a record listing. The listing is
	// narrowed to the challenge name by the search term, so the set is one or two
	// records; this only ensures a single request suffices.
	arvanCloudListPerPage = 100
)

// ErrArvanCloudAPI is returned when the ArvanCloud API refuses a request or
// answers unusably. It never carries the API key — see [arvanCloudProvider].
var ErrArvanCloudAPI = errors.New("dns01: arvancloud api")

// arvanCloudProvider creates and removes the challenge TXT record through
// ArvanCloud's CDN 4.0 DNS API.
//
// # Key custody
//
// ArvanCloud authenticates with a single API key sent verbatim in the
// Authorization header (documented form "Apikey <key>"), which fits the seam's
// one-credential shape directly. The key is held as a [secrets.Redacted] and is
// unwrapped in exactly ONE place, [arvanCloudProvider.do], directly into the
// Authorization header of an outbound request. Consequences, mirroring the other
// single-token providers:
//
//   - This struct implements [fmt.Formatter], so no formatting of it can print
//     the key. That method is required, not decorative: secrets.Redacted's own
//     redaction is bypassed by fmt when the value sits in an UNEXPORTED struct
//     field, because fmt renders such fields by raw reflection and never calls
//     their String, Format or GoString methods.
//   - The type holds no logger and no telemetry handle, so there is no local
//     call site that could emit it.
//   - Errors are built from the record name and ArvanCloud's own status and
//     message. The request is never rendered into an error, because a rendered
//     *http.Request includes its Authorization header.
//
// # Why cleanup resolves the record by VALUE rather than capturing the create ID
//
// ArvanCloud returns a UUID for each record, so a capture-the-ID cleanup was the
// starting point. It is not what this provider does, for one reason: the seam
// requires a usable cleanup back even when Present goes on to FAIL (see
// [Provider]), and on the create path the only failure that matters is the one
// where no ID came back. A create whose response is lost to a timeout or a reset
// connection leaves the record standing at ArvanCloud with this process holding
// no ID for it. A cleanup that can only delete a captured ID is therefore nil
// exactly when it is needed — the leaked standing _acme-challenge record the
// contract exists to prevent.
//
// So the closure captures the domain, the relative record name and the VALUE —
// all known before the write — and resolves the ID at cleanup time by listing
// the TXT records at that name and matching on the exact value. Deletion is
// still by ID; only the ID's discovery moved. The scoping guarantee rests on the
// value being unforgeable: it is the base64url SHA-256 digest of a key
// authorization computed from this process's ACCOUNT KEY, so no other party's
// record can carry it. Cleanup therefore removes the exact value this process
// published and cannot remove a record it did not create — including an
// operator's own TXT record at the same name, and including the OTHER challenge
// of a wildcard order, which sits at the same name with a different digest.
//
// # Propagation
//
// Present does not wait for the record to be served. The seam forbids a
// provider-side wait: the solver polls the zone's authoritative nameservers
// once, for every provider, which is a strictly stronger signal than any
// "change applied" flag the vendor could return.
type arvanCloudProvider struct {
	token  secrets.Redacted
	client *http.Client
}

var _ Provider = (*arvanCloudProvider)(nil)

// NewArvanCloud builds the provider. A nil client gets a bounded default; the
// parameter exists so a test can supply a transport pointed at a local fake and
// so an operator's proxy settings can be honored later.
func NewArvanCloud(creds Credentials, client *http.Client) (Provider, error) {
	// One value authenticates ArvanCloud; an empty or multi-value set yields
	// ok=false and is refused rather than guessed at. Fail closed.
	token, ok := creds.Single()
	if !ok {
		return nil, fmt.Errorf("%w: no api key credential", ErrArvanCloudAPI)
	}
	// The blank check asks the WRAPPED value rather than revealing it, exactly as
	// the other providers do, so this file keeps a single plaintext-unwrap site.
	// Whitespace-only counts as blank: it is not a credential. Refused at
	// construction, where the operator sees it, rather than at the first renewal
	// months later.
	if token.IsBlank() {
		return nil, fmt.Errorf("%w: blank api key (empty or whitespace only)", ErrArvanCloudAPI)
	}
	if client == nil {
		client = &http.Client{
			Timeout: arvanCloudHTTPTimeout,
			// Redirects are REFUSED rather than followed. Following one would send a
			// request carrying the zone-editing key to whatever host the response
			// named; net/http strips Authorization across origins, but a same-origin
			// redirect to an unexpected path would still be followed, and no
			// legitimate ArvanCloud API call redirects.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}
	return &arvanCloudProvider{token: token, client: client}, nil
}

// Name identifies the provider. It is a constant, never derived from the key.
func (p *arvanCloudProvider) Name() string { return "arvancloud" }

// Format renders the provider as a constant under every fmt verb, so no
// formatting of this value can print the key.
//
// See the type comment: this is load-bearing. Without it, "%+v" of this struct
// prints the API key in full, because fmt walks unexported fields by reflection
// and never calls their redaction methods. "%#v" routes through Formatter too
// when the operand implements it.
func (p *arvanCloudProvider) Format(f fmt.State, _ rune) {
	_, _ = io.WriteString(f, "dns01.arvanCloudProvider{token:[REDACTED]}")
}

// Present publishes the challenge value and returns the cleanup that withdraws
// exactly that value.
func (p *arvanCloudProvider) Present(ctx context.Context, rec Record) (CleanupFunc, error) {
	domain, err := p.domainFor(ctx, rec.Name)
	if err != nil {
		return nil, err
	}
	// The name is RELATIVE to the domain. ArvanCloud, like DigitalOcean, treats
	// an unsuffixed name as a subdomain prefix, so sending the FQDN would create
	// "_acme-challenge.example.com.example.com" — a record the API accepts, that
	// reaches the zone, and that no CA ever queries. The label-boundary split is
	// the shared [relativeRecordName].
	relative, err := relativeRecordName(rec.Name, domain)
	if err != nil {
		return nil, err
	}

	// The type is the lowercase "txt" ArvanCloud stores, the name is relative, and
	// the value is the nested {"text":...} object the API requires.
	body, err := json.Marshal(map[string]any{
		"type":  "txt",
		"name":  relative,
		"value": arvanTXTValue{Text: rec.Value},
		"ttl":   arvanCloudChallengeTTL,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: encode record: %w", ErrArvanCloudAPI, err)
	}

	// The cleanup is built BEFORE the write and returned even when the write
	// reports failure, because a failed write can still have applied: a response
	// lost to a timeout or a reset connection leaves the record created at
	// ArvanCloud with nothing here knowing its ID. Returning nil in that case
	// leaks a standing _acme-challenge TXT record that no code path can withdraw —
	// the seam's contract in dns01.go is explicit that a cleanup MUST come back
	// whenever anything may have been created.
	//
	// Returning it early is safe because the closure captures only the domain, the
	// relative name and the value — all known before the call — and nothing from
	// the response. And returning it when the write genuinely never applied is
	// harmless: the closure's first act is a read, and finding its value absent it
	// returns success without issuing any delete.
	cleanup := p.removeValue(domain, relative, rec.Value)

	if err := p.do(ctx, http.MethodPost, p.recordsPath(domain), body, nil); err != nil {
		return cleanup, fmt.Errorf("%w: create txt record for %q: %w", ErrArvanCloudAPI, rec.Name, err)
	}
	return cleanup, nil
}

// removeValue returns the cleanup closure for one published value.
//
// The domain, the relative record name and the exact value are CAPTURED. The
// closure lists the TXT records at that one name and deletes only the record
// whose value equals the captured value — no input to it can widen that, and it
// can never remove a value this process did not publish.
func (p *arvanCloudProvider) removeValue(domain, relative, value string) CleanupFunc {
	return func(ctx context.Context) error {
		id, found, err := p.findRecord(ctx, domain, relative, value)
		if err != nil {
			return fmt.Errorf("%w: find txt record for cleanup: %w", ErrArvanCloudAPI, err)
		}
		if !found {
			// Already gone is success. Cleanup runs on retry and shutdown paths, so
			// it must be idempotent, and the zone is already in the state this call
			// wanted to reach. This is also the path a cleanup returned from a
			// genuinely failed publish takes: nothing was created, so nothing is
			// deleted and no destructive request is issued.
			return nil
		}

		path := p.recordsPath(domain) + "/" + url.PathEscape(id)
		err = p.do(ctx, http.MethodDelete, path, nil, nil)
		if err == nil || errors.Is(err, errArvanCloudNotFound) {
			return nil
		}
		return fmt.Errorf("%w: delete txt record: %w", ErrArvanCloudAPI, err)
	}
}

// findRecord returns the ID of the TXT record at relative whose text is value.
//
// Every element of the match is re-checked in code rather than delegated to the
// API's search filter. The search term is a query parameter on a remote service:
// if it were ignored, mishandled, or answered by something impersonating the
// API, an unchecked caller would delete whatever record happened to come back
// first. The three checks below — type, name, and exact value — are what make
// this a lookup for one specific published value rather than a name-to-records
// primitive.
func (p *arvanCloudProvider) findRecord(ctx context.Context, domain, relative, value string) (string, bool, error) {
	// The search narrows the listing to the challenge name so a single page
	// suffices. Underscores are stripped from the term because ArvanCloud's search
	// does not match them; the record's real name is re-checked below, so an
	// over- or under-matching search cannot select the wrong record.
	query := fmt.Sprintf("?search=%s&per_page=%d",
		url.QueryEscape(strings.ReplaceAll(relative, "_", "")), arvanCloudListPerPage)
	var out arvanRecordsResponse
	if err := p.do(ctx, http.MethodGet, p.recordsPath(domain)+query, nil, &out); err != nil {
		if errors.Is(err, errArvanCloudNotFound) {
			// The domain or the record set is gone entirely; nothing to remove.
			return "", false, nil
		}
		return "", false, fmt.Errorf("list txt records for %q: %w", relative, err)
	}

	for _, r := range out.Data {
		if !strings.EqualFold(r.Type, "txt") {
			continue
		}
		if !strings.EqualFold(strings.TrimSuffix(r.Name, "."), relative) {
			continue
		}
		// The value lives in a nested object and is decoded only for TXT records:
		// other record types carry differently shaped values, so the raw form is
		// kept until the type is known.
		var v arvanTXTValue
		if err := json.Unmarshal(r.Value, &v); err != nil {
			continue
		}
		if v.Text != value {
			// The value check is what keeps a wildcard order's two challenges apart:
			// both sit at this exact name with different digests, and removing the
			// wrong one would revoke a challenge still in flight.
			continue
		}
		if r.ID == "" {
			return "", false, fmt.Errorf("record at %q has no usable id", relative)
		}
		return r.ID, true, nil
	}
	return "", false, nil
}

// domainFor finds the ArvanCloud domain that holds the record name.
//
// Candidate suffixes are tried most-specific-first, exactly as the other
// providers do, so a delegated "eu.example.com" wins over its parent
// "example.com" — writing to the parent would put the record in a zone that is
// not authoritative for the name.
//
// A domain name is the API's own path key, so a request under
// /domains/{name}/dns-records answers for exactly that domain or 404s; an
// account cannot hold two domains with the same name for this to choose between.
// DigitalOcean additionally confirms the domain NAME echoed in the response; the
// listing endpoint used here carries no domain name to confirm, so the guarantee
// "a redirected or impersonated answer cannot substitute a different domain" is
// held instead by the two properties already in force: the base URL is a
// constant and redirects are REFUSED, so no response can come from another host
// or path than the one this exact domain was interpolated into. What CAN happen
// is that none of the candidates is in the account, and that REFUSES loudly
// rather than guessing: the alternative is writing the challenge into some other
// domain, which succeeds at the API level and is never seen by the CA.
//
// A domain absent from the account answers 404 (not 403), so only a 404 advances
// the walk to the parent; any other error aborts it rather than masking a
// permission or outage fault as "no domain found".
func (p *arvanCloudProvider) domainFor(ctx context.Context, recordName string) (string, error) {
	name := strings.TrimSuffix(recordName, ".")

	for range maxZoneLabels {
		idx := strings.IndexByte(name, '.')
		if idx < 0 {
			break
		}
		name = name[idx+1:]
		if !strings.Contains(name, ".") {
			// A single label is a TLD; no account holds a domain there and querying
			// it only spends an API call.
			break
		}
		if !validDomainName(name) {
			// A candidate that is not a plain domain name is not interpolated into a
			// request path. The candidate is derived from the record name, which comes
			// from the certificate request, so this is the check that stops a crafted
			// identifier from steering a credentialed request at another API resource.
			return "", fmt.Errorf("%w: malformed domain candidate for %q", ErrArvanCloudAPI, recordName)
		}

		err := p.do(ctx, http.MethodGet, p.recordsPath(name)+"?per_page=1", nil, nil)
		if errors.Is(err, errArvanCloudNotFound) {
			continue
		}
		if err != nil {
			return "", fmt.Errorf("%w: look up domain %q: %w", ErrArvanCloudAPI, name, err)
		}
		return name, nil
	}
	return "", fmt.Errorf("%w: no domain found for %q", ErrArvanCloudAPI, recordName)
}

// recordsPath builds the dns-records path for one domain. The domain has already
// been validated as a plain domain name, so it cannot escape the path.
func (p *arvanCloudProvider) recordsPath(domain string) string {
	return "/domains/" + url.PathEscape(domain) + "/dns-records"
}

// errArvanCloudNotFound marks a 404, so cleanup can treat an already-removed
// record as done and the domain walk can treat a miss as "try the parent".
var errArvanCloudNotFound = errors.New("resource not found")

// do performs one API call and decodes its result.
//
// This is the ONLY function in the file that reveals the key, and it does so
// straight into a request header that is never logged, never stored, and never
// rendered into an error.
func (p *arvanCloudProvider) do(ctx context.Context, method, path string, body []byte, out any) error {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, arvanCloudAPIBase+path, reader)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	// Trimmed at the point of use: a file-backed secret provider commonly yields a
	// trailing newline, and a newline in a header VALUE is a header-injection
	// shape. net/http rejects it rather than sending it, so the failure would be
	// safe but opaque; trimming here makes the common case work and keeps the
	// control characters out of the request either way. The documented header form
	// is "Apikey <key>", so the stored credential is the bare key.
	req.Header.Set("Authorization", "Apikey "+strings.TrimSpace(p.token.Reveal()))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		// The transport error is wrapped as-is. url.Error renders the request URL,
		// which carries no credential: the key travels in a header, and the path
		// holds only a domain and a record ID.
		return fmt.Errorf("request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, arvanCloudMaxBody))
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode == http.StatusNotFound {
		return errArvanCloudNotFound
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return arvanCloudError(resp.StatusCode, raw)
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

// arvanCloudError renders the API's own error, using only its structured
// message.
//
// The message is truncated because it is remote input, treated as a bounded
// diagnostic rather than as trusted text. The bound goes through [safetext.Bound]
// rather than a slice expression: a fixed BYTE cut can land in the middle of a
// multi-byte UTF-8 sequence and leave a fragment that is not valid UTF-8, which
// the JSON log encoder downstream then mangles. No credential is spliced into
// this message before the cut.
func arvanCloudError(status int, raw []byte) error {
	var env arvanErrorResponse
	if err := json.Unmarshal(raw, &env); err != nil || env.Message == "" {
		return fmt.Errorf("request rejected (http %d)", status)
	}
	msg := safetext.Bound(env.Message, maxAPIMessageBytes)
	return fmt.Errorf("request rejected (http %d): %s", status, msg)
}

// The JSON shapes below are the subset of the CDN 4.0 API this provider uses.
// Only the fields actually read are declared; encoding/json ignores the rest.

// arvanTXTValue is the nested value object of a TXT record: {"text":"..."}. It
// is the create payload's value field and the decode target for a listed record
// once its type is confirmed to be TXT.
type arvanTXTValue struct {
	Text string `json:"text"`
}

// arvanRecordsResponse is the listing envelope. The value is kept raw because it
// is shaped differently per record type and is decoded only once the type is
// confirmed to be TXT.
type arvanRecordsResponse struct {
	Data []struct {
		ID    string          `json:"id"`
		Type  string          `json:"type"`
		Name  string          `json:"name"`
		Value json.RawMessage `json:"value"`
	} `json:"data"`
}

type arvanErrorResponse struct {
	Message string `json:"message"`
}
