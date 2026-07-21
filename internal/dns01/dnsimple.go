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
	"sync"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/safetext"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/secrets"
)

const (
	// dnsimpleAPIBase is the v2 API root. It is a constant rather than
	// configurable, for the same reason Cloudflare's, Route 53's and
	// DigitalOcean's are: a settable endpoint is a way to point the
	// highest-privilege credential this process holds at an attacker's server.
	dnsimpleAPIBase = "https://api.dnsimple.com/v2"

	// dnsimpleChallengeTTL is the TTL on the challenge record. DNSimple's schema
	// declares no floor above zero, so this is our choice rather than the API's
	// minimum: low is what we want, because the record is deleted minutes later
	// and a long TTL would keep resolvers serving a challenge answer after the
	// authorization it belonged to is gone.
	dnsimpleChallengeTTL = 60

	// dnsimpleHTTPTimeout bounds one API call.
	dnsimpleHTTPTimeout = 30 * time.Second

	// dnsimpleMaxBody caps how much of a response is read. A response body is
	// attacker-influenced input; without a cap a hostile or broken endpoint could
	// stream until the process runs out of memory.
	dnsimpleMaxBody = 1 << 20

	// dnsimpleListPerPage bounds one page of a record listing. DNSimple documents
	// 100 as the maximum. The listing is filtered to one name and type, so the
	// challenge set is one or two records; this only ensures a single request
	// suffices.
	dnsimpleListPerPage = 100
)

// ErrDNSimpleAPI is returned when the DNSimple API refuses a request or answers
// unusably. It never carries the API token — see [dnsimpleProvider].
var ErrDNSimpleAPI = errors.New("dns01: dnsimple api")

// dnsimpleProvider creates and removes the challenge TXT record through
// DNSimple's v2 API.
//
// # Token custody
//
// DNSimple authenticates with a single OAuth-style bearer token, which fits the
// seam's one-credential shape directly — no packing, unlike Route 53. The token
// is held as a [secrets.Redacted] and is unwrapped in exactly ONE place,
// [dnsimpleProvider.do], directly into the Authorization header of an outbound
// request. Consequences, mirroring the other three providers:
//
//   - This struct implements [fmt.Formatter], so no formatting of it can print
//     the token. That method is required, not decorative: secrets.Redacted's own
//     redaction is bypassed by fmt when the value sits in an UNEXPORTED struct
//     field, because fmt renders such fields by raw reflection and never calls
//     their String, Format or GoString methods.
//   - The type holds no logger and no telemetry handle, so there is no local
//     call site that could emit it.
//   - Errors are built from the record name and DNSimple's own status and
//     message. The request is never rendered into an error, because a rendered
//     *http.Request includes its Authorization header.
//
// # Why cleanup resolves the record by VALUE rather than capturing the create ID
//
// DNSimple has per-record integer IDs, so Cloudflare's capture-the-ID shape is
// available. It is not what this provider does, and the reason is the one
// DigitalOcean established on this seam: the contract requires a usable cleanup
// back even when Present goes on to FAIL (see [Provider]), and on the create
// path the failure that matters is the one where no ID came back. A create whose
// response is lost to a timeout or a reset connection leaves the record standing
// at DNSimple with this process holding no ID for it. A cleanup that can only
// delete a captured ID is therefore nil exactly when it is needed, which is the
// leaked standing _acme-challenge record the contract exists to prevent.
//
// So the closure captures the account, the zone, the relative record name and
// the VALUE — all known before the write — and resolves the ID at cleanup time
// by listing the TXT records at that name and matching on the exact value.
// Deletion is still by ID; only the ID's discovery moved. The scoping guarantee
// rests on the value being unforgeable: it is the base64url SHA-256 digest of a
// key authorization computed from this process's ACCOUNT KEY, so no other
// party's record can carry it. Cleanup therefore removes the exact value this
// process published and cannot remove a record it did not create — including an
// operator's own TXT record at the same name, and including the OTHER challenge
// of a wildcard order, which sits at the same name with a different digest.
//
// # Propagation
//
// Present does not wait for the record to be served. The seam forbids a
// provider-side wait: the solver polls the zone's authoritative nameservers
// once, for every provider, which is a strictly stronger signal than any
// "change applied" flag a vendor could return.
type dnsimpleProvider struct {
	token  secrets.Redacted
	client *http.Client

	// mu guards accountID. The provider is shared across concurrent issuances,
	// and the account id is resolved lazily on the first Present.
	mu sync.Mutex
	// accountID is the numeric account the token belongs to, cached after a
	// successful whoami. Zero means "not resolved yet".
	accountID int64
}

var _ Provider = (*dnsimpleProvider)(nil)

// NewDNSimple builds the provider. A nil client gets a bounded default; the
// parameter exists so a test can supply a transport pointed at a local fake and
// so an operator's proxy settings can be honored later.
func NewDNSimple(creds Credentials, client *http.Client) (Provider, error) {
	// One value authenticates DNSimple; an empty or multi-value set yields
	// ok=false and is refused rather than guessed at. Fail closed.
	token, ok := creds.Single()
	if !ok {
		return nil, fmt.Errorf("%w: no api token credential", ErrDNSimpleAPI)
	}
	// The blank check asks the WRAPPED value rather than revealing it, exactly
	// as the Cloudflare and DigitalOcean constructors do, so this file keeps a
	// single plaintext-unwrap site. Whitespace-only counts as blank: it is not a
	// credential. Refused at construction, where the operator sees it, rather
	// than at the first renewal months later.
	if token.IsBlank() {
		return nil, fmt.Errorf("%w: blank api token (empty or whitespace only)", ErrDNSimpleAPI)
	}
	if client == nil {
		client = &http.Client{
			Timeout: dnsimpleHTTPTimeout,
			// Redirects are REFUSED rather than followed. Following one would send
			// a request carrying the zone-editing token to whatever host the
			// response named; net/http strips Authorization across origins, but a
			// same-origin redirect to an unexpected path would still be followed,
			// and no legitimate DNSimple API call redirects.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}
	return &dnsimpleProvider{token: token, client: client}, nil
}

// Name identifies the provider. It is a constant, never derived from the token.
func (p *dnsimpleProvider) Name() string { return "dnsimple" }

// Format renders the provider as a constant under every fmt verb, so no
// formatting of this value can print the token.
//
// See the type comment: this is load-bearing. Without it, "%+v" of this struct
// prints the bearer token in full, because fmt walks unexported fields by
// reflection and never calls their redaction methods. "%#v" routes through
// Formatter too when the operand implements it.
func (p *dnsimpleProvider) Format(f fmt.State, _ rune) {
	_, _ = io.WriteString(f, "dns01.dnsimpleProvider{token:[REDACTED]}")
}

// Present publishes the challenge value and returns the cleanup that withdraws
// exactly that value.
func (p *dnsimpleProvider) Present(ctx context.Context, rec Record) (CleanupFunc, error) {
	account, err := p.account(ctx)
	if err != nil {
		return nil, err
	}
	zone, err := p.zoneFor(ctx, account, rec.Name)
	if err != nil {
		return nil, err
	}
	relative, err := dnsimpleRecordName(rec.Name, zone)
	if err != nil {
		return nil, err
	}

	body, err := json.Marshal(map[string]any{
		"type": "TXT",
		// The name is RELATIVE to the zone. DNSimple documents this field as
		// "the record name, without the domain. The domain will be automatically
		// appended", so sending the FQDN here would create
		// "_acme-challenge.example.com.example.com" — a record the API accepts,
		// that reaches the zone, and that no CA ever queries.
		"name": relative,
		// TXT content is "content" on this API. It is NOT DigitalOcean's "data":
		// an unrecognized field is ignored rather than rejected, so getting this
		// wrong creates an empty TXT record and reports success.
		"content": rec.Value,
		"ttl":     dnsimpleChallengeTTL,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: encode record: %w", ErrDNSimpleAPI, err)
	}

	// The cleanup is built BEFORE the write and returned even when the write
	// reports failure, because a failed write can still have applied: a response
	// lost to a timeout or a reset connection leaves the record created at
	// DNSimple with nothing here knowing its ID. Returning nil in that case leaks
	// a standing _acme-challenge TXT record that no code path can withdraw — the
	// seam's contract in dns01.go is explicit that a cleanup MUST come back
	// whenever anything may have been created, including when Present goes on to
	// fail, and the solver registers it on exactly that path.
	//
	// Returning it early is safe because the closure captures only the account,
	// the zone, the relative name and the value — all known before the call — and
	// nothing from the response. And returning it when the write genuinely never
	// applied is harmless: the closure's first act is a read, and finding its
	// value absent it returns success without issuing any delete. So the
	// pessimistic case costs one GET and cannot disturb a concurrent challenge at
	// the same name.
	cleanup := p.removeValue(account, zone, relative, rec.Value)

	path := dnsimpleZonePath(account, zone) + "/records"
	if err := p.do(ctx, http.MethodPost, path, body, nil); err != nil {
		return cleanup, fmt.Errorf("%w: create txt record for %q: %w", ErrDNSimpleAPI, rec.Name, err)
	}
	return cleanup, nil
}

// removeValue returns the cleanup closure for one published value.
//
// The account, the zone, the relative record name and the exact value are
// CAPTURED. The closure lists the TXT records at that one name and deletes only
// the record whose content equals the captured value — no input to it can widen
// that, and it can never remove a value this process did not publish.
func (p *dnsimpleProvider) removeValue(account int64, zone, relative, value string) CleanupFunc {
	return func(ctx context.Context) error {
		id, found, err := p.findRecord(ctx, account, zone, relative, value)
		if err != nil {
			return fmt.Errorf("%w: find txt record for cleanup: %w", ErrDNSimpleAPI, err)
		}
		if !found {
			// Already gone is success. Cleanup runs on retry and shutdown paths,
			// so it must be idempotent, and the zone is already in the state this
			// call wanted to reach. This is also the path a cleanup returned from
			// a genuinely failed publish takes: nothing was created, so nothing is
			// deleted and no destructive request is issued.
			return nil
		}

		path := dnsimpleZonePath(account, zone) + "/records/" + strconv.FormatInt(id, 10)
		err = p.do(ctx, http.MethodDelete, path, nil, nil)
		if err == nil || errors.Is(err, errDNSimpleNotFound) {
			return nil
		}
		return fmt.Errorf("%w: delete txt record: %w", ErrDNSimpleAPI, err)
	}
}

// findRecord returns the ID of the TXT record at relative whose content is
// value.
//
// Every element of the match is re-checked in code rather than delegated to the
// API's filter. The name filter is a query parameter on a remote service: if it
// were ignored, mishandled, or answered by something impersonating the API, an
// unchecked caller would delete whatever record happened to come back first. The
// three checks below — name, type, and exact value — are what make this a lookup
// for one specific published value rather than a name-to-records primitive.
func (p *dnsimpleProvider) findRecord(ctx context.Context, account int64, zone, relative, value string) (int64, bool, error) {
	// DNSimple's "name" filter matches the record's own name field EXACTLY, and
	// that field is relative to the zone. Unlike DigitalOcean — whose filter
	// wants the FQDN while returned records carry the relative form — both sides
	// are relative here, so there is no asymmetry to work around.
	query := fmt.Sprintf("?type=TXT&name=%s&per_page=%d", url.QueryEscape(relative), dnsimpleListPerPage)
	var out dnsimpleRecordsResponse
	if err := p.do(ctx, http.MethodGet, dnsimpleZonePath(account, zone)+"/records"+query, nil, &out); err != nil {
		if errors.Is(err, errDNSimpleNotFound) {
			// The zone or the record set is gone entirely; nothing to remove.
			return 0, false, nil
		}
		return 0, false, fmt.Errorf("list txt records for %q: %w", relative, err)
	}

	for _, r := range out.Data {
		if !strings.EqualFold(r.Type, "TXT") {
			continue
		}
		if !strings.EqualFold(strings.TrimSuffix(r.Name, "."), relative) {
			continue
		}
		if dnsimpleTXTContent(r.Content) != value {
			// The value check is what keeps a wildcard order's two challenges
			// apart: both sit at this exact name with different digests, and
			// removing the wrong one would revoke a challenge still in flight.
			continue
		}
		if r.ID <= 0 {
			return 0, false, fmt.Errorf("record at %q has no usable id", relative)
		}
		return r.ID, true, nil
	}
	return 0, false, nil
}

// dnsimpleTXTContent normalizes a TXT record's content for comparison against
// the value this process published.
//
// The value is WRITTEN bare, matching every other provider on this seam and the
// unquoted form [Record] documents. DNSimple's reference does not state whether
// it stores a TXT value verbatim or normalizes it into the quoted presentation
// form DNS uses on the wire, so the read path tolerates one pair of surrounding
// double quotes.
//
// The tolerance is deliberately in the safe direction. If DNSimple does quote
// what it stores, an exact-only comparison would never match, cleanup would find
// nothing, and the challenge record would be LEAKED — the failure this whole
// provider is shaped to avoid. Accepting the quoted form cannot widen the match
// to a record this process did not create, because the digest inside the quotes
// is still the unforgeable one; it only recognizes the same value in the other
// spelling.
func dnsimpleTXTContent(content string) string {
	if len(content) >= 2 && content[0] == '"' && content[len(content)-1] == '"' {
		return content[1 : len(content)-1]
	}
	return content
}

// account returns the numeric account the token belongs to, resolving it once
// and caching it.
//
// # Why this is resolved from the token rather than configured
//
// Every zone and record path on this API is account-scoped
// ("/v2/{account}/zones/..."), so an account id is required to write anything.
// It is taken from /v2/whoami — which reports the account the PRESENTED TOKEN
// belongs to — rather than from configuration. That makes a cross-account
// misroute impossible by construction: there is no operator-supplied number that
// could name someone else's account, so the credential can only ever address its
// own resources. An id from config would be exactly that silent misroute, and it
// would fail as a 404 that reads like a missing zone.
//
// # Why lazily, and why only success is cached
//
// The seam's constructor takes no context and neither of the other API providers
// performs I/O in one, so resolving at construction would either hang startup on
// an unreachable API or need a background context. It is therefore resolved on
// the first Present, using that call's context. Only a SUCCESSFUL lookup is
// cached: caching a failure — as a sync.Once would — would turn one transient
// network fault at the first renewal into a provider that never works again.
//
// # Why the lock is not held across the request
//
// The whoami call runs with NO lock held, and the mutex is taken only to read
// the cache and to publish the result. Holding it across the request would let
// one slow or hung whoami block every other issuance on this provider — a
// network call inside a critical section is an availability fault on a seam
// whose whole job is renewing certificates before they expire.
//
// The cost is that callers racing the first resolution can each issue their own
// whoami. That is deliberate rather than overlooked:
//
//   - It is correctness-neutral. whoami is an idempotent GET, every racer
//     computes the same account for the same token, and the first write wins
//     while the losers return the winner's value, so the cache cannot disagree
//     with itself.
//   - The herd is bounded and tiny. DNS-01 runs a handful of concurrent
//     challenges per order, and only until the first result is published.
//   - singleflight would collapse the herd, but golang.org/x/sync is an INDIRECT
//     dependency here; importing it would promote it to a direct one and change
//     go.mod to save a few idempotent GETs. Hand-rolling the same thing would add
//     a second concurrency primitive to a path taken once per provider lifetime.
//
// Both refusals below return BEFORE the lock is retaken, so neither is ever
// cached as a success and both stay reachable on every call. That matters most
// for the user-token case: it must not become a one-shot error that a later call
// silently skips past.
func (p *dnsimpleProvider) account(ctx context.Context) (int64, error) {
	if id := p.cachedAccount(); id > 0 {
		return id, nil
	}

	var out dnsimpleWhoamiResponse
	if err := p.do(ctx, http.MethodGet, "/whoami", nil, &out); err != nil {
		return 0, fmt.Errorf("%w: resolve account: %w", ErrDNSimpleAPI, err)
	}
	if out.Data.Account == nil || out.Data.Account.ID <= 0 {
		// DNSimple issues both ACCOUNT tokens and USER tokens, and whoami returns
		// a null account for the latter — a user may belong to several accounts,
		// so there is no single account this token means. Refused loudly rather
		// than guessing one: picking an account would decide, on the program's own
		// initiative, which of the operator's accounts gets written to.
		return 0, fmt.Errorf("%w: token resolves to no account; DNS-01 needs an "+
			"account token, not a user token", ErrDNSimpleAPI)
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	if p.accountID == 0 {
		p.accountID = out.Data.Account.ID
	}
	// The winner's value is returned rather than this call's, so every racer
	// leaves with the id that is actually cached.
	return p.accountID, nil
}

// cachedAccount reads the resolved account, or zero if it is not resolved yet.
func (p *dnsimpleProvider) cachedAccount() int64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.accountID
}

// dnsimpleZonePath builds the account-scoped path for one zone. The account is a
// number this process received from whoami and the zone has already been
// validated as a plain domain name, so neither can escape the path.
func dnsimpleZonePath(account int64, zone string) string {
	return "/" + strconv.FormatInt(account, 10) + "/zones/" + url.PathEscape(zone)
}

// zoneFor finds the DNSimple zone that holds the record name.
//
// Candidate suffixes are tried most-specific-first, exactly as the Cloudflare,
// Route 53 and DigitalOcean providers do, so a delegated "eu.example.com" wins
// over its parent "example.com" — writing to the parent would put the record in
// a zone that is not authoritative for the name.
//
// Like DigitalOcean and unlike Route 53, there is no ambiguity to resolve. A
// zone name is the API's own path key, so GET /v2/{account}/zones/{name} answers
// with exactly one zone or 404; one account cannot hold two zones with the same
// name for this to have to choose between. (The same name CAN exist in a
// different account, which is precisely why the account is pinned from the token
// above rather than configured.) What CAN happen is that none of the candidates
// is in the account, and that REFUSES loudly rather than guessing: the
// alternative is writing the challenge into some other zone, which succeeds at
// the API level and is never seen by the CA, so issuance fails ten minutes later
// at the propagation gate with a message about DNS rather than about the
// account.
func (p *dnsimpleProvider) zoneFor(ctx context.Context, account int64, recordName string) (string, error) {
	name := strings.TrimSuffix(recordName, ".")

	for range maxZoneLabels {
		idx := strings.IndexByte(name, '.')
		if idx < 0 {
			break
		}
		name = name[idx+1:]
		if !strings.Contains(name, ".") {
			// A single label is a TLD; no account holds a zone there and querying
			// it only spends an API call.
			break
		}
		if !validDomainName(name) {
			// A candidate that is not a plain domain name is not interpolated into
			// a request path. The candidate is derived from the record name, which
			// comes from the certificate request, so this is the check that stops a
			// crafted identifier from steering a credentialed request at another API
			// resource.
			return "", fmt.Errorf("%w: malformed zone candidate for %q", ErrDNSimpleAPI, recordName)
		}

		var out dnsimpleZoneResponse
		err := p.do(ctx, http.MethodGet, dnsimpleZonePath(account, name), nil, &out)
		if errors.Is(err, errDNSimpleNotFound) {
			continue
		}
		if err != nil {
			return "", fmt.Errorf("%w: look up zone %q: %w", ErrDNSimpleAPI, name, err)
		}
		// The response's own name is confirmed to be the one asked for rather than
		// trusted, so a redirected or impersonated answer cannot substitute a
		// different zone for the one this lookup resolved.
		if !strings.EqualFold(strings.TrimSuffix(out.Data.Name, "."), name) {
			return "", fmt.Errorf("%w: zone lookup for %q answered for a different zone", ErrDNSimpleAPI, name)
		}
		return name, nil
	}
	return "", fmt.Errorf("%w: no zone found for %q", ErrDNSimpleAPI, recordName)
}

// dnsimpleRecordName converts the fully qualified record name into the form
// DNSimple stores, which is relative to the zone.
//
// The label-boundary split is shared with the DigitalOcean provider — the rule
// is the same and a second copy is a second thing to get wrong — but the APEX
// ENCODING differs and is translated here: DigitalOcean spells the apex "@",
// while DNSimple documents "an empty string to create a record for the apex".
// The apex is unreachable for an ACME challenge, whose name always carries the
// _acme-challenge label, but the difference is spelled out rather than left for
// a future caller to discover.
func dnsimpleRecordName(fqdn, zone string) (string, error) {
	relative, err := relativeRecordName(fqdn, zone)
	if err != nil {
		// Rewrapped so the error names DNSimple rather than the provider whose
		// file the shared helper happens to live in.
		return "", fmt.Errorf("%w: record %q is not inside zone %q", ErrDNSimpleAPI, fqdn, zone)
	}
	if relative == "@" {
		return "", nil
	}
	return relative, nil
}

// errDNSimpleNotFound marks a 404, so cleanup can treat an already-removed
// record as done and the zone walk can treat a miss as "try the parent".
var errDNSimpleNotFound = errors.New("resource not found")

// do performs one API call and decodes its result.
//
// This is the ONLY function in the file that reveals the token, and it does so
// straight into a request header that is never logged, never stored, and never
// rendered into an error.
func (p *dnsimpleProvider) do(ctx context.Context, method, path string, body []byte, out any) error {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, dnsimpleAPIBase+path, reader)
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
		// The transport error is wrapped as-is. url.Error renders the request URL,
		// which carries no credential: the token travels in a header, and the path
		// holds only an account number, a zone and a record name.
		return fmt.Errorf("request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, dnsimpleMaxBody))
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode == http.StatusNotFound {
		return errDNSimpleNotFound
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return dnsimpleError(resp.StatusCode, raw)
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

// dnsimpleError renders the API's own error, using only its message.
//
// The message is bounded because it is remote input, treated as a bounded
// diagnostic rather than as trusted text. DNSimple never echoes the bearer token
// in an error, and nothing here would put it there if it did. The per-field
// "errors" object is deliberately not rendered: it echoes submitted values, and
// this provider submits a record name and a challenge digest whose shape is not
// worth reflecting into a log.
//
// The bound goes through [safetext.Bound] rather than a slice expression: a
// fixed byte cut can land inside a multi-byte rune and leave invalid UTF-8 for
// the log encoder downstream to mangle. No credential is spliced into this
// message before the cut, so there is no scrub whose ordering against the
// truncation matters here.
func dnsimpleError(status int, raw []byte) error {
	var env dnsimpleErrorResponse
	if err := json.Unmarshal(raw, &env); err != nil || env.Message == "" {
		return fmt.Errorf("request rejected (http %d)", status)
	}
	msg := safetext.Bound(env.Message, maxAPIMessageBytes)
	return fmt.Errorf("request rejected (http %d): %s", status, msg)
}

// The JSON shapes below are the subset of the v2 API this provider uses. Only
// the fields actually read are declared; encoding/json ignores the rest.

// dnsimpleWhoamiResponse carries the identity behind the token. Account is a
// POINTER because DNSimple returns it as null for a user token, and that
// distinction is the refusal in [dnsimpleProvider.account] — a value type would
// silently read as account zero.
type dnsimpleWhoamiResponse struct {
	Data struct {
		Account *struct {
			ID int64 `json:"id"`
		} `json:"account"`
	} `json:"data"`
}

type dnsimpleZoneResponse struct {
	Data struct {
		Name string `json:"name"`
	} `json:"data"`
}

type dnsimpleRecordsResponse struct {
	Data []struct {
		ID      int64  `json:"id"`
		Type    string `json:"type"`
		Name    string `json:"name"`
		Content string `json:"content"`
	} `json:"data"`
}

type dnsimpleErrorResponse struct {
	Message string `json:"message"`
}
