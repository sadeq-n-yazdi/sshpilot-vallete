package dns01

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/hex"
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

// The wire protocol below is the OVHcloud API v1. It is confirmed against the
// current vendor reference:
//
//	https://api.ovh.com/  (endpoint console)
//	https://help.ovhcloud.com/csm/en-gb-api-getting-started-ovhcloud-api
//	https://github.com/ovh/go-ovh  (the request-signing scheme)
//
// # Why the request-signing scheme rather than a bearer token
//
// OVH does not authenticate with a single Authorization header. Every request
// carries four headers — the application key, the consumer key, a
// server-time-adjusted timestamp, and a SHA-1 signature over the request — so
// the credential is genuinely THREE distinct values plus a region, not one
// token. That is why this provider is built only from a named credential set
// (application_key, application_secret, consumer_key, and an optional endpoint),
// and refuses the single-value form the token providers use: there is no one
// value to accept.
const (
	// ovhSignaturePrefix is the version tag OVH prepends to the SHA-1 hex digest
	// in X-Ovh-Signature. It identifies the signing scheme; "$1$" is the only
	// scheme OVH defines and the only one this provider emits.
	ovhSignaturePrefix = "$1$"

	// ovhDefaultEndpoint is the region used when the operator supplies no
	// endpoint. EU is the default because it is OVH's original and most common
	// region; an operator on CA or US selects it explicitly.
	ovhDefaultEndpoint = "ovh-eu"

	// ovhChallengeTTL is the TTL on the challenge record. Low on purpose: the
	// record is deleted minutes later, and a long TTL would keep resolvers
	// serving a challenge answer after the authorization it belonged to is gone.
	ovhChallengeTTL = 60

	// ovhHTTPTimeout bounds one API call.
	ovhHTTPTimeout = 30 * time.Second

	// ovhMaxBody caps how much of a response is read. A response body is
	// attacker-influenced input; without a cap a hostile or broken endpoint
	// could stream until the process runs out of memory.
	ovhMaxBody = 1 << 20
)

// ovhEndpoints maps an operator-facing region name to the fixed API base URL for
// that region.
//
// It is an ALLOWLIST, not a settable base. OVH is genuinely multi-region — EU,
// CA and US are three separate control planes on two different domains — so
// unlike Cloudflare or Route 53 the base cannot be a single constant. But
// letting the operator supply an arbitrary URL would be the same hazard Route 53
// avoids by not having one: a settable endpoint is a way to point a zone-editing
// credential at an attacker's server. So the endpoint is chosen from this closed
// set by name, and any value not in it is refused at startup.
var ovhEndpoints = map[string]string{
	"ovh-eu": "https://eu.api.ovh.com/1.0",
	"ovh-ca": "https://ca.api.ovh.com/1.0",
	"ovh-us": "https://api.us.ovhcloud.com/1.0",
}

// ErrOVHAPI is returned when the OVH API refuses a request or answers unusably,
// and when the credential set is incomplete. It never carries any credential
// field — see [ovhProvider].
var ErrOVHAPI = errors.New("dns01: ovh api")

// ovhProvider creates and removes the challenge TXT record through the OVHcloud
// API v1.
//
// # Credential custody
//
// OVH needs three secret-shaped values. Unlike Route 53 they are NOT packed into
// one string: the application key and consumer key travel in cleartext request
// headers on every call, and only the application secret is truly secret and
// never transmitted (it is the SHA-1 signing key). Packing them would gain
// nothing and cost a split at every use, so each is held as its own
// [secrets.Redacted] and revealed at a small number of documented sites:
//
//   - applicationSecret is revealed ONLY in [ovhProvider.sign], into the SHA-1
//     computation whose output is a header — never sent, never logged.
//   - applicationKey and consumerKey are revealed ONLY in [ovhProvider.do],
//     directly into the X-Ovh-Application and X-Ovh-Consumer headers. They are
//     not secret in the confidentiality sense, but they are held redacted so a
//     "%+v" of this struct cannot print them and so there is one place each is
//     read.
//
// Consequences, mirroring the other providers:
//
//   - This struct implements [fmt.Formatter], so no formatting of it can print
//     any field. That method is required, not decorative: secrets.Redacted's own
//     redaction is bypassed by fmt when a value sits in an UNEXPORTED struct
//     field, because fmt renders such fields by raw reflection and never calls
//     their String, Format or GoString methods. With three secret fields the
//     leak surface of omitting it is larger, not smaller.
//   - The type holds no logger and no telemetry handle, so there is no local
//     call site that could emit a field.
//   - Errors are built from the record name and OVH's own status and message.
//     The request is never rendered into an error, because a rendered
//     *http.Request includes its signed headers.
//
// # Why cleanup resolves the record by VALUE rather than capturing the create ID
//
// OVH gives each record an integer ID, so capturing the create response's ID is
// available. It is not what this provider does, for the reason DNSimple and
// DigitalOcean established on this seam: the contract requires a usable cleanup
// back even when Present goes on to FAIL (see [Provider]), and a create whose
// response is lost to a timeout or a reset connection leaves the record standing
// at OVH with this process holding no ID for it. A cleanup that can only delete a
// captured ID would be nil exactly when it is needed.
//
// So the closure captures the zone, the relative subdomain and the VALUE — all
// known before the write — and at cleanup time lists the TXT record IDs at that
// subdomain, fetches each, and deletes the one whose target equals the captured
// value. The scoping guarantee rests on the value being unforgeable: it is the
// base64url SHA-256 digest of a key authorization computed from this process's
// ACCOUNT KEY, so no other party's record can carry it. Cleanup therefore removes
// the exact value this process published and cannot remove a record it did not
// create — including an operator's own TXT record at the same name, and including
// the OTHER challenge of a wildcard order, which sits at the same name with a
// different digest.
//
// # Why the zone is refreshed after every write
//
// OVH keeps a staging copy of a zone and does not serve edits until the zone is
// refreshed: POST /domain/zone/{zone}/refresh applies pending changes. A create
// or delete that is not followed by a refresh is accepted by the API, reports
// success, and is NEVER served — so the CA would query a name that does not yet
// carry the value, and issuance would time out at the propagation gate. So
// Present refreshes after creating, and cleanup refreshes after deleting.
//
// # Propagation
//
// Present does not wait for the record to be served. The seam forbids a
// provider-side wait: the solver polls the zone's authoritative nameservers
// once, for every provider, which is a strictly stronger signal than any
// "change applied" flag a vendor could return.
type ovhProvider struct {
	applicationKey    secrets.Redacted
	applicationSecret secrets.Redacted
	consumerKey       secrets.Redacted
	baseURL           string
	client            *http.Client

	// now is injectable so the signing timestamp is deterministic in tests. It
	// is not configurable at runtime.
	now func() time.Time

	// mu guards timeDelta/haveDelta. The provider is shared across concurrent
	// issuances, and the server-time delta is resolved lazily on the first call.
	mu sync.Mutex
	// timeDelta is (OVH server time − local time), added to the local clock when
	// stamping a request so a skewed local clock does not produce a timestamp OVH
	// rejects. haveDelta records whether it has been resolved, so a genuine zero
	// delta is not re-fetched forever.
	timeDelta int64
	haveDelta bool
}

var _ Provider = (*ovhProvider)(nil)

// NewOVH builds the provider from the named credential set.
//
// OVH is named-only: it needs application_key, application_secret and
// consumer_key, with an optional endpoint. A single credentials_ref cannot carry
// three distinct values, so the single form is refused with a message that names
// the required keys — never guessed at by splitting one value. Fail closed.
//
// Each required field is checked for blankness at construction, where the
// operator sees it, rather than at the first renewal months later. A nil client
// gets a bounded default; the parameter exists so a test can supply a transport
// pointed at a local fake and so an operator's proxy settings can be honored
// later.
func NewOVH(creds Credentials, client *http.Client) (Provider, error) {
	appKey, err := ovhRequiredField(creds, "application_key")
	if err != nil {
		return nil, err
	}
	appSecret, err := ovhRequiredField(creds, "application_secret")
	if err != nil {
		return nil, err
	}
	consumerKey, err := ovhRequiredField(creds, "consumer_key")
	if err != nil {
		return nil, err
	}

	baseURL, err := ovhBaseURL(creds)
	if err != nil {
		return nil, err
	}

	if client == nil {
		client = &http.Client{
			Timeout: ovhHTTPTimeout,
			// Redirects are REFUSED rather than followed. The signature is bound to
			// the exact method and full URL it was computed for, so a redirect
			// cannot replay it usefully — but following one would still send a
			// request carrying the application and consumer keys to whatever host
			// the response named, and no legitimate OVH API call redirects.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}
	return &ovhProvider{
		applicationKey:    appKey,
		applicationSecret: appSecret,
		consumerKey:       consumerKey,
		baseURL:           baseURL,
		client:            client,
		now:               time.Now,
	}, nil
}

// ovhRequiredField reads one required named credential and refuses a missing or
// blank value.
//
// The blank check asks the WRAPPED value rather than revealing it, exactly as
// the token providers' constructors do, so the plaintext is not unwrapped here.
// Whitespace-only counts as blank: it is not a credential. The error names the
// FIELD (which is operator config, not a secret) but never the value.
func ovhRequiredField(creds Credentials, field string) (secrets.Redacted, error) {
	v, ok := creds.Get(field)
	if !ok {
		return "", fmt.Errorf(
			"%w: missing %s; OVH needs credentials_refs with application_key, "+
				"application_secret and consumer_key", ErrOVHAPI, field)
	}
	if v.IsBlank() {
		return "", fmt.Errorf("%w: blank %s (empty or whitespace only)", ErrOVHAPI, field)
	}
	return v, nil
}

// ovhBaseURL resolves the region endpoint to its fixed API base URL.
//
// The endpoint is optional and defaults to EU. When supplied it must name one of
// the allowlisted regions; an unknown value is refused rather than used as a
// base URL, so a stray or hostile value cannot steer the credentialed requests
// at another host. The endpoint is a region label, not a secret, so an unknown
// value is echoed to help the operator fix it.
func ovhBaseURL(creds Credentials) (string, error) {
	name := ovhDefaultEndpoint
	if v, ok := creds.Get("endpoint"); ok && !v.IsBlank() {
		name = strings.TrimSpace(v.Reveal())
	}
	base, ok := ovhEndpoints[name]
	if !ok {
		return "", fmt.Errorf("%w: unknown endpoint %q; use one of ovh-eu, ovh-ca, ovh-us", ErrOVHAPI, name)
	}
	return base, nil
}

// Name identifies the provider. It is a constant, never derived from a
// credential.
func (p *ovhProvider) Name() string { return "ovh" }

// Format renders the provider as a constant under every fmt verb, so no
// formatting of this value can print any credential field.
//
// See the type comment: this is load-bearing. Without it, "%+v" of this struct
// prints all three credential fields in full, because fmt walks unexported
// fields by reflection and never calls their redaction methods. "%#v" routes
// through Formatter too when the operand implements it.
func (p *ovhProvider) Format(f fmt.State, _ rune) {
	_, _ = io.WriteString(f, "dns01.ovhProvider{application_key:[REDACTED], application_secret:[REDACTED], consumer_key:[REDACTED]}")
}

// Present publishes the challenge value and returns the cleanup that withdraws
// exactly that value.
func (p *ovhProvider) Present(ctx context.Context, rec Record) (CleanupFunc, error) {
	zone, err := p.zoneFor(ctx, rec.Name)
	if err != nil {
		return nil, err
	}
	subDomain, err := ovhRecordName(rec.Name, zone)
	if err != nil {
		return nil, err
	}

	body, err := json.Marshal(ovhRecordCreate{
		FieldType: "TXT",
		// The subDomain is RELATIVE to the zone. OVH appends the zone itself, so
		// sending the FQDN here would create "_acme-challenge.example.com.example.com"
		// — a record the API accepts, that reaches the zone, and that no CA ever
		// queries.
		SubDomain: subDomain,
		Target:    rec.Value,
		TTL:       ovhChallengeTTL,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: encode record: %w", ErrOVHAPI, err)
	}

	// The cleanup is built BEFORE the write and returned even when the write
	// reports failure, because a failed write can still have applied: a response
	// lost to a timeout or a reset connection leaves the record created at OVH
	// with nothing here knowing its ID. Returning nil in that case leaks a
	// standing _acme-challenge TXT record that no code path can withdraw — the
	// seam's contract in dns01.go is explicit that a cleanup MUST come back
	// whenever anything may have been created, including when Present goes on to
	// fail, and the solver registers it on exactly that path.
	//
	// Returning it early is safe because the closure captures only the zone, the
	// relative subdomain and the value — all known before the call — and nothing
	// from the response. And returning it when the write genuinely never applied
	// is harmless: the closure's first act is a read, and finding its value absent
	// it returns success without issuing any delete.
	cleanup := p.removeValue(zone, subDomain, rec.Value)

	if err := p.do(ctx, http.MethodPost, p.zonePath(zone)+"/record", body, nil); err != nil {
		return cleanup, fmt.Errorf("%w: create txt record for %q: %w", ErrOVHAPI, rec.Name, err)
	}
	// OVH does not serve the new record until the zone is refreshed. A create
	// without this refresh reports success and is never seen by the CA.
	if err := p.refresh(ctx, zone); err != nil {
		return cleanup, fmt.Errorf("%w: refresh zone for %q: %w", ErrOVHAPI, rec.Name, err)
	}
	return cleanup, nil
}

// removeValue returns the cleanup closure for one published value.
//
// The zone, the relative subdomain and the exact value are CAPTURED. The closure
// lists the TXT record IDs at that subdomain, fetches each, and deletes only the
// record whose target equals the captured value — no input to it can widen that,
// and it can never remove a value this process did not publish. The zone is
// refreshed only when a record was actually deleted.
func (p *ovhProvider) removeValue(zone, subDomain, value string) CleanupFunc {
	return func(ctx context.Context) error {
		id, found, err := p.findRecord(ctx, zone, subDomain, value)
		if err != nil {
			return fmt.Errorf("%w: find txt record for cleanup: %w", ErrOVHAPI, err)
		}
		if !found {
			// Already gone is success. Cleanup runs on retry and shutdown paths,
			// so it must be idempotent, and the zone is already in the state this
			// call wanted to reach. This is also the path a cleanup returned from a
			// genuinely failed publish takes: nothing was created, so nothing is
			// deleted, no refresh is issued, and no destructive request is made.
			return nil
		}

		path := p.zonePath(zone) + "/record/" + strconv.FormatInt(id, 10)
		err = p.do(ctx, http.MethodDelete, path, nil, nil)
		if err != nil && !errors.Is(err, errOVHNotFound) {
			return fmt.Errorf("%w: delete txt record: %w", ErrOVHAPI, err)
		}
		// The delete only edits the staging zone; the change is not served until a
		// refresh, exactly like the create.
		if err := p.refresh(ctx, zone); err != nil {
			return fmt.Errorf("%w: refresh zone after cleanup: %w", ErrOVHAPI, err)
		}
		return nil
	}
}

// findRecord returns the ID of the TXT record at subDomain whose target is
// value.
//
// OVH's listing returns only IDs, so each candidate is fetched and its target,
// type and subdomain re-checked in code rather than trusted from the filter. The
// value check is what keeps a wildcard order's two challenges apart: both sit at
// this exact name with different digests, and removing the wrong one would revoke
// a challenge still in flight.
func (p *ovhProvider) findRecord(ctx context.Context, zone, subDomain, value string) (int64, bool, error) {
	query := "?fieldType=TXT&subDomain=" + url.QueryEscape(subDomain)
	var ids []int64
	if err := p.do(ctx, http.MethodGet, p.zonePath(zone)+"/record"+query, nil, &ids); err != nil {
		if errors.Is(err, errOVHNotFound) {
			// The zone or the record set is gone entirely; nothing to remove.
			return 0, false, nil
		}
		return 0, false, fmt.Errorf("list txt records for %q: %w", subDomain, err)
	}

	for _, id := range ids {
		var r ovhRecord
		err := p.do(ctx, http.MethodGet, p.zonePath(zone)+"/record/"+strconv.FormatInt(id, 10), nil, &r)
		if errors.Is(err, errOVHNotFound) {
			// The record vanished between the listing and this read; skip it.
			continue
		}
		if err != nil {
			return 0, false, fmt.Errorf("read txt record %d: %w", id, err)
		}
		if !strings.EqualFold(r.FieldType, "TXT") {
			continue
		}
		if !strings.EqualFold(strings.TrimSuffix(r.SubDomain, "."), subDomain) {
			continue
		}
		if ovhTXTContent(r.Target) != value {
			continue
		}
		if r.ID <= 0 {
			r.ID = id
		}
		return r.ID, true, nil
	}
	return 0, false, nil
}

// ovhTXTContent normalizes a TXT record's target for comparison against the
// value this process published.
//
// The value is WRITTEN bare, matching every other provider on this seam and the
// unquoted form [Record] documents. OVH's reference does not state whether it
// stores a TXT target verbatim or in the quoted presentation form DNS uses on
// the wire, so the read path tolerates one pair of surrounding double quotes.
//
// The tolerance is deliberately in the safe direction. It can only recognize the
// SAME unforgeable digest in the other spelling, never widen the match to a value
// this process did not publish. The published value is always bare, so a value
// written by this provider is found either way.
func ovhTXTContent(target string) string {
	if len(target) >= 2 && target[0] == '"' && target[len(target)-1] == '"' {
		return target[1 : len(target)-1]
	}
	return target
}

// refresh applies the zone's pending changes so OVH begins serving them. It is
// called after every create and after every delete; see the type comment for
// why an unrefreshed change is never served.
func (p *ovhProvider) refresh(ctx context.Context, zone string) error {
	return p.do(ctx, http.MethodPost, p.zonePath(zone)+"/refresh", nil, nil)
}

// zoneFor finds the OVH zone that holds the record name.
//
// Candidate suffixes are tried most-specific-first, exactly as the other
// providers do, so a delegated "eu.example.com" wins over its parent
// "example.com" — writing to the parent would put the record in a zone that is
// not authoritative for the name.
//
// GET /domain/zone/{zone} answers 200 for a zone in the account and 404 for one
// that is not, so ONLY a 404 means "try the parent". Every other failure — a
// rejected credential, a 5xx — is surfaced, never swallowed as a miss. A zone
// name is the API's own path key, so there is no ambiguity to resolve as with
// Route 53's duplicate hosted zones; the only failure is that none of the
// candidates is in the account, which REFUSES loudly rather than guessing.
func (p *ovhProvider) zoneFor(ctx context.Context, recordName string) (string, error) {
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
			return "", fmt.Errorf("%w: malformed zone candidate for %q", ErrOVHAPI, recordName)
		}

		var out ovhZone
		err := p.do(ctx, http.MethodGet, p.zonePath(name), nil, &out)
		if errors.Is(err, errOVHNotFound) {
			continue
		}
		if err != nil {
			return "", fmt.Errorf("%w: look up zone %q: %w", ErrOVHAPI, name, err)
		}
		// The response's own name is confirmed to be the one asked for rather than
		// trusted, so a redirected or impersonated answer cannot substitute a
		// different zone for the one this lookup resolved. OVH echoes the zone in
		// the "name" field.
		if out.Name != "" && !strings.EqualFold(strings.TrimSuffix(out.Name, "."), name) {
			return "", fmt.Errorf("%w: zone lookup for %q answered for a different zone", ErrOVHAPI, name)
		}
		return name, nil
	}
	return "", fmt.Errorf("%w: no zone found for %q", ErrOVHAPI, recordName)
}

// zonePath builds the API path for one zone. The zone has already been validated
// as a plain domain name, so it cannot escape the path; it is escaped anyway so a
// stray byte splits nothing.
func (p *ovhProvider) zonePath(zone string) string {
	return "/domain/zone/" + url.PathEscape(zone)
}

// ovhRecordName converts the fully qualified record name into the relative
// subdomain OVH stores.
//
// The apex is spelled "" on OVH (an empty subDomain). The apex is unreachable for
// an ACME challenge, whose name always carries the _acme-challenge label, but the
// split is checked rather than assumed so a name that does not sit inside the
// resolved zone is refused rather than written.
func ovhRecordName(fqdn, zone string) (string, error) {
	relative, err := relativeRecordName(fqdn, zone)
	if err != nil {
		// Rewrapped so the error names OVH rather than the provider whose file the
		// shared helper happens to live in.
		return "", fmt.Errorf("%w: record %q is not inside zone %q", ErrOVHAPI, fqdn, zone)
	}
	if relative == "@" {
		return "", nil
	}
	return relative, nil
}

// errOVHNotFound marks a 404, so cleanup can treat an already-removed record as
// done and the zone walk can treat a miss as "try the parent".
var errOVHNotFound = errors.New("resource not found")

// do performs one signed API call and decodes its result.
//
// It is the ONLY place the application and consumer keys are written into
// headers, and [ovhProvider.sign] is the only place the application secret is
// used. None of them is ever logged, stored, or rendered into an error: the keys
// travel in headers and the secret never leaves the signature computation.
func (p *ovhProvider) do(ctx context.Context, method, path string, body []byte, out any) error {
	fullURL := p.baseURL + path

	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, fullURL, reader)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")

	timestamp, err := p.timestamp(ctx)
	if err != nil {
		return err
	}
	// The timestamp is rendered to its decimal string ONCE and used identically in
	// the header and in the signature input; a mismatch between the two is a silent
	// 403 from OVH.
	tsStr := strconv.FormatInt(timestamp, 10)

	// Trimmed at the point of use: a file-backed secret provider commonly yields a
	// trailing newline, and a newline in a header value is a header-injection
	// shape. net/http rejects it rather than sending it, so the failure would be
	// safe but opaque; trimming here makes the common case work and keeps the
	// control characters out of the request either way. The application and
	// consumer keys are not confidential — they travel in these headers — but they
	// are held redacted so this is the single place each is read.
	appKey := strings.TrimSpace(p.applicationKey.Reveal())
	consumerKey := strings.TrimSpace(p.consumerKey.Reveal())

	bodyStr := string(body)
	signature := p.sign(consumerKey, method, fullURL, bodyStr, tsStr)

	req.Header.Set("X-Ovh-Application", appKey)
	req.Header.Set("X-Ovh-Consumer", consumerKey)
	req.Header.Set("X-Ovh-Timestamp", tsStr)
	req.Header.Set("X-Ovh-Signature", signature)

	resp, err := p.client.Do(req)
	if err != nil {
		// The transport error is wrapped as-is. url.Error renders the request URL,
		// which carries no credential: the keys travel in headers, the secret is
		// never sent, and the path holds only a zone and a record.
		return fmt.Errorf("request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, ovhMaxBody))
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode == http.StatusNotFound {
		return errOVHNotFound
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return ovhError(resp.StatusCode, raw)
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

// sign computes the X-Ovh-Signature value for one request.
//
// The scheme is OVH's: "$1$" followed by the SHA-1 hex digest of
//
//	applicationSecret + "+" + consumerKey + "+" + METHOD + "+" + fullURL + "+" + body + "+" + timestamp
//
// This is the ONLY site that reveals the application secret, and it does so into
// a one-way hash whose output is a header value. SHA-1 is dictated by the vendor
// protocol here; it is a MAC over a request this side already knows, not a
// collision-resistance use, so its weakness is not in play.
func (p *ovhProvider) sign(consumerKey, method, fullURL, body, timestamp string) string {
	secret := strings.TrimSpace(p.applicationSecret.Reveal())
	h := sha1.New()
	// Written field by field so the "+" separators are unambiguous and no
	// intermediate concatenated string carrying the secret is retained.
	_, _ = io.WriteString(h, secret)
	_, _ = io.WriteString(h, "+")
	_, _ = io.WriteString(h, consumerKey)
	_, _ = io.WriteString(h, "+")
	_, _ = io.WriteString(h, method)
	_, _ = io.WriteString(h, "+")
	_, _ = io.WriteString(h, fullURL)
	_, _ = io.WriteString(h, "+")
	_, _ = io.WriteString(h, body)
	_, _ = io.WriteString(h, "+")
	_, _ = io.WriteString(h, timestamp)
	return ovhSignaturePrefix + hex.EncodeToString(h.Sum(nil))
}

// timestamp returns the current time adjusted by the OVH server-time delta.
//
// OVH rejects a request whose timestamp drifts too far from its own clock, so a
// skewed local clock would fail every call. The delta between OVH's clock and the
// local one is fetched once from the unauthenticated /auth/time endpoint and
// cached; the timestamp is then the local time plus that delta. Only a successful
// fetch is cached, so a transient fault at the first call does not permanently
// break the provider, and the lock is not held across the request so one slow
// fetch cannot block every issuance.
func (p *ovhProvider) timestamp(ctx context.Context) (int64, error) {
	if delta, ok := p.cachedDelta(); ok {
		return p.now().Unix() + delta, nil
	}

	server, err := p.serverTime(ctx)
	if err != nil {
		return 0, err
	}
	delta := server - p.now().Unix()

	p.mu.Lock()
	if !p.haveDelta {
		p.timeDelta = delta
		p.haveDelta = true
	}
	delta = p.timeDelta
	p.mu.Unlock()

	return p.now().Unix() + delta, nil
}

// cachedDelta reads the resolved server-time delta, or reports that it is not
// resolved yet.
func (p *ovhProvider) cachedDelta() (int64, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.timeDelta, p.haveDelta
}

// serverTime fetches OVH's current unix time from the unauthenticated
// /auth/time endpoint, which answers with the seconds as plain text.
func (p *ovhProvider) serverTime(ctx context.Context) (int64, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.baseURL+"/auth/time", nil)
	if err != nil {
		return 0, fmt.Errorf("%w: build time request: %w", ErrOVHAPI, err)
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("%w: fetch server time: %w", ErrOVHAPI, err)
	}
	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, ovhMaxBody))
	if err != nil {
		return 0, fmt.Errorf("%w: read server time: %w", ErrOVHAPI, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return 0, ovhError(resp.StatusCode, raw)
	}
	secs, err := strconv.ParseInt(strings.TrimSpace(string(raw)), 10, 64)
	if err != nil {
		// The body is NOT quoted into the error: an unparseable answer from
		// something impersonating the API is attacker-controlled text.
		return 0, fmt.Errorf("%w: unparseable server time (http %d)", ErrOVHAPI, resp.StatusCode)
	}
	return secs, nil
}

// ovhError renders the API's own error, using only its message.
//
// The message is bounded because it is remote input, treated as a bounded
// diagnostic rather than as trusted text. OVH never echoes a credential in an
// error, and nothing here would put one there if it did.
//
// The bound goes through [safetext.Bound] rather than a slice expression: a fixed
// byte cut can land inside a multi-byte rune and leave invalid UTF-8 for the log
// encoder downstream to mangle. No credential is spliced into this message before
// the cut, so there is no scrub whose ordering against the truncation matters
// here.
func ovhError(status int, raw []byte) error {
	var env ovhErrorResponse
	if err := json.Unmarshal(raw, &env); err != nil || env.Message == "" {
		return fmt.Errorf("request rejected (http %d)", status)
	}
	msg := safetext.Bound(env.Message, maxAPIMessageBytes)
	return fmt.Errorf("request rejected (http %d): %s", status, msg)
}

// The JSON shapes below are the subset of the OVH API this provider uses. Only
// the fields actually read or written are declared; encoding/json ignores the
// rest.

// ovhRecordCreate is the POST body for creating a record.
type ovhRecordCreate struct {
	FieldType string `json:"fieldType"`
	SubDomain string `json:"subDomain"`
	Target    string `json:"target"`
	TTL       int    `json:"ttl"`
}

// ovhRecord is one record as GET /domain/zone/{zone}/record/{id} returns it.
type ovhRecord struct {
	ID        int64  `json:"id"`
	FieldType string `json:"fieldType"`
	SubDomain string `json:"subDomain"`
	Target    string `json:"target"`
}

// ovhZone is the subset of a zone read that confirms its identity.
type ovhZone struct {
	Name string `json:"name"`
}

// ovhErrorResponse carries the API's own error message.
type ovhErrorResponse struct {
	Message string `json:"message"`
}
