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

// The wire protocol below is Gandi LiveDNS v5, addressed by resource record set
// (rrset): a record is keyed by (name, type) within a domain, and one rrset
// holds a SET of values. The endpoints, the Bearer scheme and the TTL floor are
// confirmed against the current vendor reference:
//
//	https://api.gandi.net/docs/livedns/
const (
	// gandiAPIBase is the LiveDNS v5 root. It is a constant rather than
	// configurable, for the same reason Cloudflare's, Route 53's, DigitalOcean's
	// and DNSimple's are: a settable endpoint is a way to point the
	// highest-privilege credential this process holds at an attacker's server.
	gandiAPIBase = "https://api.gandi.net/v5/livedns"

	// gandiChallengeTTL is the TTL on a challenge rrset this provider creates.
	//
	// Unlike the 60s the other providers use, this is 300: Gandi LiveDNS rejects
	// an rrset_ttl below 300, so a lower value is not "more aggressive cleanup",
	// it is a request the API refuses. It is still the floor rather than a large
	// value, because the record is deleted minutes later and a long TTL would
	// keep resolvers serving a challenge answer after the authorization it
	// belonged to is gone.
	gandiChallengeTTL = 300

	// gandiHTTPTimeout bounds one API call.
	gandiHTTPTimeout = 30 * time.Second

	// gandiMaxBody caps how much of a response is read. A response body is
	// attacker-influenced input; without a cap a hostile or broken endpoint
	// could stream until the process runs out of memory.
	gandiMaxBody = 1 << 20
)

// ErrGandiAPI is returned when the Gandi LiveDNS API refuses a request or
// answers unusably. It never carries the API token — see [gandiProvider].
var ErrGandiAPI = errors.New("dns01: gandi api")

// gandiProvider creates and removes the challenge TXT record through Gandi's
// LiveDNS v5 API.
//
// # Token custody
//
// Gandi's current credential is a Personal Access Token presented as
// "Authorization: Bearer <PAT>"; the legacy "Apikey <key>" scheme is deprecated
// by the vendor and this provider does not offer it, so there is one auth shape
// to reason about rather than two. The PAT fits the seam's one-credential shape
// directly — no packing, unlike Route 53. It is held as a [secrets.Redacted]
// and is unwrapped in exactly ONE place, [gandiProvider.do], directly into the
// Authorization header of an outbound request. Consequences, mirroring the other
// providers:
//
//   - This struct implements [fmt.Formatter], so no formatting of it can print
//     the token. That method is required, not decorative: secrets.Redacted's own
//     redaction is bypassed by fmt when the value sits in an UNEXPORTED struct
//     field, because fmt renders such fields by raw reflection and never calls
//     their String, Format or GoString methods.
//   - The type holds no logger and no telemetry handle, so there is no local
//     call site that could emit it.
//   - Errors are built from the record name and Gandi's own status and message.
//     The request is never rendered into an error, because a rendered
//     *http.Request includes its Authorization header.
//
// # Why cleanup re-reads the rrset instead of capturing an ID or deleting by name
//
// This is the security heart of the provider, and it is where Gandi's model
// diverges from both the by-ID providers AND from the reference client. Gandi
// has no per-record identifier: a record is an rrset keyed by (name, type)
// holding a SET of values. The obvious cleanup — DELETE the rrset — is what
// go-acme/lego does, and it is WRONG for this seam: a single ACME order
// legitimately puts two TXT values at one name, because a certificate covering
// both "example.com" and "*.example.com" publishes both challenges at
// "_acme-challenge.example.com" with different digests ([ChallengeRecordName]
// strips the wildcard prefix precisely because RFC 8555 says so). Deleting the
// rrset would revoke the sibling challenge still in flight, and would also
// destroy any operator TXT value that happens to share the name.
//
// So Present reads the current rrset and PUTs back the union, and cleanup reads
// the current rrset and PUTs back the difference — issuing an rrset DELETE only
// when the value it published was the SOLE value. The scoping guarantee rests on
// SET SUBTRACTION against an unforgeable value: the challenge value is the
// base64url SHA-256 digest of a key authorization computed from this process's
// ACCOUNT KEY, so no other party's value can equal it. Cleanup therefore removes
// the exact value this process published and leaves every other value byte for
// byte, so it cannot remove a record it did not create.
//
// The read-modify-write is not atomic. Within this process the solver serializes
// challenges, so the race needs a second writer to the same name in the same
// zone — another ACME client, or a second instance of this program validating
// the same domain concurrently. That is called out rather than papered over:
// Gandi's rrset PUT is an unconditional replace with no compare-and-set to close
// it.
//
// # Propagation
//
// Present does not wait for the record to be served. The seam forbids a
// provider-side wait: the solver polls the zone's authoritative nameservers
// once, for every provider, which is a strictly stronger signal than any
// "change applied" flag a vendor could return.
type gandiProvider struct {
	token  secrets.Redacted
	client *http.Client
}

var _ Provider = (*gandiProvider)(nil)

// NewGandi builds the provider. A nil client gets a bounded default; the
// parameter exists so a test can supply a transport pointed at a local fake and
// so an operator's proxy settings can be honored later.
func NewGandi(creds Credentials, client *http.Client) (Provider, error) {
	// One value authenticates Gandi; an empty or multi-value set yields
	// ok=false and is refused rather than guessed at. Fail closed.
	token, ok := creds.Single()
	if !ok {
		return nil, fmt.Errorf("%w: no api token credential", ErrGandiAPI)
	}
	// The blank check asks the WRAPPED value rather than revealing it, exactly as
	// the Cloudflare, DigitalOcean and DNSimple constructors do, so this file
	// keeps a single plaintext-unwrap site. Whitespace-only counts as blank: it
	// is not a credential. Refused at construction, where the operator sees it,
	// rather than at the first renewal months later.
	if token.IsBlank() {
		return nil, fmt.Errorf("%w: blank api token (empty or whitespace only)", ErrGandiAPI)
	}
	if client == nil {
		client = &http.Client{
			Timeout: gandiHTTPTimeout,
			// Redirects are REFUSED rather than followed. Following one would send
			// a request carrying the zone-editing token to whatever host the
			// response named; net/http strips Authorization across origins, but a
			// same-origin redirect to an unexpected path would still be followed,
			// and no legitimate LiveDNS call redirects.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}
	return &gandiProvider{token: token, client: client}, nil
}

// Name identifies the provider. It is a constant, never derived from the token.
func (p *gandiProvider) Name() string { return "gandi" }

// Format renders the provider as a constant under every fmt verb, so no
// formatting of this value can print the token.
//
// See the type comment: this is load-bearing. Without it, "%+v" of this struct
// prints the bearer token in full, because fmt walks unexported fields by
// reflection and never calls their redaction methods. "%#v" routes through
// Formatter too when the operand implements it.
func (p *gandiProvider) Format(f fmt.State, _ rune) {
	_, _ = io.WriteString(f, "dns01.gandiProvider{token:[REDACTED]}")
}

// Present publishes the challenge value and returns the cleanup that withdraws
// exactly that value.
func (p *gandiProvider) Present(ctx context.Context, rec Record) (CleanupFunc, error) {
	domain, err := p.domainFor(ctx, rec.Name)
	if err != nil {
		return nil, err
	}
	relative, err := gandiRecordName(rec.Name, domain)
	if err != nil {
		return nil, err
	}

	existing, ttl, err := p.currentTXT(ctx, domain, relative)
	if err != nil {
		return nil, err
	}

	// Merge into the rrset rather than replacing it: an operator TXT value at
	// this name, or a sibling wildcard challenge, must survive a create. Kept
	// values are carried BYTE FOR BYTE as the API returned them; only this
	// process's own value is added, in the bare form [Record] documents.
	values := existing
	if indexOfTXT(existing, rec.Value) < 0 {
		values = append(slices.Clone(existing), rec.Value)
	}
	if ttl < gandiChallengeTTL {
		// An existing rrset's own TTL is preserved when it already meets the
		// floor, so merging a challenge into an operator's record does not
		// silently rewrite that record's TTL. Only when there was no rrset — ttl
		// zero — or a value below the floor does the challenge TTL apply.
		ttl = gandiChallengeTTL
	}

	// The cleanup is built BEFORE the write and returned even when the write
	// reports failure, because a failed write can still have applied: a response
	// lost to a timeout or a reset connection leaves the rrset replaced at Gandi
	// with nothing here knowing it. Returning nil in that case leaks a standing
	// _acme-challenge TXT value that no code path can withdraw — the seam's
	// contract in dns01.go is explicit that a cleanup MUST come back whenever
	// anything may have been created, including when Present goes on to fail, and
	// the solver registers it on exactly that path.
	//
	// Returning it early is safe because the closure captures only the domain,
	// the relative name and the value — all known before the call — and nothing
	// from the response. And returning it when the write genuinely never applied
	// is harmless: the closure's first act is a read, and finding its value
	// absent it returns success without issuing any destructive request.
	cleanup := p.removeValue(domain, relative, rec.Value)

	if err := p.putTXT(ctx, domain, relative, ttl, values); err != nil {
		return cleanup, fmt.Errorf("%w: publish txt value for %q: %w", ErrGandiAPI, rec.Name, err)
	}
	return cleanup, nil
}

// removeValue returns the cleanup closure for one published value.
//
// The domain, the relative name and the exact value are CAPTURED. The closure
// re-reads the rrset because Gandi's write is a whole-rrset replace, but it only
// ever subtracts the one captured value — no input to it can widen that, and it
// can never remove a value this process did not publish.
func (p *gandiProvider) removeValue(domain, relative, value string) CleanupFunc {
	return func(ctx context.Context) error {
		existing, ttl, err := p.currentTXT(ctx, domain, relative)
		if err != nil {
			return fmt.Errorf("%w: read txt rrset for cleanup: %w", ErrGandiAPI, err)
		}
		idx := indexOfTXT(existing, value)
		if idx < 0 {
			// Already gone is success. Cleanup runs on retry and shutdown paths,
			// so it must be idempotent, and the zone is already in the state this
			// call wanted to reach. This is also the path a cleanup returned from
			// a genuinely failed publish takes: our value is absent, so nothing is
			// written or deleted and no destructive request is issued.
			return nil
		}

		// Every OTHER value is carried byte for byte; only ours is dropped. If it
		// was the sole value, the rrset itself goes, because a PUT with an empty
		// value list is not how the set is emptied.
		remaining := slices.Delete(slices.Clone(existing), idx, idx+1)
		if len(remaining) == 0 {
			if err := p.deleteTXT(ctx, domain, relative); err != nil {
				return fmt.Errorf("%w: delete txt rrset: %w", ErrGandiAPI, err)
			}
			return nil
		}
		if ttl < gandiChallengeTTL {
			ttl = gandiChallengeTTL
		}
		if err := p.putTXT(ctx, domain, relative, ttl, remaining); err != nil {
			return fmt.Errorf("%w: remove txt value: %w", ErrGandiAPI, err)
		}
		return nil
	}
}

// currentTXT returns the values and TTL of the TXT rrset at relative, or an
// empty slice when no such rrset exists.
//
// A 404 is the normal state before the first challenge and reports as empty,
// matching the reference client. The GET addresses one exact (name, type) path,
// so unlike Route 53's start-at listing there is no adjacent rrset to filter
// out; the values are taken as returned.
func (p *gandiProvider) currentTXT(ctx context.Context, domain, relative string) ([]string, int, error) {
	var out gandiRRSet
	err := p.do(ctx, http.MethodGet, gandiRRSetPath(domain, relative), nil, &out)
	if errors.Is(err, errGandiNotFound) {
		return nil, 0, nil
	}
	if err != nil {
		return nil, 0, fmt.Errorf("%w: read txt rrset for %q: %w", ErrGandiAPI, relative, err)
	}
	return out.Values, out.TTL, nil
}

// putTXT creates or replaces the TXT rrset at relative with exactly values.
//
// A PUT to the typed rrset path creates the set when it is absent and replaces
// it when it is present, so one call covers both the first challenge and a merge
// into an existing set — there is no separate create path to keep in step.
func (p *gandiProvider) putTXT(ctx context.Context, domain, relative string, ttl int, values []string) error {
	body, err := json.Marshal(gandiRRSet{TTL: ttl, Values: values})
	if err != nil {
		return fmt.Errorf("encode rrset: %w", err)
	}
	return p.do(ctx, http.MethodPut, gandiRRSetPath(domain, relative), body, nil)
}

// deleteTXT removes the whole TXT rrset at relative. It is called ONLY when the
// value this process published was the last one in the set; the value-scoping
// decision lives in [gandiProvider.removeValue], never here.
func (p *gandiProvider) deleteTXT(ctx context.Context, domain, relative string) error {
	err := p.do(ctx, http.MethodDelete, gandiRRSetPath(domain, relative), nil, nil)
	if err == nil || errors.Is(err, errGandiNotFound) {
		return nil
	}
	return err
}

// gandiRRSetPath builds the typed rrset path. Both segments are escaped: the
// domain has been validated as a plain domain name by [gandiProvider.domainFor]
// and the relative name is the challenge label, but escaping keeps a stray byte
// in either from splitting the path rather than trusting the shape.
func gandiRRSetPath(domain, relative string) string {
	return "/domains/" + url.PathEscape(domain) + "/records/" + url.PathEscape(relative) + "/TXT"
}

// indexOfTXT returns the position of value in values, or -1. The comparison
// tolerates one pair of surrounding double quotes on the stored side, because
// DNS presents TXT content quoted and it is not guaranteed which form Gandi
// echoes back. The tolerance is in the safe direction: it can only recognize the
// SAME unforgeable digest in the other spelling, never widen the match to a
// value this process did not publish. The published value is always bare, so a
// value written by this provider is found either way.
func indexOfTXT(values []string, value string) int {
	for i, v := range values {
		if gandiTXTContent(v) == value {
			return i
		}
	}
	return -1
}

// gandiTXTContent strips one pair of surrounding double quotes for comparison.
// It is used ONLY to match this process's own value; kept values are written
// back in their original form, so no operator value is rewritten by it.
func gandiTXTContent(v string) string {
	if len(v) >= 2 && v[0] == '"' && v[len(v)-1] == '"' {
		return v[1 : len(v)-1]
	}
	return v
}

// domainFor finds the Gandi domain that holds the record name.
//
// Candidate suffixes are tried most-specific-first, exactly as the other
// providers do, so a delegated "eu.example.com" wins over its parent
// "example.com" — writing to the parent would put the record in a zone that is
// not authoritative for the name.
//
// GET /domains/{fqdn} answers 200 for a domain in the account and 404 ("Unknown
// domain") for one that is not, so ONLY a 404 means "try the parent". Every
// other failure — a rejected token, a 5xx — is surfaced, never swallowed as a
// miss: treating a 403 as "try the parent" would turn a bad credential into a
// misleading "no domain found" after walking the whole name. A domain name is
// the API's own path key, so there is no ambiguity to resolve as with Route 53's
// duplicate hosted zones; the only failure is that none of the candidates is in
// the account, which REFUSES loudly rather than guessing.
func (p *gandiProvider) domainFor(ctx context.Context, recordName string) (string, error) {
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
			// A candidate that is not a plain domain name is not interpolated into
			// a request path. The candidate is derived from the record name, which
			// comes from the certificate request, so this is the check that stops a
			// crafted identifier from steering a credentialed request at another
			// API resource.
			return "", fmt.Errorf("%w: malformed domain candidate for %q", ErrGandiAPI, recordName)
		}

		var out gandiDomainResponse
		err := p.do(ctx, http.MethodGet, "/domains/"+url.PathEscape(name), nil, &out)
		if errors.Is(err, errGandiNotFound) {
			continue
		}
		if err != nil {
			return "", fmt.Errorf("%w: look up domain %q: %w", ErrGandiAPI, name, err)
		}
		// The response's own name is confirmed to be the one asked for rather than
		// trusted, so a redirected or impersonated answer cannot substitute a
		// different domain for the one this lookup resolved.
		if !strings.EqualFold(strings.TrimSuffix(out.FQDN, "."), name) {
			return "", fmt.Errorf("%w: domain lookup for %q answered for a different domain", ErrGandiAPI, name)
		}
		return name, nil
	}
	return "", fmt.Errorf("%w: no domain found for %q", ErrGandiAPI, recordName)
}

// gandiRecordName converts the fully qualified record name into the form Gandi
// stores in an rrset, which is relative to the domain.
//
// The label-boundary split is shared with the DigitalOcean provider — the rule
// is the same and a second copy is a second thing to get wrong — and Gandi's
// apex encoding is "@", the same as DigitalOcean's, so no translation is needed.
// The apex is unreachable for an ACME challenge, whose name always carries the
// _acme-challenge label, but the split is checked rather than assumed so a name
// that does not sit inside the resolved domain is refused rather than written.
func gandiRecordName(fqdn, domain string) (string, error) {
	relative, err := relativeRecordName(fqdn, domain)
	if err != nil {
		// Rewrapped so the error names Gandi rather than the provider whose file
		// the shared helper happens to live in.
		return "", fmt.Errorf("%w: record %q is not inside domain %q", ErrGandiAPI, fqdn, domain)
	}
	return relative, nil
}

// errGandiNotFound marks a 404, so the domain walk can treat a miss as "try the
// parent", a missing rrset reads as empty, and a delete of an already-removed
// rrset is done.
var errGandiNotFound = errors.New("resource not found")

// do performs one API call and decodes its result.
//
// This is the ONLY function in the file that reveals the token, and it does so
// straight into a request header that is never logged, never stored, and never
// rendered into an error.
func (p *gandiProvider) do(ctx context.Context, method, path string, body []byte, out any) error {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, gandiAPIBase+path, reader)
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
		// holds only a domain and a record name.
		return fmt.Errorf("request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, gandiMaxBody))
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode == http.StatusNotFound {
		return errGandiNotFound
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return gandiError(resp.StatusCode, raw)
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

// gandiError renders the API's own error, using only its message.
//
// The message is bounded because it is remote input, treated as a bounded
// diagnostic rather than as trusted text. Gandi never echoes the bearer token in
// an error, and nothing here would put it there if it did.
//
// The bound goes through [safetext.Bound] rather than a slice expression: a
// fixed byte cut can land inside a multi-byte rune and leave invalid UTF-8 for
// the log encoder downstream to mangle. No credential is spliced into this
// message before the cut, so there is no scrub whose ordering against the
// truncation matters here.
func gandiError(status int, raw []byte) error {
	var env gandiErrorResponse
	if err := json.Unmarshal(raw, &env); err != nil || env.Message == "" {
		return fmt.Errorf("request rejected (http %d)", status)
	}
	msg := safetext.Bound(env.Message, maxAPIMessageBytes)
	return fmt.Errorf("request rejected (http %d): %s", status, msg)
}

// The JSON shapes below are the subset of the LiveDNS v5 API this provider uses.
// Only the fields actually read or written are declared; encoding/json ignores
// the rest.

// gandiRRSet is one TXT record set. It is both the GET result and the PUT body:
// the API names the fields rrset_ttl and rrset_values on both.
type gandiRRSet struct {
	TTL    int      `json:"rrset_ttl"`
	Values []string `json:"rrset_values"`
}

type gandiDomainResponse struct {
	FQDN string `json:"fqdn"`
}

type gandiErrorResponse struct {
	Message string `json:"message"`
}
