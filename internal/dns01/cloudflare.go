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

const (
	// cloudflareAPIBase is the v4 API root. It is a constant rather than
	// configurable: a settable endpoint would be a way to point the highest-
	// privilege credential this process holds at an attacker's server.
	cloudflareAPIBase = "https://api.cloudflare.com/client/v4"

	// cloudflareChallengeTTL is the TTL set on the challenge record. Cloudflare's
	// minimum for an explicit TTL is 60s; low is what we want, because the record
	// is deleted minutes later and a long TTL would keep resolvers serving a
	// challenge answer after the authorization it belonged to is gone.
	cloudflareChallengeTTL = 60

	// cloudflareHTTPTimeout bounds one API call.
	cloudflareHTTPTimeout = 30 * time.Second

	// cloudflareRecordMissingCode is Cloudflare's "DNS record does not exist"
	// error code, which a delete of an already-removed record returns.
	cloudflareRecordMissingCode = 81044

	// cloudflareMaxBody caps how much of an API response is read. A response
	// body is attacker-influenced input; without a cap a hostile or broken
	// endpoint could stream until the process runs out of memory.
	cloudflareMaxBody = 1 << 20
)

// ErrCloudflareAPI is returned when the Cloudflare API refuses a request or
// answers unusably. It never carries the API token — see [cloudflareProvider].
var ErrCloudflareAPI = errors.New("dns01: cloudflare api")

// cloudflareProvider creates and removes the challenge TXT record through
// Cloudflare's v4 API.
//
// # Token custody
//
// The token is held as a [secrets.Redacted] and is unwrapped in exactly ONE
// place, [cloudflareProvider.do], directly into the Authorization header of an
// outbound request. Consequences of that being the only Reveal in the file:
//
//   - The struct cannot be logged into revealing it, because it implements
//     [fmt.Formatter] and renders as a constant under every verb. That method is
//     not decoration: secrets.Redacted's own redaction is bypassed by fmt when
//     the value sits in an UNEXPORTED struct field, because fmt renders such
//     fields by raw reflection and never calls their String, Format or GoString
//     methods. Verified: without the Format method below, "%+v" of this provider
//     prints the bearer token in full. So an added slog.Any("provider", p), or a
//     %+v of it in a future error, prints nothing useful.
//   - This type holds NO logger and NO telemetry handle at all, so there is no
//     local call site that could emit it even by mistake.
//   - Errors below are built from the record name and Cloudflare's own error
//     code and message. The request is never rendered into an error, because a
//     rendered *http.Request includes its headers.
//
// # Scope of writes
//
// Removal deletes a specific record ID that this process received from the
// create call — never a name lookup. The provider therefore cannot delete a
// record it did not create, including an operator's own TXT record at the same
// name. Creation, however, is only as narrow as the TOKEN: the Cloudflare API
// has no per-record scoping, so a token with Zone:DNS:Edit can write any record
// in the zones it covers. That is a limit of the API, not something this code
// can close, and it is stated here rather than papered over — an operator
// should issue a token scoped to the single zone being validated, which is the
// narrowest grant Cloudflare offers.
type cloudflareProvider struct {
	token  secrets.Redacted
	client *http.Client
}

var _ Provider = (*cloudflareProvider)(nil)

// NewCloudflare builds the provider. A nil client gets a bounded default; the
// parameter exists so a test can supply a transport pointed at a local fake and
// so an operator's proxy settings can be honored later.
func NewCloudflare(creds Credentials, client *http.Client) (Provider, error) {
	// Cloudflare authenticates with one value; an empty set (or one carrying
	// several values with no lone one) yields ok=false and is refused rather
	// than guessed at. Fail closed.
	token, ok := creds.Single()
	if !ok {
		return nil, fmt.Errorf("%w: no api token credential", ErrCloudflareAPI)
	}
	// A whitespace-only token is refused as firmly as an empty one: it is not a
	// credential, and accepting it would send "Bearer    " and learn nothing
	// until Cloudflare rejected the first challenge. IsBlank answers this
	// without unwrapping the token here, so this file keeps a single plaintext
	// unwrap site.
	if token.IsBlank() {
		return nil, fmt.Errorf("%w: blank api token (empty or whitespace only)", ErrCloudflareAPI)
	}
	if client == nil {
		client = &http.Client{
			Timeout: cloudflareHTTPTimeout,
			// Redirects are REFUSED rather than followed. Following one would
			// send a request carrying the zone-editing token to whatever host
			// the response named; net/http strips Authorization across origins,
			// but a same-origin redirect to an unexpected path would still be
			// followed, and no legitimate Cloudflare API call redirects.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}
	return &cloudflareProvider{token: token, client: client}, nil
}

// Name identifies the provider. It is a constant, never derived from the token.
func (p *cloudflareProvider) Name() string { return "cloudflare" }

// Format renders the provider as a constant under every fmt verb, so no
// formatting of this value can print the token.
//
// It exists because secrets.Redacted alone is NOT sufficient here. fmt walks a
// struct's unexported fields with raw reflection and does not invoke their
// String, GoString, Format or MarshalJSON methods, so "%+v" of a struct holding
// a Redacted in an unexported field prints the underlying secret verbatim.
// Implementing Formatter on the CONTAINING type is what stops fmt from
// descending into the fields at all.
//
// GoString is covered too: "%#v" routes through Formatter when the operand
// implements it.
func (p *cloudflareProvider) Format(f fmt.State, _ rune) {
	_, _ = io.WriteString(f, "dns01.cloudflareProvider{token:[REDACTED]}")
}

// Present creates the TXT record and returns the delete-by-ID cleanup for it.
func (p *cloudflareProvider) Present(ctx context.Context, rec Record) (CleanupFunc, error) {
	zoneID, err := p.zoneID(ctx, rec.Name)
	if err != nil {
		return nil, err
	}

	body, err := json.Marshal(map[string]any{
		"type":    "TXT",
		"name":    rec.Name,
		"content": rec.Value,
		"ttl":     cloudflareChallengeTTL,
		"comment": "sshpilot-vallet ACME DNS-01 challenge",
	})
	if err != nil {
		return nil, fmt.Errorf("%w: encode record: %w", ErrCloudflareAPI, err)
	}

	var created struct {
		ID string `json:"id"`
	}
	if err := p.do(ctx, http.MethodPost, "/zones/"+zoneID+"/dns_records", body, &created); err != nil {
		return nil, fmt.Errorf("%w: create txt record for %q: %w", ErrCloudflareAPI, rec.Name, err)
	}
	if created.ID == "" {
		// A create that reports success without an ID leaves a record this
		// process cannot delete. Refused loudly rather than returned with a
		// no-op cleanup, so the caller aborts issuance instead of proceeding
		// with an unremovable challenge record standing in the zone.
		return nil, fmt.Errorf("%w: create txt record for %q returned no record id", ErrCloudflareAPI, rec.Name)
	}

	return p.deleteRecord(zoneID, created.ID), nil
}

// deleteRecord returns the cleanup closure for one created record.
//
// The zone and record IDs are CAPTURED, not looked up again. That is the whole
// scoping guarantee: this closure can address exactly one record, the one that
// was just created, and no input to it can widen that.
func (p *cloudflareProvider) deleteRecord(zoneID, recordID string) CleanupFunc {
	return func(ctx context.Context) error {
		err := p.do(ctx, http.MethodDelete, "/zones/"+zoneID+"/dns_records/"+recordID, nil, nil)
		if err == nil || errors.Is(err, errCloudflareNotFound) {
			// Already gone is success: cleanup must be idempotent because it
			// runs on retry and shutdown paths, and a second delete of a
			// removed record is the intended end state either way.
			return nil
		}
		return fmt.Errorf("%w: delete txt record: %w", ErrCloudflareAPI, err)
	}
}

// errCloudflareNotFound marks a 404 or Cloudflare's "record does not exist"
// code, so cleanup can treat an already-removed record as done.
var errCloudflareNotFound = errors.New("record not found")

// zoneID finds the zone that holds the record name.
//
// Cloudflare addresses records by zone, and the zone is not derivable from the
// name by string rules — a name may sit in a zone at any label depth, and the
// public-suffix boundary is not a reliable guide. So candidate suffixes are
// tried from the most specific downward and the first match wins, which selects
// the most specific zone the token can see. That matters when a token covers
// both "example.com" and a delegated "eu.example.com": writing to the parent
// would put the record in a zone that is not authoritative for the name.
func (p *cloudflareProvider) zoneID(ctx context.Context, recordName string) (string, error) {
	name := strings.TrimSuffix(recordName, ".")

	for range maxZoneLabels {
		idx := strings.IndexByte(name, '.')
		if idx < 0 {
			break
		}
		name = name[idx+1:]
		if !strings.Contains(name, ".") {
			// A single label is a TLD; Cloudflare hosts no zone there and
			// querying it only spends an API call.
			break
		}

		var zones []struct {
			ID string `json:"id"`
		}
		// Built with url.Values rather than concatenated. The candidate is a
		// domain suffix derived from the certificate name, so in normal
		// operation it is not arbitrary text — but concatenating it raw means a
		// name containing "&" or "#" splits the query or truncates it, and the
		// zone lookup would then be answered for a name nobody asked about.
		// Encoding the whole parameter set makes that unrepresentable rather
		// than relying on each call site to remember one escape.
		query := url.Values{"status": {"active"}, "name": {name}}.Encode()
		if err := p.do(ctx, http.MethodGet, "/zones?"+query, nil, &zones); err != nil {
			return "", fmt.Errorf("%w: look up zone %q: %w", ErrCloudflareAPI, name, err)
		}
		if len(zones) > 0 && zones[0].ID != "" {
			return zones[0].ID, nil
		}
	}
	return "", fmt.Errorf("%w: no zone found for %q", ErrCloudflareAPI, recordName)
}

// cloudflareEnvelope is the uniform response wrapper the v4 API returns.
type cloudflareEnvelope struct {
	Success bool            `json:"success"`
	Errors  []cloudflareErr `json:"errors"`
	Result  json.RawMessage `json:"result"`
}

type cloudflareErr struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// do performs one API call and decodes its result.
//
// This is the ONLY function in the package that reveals the token, and it does
// so straight into a request header that is never logged, never stored, and
// never rendered into an error.
func (p *cloudflareProvider) do(ctx context.Context, method, path string, body []byte, out any) error {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, cloudflareAPIBase+path, reader)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+p.token.Reveal())
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		// The transport error is wrapped as-is. url.Error renders the request
		// URL, which carries no credential: the token travels in a header, and
		// the query string holds only the zone name.
		return fmt.Errorf("request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, cloudflareMaxBody))
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode == http.StatusNotFound {
		return errCloudflareNotFound
	}

	var env cloudflareEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		// The body is NOT quoted into the error. An unparseable response from
		// something impersonating the API is attacker-controlled text, and
		// echoing it into logs is how log injection and secret-shaped confusion
		// both start. The status code is the diagnostic.
		return fmt.Errorf("unparseable response (http %d)", resp.StatusCode)
	}
	if !env.Success {
		return cloudflareErrors(resp.StatusCode, env.Errors)
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(env.Result, out); err != nil {
		return fmt.Errorf("decode result (http %d)", resp.StatusCode)
	}
	return nil
}

// cloudflareErrors renders the API's own error list.
//
// Only the numeric code and Cloudflare's message text are used, and the message
// is truncated: it is remote input, so it is treated as a bounded diagnostic
// rather than as trusted text. Cloudflare never echoes the bearer token in an
// error, and nothing here would put it there if it did.
//
// The bound goes through [safetext.Bound] rather than a slice expression. A
// fixed BYTE cut on remote text can land in the middle of a multi-byte UTF-8
// sequence and leave a fragment that is not valid UTF-8, which the JSON log
// encoder downstream then mangles — so a party choosing message lengths could
// corrupt this server's log encoding. No credential is spliced into this
// message before the cut, so unlike the Origin CA client's error summary there
// is no scrub whose ordering against the truncation matters here.
func cloudflareErrors(status int, errs []cloudflareErr) error {
	if len(errs) == 0 {
		return fmt.Errorf("request rejected (http %d)", status)
	}
	if errs[0].Code == cloudflareRecordMissingCode {
		// "record does not exist": the zone is already in the state cleanup
		// wants, so the caller can treat it as done. Mapped here rather than in
		// deleteRecord so the 404 and the in-band code take the same path.
		return errCloudflareNotFound
	}
	msg := safetext.Bound(errs[0].Message, maxAPIMessageBytes)
	return fmt.Errorf("request rejected (http %d, code %d): %s", status, errs[0].Code, msg)
}
