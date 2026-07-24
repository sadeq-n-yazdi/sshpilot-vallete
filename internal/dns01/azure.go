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

// The wire protocol below is the Azure DNS Management API (resource provider
// Microsoft.Network, record sets), authenticated with an Azure AD service
// principal through the OAuth2 client-credentials grant. It is confirmed against
// the current vendor reference:
//
//	https://learn.microsoft.com/en-us/rest/api/dns/record-sets
//	https://learn.microsoft.com/en-us/rest/api/dns/zones/list
//	https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-client-creds-grant-flow
//
// # Why the client-credentials flow rather than a single token
//
// Azure does not authenticate with one API token. A service principal presents a
// tenant id, a client (application) id and a client secret to Entra ID's token
// endpoint and receives a short-lived bearer token, which is then sent to the
// management API. The subscription id is not secret and is not part of
// authentication, but it is REQUIRED to address any resource and cannot be
// discovered — so it rides the same named-credential seam. That is why this
// provider is built only from a named credential set (tenant_id, client_id,
// client_secret, subscription_id) and refuses the single-value form the token
// providers use: there is no one value to accept.
const (
	// azureLoginBase is Entra ID's public token endpoint host. It is a constant
	// rather than configurable for the same reason the management base is: a
	// settable endpoint is a way to point a zone-editing credential — here the
	// client secret — at an attacker's server.
	azureLoginBase = "https://login.microsoftonline.com"

	// azureManagementBase is the Azure Resource Manager endpoint. Fixed for the
	// same reason: a settable base would let a misconfiguration send the bearer
	// token to another host.
	azureManagementBase = "https://management.azure.com"

	// azureScope is the OAuth2 scope requested for the management plane. The
	// ".default" suffix asks for the application's pre-consented permissions,
	// which is the client-credentials flow's only valid scope shape.
	azureScope = "https://management.azure.com/.default"

	// azureAPIVersion pins the DNS resource-provider API version. Azure requires
	// an explicit api-version on every management call.
	azureAPIVersion = "2018-05-01"

	// azureChallengeTTL is the TTL on the challenge record. Low on purpose: the
	// record is deleted minutes later, and a long TTL would keep resolvers
	// serving a challenge answer after the authorization it belonged to is gone.
	azureChallengeTTL = 60

	// azureHTTPTimeout bounds one API call.
	azureHTTPTimeout = 30 * time.Second

	// azureMaxBody caps how much of a response is read. A response body is
	// attacker-influenced input; without a cap a hostile or broken endpoint could
	// stream until the process runs out of memory.
	azureMaxBody = 1 << 20

	// azureMaxZonePages bounds the pagination walk of the subscription's zone
	// list. It is a loop guard, not a policy: no subscription holds this many
	// pages of DNS zones, and an unbounded follow of a hostile nextLink would
	// spin forever.
	azureMaxZonePages = 100
)

// ErrAzureAPI is returned when the Azure API refuses a request or answers
// unusably, and when the credential set is incomplete. It never carries any
// credential field or the bearer token — see [azureProvider].
var ErrAzureAPI = errors.New("dns01: azure api")

// ErrAzureAmbiguousZone is returned when more than one DNS zone in the
// subscription matches the name being validated.
//
// It is a separate error because it is a configuration fault with a specific
// remedy, and because the alternative — picking one — is the failure this
// provider most needs to avoid. A subscription may legitimately hold two zones
// with the same name in different resource groups; only one of them is the one
// the registrar's delegation actually points at. Writing the challenge record
// into the other one succeeds at the API level and is never seen by the CA, so
// issuance fails ten minutes later with a message about DNS rather than about
// the subscription. Refusing here names the real problem while the operator can
// still fix it.
var ErrAzureAmbiguousZone = errors.New("dns01: azure ambiguous dns zone")

// errAzureNotFound marks a 404, so cleanup can treat an already-removed record
// set as done and a missing record set on read as an empty set.
var errAzureNotFound = errors.New("resource not found")

// azureProvider creates and removes the challenge TXT record through the Azure
// DNS management API.
//
// # Credential custody
//
// Azure needs four named values. Only client_secret is truly secret — it is the
// application password exchanged at the token endpoint. tenant_id, client_id and
// subscription_id are identifiers that travel in cleartext (a URL path or a form
// field), but they are held as [secrets.Redacted] anyway so a "%+v" of this
// struct cannot print any of them and so there is one documented site each is
// read. Consequences, mirroring the other providers:
//
//   - This struct implements [fmt.Formatter], so no formatting of it can print
//     any field. That method is required, not decorative: secrets.Redacted's own
//     redaction is bypassed by fmt when a value sits in an UNEXPORTED struct
//     field, because fmt renders such fields by raw reflection and never calls
//     their String, Format or GoString methods.
//   - The type holds no logger and no telemetry handle, so there is no local
//     call site that could emit a field.
//   - The bearer token fetched from the token endpoint is a zone-rewriting
//     secret for its lifetime. It is held only in a LOCAL string, written
//     straight into an Authorization header, and never stored in this struct nor
//     rendered into an error — so it cannot be caught by struct formatting.
//   - Errors are built from the record name and Azure's own status and message.
//     The request is never rendered into an error, because a rendered
//     *http.Request includes its Authorization header.
//
// # Why cleanup re-reads instead of capturing an ID
//
// Azure keys a record set by (name, type) and holds a SET of TXT values; it has
// no per-record identifier. A single ACME order legitimately needs two TXT
// values at one name — a certificate covering both "example.com" and
// "*.example.com" puts both challenges at "_acme-challenge.example.com" with
// different digests, because [ChallengeRecordName] strips the wildcard prefix.
//
// So Present reads the current set and writes back the union, and cleanup reads
// the current set and writes back the difference — deleting the record set
// outright only when the value it created was the last one in it. The scoping
// guarantee is preserved by SET SUBTRACTION rather than by an opaque ID: cleanup
// removes the exact value this process published and leaves every other value in
// place, so it cannot remove a record it did not create — including an
// operator's own TXT record at the same name, and including the other challenge
// of a wildcard order.
//
// The read-modify-write is not atomic. Within this process the solver serializes
// challenges, so the race needs a second writer to the same name in the same
// zone — another ACME client, or a second instance of this program validating
// the same domain concurrently. That is called out rather than papered over;
// Azure's If-Match ETag could close it but is deliberately not used, to keep
// this provider the same shape as Route 53 and Gandi on this seam.
type azureProvider struct {
	tenantID       secrets.Redacted
	clientID       secrets.Redacted
	clientSecret   secrets.Redacted
	subscriptionID secrets.Redacted
	client         *http.Client
}

var _ Provider = (*azureProvider)(nil)

// NewAzure builds the provider from the named credential set.
//
// Azure is named-only: it needs tenant_id, client_id, client_secret and
// subscription_id. A single credentials_ref cannot carry four distinct values,
// so the single form is refused with a message that names the required keys —
// never guessed at by splitting one value. Fail closed.
//
// Each required field is checked for blankness at construction, where the
// operator sees it, rather than at the first renewal months later. A nil client
// gets a bounded default; the parameter exists so a test can supply a transport
// pointed at a local fake and so an operator's proxy settings can be honored
// later.
func NewAzure(creds Credentials, client *http.Client) (Provider, error) {
	tenantID, err := azureRequiredField(creds, "tenant_id")
	if err != nil {
		return nil, err
	}
	clientID, err := azureRequiredField(creds, "client_id")
	if err != nil {
		return nil, err
	}
	clientSecret, err := azureRequiredField(creds, "client_secret")
	if err != nil {
		return nil, err
	}
	subscriptionID, err := azureRequiredField(creds, "subscription_id")
	if err != nil {
		return nil, err
	}

	if client == nil {
		client = &http.Client{
			Timeout: azureHTTPTimeout,
			// Redirects are REFUSED rather than followed. Following one would send a
			// request carrying either the client secret (to the token endpoint) or
			// the bearer token (to the management endpoint) to whatever host the
			// response named, and no legitimate Azure API call redirects.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}
	return &azureProvider{
		tenantID:       tenantID,
		clientID:       clientID,
		clientSecret:   clientSecret,
		subscriptionID: subscriptionID,
		client:         client,
	}, nil
}

// azureRequiredField reads one required named credential and refuses a missing
// or blank value.
//
// The blank check asks the WRAPPED value rather than revealing it, exactly as
// the token providers' constructors do, so the plaintext is not unwrapped here.
// Whitespace-only counts as blank: it is not a credential. The error names the
// FIELD (which is operator config, not a secret) but never the value.
func azureRequiredField(creds Credentials, field string) (secrets.Redacted, error) {
	v, ok := creds.Get(field)
	if !ok {
		return "", fmt.Errorf(
			"%w: missing %s; Azure needs credentials_refs with tenant_id, client_id, "+
				"client_secret and subscription_id", ErrAzureAPI, field)
	}
	if v.IsBlank() {
		return "", fmt.Errorf("%w: blank %s (empty or whitespace only)", ErrAzureAPI, field)
	}
	return v, nil
}

// Name identifies the provider. It is a constant, never derived from a
// credential.
func (p *azureProvider) Name() string { return "azure" }

// Format renders the provider as a constant under every fmt verb, so no
// formatting of this value can print any credential field.
//
// See the type comment: this is load-bearing. Without it, "%+v" of this struct
// prints all four credential fields in full, because fmt walks unexported fields
// by reflection and never calls their redaction methods. "%#v" routes through
// Formatter too when the operand implements it.
func (p *azureProvider) Format(f fmt.State, _ rune) {
	_, _ = io.WriteString(f, "dns01.azureProvider{tenant_id:[REDACTED], client_id:[REDACTED], client_secret:[REDACTED], subscription_id:[REDACTED]}")
}

// Present publishes the challenge value and returns the cleanup that withdraws
// exactly that value.
func (p *azureProvider) Present(ctx context.Context, rec Record) (CleanupFunc, error) {
	token, err := p.token(ctx)
	if err != nil {
		return nil, err
	}
	zone, group, err := p.zoneFor(ctx, token, rec.Name)
	if err != nil {
		return nil, err
	}
	relative, err := azureRecordName(rec.Name, zone)
	if err != nil {
		return nil, err
	}

	existing, ttl, err := p.currentTXT(ctx, token, group, zone, relative)
	if err != nil {
		return nil, err
	}
	values := existing
	if !slices.Contains(values, rec.Value) {
		values = append(slices.Clone(existing), rec.Value)
	}
	if ttl <= 0 {
		ttl = azureChallengeTTL
	}

	// The cleanup is built BEFORE the write and returned even when the write
	// reports failure, because a failed write can still have applied: a response
	// lost to a timeout or a reset connection leaves the change committed at Azure
	// with nothing here knowing it. Returning nil in that case leaks a standing
	// _acme-challenge TXT record that no code path can withdraw — the seam's
	// contract in dns01.go is explicit that a cleanup MUST come back whenever
	// anything may have been created, including when Present goes on to fail, and
	// the solver registers it on exactly that path.
	//
	// Returning it early is safe because the closure captures only the resource
	// group, zone, relative name and the value — all known before the call — and
	// nothing from the response. And returning it when the write genuinely never
	// applied is harmless: the closure's first act is a read, and finding its
	// value absent it returns success without submitting any change.
	cleanup := p.removeValue(group, zone, relative, rec.Value)

	if err := p.putRecordSet(ctx, token, group, zone, relative, ttl, values); err != nil {
		return cleanup, fmt.Errorf("%w: publish txt value for %q: %w", ErrAzureAPI, rec.Name, err)
	}
	return cleanup, nil
}

// removeValue returns the cleanup closure for one published value.
//
// The resource group, zone, relative name and the exact value are CAPTURED. The
// closure re-reads the record set because Azure's write replaces the whole set,
// but it only ever subtracts the one captured value — no input to it can widen
// that, and it can never remove a value this process did not publish. The record
// set is deleted outright only when the captured value was its last member.
func (p *azureProvider) removeValue(group, zone, relative, value string) CleanupFunc {
	return func(ctx context.Context) error {
		token, err := p.token(ctx)
		if err != nil {
			return fmt.Errorf("%w: token for cleanup: %w", ErrAzureAPI, err)
		}
		existing, ttl, err := p.currentTXT(ctx, token, group, zone, relative)
		if err != nil {
			return fmt.Errorf("%w: read txt record for cleanup: %w", ErrAzureAPI, err)
		}
		if !slices.Contains(existing, value) {
			// Already gone is success. Cleanup runs on retry and shutdown paths, so
			// it must be idempotent, and the zone is already in the state this call
			// wanted to reach. This is also the path a cleanup returned from a
			// genuinely failed publish takes: nothing was created, so nothing is
			// removed and no destructive request is made.
			return nil
		}

		remaining := slices.DeleteFunc(slices.Clone(existing), func(v string) bool { return v == value })
		if len(remaining) == 0 {
			// Nothing of ours or anyone else's is left, so the set itself goes.
			// Azure rejects a record set with an empty TXTRecords array, so an empty
			// remainder is a DELETE rather than a PUT of nothing.
			if err := p.deleteRecordSet(ctx, token, group, zone, relative); err != nil {
				return fmt.Errorf("%w: remove txt record set: %w", ErrAzureAPI, err)
			}
			return nil
		}
		if ttl <= 0 {
			ttl = azureChallengeTTL
		}
		if err := p.putRecordSet(ctx, token, group, zone, relative, ttl, remaining); err != nil {
			return fmt.Errorf("%w: remove txt value: %w", ErrAzureAPI, err)
		}
		return nil
	}
}

// zoneFor finds the single DNS zone in the subscription that should hold the
// record, and the resource group it lives in.
//
// The subscription's zones are listed once (following pagination) and matched in
// memory. Candidate suffixes are tried most-specific-first, exactly as the other
// providers do, so a delegated "eu.example.com" wins over its parent
// "example.com" — writing to the parent would put the record in a zone that is
// not authoritative for the name.
//
// More than one zone with the same name REFUSES. Azure permits two zones with
// the same name in different resource groups, and only the one the registrar
// delegates to is real; picking the first would be a coin flip resolved
// silently.
func (p *azureProvider) zoneFor(ctx context.Context, token, recordName string) (zone, group string, err error) {
	zones, err := p.listZones(ctx, token)
	if err != nil {
		return "", "", err
	}

	name := strings.TrimSuffix(recordName, ".")
	for range maxZoneLabels {
		idx := strings.IndexByte(name, '.')
		if idx < 0 {
			break
		}
		name = name[idx+1:]
		if !strings.Contains(name, ".") {
			// A single label is a TLD; no subscription hosts a zone there and
			// matching it only wastes work.
			break
		}

		var matches []azureZone
		for _, z := range zones {
			if strings.EqualFold(strings.TrimSuffix(z.name, "."), name) {
				matches = append(matches, z)
			}
		}
		switch len(matches) {
		case 0:
			continue
		case 1:
			m := matches[0]
			// Both the zone name and the resource group are interpolated into the
			// path of a subsequent bearer-token request. They are validated against
			// their documented shapes so a hostile or confused response — a zone id
			// carrying a traversal sequence in its resource-group segment — cannot
			// steer a credentialed PUT or DELETE at another resource.
			if !validDomainName(m.name) {
				return "", "", fmt.Errorf("%w: malformed zone name in response", ErrAzureAPI)
			}
			if !validResourceGroup(m.resourceGroup) {
				return "", "", fmt.Errorf("%w: malformed resource group in response", ErrAzureAPI)
			}
			return m.name, m.resourceGroup, nil
		default:
			return "", "", fmt.Errorf("%w: %d dns zones named %q in the subscription; "+
				"remove the duplicate or the challenge record may be written to the zone the registrar does not delegate to",
				ErrAzureAmbiguousZone, len(matches), name)
		}
	}
	return "", "", fmt.Errorf("%w: no dns zone found for %q", ErrAzureAPI, recordName)
}

// listZones returns every DNS zone in the subscription, following pagination.
//
// The subscription-wide listing is paged; reading only the first page would make
// a zone on a later page read as "no zone found", failing closed but silently
// breaking issuance for that domain. The nextLink is an absolute URL returned by
// the API, so the walk is bounded by azureMaxZonePages against a hostile or
// looping link.
func (p *azureProvider) listZones(ctx context.Context, token string) ([]azureZone, error) {
	next := p.subscriptionPath("/providers/Microsoft.Network/dnszones") + "?api-version=" + azureAPIVersion

	var zones []azureZone
	for range azureMaxZonePages {
		var out azureZoneListResponse
		if err := p.do(ctx, http.MethodGet, next, nil, &out, token); err != nil {
			return nil, fmt.Errorf("%w: list dns zones: %w", ErrAzureAPI, err)
		}
		for _, z := range out.Value {
			group, ok := azureResourceGroupFromID(z.ID)
			if !ok {
				// A zone id that is not the documented
				// "/subscriptions/.../resourceGroups/<rg>/..." shape is not trusted
				// to yield a resource group; skipping it is safe because a zone this
				// process cannot address is one it must not write to.
				continue
			}
			zones = append(zones, azureZone{name: z.Name, resourceGroup: group})
		}
		if out.NextLink == "" {
			return zones, nil
		}
		if !strings.HasPrefix(out.NextLink, azureManagementBase+"/") {
			// The continuation link must stay on the management host. A link
			// pointing elsewhere would send the bearer token to another server, so
			// it is refused rather than followed.
			return nil, fmt.Errorf("%w: zone list continuation left the management host", ErrAzureAPI)
		}
		next = out.NextLink
	}
	return nil, fmt.Errorf("%w: dns zone list did not terminate within %d pages", ErrAzureAPI, azureMaxZonePages)
}

// currentTXT returns the TXT values currently published at the record set and
// its TTL.
//
// A missing record set is not an error: it is the normal state before the first
// challenge, and it reports as an empty slice.
func (p *azureProvider) currentTXT(ctx context.Context, token, group, zone, relative string) ([]string, int, error) {
	var out azureRecordSet
	err := p.do(ctx, http.MethodGet, p.recordSetURL(group, zone, relative), nil, &out, token)
	if errors.Is(err, errAzureNotFound) {
		return nil, 0, nil
	}
	if err != nil {
		return nil, 0, fmt.Errorf("%w: read txt record set: %w", ErrAzureAPI, err)
	}

	values := make([]string, 0, len(out.Properties.TXTRecords))
	for _, r := range out.Properties.TXTRecords {
		values = append(values, azureTXTContent(r.Value))
	}
	return values, out.Properties.TTL, nil
}

// putRecordSet writes the TXT record set with the given values.
func (p *azureProvider) putRecordSet(ctx context.Context, token, group, zone, relative string, ttl int, values []string) error {
	records := make([]azureTXTRecord, 0, len(values))
	for _, v := range values {
		// Each value is written as a single character-string. The ACME challenge
		// value is a 43-character base64url digest, well under the 255-byte TXT
		// per-string limit, so it never needs chunking.
		records = append(records, azureTXTRecord{Value: []string{v}})
	}
	body, err := json.Marshal(azureRecordSet{Properties: azureRecordSetProps{TTL: ttl, TXTRecords: records}})
	if err != nil {
		return fmt.Errorf("encode record set: %w", err)
	}
	return p.do(ctx, http.MethodPut, p.recordSetURL(group, zone, relative), body, nil, token)
}

// deleteRecordSet removes the TXT record set. A 404 is treated as success so
// cleanup is idempotent.
func (p *azureProvider) deleteRecordSet(ctx context.Context, token, group, zone, relative string) error {
	err := p.do(ctx, http.MethodDelete, p.recordSetURL(group, zone, relative), nil, nil, token)
	if errors.Is(err, errAzureNotFound) {
		return nil
	}
	return err
}

// subscriptionPath builds a management URL under the configured subscription.
//
// This is the ONLY place the subscription id is revealed. It is not a secret —
// it travels in every request path — but it is held redacted so this is the one
// documented site it is read, and it is path-escaped so a stray byte splits
// nothing.
func (p *azureProvider) subscriptionPath(suffix string) string {
	return azureManagementBase + "/subscriptions/" +
		url.PathEscape(strings.TrimSpace(p.subscriptionID.Reveal())) + suffix
}

// recordSetURL builds the management URL for one TXT record set. The resource
// group, zone and relative name have already been validated as safe path
// segments, but each is escaped anyway so a stray byte cannot split the path.
func (p *azureProvider) recordSetURL(group, zone, relative string) string {
	return p.subscriptionPath(
		"/resourceGroups/"+url.PathEscape(group)+
			"/providers/Microsoft.Network/dnszones/"+url.PathEscape(zone)+
			"/TXT/"+url.PathEscape(relative)) + "?api-version=" + azureAPIVersion
}

// token exchanges the service-principal credentials for a management bearer
// token via the OAuth2 client-credentials grant.
//
// This is the ONLY place the tenant id, client id and client secret are
// revealed, and each is written straight into the token request — the tenant id
// into the URL path, the client id and client secret into the form body. The
// returned token is a zone-rewriting secret for its lifetime; it is kept in a
// local string by every caller and never stored on the provider, so it cannot be
// caught by a "%+v" of this struct.
func (p *azureProvider) token(ctx context.Context) (string, error) {
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", strings.TrimSpace(p.clientID.Reveal()))
	form.Set("client_secret", strings.TrimSpace(p.clientSecret.Reveal()))
	form.Set("scope", azureScope)

	tokenURL := azureLoginBase + "/" +
		url.PathEscape(strings.TrimSpace(p.tenantID.Reveal())) + "/oauth2/v2.0/token"

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("%w: build token request: %w", ErrAzureAPI, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		// The transport error is wrapped as-is. url.Error renders the request URL,
		// which carries only the tenant id in its path — the client id and secret
		// travel in the body, never the URL.
		return "", fmt.Errorf("%w: token request failed: %w", ErrAzureAPI, err)
	}
	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, azureMaxBody))
	if err != nil {
		return "", fmt.Errorf("%w: read token response: %w", ErrAzureAPI, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", azureTokenError(resp.StatusCode, raw)
	}

	var tok azureTokenResponse
	if err := json.Unmarshal(raw, &tok); err != nil {
		// The body is NOT quoted into the error. An unparseable response from
		// something impersonating the endpoint is attacker-controlled text.
		return "", fmt.Errorf("%w: unparseable token response (http %d)", ErrAzureAPI, resp.StatusCode)
	}
	if strings.TrimSpace(tok.AccessToken) == "" {
		return "", fmt.Errorf("%w: token response carried no access_token (http %d)", ErrAzureAPI, resp.StatusCode)
	}
	return tok.AccessToken, nil
}

// do performs one management API call, authenticated with the supplied bearer
// token, and decodes its result.
//
// The token is written into the Authorization header and nowhere else — never
// logged, never stored, never rendered into an error. A 404 is returned as
// [errAzureNotFound] so callers can treat an absent record set as empty or an
// already-removed one as done.
func (p *azureProvider) do(ctx context.Context, method, fullURL string, body []byte, out any, token string) error {
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
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := p.client.Do(req)
	if err != nil {
		// The transport error is wrapped as-is. url.Error renders the request URL,
		// which carries no credential: the token travels in a header, and the path
		// holds only the subscription, resource group, zone and record name.
		return fmt.Errorf("request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, azureMaxBody))
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode == http.StatusNotFound {
		return errAzureNotFound
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return azureError(resp.StatusCode, raw)
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

// azureError renders the management API's own error, using only its structured
// code and message.
//
// The message is bounded because it is remote input, treated as a bounded
// diagnostic rather than as trusted text. Azure never echoes a credential in an
// error, and nothing here would put one there if it did.
//
// The bound goes through [safetext.Bound] rather than a slice expression: a
// fixed byte cut can land inside a multi-byte rune and leave invalid UTF-8 for
// the log encoder downstream to mangle. No credential is spliced into this
// message before the cut, so there is no scrub whose ordering against the
// truncation matters here.
func azureError(status int, raw []byte) error {
	var env azureErrorResponse
	if err := json.Unmarshal(raw, &env); err != nil || env.Error.Code == "" {
		return fmt.Errorf("request rejected (http %d)", status)
	}
	msg := safetext.Bound(env.Error.Message, maxAPIMessageBytes)
	return fmt.Errorf("request rejected (http %d, code %s): %s", status, env.Error.Code, msg)
}

// azureTokenError renders the token endpoint's own error. Entra ID uses the
// OAuth2 error shape ({"error":..,"error_description":..}) rather than the
// management API's, so it is parsed separately. The description is bounded for
// the same reason as azureError's message; the endpoint never echoes the client
// secret.
func azureTokenError(status int, raw []byte) error {
	var env azureTokenErrorResponse
	if err := json.Unmarshal(raw, &env); err != nil || env.Error == "" {
		return fmt.Errorf("%w: token request rejected (http %d)", ErrAzureAPI, status)
	}
	desc := safetext.Bound(env.Description, maxAPIMessageBytes)
	return fmt.Errorf("%w: token request rejected (http %d, %s): %s", ErrAzureAPI, status, env.Error, desc)
}

// azureRecordName converts the fully qualified record name into the relative
// name Azure stores.
//
// The apex is spelled "@" on Azure. The apex is unreachable for an ACME
// challenge, whose name always carries the _acme-challenge label, but the split
// is checked rather than assumed so a name that does not sit inside the resolved
// zone is refused rather than written.
func azureRecordName(fqdn, zone string) (string, error) {
	relative, err := relativeRecordName(fqdn, zone)
	if err != nil {
		// Rewrapped so the error names Azure rather than the provider whose file
		// the shared helper happens to live in.
		return "", fmt.Errorf("%w: record %q is not inside zone %q", ErrAzureAPI, fqdn, zone)
	}
	return relative, nil
}

// azureTXTContent normalizes a TXT record's chunked value for comparison against
// the value this process published.
//
// Azure stores a TXT record's content as an array of character-strings; on the
// wire DNS reassembles them by concatenation, so the value this process knows is
// the chunks joined with no separator. The published value is always a single
// chunk, so a value written by this provider round-trips exactly, and the join
// can only ever reproduce the SAME value in the other spelling — never widen the
// match to a value this process did not publish.
func azureTXTContent(chunks []string) string {
	return strings.Join(chunks, "")
}

// azureResourceGroupFromID extracts the resource group from a zone's resource
// id, which has the documented shape
// "/subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.Network/dnszones/<name>".
//
// The match on "resourceGroups" is case-insensitive because Azure's own tooling
// is inconsistent about the casing of that segment. The extracted value is NOT
// trusted as a path segment here; the caller validates it with
// [validResourceGroup] before it is interpolated into a request.
func azureResourceGroupFromID(id string) (string, bool) {
	segments := strings.Split(strings.TrimPrefix(id, "/"), "/")
	for i := 0; i+1 < len(segments); i++ {
		if strings.EqualFold(segments[i], "resourceGroups") {
			rg := segments[i+1]
			if rg == "" {
				return "", false
			}
			return rg, true
		}
	}
	return "", false
}

// validResourceGroup reports whether rg is the shape Azure documents for a
// resource-group name: 1–90 characters of alphanumerics, underscore, hyphen,
// period and parentheses. It exists to keep a value taken from an API response
// from escaping into a URL path as anything other than a resource group.
//
// It deliberately accepts only ASCII: Azure also permits Unicode word
// characters, but the challenge path never needs one, and refusing them is the
// safe direction — the failure is a loud "malformed resource group" at startup
// of issuance, not a mis-addressed credentialed write.
func validResourceGroup(rg string) bool {
	if rg == "" || len(rg) > 90 {
		return false
	}
	// "." and ".." are the path-traversal segments, and Azure forbids both as
	// resource-group names in any case. They must be refused explicitly because
	// the character check below permits the period. A trailing period is likewise
	// invalid per Azure and is refused rather than trusted into a path.
	if rg == "." || rg == ".." || rg[len(rg)-1] == '.' {
		return false
	}
	for i := 0; i < len(rg); i++ {
		c := rg[i]
		ok := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			c == '_' || c == '-' || c == '.' || c == '(' || c == ')'
		if !ok {
			return false
		}
	}
	return true
}

// The JSON shapes below are the subset of the Azure API this provider uses. Only
// the fields actually read or written are declared; encoding/json ignores the
// rest.

// azureTokenResponse is the OAuth2 client-credentials token response.
type azureTokenResponse struct {
	AccessToken string `json:"access_token"`
}

// azureTokenErrorResponse is the OAuth2 error response from the token endpoint.
type azureTokenErrorResponse struct {
	Error       string `json:"error"`
	Description string `json:"error_description"`
}

// azureZoneListResponse is one page of GET .../dnszones.
type azureZoneListResponse struct {
	Value []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"value"`
	NextLink string `json:"nextLink"`
}

// azureZone is a resolved zone: its name and the resource group holding it.
type azureZone struct {
	name          string
	resourceGroup string
}

// azureRecordSet is the record-set resource for a TXT record set.
type azureRecordSet struct {
	Properties azureRecordSetProps `json:"properties"`
}

type azureRecordSetProps struct {
	TTL        int              `json:"TTL"`
	TXTRecords []azureTXTRecord `json:"TXTRecords"`
}

type azureTXTRecord struct {
	Value []string `json:"value"`
}

// azureErrorResponse carries the management API's own error.
type azureErrorResponse struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}
