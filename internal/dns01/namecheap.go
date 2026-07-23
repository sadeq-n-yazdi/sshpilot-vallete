package dns01

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/safetext"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/secrets"
)

// The wire protocol below is the Namecheap API, a single XML endpoint driven by
// a Command parameter rather than a REST resource tree. The endpoints, the
// authentication parameters and the getHosts/setHosts field names are confirmed
// against the current vendor reference:
//
//	https://www.namecheap.com/support/api/methods/domains-dns/get-hosts/
//	https://www.namecheap.com/support/api/methods/domains-dns/set-hosts/
//	https://www.namecheap.com/support/api/methods/domains/get-list/
const (
	// namecheapEndpoint is the production API endpoint. It is a constant rather
	// than configurable, for the same reason every other provider's base is: a
	// settable endpoint is a way to point the highest-privilege credential this
	// process holds at an attacker's server. The sandbox endpoint
	// (api.sandbox.namecheap.com) is deliberately not offered — a second base
	// URL is a second thing an operator can point a live credential at by
	// mistake.
	namecheapEndpoint = "https://api.namecheap.com/xml.response"

	// The three commands this provider issues. getList enumerates the account's
	// domains, getHosts reads a domain's complete host-record set, and setHosts
	// REPLACES that entire set (see the type comment for why that shapes
	// everything below).
	namecheapCmdGetList  = "namecheap.domains.getList"
	namecheapCmdGetHosts = "namecheap.domains.dns.getHosts"
	namecheapCmdSetHosts = "namecheap.domains.dns.setHosts"

	// namecheapChallengeTTL is the TTL on the challenge TXT record, as the string
	// the API takes. 60 is Namecheap's floor; low on purpose, because the record
	// is deleted minutes later and a long TTL would keep resolvers serving a
	// challenge answer after the authorization it belonged to is gone.
	namecheapChallengeTTL = "60"

	// namecheapDefaultMXPref is the MXPref sent for a record whose stored value
	// is absent. Namecheap requires an MXPref on every record in a setHosts call;
	// 10 is its documented default for non-MX records.
	namecheapDefaultMXPref = "10"

	// namecheapPageSize is the getList page size. 100 is Namecheap's documented
	// maximum, so the account is enumerated in as few round-trips as possible.
	namecheapPageSize = 100

	// namecheapMaxPages bounds the getList walk so a hostile or broken paging
	// response cannot loop forever. 100 pages of 100 covers 10,000 domains.
	namecheapMaxPages = 100

	// namecheapHTTPTimeout bounds one API call.
	namecheapHTTPTimeout = 30 * time.Second

	// namecheapMaxBody caps how much of a response is read. A response body is
	// attacker-influenced input; without a cap a hostile or broken endpoint could
	// stream until the process runs out of memory.
	namecheapMaxBody = 1 << 20
)

// ErrNamecheapAPI is returned when the Namecheap API refuses a request or
// answers unusably. It never carries the API key — see [namecheapProvider].
var ErrNamecheapAPI = errors.New("dns01: namecheap api")

// namecheapProvider creates and removes the challenge TXT record through the
// Namecheap API.
//
// # Credential custody
//
// Namecheap authenticates with four values sent on every call: ApiUser, ApiKey,
// UserName and a ClientIp that must be on the account's API allowlist. Only
// ApiKey is a secret — ApiUser and UserName are account handles and ClientIp is
// a public address — but the four are packed into ONE [secrets.Redacted] and
// unwrapped in exactly ONE place, [splitNamecheapCredential], for the same
// reason Route 53 packs its two halves: keeping a single unwrap site means there
// is one line of source that can produce plaintext, rather than a field per
// value each with its own handling rule. The split feeds
// [namecheapProvider.authParams], which writes the values straight into the
// request body. Consequences, mirroring the other providers:
//
//   - This struct implements [fmt.Formatter], so no formatting of it can print
//     the key. That method is required, not decorative: secrets.Redacted's own
//     redaction is bypassed by fmt when the value sits in an UNEXPORTED struct
//     field, because fmt renders such fields by raw reflection and never calls
//     their String, Format or GoString methods.
//   - The type holds no logger and no telemetry handle, so there is no local
//     call site that could emit it.
//   - Every request is a POST whose credentials travel in the FORM BODY, never
//     the URL query. A GET would put ApiKey in the URL, and a transport error's
//     url.Error renders that URL into the error text; keeping the key out of the
//     URL keeps it out of every error and access log along the way.
//
// # Why cleanup re-reads the whole host set instead of capturing an ID
//
// This is the security heart of the provider, and Namecheap's model makes it
// sharper than any other provider here. There is no per-record API and no
// per-record identifier: setHosts REPLACES the domain's ENTIRE host-record set
// in one call. There is no "add one TXT" primitive. So publishing a challenge
// means reading the full current set, appending our one TXT, and re-submitting
// the WHOLE set; removing it means reading the full set again and re-submitting
// it MINUS our one value.
//
// Every record the account holds — A, AAAA, CNAME, MX, TXT, CAA — is therefore
// carried through byte for byte on every write. Dropping one, or getting its
// MXPref or TTL wrong, does not fail: setHosts succeeds and the record is simply
// gone. That is why:
//
//   - A getHosts error, or a domain not served by Namecheap DNS, ABORTS before
//     any setHosts. A setHosts built on a partial or empty read would wipe the
//     zone. This is the analog of the "cleanup after a failed publish submits no
//     change" guarantee the other providers make.
//   - Preserved records are re-sent exactly as getHosts returned them; only our
//     own value is added or removed. The scoping guarantee rests on matching an
//     unforgeable value: the challenge value is the base64url SHA-256 digest of a
//     key authorization computed from this process's ACCOUNT KEY, so no other
//     party's value can equal it, and cleanup removes exactly the value this
//     process published and leaves every other record standing.
//
// The read-modify-write is not atomic. Within this process the solver serializes
// challenges, so the race needs a second writer to the same domain — another
// ACME client, or a second instance of this program validating the same domain
// concurrently. That is called out rather than papered over: Namecheap's
// setHosts is an unconditional whole-set replace with no compare-and-set to
// close it.
//
// # Propagation
//
// Present does not wait for the record to be served. The seam forbids a
// provider-side wait: the solver polls the zone's authoritative nameservers
// once, for every provider, which is a strictly stronger signal than any
// "change applied" flag a vendor could return.
type namecheapProvider struct {
	// credential is the four values packed as
	// "api_user\x00api_key\x00username\x00client_ip". NUL cannot appear in any of
	// them, so the pack is unambiguous, and the whole thing is redacted so the one
	// secret among them (api_key) can never leak — see [splitNamecheapCredential].
	credential secrets.Redacted
	client     *http.Client
}

var _ Provider = (*namecheapProvider)(nil)

// namecheapCredentialSep packs the four credential values into one Redacted. NUL
// is used because it cannot occur in an API user, key, account handle or IP, so
// the split is unambiguous.
const namecheapCredentialSep = "\x00"

// namecheapCredentialFields are the four required named credentials, in the
// order they are packed. The order is the contract splitNamecheapCredential
// unpacks against.
var namecheapCredentialFields = []string{"api_user", "api_key", "username", "client_ip"}

// NewNamecheap builds the provider from the credential set.
//
// Namecheap needs four named values — api_user, api_key, username and client_ip
// — supplied through credentials_refs. There is deliberately no single-value
// packed form for the OPERATOR: four fields colon-packed into one reference would
// be a bespoke encoding to mis-paste, and the named map already expresses this
// shape. Each value is required and must be non-blank; a missing or
// whitespace-only value is refused at construction, where the operator sees it,
// rather than at the first renewal months later. The error names the FIELD, not
// its value.
//
// Internally the four are packed into one [secrets.Redacted] so the plaintext is
// unwrapped in a single place — the same custody model Route 53 uses for its two
// halves. The packed value is parsed once here so a malformed credential fails at
// startup, mirroring Route 53.
//
// A nil client gets a bounded default; the parameter exists so a test can supply
// a transport pointed at a local fake and so an operator's proxy settings can be
// honored later.
func NewNamecheap(creds Credentials, client *http.Client) (Provider, error) {
	parts := make([]secrets.Redacted, len(namecheapCredentialFields))
	for i, name := range namecheapCredentialFields {
		v, ok := creds.Get(name)
		// IsBlank inspects the wrapped value without revealing it, so this refusal
		// keeps the single-unwrap-site guarantee. Whitespace-only counts as blank:
		// it is not a credential.
		if !ok || v.IsBlank() {
			return nil, fmt.Errorf("%w: missing or blank %s credential", ErrNamecheapAPI, name)
		}
		parts[i] = v
	}
	// Join packs without revealing — it operates on the wrapped values — so no
	// plaintext exists between here and the one unwrap site.
	credential := secrets.Join(namecheapCredentialSep, parts...)
	if _, err := splitNamecheapCredential(credential); err != nil {
		return nil, err
	}

	if client == nil {
		client = &http.Client{
			Timeout: namecheapHTTPTimeout,
			// Redirects are REFUSED rather than followed. Following one would send
			// a request carrying the API key to whatever host the response named;
			// no legitimate Namecheap call redirects.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}
	return &namecheapProvider{credential: credential, client: client}, nil
}

// namecheapCredentials is the unpacked four-value credential.
type namecheapCredentials struct {
	apiUser, apiKey, userName, clientIP string
}

// splitNamecheapCredential unpacks the four values. This is the ONLY function in
// the file that reveals the credential, and the values it returns are written
// straight into a request body by [namecheapProvider.authParams] and nowhere
// else. Each value is trimmed, because a file-backed secret commonly carries a
// trailing newline and an untrimmed newline in a form field is a request-splitting
// shape; the parse is strict — four non-empty parts — and its error names none of
// them.
func splitNamecheapCredential(c secrets.Redacted) (namecheapCredentials, error) {
	parts := strings.Split(c.Reveal(), namecheapCredentialSep)
	if len(parts) != len(namecheapCredentialFields) {
		return namecheapCredentials{}, fmt.Errorf("%w: malformed packed credential", ErrNamecheapAPI)
	}
	out := namecheapCredentials{
		apiUser:  strings.TrimSpace(parts[0]),
		apiKey:   strings.TrimSpace(parts[1]),
		userName: strings.TrimSpace(parts[2]),
		clientIP: strings.TrimSpace(parts[3]),
	}
	if out.apiUser == "" || out.apiKey == "" || out.userName == "" || out.clientIP == "" {
		return namecheapCredentials{}, fmt.Errorf("%w: incomplete packed credential", ErrNamecheapAPI)
	}
	return out, nil
}

// Name identifies the provider. It is a constant, never derived from the
// credential.
func (p *namecheapProvider) Name() string { return "namecheap" }

// Format renders the provider as a constant under every fmt verb, so no
// formatting of this value can print the API key.
//
// See the type comment: this is load-bearing. Without it, "%+v" of this struct
// prints the key in full, because fmt walks unexported fields by reflection and
// never calls their redaction methods. "%#v" routes through Formatter too when
// the operand implements it.
func (p *namecheapProvider) Format(f fmt.State, _ rune) {
	_, _ = io.WriteString(f, "dns01.namecheapProvider{apiKey:[REDACTED]}")
}

// Present publishes the challenge value and returns the cleanup that withdraws
// exactly that value.
func (p *namecheapProvider) Present(ctx context.Context, rec Record) (CleanupFunc, error) {
	domain, err := p.domainFor(ctx, rec.Name)
	if err != nil {
		return nil, err
	}
	sld, tld, err := splitDomain(domain)
	if err != nil {
		return nil, err
	}
	host, err := namecheapRecordName(rec.Name, domain)
	if err != nil {
		return nil, err
	}

	// The full current set is read FIRST, and any failure returns before a single
	// setHosts is issued. A setHosts built on a failed or partial read would
	// replace the domain's entire host set with a truncated one — the zone-wipe
	// this ordering exists to prevent.
	hosts, emailType, usingOurDNS, err := p.getHosts(ctx, sld, tld)
	if err != nil {
		return nil, err
	}
	if !usingOurDNS {
		// setHosts against a domain whose DNS is hosted elsewhere is meaningless
		// at best and, at worst, switches the domain onto Namecheap DNS and drops
		// every externally-served record. Refuse rather than write.
		return nil, fmt.Errorf(
			"%w: domain %q is not using namecheap dns; refusing to replace its host records", ErrNamecheapAPI, domain)
	}

	// The cleanup is built BEFORE the write and returned even when the write
	// reports failure, because a failed write can still have applied: a response
	// lost to a timeout or a reset connection leaves the set replaced at Namecheap
	// with nothing here knowing it. Returning nil in that case leaks a standing
	// _acme-challenge TXT record that no code path can withdraw — the seam's
	// contract in dns01.go is explicit that a cleanup MUST come back whenever
	// anything may have been created, including when Present goes on to fail.
	//
	// Returning it early is safe because the closure captures only sld, tld, the
	// host label and the value — all known before the call — and nothing from the
	// response. Returning it when the write never applied is harmless: the
	// closure's first act is a fresh read, and finding its value absent it returns
	// success without issuing any setHosts.
	cleanup := p.removeValue(sld, tld, host, rec.Value)

	updated := hosts
	if namecheapIndexOf(hosts, host, rec.Value) < 0 {
		updated = append(slices.Clone(hosts), namecheapHost{
			Name:    host,
			Type:    "TXT",
			Address: rec.Value,
			MXPref:  namecheapDefaultMXPref,
			TTL:     namecheapChallengeTTL,
		})
	}
	if err := p.setHosts(ctx, sld, tld, emailType, updated); err != nil {
		return cleanup, fmt.Errorf("%w: publish txt value for %q: %w", ErrNamecheapAPI, rec.Name, err)
	}
	return cleanup, nil
}

// removeValue returns the cleanup closure for one published value.
//
// The sld, tld, host label and exact value are CAPTURED. The closure re-reads
// the whole host set because setHosts is a whole-set replace, but it only ever
// subtracts the one captured value — no input to it can widen that, and it can
// never remove a record this process did not publish.
func (p *namecheapProvider) removeValue(sld, tld, host, value string) CleanupFunc {
	return func(ctx context.Context) error {
		hosts, emailType, usingOurDNS, err := p.getHosts(ctx, sld, tld)
		if err != nil {
			return fmt.Errorf("%w: read hosts for cleanup: %w", ErrNamecheapAPI, err)
		}
		if !usingOurDNS {
			// The domain's DNS was moved off Namecheap after the challenge was
			// published. Our record is no longer served from here, and a setHosts
			// now could switch the domain back onto Namecheap DNS and wipe the
			// externally-hosted records. There is nothing safe to do and nothing
			// of ours being served, so report success without writing.
			return nil
		}
		idx := namecheapIndexOf(hosts, host, value)
		if idx < 0 {
			// Already gone is success. Cleanup runs on retry and shutdown paths and
			// may run twice, and the zone is already in the state this call wanted.
			// This is also the path a cleanup returned from a genuinely failed
			// publish takes: our value is absent, so no setHosts is issued.
			return nil
		}
		remaining := slices.Delete(slices.Clone(hosts), idx, idx+1)
		if err := p.setHosts(ctx, sld, tld, emailType, remaining); err != nil {
			return fmt.Errorf("%w: remove txt value: %w", ErrNamecheapAPI, err)
		}
		return nil
	}
}

// domainFor finds the account domain that holds the record name.
//
// Namecheap's getHosts and setHosts address a domain by its SLD and TLD as
// SEPARATE parameters, so the registrable boundary must be known exactly — and
// it cannot be guessed from the record name, because multi-label public suffixes
// like "co.uk" make "the last two labels" wrong. So the account's domains are
// enumerated through getList and the record name is matched against them,
// most-specific (longest) at a LABEL BOUNDARY winning: a delegated
// "eu.example.com" beats its parent "example.com". No match REFUSES loudly
// rather than guessing a split, because guessing would write the challenge into
// a domain the CA never queries, and issuance would fail minutes later with a
// message about DNS rather than about the account.
func (p *namecheapProvider) domainFor(ctx context.Context, recordName string) (string, error) {
	domains, err := p.accountDomains(ctx)
	if err != nil {
		return "", err
	}

	name := strings.ToLower(strings.TrimSuffix(recordName, "."))
	best := ""
	for _, d := range domains {
		cand := strings.ToLower(strings.TrimSuffix(d, "."))
		if name == cand || strings.HasSuffix(name, "."+cand) {
			if len(cand) > len(best) {
				best = cand
			}
		}
	}
	if best == "" {
		return "", fmt.Errorf("%w: no domain in the account matches %q", ErrNamecheapAPI, recordName)
	}
	if !validDomainName(best) {
		// A domain name reaches the SLD/TLD split and the form body; a value that
		// is not a plain domain name is refused rather than sent.
		return "", fmt.Errorf("%w: malformed account domain %q", ErrNamecheapAPI, best)
	}
	return best, nil
}

// accountDomains enumerates every domain in the account through getList,
// following the paging cursor to a bounded cap.
func (p *namecheapProvider) accountDomains(ctx context.Context) ([]string, error) {
	var domains []string
	for page := 1; page <= namecheapMaxPages; page++ {
		params := url.Values{}
		params.Set("Command", namecheapCmdGetList)
		params.Set("Page", strconv.Itoa(page))
		params.Set("PageSize", strconv.Itoa(namecheapPageSize))

		var resp namecheapGetListResponse
		if err := p.do(ctx, params, &resp); err != nil {
			return nil, fmt.Errorf("%w: list account domains: %w", ErrNamecheapAPI, err)
		}
		for _, d := range resp.Domains {
			if d.Name != "" {
				domains = append(domains, d.Name)
			}
		}
		// Stop when the pages seen cover the reported total, or a page came back
		// empty (a defensive guard against a total that never catches up).
		if len(resp.Domains) == 0 || len(domains) >= resp.Paging.TotalItems {
			break
		}
	}
	return domains, nil
}

// getHosts reads a domain's complete host-record set, its email routing type and
// whether Namecheap is authoritative for it.
//
// The EmailType is read so it can be echoed back on setHosts: setHosts takes an
// EmailType, and re-submitting the set without the current one could silently
// change the domain's mail routing. IsUsingOurDNS is read so the caller can
// refuse to replace the host set of a domain served elsewhere.
func (p *namecheapProvider) getHosts(ctx context.Context, sld, tld string) (hosts []namecheapHost, emailType string, usingOurDNS bool, err error) {
	params := url.Values{}
	params.Set("Command", namecheapCmdGetHosts)
	params.Set("SLD", sld)
	params.Set("TLD", tld)

	var resp namecheapGetHostsResponse
	if err := p.do(ctx, params, &resp); err != nil {
		return nil, "", false, fmt.Errorf("%w: read hosts for %q: %w", ErrNamecheapAPI, sld+"."+tld, err)
	}
	return resp.Result.Hosts, resp.Result.EmailType, strings.EqualFold(resp.Result.IsUsingOurDNS, "true"), nil
}

// setHosts replaces the domain's entire host-record set with exactly hosts.
//
// Every record is re-sent with the fields Namecheap requires — HostName,
// RecordType, Address, MXPref and TTL, 1-indexed — so a preserved record keeps
// its type, value, mail priority and TTL. A record whose stored MXPref or TTL is
// empty is given the documented defaults rather than an empty field the API
// would reject.
//
// When hosts is empty the call clears every host record, which is the intended
// end state on the exotic path where the challenge TXT was the domain's only
// record; a real DNS-hosted domain always carries other records, so cleanup
// normally re-sends a non-empty set.
func (p *namecheapProvider) setHosts(ctx context.Context, sld, tld, emailType string, hosts []namecheapHost) error {
	params := url.Values{}
	params.Set("Command", namecheapCmdSetHosts)
	params.Set("SLD", sld)
	params.Set("TLD", tld)
	if emailType != "" {
		params.Set("EmailType", emailType)
	}
	for i, h := range hosts {
		n := strconv.Itoa(i + 1)
		params.Set("HostName"+n, h.Name)
		params.Set("RecordType"+n, h.Type)
		params.Set("Address"+n, h.Address)
		mxPref := h.MXPref
		if mxPref == "" {
			mxPref = namecheapDefaultMXPref
		}
		params.Set("MXPref"+n, mxPref)
		ttl := h.TTL
		if ttl == "" {
			ttl = namecheapChallengeTTL
		}
		params.Set("TTL"+n, ttl)
	}

	var resp namecheapSetHostsResponse
	if err := p.do(ctx, params, &resp); err != nil {
		return err
	}
	if !strings.EqualFold(resp.Result.IsSuccess, "true") {
		return fmt.Errorf("%w: sethosts reported no success", ErrNamecheapAPI)
	}
	return nil
}

// namecheapIndexOf returns the position of the TXT record at host with the given
// value, or -1. The match is on the host label (case-insensitively), the TXT
// type, and the exact value, tolerating one pair of surrounding quotes on the
// stored side — DNS presents TXT content quoted and it is not guaranteed which
// form the API echoes back. The tolerance is in the safe direction: it can only
// recognize the SAME unforgeable digest in the other spelling, never widen the
// match to a value this process did not publish.
func namecheapIndexOf(hosts []namecheapHost, host, value string) int {
	for i, h := range hosts {
		if strings.EqualFold(h.Name, host) && strings.EqualFold(h.Type, "TXT") && namecheapUnquote(h.Address) == value {
			return i
		}
	}
	return -1
}

// namecheapUnquote strips one pair of surrounding double quotes for comparison.
// It is used ONLY to match this process's own value; kept records are re-sent in
// their original form, so no other record is rewritten by it.
func namecheapUnquote(v string) string {
	if len(v) >= 2 && v[0] == '"' && v[len(v)-1] == '"' {
		return v[1 : len(v)-1]
	}
	return v
}

// splitDomain splits a registrable domain into the SLD (first label) and TLD
// (the remainder) the API addresses separately. "example.co.uk" splits into
// "example" and "co.uk". The domain has already been matched from the account
// list and validated as a plain domain name, so this only has to find the first
// label boundary and refuse a value with no interior dot.
func splitDomain(domain string) (sld, tld string, err error) {
	domain = strings.TrimSuffix(domain, ".")
	idx := strings.IndexByte(domain, '.')
	if idx <= 0 || idx >= len(domain)-1 {
		return "", "", fmt.Errorf("%w: %q is not a registrable domain", ErrNamecheapAPI, domain)
	}
	return domain[:idx], domain[idx+1:], nil
}

// namecheapRecordName converts the fully qualified record name into the host
// label Namecheap stores, which is relative to the domain (the apex is "@"). The
// label-boundary split is shared with the other providers; a name that does not
// sit inside the resolved domain is refused rather than written.
func namecheapRecordName(fqdn, domain string) (string, error) {
	relative, err := relativeRecordName(fqdn, domain)
	if err != nil {
		return "", fmt.Errorf("%w: record %q is not inside domain %q", ErrNamecheapAPI, fqdn, domain)
	}
	return relative, nil
}

// authParams builds the four credential parameters sent on every call.
//
// The values come from [splitNamecheapCredential], the single unwrap site, and
// are written straight into form fields that are POSTed in the request body —
// never the URL query — so the key reaches neither an access log nor a transport
// error.
func (p *namecheapProvider) authParams() (url.Values, error) {
	creds, err := splitNamecheapCredential(p.credential)
	if err != nil {
		return nil, err
	}
	v := url.Values{}
	v.Set("ApiUser", creds.apiUser)
	v.Set("ApiKey", creds.apiKey)
	v.Set("UserName", creds.userName)
	v.Set("ClientIp", creds.clientIP)
	return v, nil
}

// do performs one API call and decodes its result into out.
//
// Every call is a POST to the single endpoint with the credentials and the
// command parameters in the form body. Namecheap answers HTTP 200 even when it
// rejects a request, carrying the outcome in the ApiResponse Status attribute,
// so success is the Status attribute reading "OK" — an HTTP 2xx alone is not
// enough. The status envelope is decoded first, from its own struct, and only a
// success is decoded into the caller's payload struct.
func (p *namecheapProvider) do(ctx context.Context, params url.Values, out any) error {
	body, err := p.authParams()
	if err != nil {
		return err
	}
	for k, vs := range params {
		for _, v := range vs {
			body.Set(k, v)
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, namecheapEndpoint, strings.NewReader(body.Encode()))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "text/xml")

	resp, err := p.client.Do(req)
	if err != nil {
		// The transport error is wrapped as-is. url.Error renders the request URL,
		// which is the bare endpoint with no query — the credentials are in the
		// body, so nothing here carries them.
		return fmt.Errorf("request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, namecheapMaxBody))
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("request rejected (http %d)", resp.StatusCode)
	}

	// The status envelope is decoded first. An unparseable body is NOT quoted into
	// the error: a response from something impersonating the API is
	// attacker-controlled text, and echoing it into logs is how log injection
	// starts. The status code is the diagnostic.
	var hdr namecheapHeader
	if err := xml.Unmarshal(raw, &hdr); err != nil {
		return fmt.Errorf("unparseable response (http %d)", resp.StatusCode)
	}
	if !strings.EqualFold(hdr.Status, "OK") {
		return namecheapError(hdr.Errors)
	}
	if out != nil {
		if err := xml.Unmarshal(raw, out); err != nil {
			return fmt.Errorf("unparseable response (http %d)", resp.StatusCode)
		}
	}
	return nil
}

// namecheapError renders the API's own error, using only its number and message.
//
// The message is bounded because it is remote input, treated as a bounded
// diagnostic rather than as trusted text, and the bound goes through
// [safetext.Bound] rather than a slice expression so a fixed byte cut cannot
// leave invalid UTF-8 for the log encoder downstream. Namecheap never echoes the
// API key in an error, and nothing here would put it there if it did.
func namecheapError(errs []namecheapAPIError) error {
	if len(errs) == 0 {
		return fmt.Errorf("%w: request rejected", ErrNamecheapAPI)
	}
	e := errs[0]
	msg := safetext.Bound(strings.TrimSpace(e.Description), maxAPIMessageBytes)
	if e.Number != "" {
		return fmt.Errorf("%w: request rejected (error %s): %s", ErrNamecheapAPI, e.Number, msg)
	}
	return fmt.Errorf("%w: request rejected: %s", ErrNamecheapAPI, msg)
}

// namecheapHeader is the ApiResponse status envelope. It is decoded on its own
// from every response so do can check the Status attribute before trusting any
// payload; the payload structs below therefore omit it.
type namecheapHeader struct {
	XMLName xml.Name            `xml:"ApiResponse"`
	Status  string              `xml:"Status,attr"`
	Errors  []namecheapAPIError `xml:"Errors>Error"`
}

// namecheapAPIError is one entry from the Errors block. The message is chardata
// — Namecheap's error text — not the credential.
type namecheapAPIError struct {
	Number      string `xml:"Number,attr"`
	Description string `xml:",chardata"`
}

// namecheapHost is one host record. Every field is an attribute on the <host>
// element, and every field is re-sent on setHosts, so a preserved record keeps
// its type, value, mail priority and TTL.
type namecheapHost struct {
	Name    string `xml:"Name,attr"`
	Type    string `xml:"Type,attr"`
	Address string `xml:"Address,attr"`
	MXPref  string `xml:"MXPref,attr"`
	TTL     string `xml:"TTL,attr"`
}

// The XML shapes below are the subset of the API this provider uses. Only the
// fields actually read are declared; encoding/xml ignores the rest and matches
// on local element name, so the response namespace is not restated here.

type namecheapGetHostsResponse struct {
	Result struct {
		Domain        string          `xml:"Domain,attr"`
		EmailType     string          `xml:"EmailType,attr"`
		IsUsingOurDNS string          `xml:"IsUsingOurDNS,attr"`
		Hosts         []namecheapHost `xml:"host"`
	} `xml:"CommandResponse>DomainDNSGetHostsResult"`
}

type namecheapSetHostsResponse struct {
	Result struct {
		IsSuccess string `xml:"IsSuccess,attr"`
	} `xml:"CommandResponse>DomainDNSSetHostsResult"`
}

type namecheapGetListResponse struct {
	Domains []struct {
		Name string `xml:"Name,attr"`
	} `xml:"CommandResponse>DomainGetListResult>Domain"`
	Paging struct {
		TotalItems int `xml:"TotalItems"`
	} `xml:"CommandResponse>Paging"`
}
