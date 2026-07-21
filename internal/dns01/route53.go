package dns01

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/safetext"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/secrets"
)

const (
	// route53Endpoint is the global Route 53 endpoint. Route 53 is not a
	// regional service: there is one control plane, always signed for
	// us-east-1. It is a constant rather than configurable for the same reason
	// Cloudflare's base is — a settable endpoint is a way to point a
	// zone-editing credential at an attacker's server.
	route53Endpoint = "https://route53.amazonaws.com"

	// route53APIPrefix is the API version path segment.
	route53APIPrefix = "/2013-04-01"

	// route53SigningRegion and route53Service are the SigV4 scope. Both are
	// fixed by the service, not by the deployment.
	route53SigningRegion = "us-east-1"
	route53Service       = "route53"

	// route53ChallengeTTL is the TTL on the challenge record. Low on purpose:
	// the record is deleted minutes later, and a long TTL would keep resolvers
	// serving a challenge answer after the authorization it belonged to is
	// gone.
	route53ChallengeTTL = 60

	// route53HTTPTimeout bounds one API call.
	route53HTTPTimeout = 30 * time.Second

	// route53MaxBody caps how much of a response is read. A response body is
	// attacker-influenced input; without a cap a hostile or broken endpoint
	// could stream until the process runs out of memory.
	route53MaxBody = 1 << 20
)

// ErrRoute53API is returned when the Route 53 API refuses a request or answers
// unusably. It never carries the credential — see [route53Provider].
var ErrRoute53API = errors.New("dns01: route53 api")

// ErrRoute53AmbiguousZone is returned when more than one public hosted zone
// matches the name being validated.
//
// It is a separate error because it is a configuration fault with a specific
// remedy, and because the alternative — picking one — is the failure this
// provider most needs to avoid. An AWS account may legitimately hold two public
// hosted zones with the same name; only one of them is the one the registrar's
// delegation actually points at. Writing the challenge record into the other
// one succeeds at the API level, reaches INSYNC, and is never seen by the CA,
// so issuance fails ten minutes later at the propagation gate with a message
// about DNS rather than about the account. Refusing here names the real
// problem while the operator can still fix it.
var ErrRoute53AmbiguousZone = errors.New("dns01: route53 ambiguous hosted zone")

// route53Provider creates and removes the challenge TXT record through the
// Route 53 API.
//
// # Credential custody
//
// The seam hands a provider ONE [secrets.Redacted]. Route 53 needs two values,
// so the credential is packed as "ACCESS_KEY_ID:SECRET_ACCESS_KEY" and split
// after unwrapping. The whole packed string is held redacted rather than only
// the secret half: the access key ID is not itself a secret — it travels in
// cleartext in every Authorization header — but keeping the pair together means
// there is exactly one unwrap site to audit instead of two fields with
// different handling rules.
//
// The unwrap happens in exactly one place, [route53Provider.do], immediately
// before signing. Consequences, mirroring the Cloudflare provider:
//
//   - This struct implements [fmt.Formatter], so no formatting of it can print
//     the credential. That method is required, not decorative:
//     secrets.Redacted's own redaction is bypassed by fmt when the value sits
//     in an UNEXPORTED struct field, because fmt renders such fields by raw
//     reflection and never calls their String, Format or GoString methods.
//   - The type holds no logger and no telemetry handle, so there is no local
//     call site that could emit it.
//   - Errors are built from the record name and Route 53's own error code. The
//     request is never rendered into an error, because a rendered
//     *http.Request includes its Authorization header.
//
// # Why cleanup re-reads instead of capturing an ID
//
// This is the one place the Route 53 provider cannot follow Cloudflare's shape,
// and the reason is in the API. Route 53 has no per-record identifiers: a
// resource record set is keyed by (name, type) and holds a SET of values.
// CREATE fails outright if the set already exists, and DELETE requires the
// caller to submit the exact, complete current value set.
//
// That matters because a single ACME order legitimately needs two TXT values at
// one name. A certificate covering both "example.com" and "*.example.com" puts
// both challenges at "_acme-challenge.example.com" with different digests —
// [ChallengeRecordName] strips the wildcard prefix precisely because RFC 8555
// says so. A naive CREATE would fail on the second challenge, and a naive
// UPSERT would silently discard the first one's value.
//
// So Present reads the current set and UPSERTs the union, and cleanup reads the
// current set and writes back the difference — deleting the set outright only
// when the value it created was the last one in it. The scoping guarantee is
// preserved by SET SUBTRACTION rather than by an opaque ID: cleanup removes the
// exact value this process published and leaves every other value in place,
// so it still cannot remove a record it did not create, including an operator's
// own TXT record at the same name.
//
// The read-modify-write is not atomic. Within this process the solver
// serializes challenges, so the race needs a second writer to the same name in
// the same zone — another ACME client, or a second instance of this program
// validating the same domain concurrently. That is called out rather than
// papered over: Route 53 offers no conditional write to close it.
type route53Provider struct {
	credential secrets.Redacted
	client     *http.Client

	// now is injectable so the SigV4 timestamp is deterministic in tests. It is
	// not configurable at runtime.
	now func() time.Time
}

var _ Provider = (*route53Provider)(nil)

// NewRoute53 builds the provider from the credential set.
//
// Route 53 needs two values. The named form supplies them as access_key_id and
// secret_access_key; the back-compat single form supplies them colon-packed as
// "ACCESS_KEY_ID:SECRET_ACCESS_KEY". Both are normalized to the packed shape by
// route53Credential, so the provider keeps exactly one stored value and one
// unwrap site (do), which is the custody model the type comment describes.
//
// A nil client gets a bounded default; the parameter exists so a test can
// supply a transport pointed at a local fake and so an operator's proxy
// settings can be honored later.
func NewRoute53(creds Credentials, client *http.Client) (Provider, error) {
	credential, err := route53Credential(creds)
	if err != nil {
		return nil, err
	}
	// Parsed once at construction so a malformed credential fails at startup,
	// where the operator sees it, rather than at the first renewal months
	// later. The parsed halves are deliberately NOT stored — only the check
	// runs here; the split happens again at signing time inside the single
	// unwrap site.
	if _, _, err := splitAWSCredential(credential); err != nil {
		return nil, err
	}
	if client == nil {
		client = &http.Client{
			Timeout: route53HTTPTimeout,
			// Redirects are REFUSED rather than followed. A SigV4 signature is
			// bound to the host and path it was computed for, so a redirect
			// cannot replay it usefully — but following one would still send a
			// request built for the Route 53 API to whatever host the response
			// named, and no legitimate Route 53 call redirects.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}
	return &route53Provider{credential: credential, client: client, now: time.Now}, nil
}

// route53Credential normalizes the credential set into the single packed
// "ACCESS_KEY_ID:SECRET_ACCESS_KEY" form the provider stores and splits at
// signing time.
//
// Precedence is explicit rather than a fall-through, because a lenient fallback
// here would be a security bug:
//
//   - Both named halves present -> use them. They are packed with a colon
//     through secrets.Join so the one downstream unwrap site (splitAWSCredential
//     in do) is unchanged and this file keeps no Reveal of its own. AWS
//     access-key IDs and secrets do not contain a colon, so the repack is
//     unambiguous; an id that does contain one is operator error that fails
//     visibly at AWS, never a silent cross-credential mix.
//   - Exactly one named half present -> REFUSE. The missing half cannot be
//     inferred, and colon-splitting a lone access_key_id would tear an operator
//     value into the wrong parts. The error names neither half.
//   - Neither named half -> fall back to the single packed reference via
//     Single(). An empty set yields ok=false and is refused.
func route53Credential(creds Credentials) (secrets.Redacted, error) {
	id, idOK := creds.Get("access_key_id")
	secret, secretOK := creds.Get("secret_access_key")

	switch {
	case idOK && secretOK:
		return secrets.Join(":", id, secret), nil
	case idOK != secretOK:
		return "", fmt.Errorf(
			"%w: named credentials need both access_key_id and secret_access_key", ErrRoute53API)
	default:
		packed, ok := creds.Single()
		if !ok {
			return "", fmt.Errorf("%w: no credential supplied", ErrRoute53API)
		}
		return packed, nil
	}
}

// splitAWSCredential parses the packed credential.
//
// The parse is strict — exactly two non-empty halves — and its error names
// neither half. A lenient parse here would be a security bug rather than a
// convenience: a credential accidentally supplied as just a secret, or with a
// stray newline from a file-backed secret provider, would otherwise be signed
// with silently and fail as an opaque 403 from AWS.
func splitAWSCredential(credential secrets.Redacted) (keyID, secret string, err error) {
	raw := strings.TrimSpace(credential.Reveal())
	keyID, secret, found := strings.Cut(raw, ":")
	if !found || strings.TrimSpace(keyID) == "" || strings.TrimSpace(secret) == "" {
		return "", "", fmt.Errorf(
			"%w: credential must be %q with both halves non-empty", ErrRoute53API, "ACCESS_KEY_ID:SECRET_ACCESS_KEY")
	}
	return strings.TrimSpace(keyID), strings.TrimSpace(secret), nil
}

// Name identifies the provider. It is a constant, never derived from the
// credential.
func (p *route53Provider) Name() string { return "route53" }

// Format renders the provider as a constant under every fmt verb, so no
// formatting of this value can print the credential.
//
// See the type comment: this is load-bearing. Without it, "%+v" of this struct
// prints the packed access key and secret in full, because fmt walks unexported
// fields by reflection and never calls their redaction methods. "%#v" routes
// through Formatter too when the operand implements it.
func (p *route53Provider) Format(f fmt.State, _ rune) {
	_, _ = io.WriteString(f, "dns01.route53Provider{credential:[REDACTED]}")
}

// Present publishes the challenge value and returns the cleanup that withdraws
// exactly that value.
//
// It deliberately does NOT wait for the change to reach INSYNC. See
// [route53Provider.changeRecords] for why that wait would be both redundant and
// weaker than the gate the solver already applies.
func (p *route53Provider) Present(ctx context.Context, rec Record) (CleanupFunc, error) {
	zoneID, err := p.hostedZoneID(ctx, rec.Name)
	if err != nil {
		return nil, err
	}

	fqdn := rec.Name + "."
	existing, ttl, err := p.currentTXT(ctx, zoneID, fqdn)
	if err != nil {
		return nil, err
	}

	values := existing
	if !slices.Contains(values, rec.Value) {
		values = append(slices.Clone(existing), rec.Value)
	}
	if ttl <= 0 {
		ttl = route53ChallengeTTL
	}

	// The cleanup is built BEFORE the write and returned even when the write
	// reports failure, because a failed write can still have applied: a
	// response lost to a timeout or a reset connection leaves the change
	// committed at AWS with nothing here knowing it. Returning nil in that case
	// leaks a standing _acme-challenge TXT record that no code path can
	// withdraw — the seam's contract in dns01.go is explicit that a cleanup
	// MUST come back whenever anything may have been created, including when
	// Present goes on to fail, and the solver registers it on exactly that
	// path.
	//
	// Returning it early is safe here only because the closure captures
	// zoneID, fqdn and the value — all known before the call — and nothing
	// from the response. And returning it when the write genuinely never
	// applied is harmless because the closure's first act is a read: finding
	// its value absent, it returns success without submitting any change. So
	// the pessimistic case costs one GET and cannot disturb a concurrent
	// challenge at the same name.
	cleanup := p.removeValue(zoneID, fqdn, rec.Value)

	if err := p.changeRecords(ctx, zoneID, "UPSERT", fqdn, ttl, values); err != nil {
		return cleanup, fmt.Errorf("%w: publish txt value for %q: %w", ErrRoute53API, rec.Name, err)
	}
	return cleanup, nil
}

// removeValue returns the cleanup closure for one published value.
//
// The zone, name and the exact value are CAPTURED. The closure re-reads the
// record set because Route 53's delete requires the full current set, but it
// only ever subtracts the one captured value — no input to it can widen that,
// and it can never remove a value this process did not publish.
func (p *route53Provider) removeValue(zoneID, fqdn, value string) CleanupFunc {
	return func(ctx context.Context) error {
		existing, ttl, err := p.currentTXT(ctx, zoneID, fqdn)
		if err != nil {
			return fmt.Errorf("%w: read txt record for cleanup: %w", ErrRoute53API, err)
		}
		if !slices.Contains(existing, value) {
			// Already gone is success. Cleanup runs on retry and shutdown
			// paths, so it must be idempotent, and the zone is already in the
			// state this call wanted to reach.
			return nil
		}

		remaining := slices.DeleteFunc(slices.Clone(existing), func(v string) bool { return v == value })

		action, values := "UPSERT", remaining
		if len(remaining) == 0 {
			// Nothing of ours or anyone else's is left, so the set itself goes.
			// DELETE must submit the exact current contents, which is why the
			// values read back a moment ago are sent rather than a synthesized
			// set.
			action, values = "DELETE", existing
		}

		if err := p.changeRecords(ctx, zoneID, action, fqdn, ttl, values); err != nil {
			return fmt.Errorf("%w: remove txt value: %w", ErrRoute53API, err)
		}
		return nil
	}
}

// hostedZoneID finds the single public hosted zone that should hold the record.
//
// Candidate suffixes are tried most-specific-first, exactly as the Cloudflare
// provider does, so a delegated "eu.example.com" wins over its parent
// "example.com" — writing to the parent would put the record in a zone that is
// not authoritative for the name.
//
// Two Route 53 specifics are handled here and are the security content of this
// function:
//
//   - PRIVATE hosted zones are discarded. A private zone is visible only inside
//     its associated VPCs; the CA queries the public internet. A challenge
//     record written into a private zone is accepted, reaches INSYNC, and is
//     never seen. Private zones are common in accounts that also hold the
//     public zone for the same name, which is exactly when this matters.
//   - More than one surviving match REFUSES. AWS permits several public hosted
//     zones with the same name, and only the one the registrar delegates to is
//     real. Picking the first would be a coin flip resolved silently.
func (p *route53Provider) hostedZoneID(ctx context.Context, recordName string) (string, error) {
	name := strings.TrimSuffix(recordName, ".")

	for range maxZoneLabels {
		idx := strings.IndexByte(name, '.')
		if idx < 0 {
			break
		}
		name = name[idx+1:]
		if !strings.Contains(name, ".") {
			// A single label is a TLD; no account hosts a zone there and
			// querying it only spends an API call.
			break
		}

		matches, err := p.publicZonesNamed(ctx, name)
		if err != nil {
			return "", err
		}
		switch len(matches) {
		case 0:
			continue
		case 1:
			return matches[0], nil
		default:
			return "", fmt.Errorf("%w: %d public hosted zones named %q; "+
				"remove the duplicate or the challenge record may be written to the zone the registrar does not delegate to",
				ErrRoute53AmbiguousZone, len(matches), name)
		}
	}
	return "", fmt.Errorf("%w: no public hosted zone found for %q", ErrRoute53API, recordName)
}

// publicZonesNamed returns the IDs of the public hosted zones named exactly
// zoneName.
//
// ListHostedZonesByName returns zones ordered lexicographically STARTING at the
// requested name, not only zones matching it, so the response routinely
// contains unrelated zones that sort after the query. Filtering on an exact
// name match is therefore required for correctness, not defensive tidiness:
// trusting the first entry would select whatever zone happens to sort next when
// the requested name does not exist at all.
func (p *route53Provider) publicZonesNamed(ctx context.Context, zoneName string) ([]string, error) {
	var out listHostedZonesByNameResponse
	path := route53APIPrefix + "/hostedzonesbyname?dnsname=" + uriEncode(zoneName+".")
	if err := p.do(ctx, http.MethodGet, path, nil, &out); err != nil {
		return nil, fmt.Errorf("%w: look up hosted zone %q: %w", ErrRoute53API, zoneName, err)
	}

	var ids []string
	for _, z := range out.HostedZones {
		if !strings.EqualFold(strings.TrimSuffix(z.Name, "."), zoneName) {
			continue
		}
		if z.Config.PrivateZone {
			continue
		}
		id := strings.TrimPrefix(z.ID, "/hostedzone/")
		if !validZoneID(id) {
			// A zone ID that is not the shape AWS documents is not
			// interpolated into a request path. The ID reaches a URL, so this
			// is the check that stops a hostile or confused response from
			// steering a signed, credentialed request at another resource.
			return nil, fmt.Errorf("%w: malformed hosted zone id in response", ErrRoute53API)
		}
		ids = append(ids, id)
	}
	return ids, nil
}

// validZoneID reports whether id is the opaque alphanumeric identifier Route 53
// documents. It exists to keep a response value from escaping into a URL path.
func validZoneID(id string) bool {
	if id == "" || len(id) > 64 {
		return false
	}
	for i := range len(id) {
		c := id[i]
		isAlnum := (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
		if !isAlnum {
			return false
		}
	}
	return true
}

// currentTXT returns the TXT values currently published at fqdn and their TTL.
//
// A missing record set is not an error: it is the normal state before the first
// challenge, and it reports as an empty slice.
func (p *route53Provider) currentTXT(ctx context.Context, zoneID, fqdn string) ([]string, int, error) {
	var out listResourceRecordSetsResponse
	path := fmt.Sprintf("%s/hostedzone/%s/rrset?name=%s&type=TXT&maxitems=1",
		route53APIPrefix, zoneID, uriEncode(fqdn))
	if err := p.do(ctx, http.MethodGet, path, nil, &out); err != nil {
		return nil, 0, fmt.Errorf("%w: list txt records for %q: %w", ErrRoute53API, fqdn, err)
	}

	for _, rrset := range out.ResourceRecordSets {
		// The listing starts AT the requested name and continues past it, so
		// the returned set must be confirmed to be the one asked for. Without
		// this check an empty name would read as "the next record set in the
		// zone", and cleanup would then compute a difference against an
		// unrelated record and write it back.
		if !strings.EqualFold(rrset.Name, fqdn) || rrset.Type != "TXT" {
			continue
		}
		values := make([]string, 0, len(rrset.ResourceRecords))
		for _, rr := range rrset.ResourceRecords {
			values = append(values, unquoteTXT(rr.Value))
		}
		return values, rrset.TTL, nil
	}
	return nil, 0, nil
}

// changeRecords submits one ChangeResourceRecordSets action.
//
// # Why this does not wait for the change to reach INSYNC
//
// ChangeResourceRecordSets returns a change ID whose status goes PENDING then
// INSYNC, and polling GetChange until INSYNC is the conventional thing to do.
// It is omitted deliberately, for two independent reasons.
//
// First, the seam forbids it: a provider must not wait for propagation, because
// that check is common to every provider and is performed once by the solver.
//
// Second — and this is the part worth stating — the solver's gate is not merely
// an alternative to INSYNC, it is a STRICTLY STRONGER signal for this purpose.
// The gate queries the zone's authoritative nameservers directly and returns
// only values that ALL of them serve. For a zone hosted here, those
// authoritative nameservers ARE the Route 53 fleet, so "every authoritative
// server is serving this value" already entails "the change is in sync"; the
// converse does not hold. Worse, INSYNC can report success in exactly the case
// that most needs catching: a change written to a PRIVATE hosted zone, or to a
// public zone the registrar does not delegate to, reaches INSYNC promptly while
// the nameservers the CA actually queries never serve it. INSYNC answers "the
// servers in my account agree"; the gate answers "the value is being served
// where the CA will look". Only the second is the question issuance turns on.
//
// So GetChange is not called, and route53:GetChange is not in the documented
// IAM policy.
func (p *route53Provider) changeRecords(ctx context.Context, zoneID, action, fqdn string, ttl int, values []string) error {
	records := make([]resourceRecord, 0, len(values))
	for _, v := range values {
		records = append(records, resourceRecord{Value: quoteTXT(v)})
	}

	body, err := xml.Marshal(changeResourceRecordSetsRequest{
		Batch: changeBatch{
			Comment: "sshpilot-vallet ACME DNS-01 challenge",
			Changes: []change{{
				Action: action,
				RecordSet: resourceRecordSet{
					Name:            fqdn,
					Type:            "TXT",
					TTL:             ttl,
					ResourceRecords: records,
				},
			}},
		},
	})
	if err != nil {
		return fmt.Errorf("encode change batch: %w", err)
	}

	path := route53APIPrefix + "/hostedzone/" + zoneID + "/rrset/"
	return p.do(ctx, http.MethodPost, path, body, nil)
}

// quoteTXT renders a value as Route 53 stores TXT content: a quoted string.
//
// The ACME challenge value is a base64url SHA-256 digest — 43 characters of
// [A-Za-z0-9_-] — so it contains nothing needing escaping and cannot exceed the
// 255-byte per-string limit. Quotes and backslashes are escaped regardless
// rather than assumed absent, because this function's correctness should not
// depend on a caller's value shape.
func quoteTXT(v string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`)
	return `"` + r.Replace(v) + `"`
}

// unquoteTXT reverses quoteTXT for values read back from the API, so the
// comparison cleanup makes is against the value as this package knows it.
func unquoteTXT(v string) string {
	if len(v) >= 2 && strings.HasPrefix(v, `"`) && strings.HasSuffix(v, `"`) {
		v = v[1 : len(v)-1]
	}
	return strings.NewReplacer(`\\`, `\`, `\"`, `"`).Replace(v)
}

// do performs one signed API call and decodes its result.
//
// This is the ONLY function in the package that reveals the Route 53
// credential, and it does so into a signature computation whose output is an
// Authorization header that is never logged, never stored, and never rendered
// into an error.
func (p *route53Provider) do(ctx context.Context, method, path string, body []byte, out any) error {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, route53Endpoint+path, reader)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/xml")
	}

	keyID, secret, err := splitAWSCredential(p.credential)
	if err != nil {
		return err
	}
	if err := signV4(req, body, keyID, secret, route53SigningRegion, route53Service, p.now()); err != nil {
		return err
	}

	resp, err := p.client.Do(req)
	if err != nil {
		// The transport error is wrapped as-is. url.Error renders the request
		// URL, which carries no credential: the signature travels in a header,
		// and the path holds only a zone ID and a record name.
		return fmt.Errorf("request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, route53MaxBody))
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return route53Error(resp.StatusCode, raw)
	}
	if out == nil {
		return nil
	}
	if err := xml.Unmarshal(raw, out); err != nil {
		// The body is NOT quoted into the error. An unparseable response from
		// something impersonating the API is attacker-controlled text, and
		// echoing it into logs is how log injection starts. The status code is
		// the diagnostic.
		return fmt.Errorf("unparseable response (http %d)", resp.StatusCode)
	}
	return nil
}

// route53Error renders the API's own error, using only its structured code and
// message.
//
// The message is truncated because it is remote input, treated as a bounded
// diagnostic rather than as trusted text. Route 53 never echoes a credential in
// an error, and nothing here would put one there if it did.
//
// The bound goes through [safetext.Bound] rather than a slice expression. A
// fixed BYTE cut can land in the middle of a multi-byte UTF-8 sequence and
// leave a fragment that is not valid UTF-8, which the JSON log encoder
// downstream then mangles. No credential is spliced into this message before
// the cut, so there is no scrub whose ordering against the truncation matters
// here.
func route53Error(status int, raw []byte) error {
	var env route53ErrorResponse
	if err := xml.Unmarshal(raw, &env); err != nil || env.Error.Code == "" {
		return fmt.Errorf("request rejected (http %d)", status)
	}
	msg := safetext.Bound(env.Error.Message, maxAPIMessageBytes)
	return fmt.Errorf("request rejected (http %d, code %s): %s", status, env.Error.Code, msg)
}

// The XML shapes below are the subset of the 2013-04-01 API this provider uses.
// Only the fields actually read are declared; encoding/xml ignores the rest.

type listHostedZonesByNameResponse struct {
	HostedZones []struct {
		ID     string `xml:"Id"`
		Name   string `xml:"Name"`
		Config struct {
			PrivateZone bool `xml:"PrivateZone"`
		} `xml:"Config"`
	} `xml:"HostedZones>HostedZone"`
}

type listResourceRecordSetsResponse struct {
	ResourceRecordSets []struct {
		Name            string `xml:"Name"`
		Type            string `xml:"Type"`
		TTL             int    `xml:"TTL"`
		ResourceRecords []struct {
			Value string `xml:"Value"`
		} `xml:"ResourceRecords>ResourceRecord"`
	} `xml:"ResourceRecordSets>ResourceRecordSet"`
}

type route53ErrorResponse struct {
	Error struct {
		Code    string `xml:"Code"`
		Message string `xml:"Message"`
	} `xml:"Error"`
}

type changeResourceRecordSetsRequest struct {
	XMLName xml.Name    `xml:"https://route53.amazonaws.com/doc/2013-04-01/ ChangeResourceRecordSetsRequest"`
	Batch   changeBatch `xml:"ChangeBatch"`
}

type changeBatch struct {
	Comment string   `xml:"Comment,omitempty"`
	Changes []change `xml:"Changes>Change"`
}

type change struct {
	Action    string            `xml:"Action"`
	RecordSet resourceRecordSet `xml:"ResourceRecordSet"`
}

type resourceRecordSet struct {
	Name            string           `xml:"Name"`
	Type            string           `xml:"Type"`
	TTL             int              `xml:"TTL"`
	ResourceRecords []resourceRecord `xml:"ResourceRecords>ResourceRecord"`
}

type resourceRecord struct {
	Value string `xml:"Value"`
}
