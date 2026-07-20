package dns01

import (
	"encoding/xml"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/secrets"
)

// The credential every test in this file hands the provider. Both halves are
// distinctive so a leak into any output is unmistakable.
const (
	testAWSKeyID  = "AKIAVALLETTESTKEYID"
	testAWSSecret = "aws-secret-DO-NOT-LEAK-4d7b1e93"
	testAWSCred   = testAWSKeyID + ":" + testAWSSecret
)

// route53Zone is one hosted zone in the fake account.
type route53Zone struct {
	id      string
	name    string
	private bool
}

// route53API is a local stand-in for the Route 53 2013-04-01 API. No test in
// this package contacts AWS.
//
// It holds real state and APPLIES the changes it receives rather than only
// recording them. That is deliberate: the union-on-publish and
// subtract-on-cleanup logic is the part of this provider most likely to be
// wrong, and a fake that merely records requests would let a provider that
// clobbers a co-existing value pass every test.
type route53API struct {
	t *testing.T

	zones []route53Zone

	// records maps a fully-qualified name to the TXT values currently
	// published at it, mirroring Route 53's set-valued record sets.
	records map[string][]string
	ttls    map[string]int

	// requests records every method+path issued, so a test can assert what the
	// provider did NOT do.
	requests []string

	// changeStatus overrides the response to a change submission, so the
	// API-rejection path can be driven.
	changeStatus int
	// listStatus overrides the response to a record listing.
	listStatus int
}

func newRoute53API(t *testing.T, zones ...route53Zone) (*route53API, *route53Provider) {
	t.Helper()

	if len(zones) == 0 {
		zones = []route53Zone{{id: "Z1PUBLIC", name: "example.com"}}
	}
	api := &route53API{
		t:       t,
		zones:   zones,
		records: map[string][]string{},
		ttls:    map[string]int{},
	}
	srv := httptest.NewServer(api)
	t.Cleanup(srv.Close)

	provider, err := NewRoute53(secrets.NewRedacted(testAWSCred), srv.Client())
	if err != nil {
		t.Fatalf("NewRoute53: %v", err)
	}
	p := provider.(*route53Provider)
	// The endpoint is a constant by design, so the test rewrites the request
	// host in the transport instead of making it configurable — a configurable
	// endpoint is exactly the setting that lets a misconfiguration point a
	// zone-editing credential at another host.
	p.client = &http.Client{Transport: rewriteRoute53Host{srv.URL, srv.Client().Transport}}
	return api, p
}

// rewriteRoute53Host redirects requests for the real endpoint at the local fake.
type rewriteRoute53Host struct {
	base string
	next http.RoundTripper
}

func (r rewriteRoute53Host) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	u, err := req.URL.Parse(r.base + strings.TrimPrefix(req.URL.String(), route53Endpoint))
	if err != nil {
		return nil, err
	}
	clone.URL = u
	clone.Host = u.Host
	next := r.next
	if next == nil {
		next = http.DefaultTransport
	}
	return next.RoundTrip(clone)
}

func (a *route53API) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.requests = append(a.requests, r.Method+" "+r.URL.Path+"?"+r.URL.RawQuery)

	// Every call must be signed with the configured key, and the signature must
	// be a signature — the secret itself must never appear in the header.
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, sigV4Algorithm+" Credential="+testAWSKeyID+"/") {
		a.t.Errorf("Authorization header is not a SigV4 signature for the configured key: %q", auth)
	}
	if strings.Contains(auth, testAWSSecret) {
		a.t.Errorf("the secret access key appears in the Authorization header: %q", auth)
	}

	w.Header().Set("Content-Type", "application/xml")
	switch {
	case r.Method == http.MethodGet && r.URL.Path == route53APIPrefix+"/hostedzonesbyname":
		a.listZones(w, r)
	case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/rrset"):
		a.listRecords(w, r)
	case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/rrset/"):
		a.applyChange(w, r)
	default:
		a.t.Errorf("unexpected request %s %s", r.Method, r.URL)
		w.WriteHeader(http.StatusNotFound)
	}
}

// listZones mimics ListHostedZonesByName, INCLUDING the behavior that makes
// exact-match filtering necessary: the response is every zone that sorts at or
// after the requested name, not only the zones that match it.
func (a *route53API) listZones(w http.ResponseWriter, r *http.Request) {
	want := r.URL.Query().Get("dnsname")

	var b strings.Builder
	b.WriteString(`<ListHostedZonesByNameResponse><HostedZones>`)
	for _, z := range a.zones {
		if z.name+"." < want {
			continue
		}
		fmt.Fprintf(&b,
			`<HostedZone><Id>/hostedzone/%s</Id><Name>%s.</Name><Config><PrivateZone>%t</PrivateZone></Config></HostedZone>`,
			z.id, z.name, z.private)
	}
	b.WriteString(`</HostedZones></ListHostedZonesByNameResponse>`)
	a.write(w, http.StatusOK, b.String())
}

// listRecords mimics ListResourceRecordSets, which likewise returns the record
// sets at or after the requested name.
func (a *route53API) listRecords(w http.ResponseWriter, r *http.Request) {
	if a.listStatus != 0 {
		a.write(w, a.listStatus, `<ErrorResponse><Error><Code>AccessDenied</Code><Message>no</Message></Error></ErrorResponse>`)
		return
	}
	name := r.URL.Query().Get("name")

	var b strings.Builder
	b.WriteString(`<ListResourceRecordSetsResponse><ResourceRecordSets>`)
	if values, ok := a.records[name]; ok {
		fmt.Fprintf(&b, `<ResourceRecordSet><Name>%s</Name><Type>TXT</Type><TTL>%d</TTL><ResourceRecords>`,
			name, a.ttls[name])
		for _, v := range values {
			fmt.Fprintf(&b, `<ResourceRecord><Value>%s</Value></ResourceRecord>`, quoteTXT(v))
		}
		b.WriteString(`</ResourceRecords></ResourceRecordSet>`)
	}
	b.WriteString(`</ResourceRecordSets></ListResourceRecordSetsResponse>`)
	a.write(w, http.StatusOK, b.String())
}

// applyChange executes an UPSERT or DELETE against the fake's state, enforcing
// the real API's rule that a DELETE must name the exact current contents.
func (a *route53API) applyChange(w http.ResponseWriter, r *http.Request) {
	if a.changeStatus != 0 {
		a.write(w, a.changeStatus,
			`<ErrorResponse><Error><Code>InvalidChangeBatch</Code><Message>the change was refused</Message></Error></ErrorResponse>`)
		return
	}

	var req changeResourceRecordSetsRequest
	if err := xml.NewDecoder(r.Body).Decode(&req); err != nil {
		a.t.Errorf("undecodable change batch: %v", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if len(req.Batch.Changes) != 1 {
		a.t.Fatalf("change batch has %d changes, want 1", len(req.Batch.Changes))
	}

	ch := req.Batch.Changes[0]
	rrset := ch.RecordSet
	values := make([]string, 0, len(rrset.ResourceRecords))
	for _, rr := range rrset.ResourceRecords {
		values = append(values, unquoteTXT(rr.Value))
	}

	switch ch.Action {
	case "UPSERT":
		a.records[rrset.Name] = values
		a.ttls[rrset.Name] = rrset.TTL
	case "DELETE":
		current := a.records[rrset.Name]
		if !sameSet(current, values) {
			// Route 53 rejects a DELETE that does not match the current set
			// exactly. Enforced here so a provider that guesses the contents
			// fails the test instead of appearing to work.
			a.write(w, http.StatusBadRequest,
				`<ErrorResponse><Error><Code>InvalidChangeBatch</Code><Message>values do not match</Message></Error></ErrorResponse>`)
			return
		}
		delete(a.records, rrset.Name)
		delete(a.ttls, rrset.Name)
	default:
		a.t.Errorf("unexpected action %q", ch.Action)
	}

	a.write(w, http.StatusOK,
		`<ChangeResourceRecordSetsResponse><ChangeInfo><Id>/change/C1</Id><Status>PENDING</Status></ChangeInfo></ChangeResourceRecordSetsResponse>`)
}

func (a *route53API) write(w http.ResponseWriter, status int, body string) {
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
}

func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	x, y := slices.Clone(a), slices.Clone(b)
	slices.Sort(x)
	slices.Sort(y)
	return slices.Equal(x, y)
}

func route53Record() Record {
	return Record{Name: "_acme-challenge.vallet.example.com", Value: "digest-value-one"}
}

// TestRoute53PublishesAndRemovesTheChallengeRecord is the happy path: the value
// is published at the right name and the cleanup takes it away again.
func TestRoute53PublishesAndRemovesTheChallengeRecord(t *testing.T) {
	api, provider := newRoute53API(t)

	cleanup, err := provider.Present(t.Context(), route53Record())
	if err != nil {
		t.Fatalf("Present: %v", err)
	}

	const fqdn = "_acme-challenge.vallet.example.com."
	if got := api.records[fqdn]; !slices.Equal(got, []string{"digest-value-one"}) {
		t.Fatalf("published values = %v, want the challenge digest", got)
	}
	if got := api.ttls[fqdn]; got != route53ChallengeTTL {
		t.Errorf("TTL = %d, want %d: a long TTL keeps resolvers serving a "+
			"withdrawn challenge answer", got, route53ChallengeTTL)
	}

	if err := cleanup(t.Context()); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if _, ok := api.records[fqdn]; ok {
		t.Errorf("cleanup left the record set behind: %v", api.records[fqdn])
	}
}

// TestRoute53PreservesACoexistingValue is the multi-value test, and the one
// that distinguishes this provider from a naive port of the Cloudflare shape.
//
// A certificate covering both example.com and *.example.com puts two different
// digests at _acme-challenge.example.com, because ChallengeRecordName strips
// the wildcard prefix. Route 53 keys a record set by (name, type) and holds a
// SET of values, so an UPSERT that writes only the new value silently discards
// the other challenge, and a DELETE of the whole set on cleanup destroys it.
//
// Both directions are asserted: publishing the second value must keep the
// first, and cleaning up the second must leave the first standing.
func TestRoute53PreservesACoexistingValue(t *testing.T) {
	api, provider := newRoute53API(t)
	const fqdn = "_acme-challenge.vallet.example.com."

	first := route53Record()
	cleanupFirst, err := provider.Present(t.Context(), first)
	if err != nil {
		t.Fatalf("Present(first): %v", err)
	}

	second := Record{Name: first.Name, Value: "digest-value-two"}
	cleanupSecond, err := provider.Present(t.Context(), second)
	if err != nil {
		t.Fatalf("Present(second): %v", err)
	}

	if got := api.records[fqdn]; !sameSet(got, []string{"digest-value-one", "digest-value-two"}) {
		t.Fatalf("after two challenges the record set holds %v, want both digests: "+
			"publishing the second must not discard the first", got)
	}

	if err := cleanupSecond(t.Context()); err != nil {
		t.Fatalf("cleanup(second): %v", err)
	}
	if got := api.records[fqdn]; !slices.Equal(got, []string{"digest-value-one"}) {
		t.Fatalf("after removing the second value the set holds %v, want only the first: "+
			"cleanup must subtract its own value, not delete the set", got)
	}

	if err := cleanupFirst(t.Context()); err != nil {
		t.Fatalf("cleanup(first): %v", err)
	}
	if _, ok := api.records[fqdn]; ok {
		t.Errorf("removing the last value left an empty record set behind")
	}
}

// TestRoute53CleanupLeavesAnUnrelatedValueAlone is the scoping test.
//
// Route 53 gives no per-record ID, so the guarantee that cleanup cannot destroy
// a record this process did not create rests on set subtraction. An operator's
// own TXT value sitting at the same name must survive both the publish and the
// cleanup.
func TestRoute53CleanupLeavesAnUnrelatedValueAlone(t *testing.T) {
	api, provider := newRoute53API(t)
	const fqdn = "_acme-challenge.vallet.example.com."

	api.records[fqdn] = []string{"operator-owned-value"}
	api.ttls[fqdn] = 300

	cleanup, err := provider.Present(t.Context(), route53Record())
	if err != nil {
		t.Fatalf("Present: %v", err)
	}
	if got := api.records[fqdn]; !sameSet(got, []string{"operator-owned-value", "digest-value-one"}) {
		t.Fatalf("publish produced %v, want the operator's value kept alongside ours", got)
	}

	if err := cleanup(t.Context()); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if got := api.records[fqdn]; !slices.Equal(got, []string{"operator-owned-value"}) {
		t.Errorf("cleanup produced %v, want the operator's value untouched: the "+
			"provider must not remove a value it did not publish", got)
	}
}

// TestRoute53CleanupIsIdempotent proves an already-removed value is not an
// error. Cleanup runs on retry and shutdown paths and may run twice; treating
// "already gone" as a failure would make a correct end state look like a leak.
func TestRoute53CleanupIsIdempotent(t *testing.T) {
	_, provider := newRoute53API(t)

	cleanup, err := provider.Present(t.Context(), route53Record())
	if err != nil {
		t.Fatalf("Present: %v", err)
	}
	if err := cleanup(t.Context()); err != nil {
		t.Fatalf("first cleanup: %v", err)
	}
	if err := cleanup(t.Context()); err != nil {
		t.Errorf("second cleanup: %v, want nil", err)
	}
}

// TestRoute53CleanupReportsAFailure is the other half of idempotence: an
// already-gone record is success, but a REFUSED removal must be reported.
//
// Swallowing it would leave an _acme-challenge TXT record standing in the zone
// with the solver believing it had been withdrawn, and the solver's loud
// operator-facing log line depends on this error surfacing.
func TestRoute53CleanupReportsAFailure(t *testing.T) {
	api, provider := newRoute53API(t)

	cleanup, err := provider.Present(t.Context(), route53Record())
	if err != nil {
		t.Fatalf("Present: %v", err)
	}

	api.changeStatus = http.StatusBadRequest
	if err := cleanup(t.Context()); err == nil {
		t.Fatal("cleanup swallowed an API refusal; the record is still published " +
			"and nothing would tell the operator")
	}
}

// TestRoute53PresentReportsAnAPIRejection checks the publish path fails loudly
// AND still hands back a cleanup.
//
// The cleanup is the security-relevant half. A failed write can still have
// applied — a response lost to a timeout or a reset connection leaves the
// change committed at AWS with nothing here knowing it — so returning nil would
// leak a standing _acme-challenge TXT record that no code path can withdraw.
// The seam's contract requires a cleanup whenever anything may have been
// created, including when Present fails, and the solver registers it on exactly
// that path.
func TestRoute53PresentReportsAnAPIRejection(t *testing.T) {
	api, provider := newRoute53API(t)
	api.changeStatus = http.StatusBadRequest

	cleanup, err := provider.Present(t.Context(), route53Record())
	if err == nil {
		t.Fatal("Present accepted a refused change")
	}
	if !errors.Is(err, ErrRoute53API) {
		t.Errorf("error = %v, want ErrRoute53API", err)
	}
	if cleanup == nil {
		t.Fatal("Present returned no cleanup for a write that may still have applied: " +
			"a lost response leaves the record published with nothing able to remove it")
	}
	if !strings.Contains(err.Error(), "InvalidChangeBatch") {
		t.Errorf("error %v does not carry the API's own code, which is the diagnostic", err)
	}
}

// TestRoute53CleanupAfterAFailedPublishSubmitsNoChange is the other half of the
// contract above: the cleanup returned on the error path must be safe to run
// when the write genuinely never applied.
//
// This is what makes returning a cleanup pessimistically harmless rather than a
// new hazard. Because cleanup reads before it writes, a value that was never
// created is simply absent, and the closure returns success without submitting
// any ChangeResourceRecordSets. That matters beyond tidiness: an unconditional
// write here would be a read-modify-write against a record set this process may
// never have touched, which could clobber a concurrent challenge at the same
// name — the exact hazard the set-subtraction design exists to avoid.
func TestRoute53CleanupAfterAFailedPublishSubmitsNoChange(t *testing.T) {
	api, provider := newRoute53API(t)
	const fqdn = "_acme-challenge.vallet.example.com."

	// A concurrent challenge is already standing at the same name.
	api.records[fqdn] = []string{"someone-elses-challenge"}
	api.ttls[fqdn] = 60

	api.changeStatus = http.StatusBadRequest
	cleanup, err := provider.Present(t.Context(), route53Record())
	if err == nil {
		t.Fatal("Present accepted a refused change")
	}
	if cleanup == nil {
		t.Fatal("Present returned no cleanup")
	}

	api.changeStatus = 0
	api.requests = nil
	if err := cleanup(t.Context()); err != nil {
		t.Fatalf("cleanup after a failed publish: %v, want nil", err)
	}

	for _, req := range api.requests {
		if strings.HasPrefix(req, http.MethodPost) {
			t.Errorf("cleanup submitted a change for a value that was never published: %q", req)
		}
	}
	if got := api.records[fqdn]; !slices.Equal(got, []string{"someone-elses-challenge"}) {
		t.Errorf("cleanup disturbed a concurrent challenge: record set = %v", got)
	}
}

// TestRoute53RefusesAmbiguousHostedZones is the zone-selection test that
// matters most.
//
// AWS permits two public hosted zones with the same name, and only the one the
// registrar delegates to is real. Picking either is a coin flip: the record is
// accepted, the change reaches INSYNC, and the CA never sees it, so issuance
// fails much later with a message about DNS rather than about the account.
func TestRoute53RefusesAmbiguousHostedZones(t *testing.T) {
	api, provider := newRoute53API(t,
		route53Zone{id: "Z1PUBLIC", name: "example.com"},
		route53Zone{id: "Z2PUBLIC", name: "example.com"},
	)

	_, err := provider.Present(t.Context(), route53Record())
	if err == nil {
		t.Fatal("Present picked one of two identically named public hosted zones")
	}
	if !errors.Is(err, ErrRoute53AmbiguousZone) {
		t.Errorf("error = %v, want ErrRoute53AmbiguousZone", err)
	}
	for _, req := range api.requests {
		if strings.HasPrefix(req, http.MethodPost) {
			t.Errorf("a change was submitted despite the zone being ambiguous: %q", req)
		}
	}
}

// TestRoute53IgnoresPrivateHostedZones checks that a private zone is never
// selected.
//
// A private zone is visible only inside its associated VPCs, while the CA
// queries the public internet, so a challenge written there is accepted and
// never seen.
//
// The arrangement is split-horizon DNS, which is where this actually bites: a
// private zone for the internal subdomain "vallet.example.com" alongside the
// public zone for the parent "example.com". It is chosen over the simpler
// two-zones-with-one-name case for a testing reason. With both zones named
// "example.com", dropping the private-zone filter makes the selection AMBIGUOUS
// and the ambiguity guard rejects it — so the test passes for the wrong reason
// and would keep passing if the private-zone filter were deleted outright.
// Here the private zone is the more specific one, so without the filter it wins
// the most-specific-match walk outright and the record is written into it, with
// no other check in a position to object.
func TestRoute53IgnoresPrivateHostedZones(t *testing.T) {
	api, provider := newRoute53API(t,
		route53Zone{id: "ZPUBLIC", name: "example.com"},
		route53Zone{id: "ZPRIVATE", name: "vallet.example.com", private: true},
	)

	if _, err := provider.Present(t.Context(), route53Record()); err != nil {
		t.Fatalf("Present: %v", err)
	}
	for _, req := range api.requests {
		if strings.Contains(req, "ZPRIVATE") {
			t.Errorf("the private hosted zone was addressed: %q", req)
		}
	}
	if !slices.ContainsFunc(api.requests, func(s string) bool { return strings.Contains(s, "ZPUBLIC") }) {
		t.Error("the public hosted zone was never addressed")
	}
}

// TestRoute53PrefersTheMostSpecificZone checks a delegated subdomain wins over
// its parent. Writing to the parent would put the record in a zone that is not
// authoritative for the name, so the CA would never see it.
func TestRoute53PrefersTheMostSpecificZone(t *testing.T) {
	api, provider := newRoute53API(t,
		route53Zone{id: "ZPARENT", name: "example.com"},
		route53Zone{id: "ZCHILD", name: "vallet.example.com"},
	)

	if _, err := provider.Present(t.Context(), route53Record()); err != nil {
		t.Fatalf("Present: %v", err)
	}
	for _, req := range api.requests {
		if strings.Contains(req, "ZPARENT") {
			t.Errorf("the parent zone was addressed despite a delegated child existing: %q", req)
		}
	}
}

// TestRoute53RefusesWhenNoZoneMatches checks the account-holds-nothing case
// fails rather than writing somewhere arbitrary.
func TestRoute53RefusesWhenNoZoneMatches(t *testing.T) {
	_, provider := newRoute53API(t, route53Zone{id: "ZOTHER", name: "unrelated.test"})

	_, err := provider.Present(t.Context(), route53Record())
	if err == nil {
		t.Fatal("Present succeeded with no hosted zone for the name")
	}
	if !errors.Is(err, ErrRoute53API) {
		t.Errorf("error = %v, want ErrRoute53API", err)
	}
}

// TestRoute53RefusesAMalformedCredential proves the provider will not start
// without a well-formed pair.
//
// The parse is strict on purpose. A credential supplied as just a secret, or
// with a half missing, would otherwise be signed with and fail as an opaque 403
// from AWS, which reads like an outage rather than like the configuration fault
// it is.
func TestRoute53RefusesAMalformedCredential(t *testing.T) {
	for _, tc := range []struct{ name, cred string }{
		{"empty", ""},
		{"no separator", "AKIAONLYTHEKEYID"},
		{"empty secret", "AKIAONLYTHEKEYID:"},
		{"empty key id", ":" + testAWSSecret},
		{"whitespace only", "  :  "},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewRoute53(secrets.NewRedacted(tc.cred), nil)
			if !errors.Is(err, ErrRoute53API) {
				t.Errorf("NewRoute53(%q) = %v, want ErrRoute53API", tc.cred, err)
			}
		})
	}
}

// TestRoute53AcceptsAWrappedCredential is the positive control for the test
// above: the strict parse must still accept the documented format, including
// the trailing newline a file-backed secret provider commonly yields.
func TestRoute53AcceptsAWrappedCredential(t *testing.T) {
	if _, err := NewRoute53(secrets.NewRedacted(testAWSCred+"\n"), nil); err != nil {
		t.Errorf("NewRoute53 rejected a valid credential with a trailing newline: %v", err)
	}
}

// TestRoute53CredentialNeverAppearsInOutput checks every rendering path the
// credential could escape through.
//
// The %+v case is the one that fails without the Format method: fmt walks a
// struct's unexported fields by reflection and does not call their String,
// GoString or MarshalJSON methods, so a secrets.Redacted in an unexported field
// is printed verbatim unless the CONTAINING type implements fmt.Formatter.
func TestRoute53CredentialNeverAppearsInOutput(t *testing.T) {
	_, provider := newRoute53API(t)

	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
		rendered := fmt.Sprintf(verb, provider)
		if strings.Contains(rendered, testAWSSecret) {
			t.Errorf("fmt %s of the provider prints the secret access key: %s", verb, rendered)
		}
		if strings.Contains(rendered, testAWSKeyID) {
			t.Errorf("fmt %s of the provider prints the access key id: %s", verb, rendered)
		}
	}
}

// TestRoute53ErrorsNeverCarryTheCredential checks the failure paths, which are
// where a credential most plausibly reaches a log.
func TestRoute53ErrorsNeverCarryTheCredential(t *testing.T) {
	api, provider := newRoute53API(t)

	api.changeStatus = http.StatusForbidden
	_, presentErr := provider.Present(t.Context(), route53Record())

	api.changeStatus = 0
	cleanup, err := provider.Present(t.Context(), route53Record())
	if err != nil {
		t.Fatalf("Present: %v", err)
	}
	api.listStatus = http.StatusForbidden
	cleanupErr := cleanup(t.Context())

	for _, e := range []error{presentErr, cleanupErr} {
		if e == nil {
			t.Fatal("expected an error to inspect")
		}
		if strings.Contains(e.Error(), testAWSSecret) || strings.Contains(e.Error(), testAWSKeyID) {
			t.Errorf("error text carries the credential: %v", e)
		}
	}
}

// TestRoute53DoesNotPollChangeStatus pins the decision documented on
// changeRecords: the provider does not wait for the change to reach INSYNC.
//
// The seam forbids a provider waiting for propagation, and the solver's gate is
// strictly stronger for this purpose — it reports only values every
// authoritative nameserver actually serves, whereas INSYNC reports success even
// for a change written to a private or undelegated zone that the CA will never
// see. A GetChange poll appearing here would be both redundant and a weaker
// signal, so its absence is asserted rather than left to convention.
func TestRoute53DoesNotPollChangeStatus(t *testing.T) {
	api, provider := newRoute53API(t)

	if _, err := provider.Present(t.Context(), route53Record()); err != nil {
		t.Fatalf("Present: %v", err)
	}
	for _, req := range api.requests {
		if strings.Contains(req, "/change/") || strings.Contains(req, "getchange") {
			t.Errorf("Present polled the change status: %q", req)
		}
	}
}

// TestRoute53RejectsAMalformedZoneIDFromTheAPI checks that a response value
// destined for a URL path is validated.
//
// The hosted zone ID is interpolated into the path of a subsequent signed,
// credentialed request. A hostile or confused response returning a traversal
// sequence there could steer that request at another resource, so the ID is
// checked against the opaque alphanumeric shape AWS documents.
func TestRoute53RejectsAMalformedZoneIDFromTheAPI(t *testing.T) {
	_, provider := newRoute53API(t, route53Zone{id: "../../hostedzone/ZEVIL", name: "example.com"})

	_, err := provider.Present(t.Context(), route53Record())
	if err == nil {
		t.Fatal("Present accepted a malformed hosted zone id from the API")
	}
	if !errors.Is(err, ErrRoute53API) {
		t.Errorf("error = %v, want ErrRoute53API", err)
	}
}

// TestRoute53IsRegisteredInTheSeam checks the provider is reachable through the
// registry, which is what config actually calls.
func TestRoute53IsRegisteredInTheSeam(t *testing.T) {
	p, err := NewAPIProvider("route53", secrets.NewRedacted(testAWSCred), nil)
	if err != nil {
		t.Fatalf("NewAPIProvider(route53): %v", err)
	}
	if got := p.Name(); got != "route53" {
		t.Errorf("Name() = %q, want %q", got, "route53")
	}
}
