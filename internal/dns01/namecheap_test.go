package dns01

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/secrets"
)

// The credentials every test hands the provider. The key is distinctive so a
// leak into any output is unmistakable; the others are handles and are not
// secret, but are still checked never to be needed in plaintext where a secret
// would be.
const (
	testNCAPIUser  = "valletapiuser"
	testNCAPIKey   = "namecheap-key-DO-NOT-LEAK-9f3a1c"
	testNCUserName = "valletapiuser"
	testNCClientIP = "203.0.113.7"
)

func testNamecheapCreds() Credentials {
	return NewNamedCredentials(map[string]secrets.Redacted{
		"api_user":  secrets.NewRedacted(testNCAPIUser),
		"api_key":   secrets.NewRedacted(testNCAPIKey),
		"username":  secrets.NewRedacted(testNCUserName),
		"client_ip": secrets.NewRedacted(testNCClientIP),
	})
}

// namecheapZone is one domain's host set in the fake account, plus the two
// domain-level attributes getHosts reports.
type namecheapZone struct {
	emailType   string
	usingOurDNS bool
	hosts       []namecheapHost
}

// namecheapAPI is a local stand-in for the Namecheap XML API. No test in this
// package contacts Namecheap.
//
// It holds real state and APPLIES setHosts as a WHOLE-SET REPLACE — the exact
// semantics that make record preservation the real risk — rather than only
// recording requests. A fake that merely recorded calls would let a provider
// that drops a co-existing record pass every test.
type namecheapAPI struct {
	t *testing.T

	domains []string                  // what getList enumerates
	zones   map[string]*namecheapZone // keyed by "SLD.TLD"

	requests []string // every Command issued, so a test can assert what was NOT done

	getHostsErr bool // drive the getHosts failure path
	setHostsErr bool // drive the setHosts failure path
}

func newNamecheapAPI(t *testing.T, domains []string, zones map[string]*namecheapZone) (*namecheapAPI, *namecheapProvider) {
	t.Helper()

	api := &namecheapAPI{t: t, domains: domains, zones: zones}
	srv := httptest.NewServer(api)
	t.Cleanup(srv.Close)

	provider, err := NewNamecheap(testNamecheapCreds(), srv.Client())
	if err != nil {
		t.Fatalf("NewNamecheap: %v", err)
	}
	p := provider.(*namecheapProvider)
	// The endpoint is a constant by design, so the test rewrites the request host
	// in the transport instead of making it configurable — a configurable endpoint
	// is exactly the setting that lets a misconfiguration point a zone-editing
	// credential at another host.
	p.client = &http.Client{Transport: rewriteNamecheapHost{srv.URL, srv.Client().Transport}}
	return api, p
}

// rewriteNamecheapHost redirects requests for the real endpoint at the local fake.
type rewriteNamecheapHost struct {
	base string
	next http.RoundTripper
}

func (r rewriteNamecheapHost) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	u, err := req.URL.Parse(r.base + strings.TrimPrefix(req.URL.String(), namecheapEndpoint))
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

func (a *namecheapAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		a.t.Fatalf("parse form: %v", err)
	}
	// The credentials must travel in the body, never the URL — a GET would put the
	// key in the query, and a transport error would render it into an error.
	if r.URL.RawQuery != "" {
		a.t.Errorf("parameters leaked into the URL query: %q", r.URL.RawQuery)
	}
	if got := r.PostForm.Get("ApiKey"); got != testNCAPIKey {
		a.t.Errorf("ApiKey missing or wrong in the request body: %q", got)
	}
	if got := r.PostForm.Get("ApiUser"); got != testNCAPIUser {
		a.t.Errorf("ApiUser = %q, want %q", got, testNCAPIUser)
	}
	if got := r.PostForm.Get("ClientIp"); got != testNCClientIP {
		a.t.Errorf("ClientIp = %q, want %q", got, testNCClientIP)
	}

	cmd := r.PostForm.Get("Command")
	a.requests = append(a.requests, cmd)

	w.Header().Set("Content-Type", "text/xml")
	switch cmd {
	case namecheapCmdGetList:
		a.getList(w)
	case namecheapCmdGetHosts:
		a.getHosts(w, r)
	case namecheapCmdSetHosts:
		a.setHosts(w, r)
	default:
		a.t.Errorf("unexpected command %q", cmd)
		a.writeErr(w, "1", "unknown command")
	}
}

func (a *namecheapAPI) getList(w http.ResponseWriter) {
	var b strings.Builder
	b.WriteString(`<ApiResponse Status="OK" xmlns="http://api.namecheap.com/xml.response"><Errors/><CommandResponse Type="namecheap.domains.getList"><DomainGetListResult>`)
	for _, d := range a.domains {
		fmt.Fprintf(&b, `<Domain ID="1" Name="%s" IsOurDNS="true"/>`, d)
	}
	fmt.Fprintf(&b, `</DomainGetListResult><Paging><TotalItems>%d</TotalItems><CurrentPage>1</CurrentPage><PageSize>%d</PageSize></Paging></CommandResponse></ApiResponse>`,
		len(a.domains), namecheapPageSize)
	a.write(w, http.StatusOK, b.String())
}

func (a *namecheapAPI) getHosts(w http.ResponseWriter, r *http.Request) {
	if a.getHostsErr {
		a.writeErr(w, "2011166", "getHosts is temporarily unavailable")
		return
	}
	key := r.PostForm.Get("SLD") + "." + r.PostForm.Get("TLD")
	z := a.zones[key]
	if z == nil {
		a.writeErr(w, "2019166", "domain not found")
		return
	}
	var b strings.Builder
	fmt.Fprintf(&b,
		`<ApiResponse Status="OK" xmlns="http://api.namecheap.com/xml.response"><Errors/><CommandResponse Type="namecheap.domains.dns.getHosts"><DomainDNSGetHostsResult Domain="%s" EmailType="%s" IsUsingOurDNS="%t">`,
		key, z.emailType, z.usingOurDNS)
	for _, h := range z.hosts {
		fmt.Fprintf(&b, `<host HostId="1" Name="%s" Type="%s" Address="%s" MXPref="%s" TTL="%s"/>`,
			h.Name, h.Type, h.Address, h.MXPref, h.TTL)
	}
	b.WriteString(`</DomainDNSGetHostsResult></CommandResponse></ApiResponse>`)
	a.write(w, http.StatusOK, b.String())
}

// setHosts REPLACES the domain's whole host set with the records the request
// carries, exactly as Namecheap does. This is what turns a provider that drops a
// preserved record into a failing test rather than a silent zone wipe.
func (a *namecheapAPI) setHosts(w http.ResponseWriter, r *http.Request) {
	if a.setHostsErr {
		a.writeErr(w, "2016166", "setHosts was refused")
		return
	}
	key := r.PostForm.Get("SLD") + "." + r.PostForm.Get("TLD")
	z := a.zones[key]
	if z == nil {
		a.writeErr(w, "2019166", "domain not found")
		return
	}

	var hosts []namecheapHost
	for i := 1; ; i++ {
		n := strconv.Itoa(i)
		if _, ok := r.PostForm["HostName"+n]; !ok {
			break
		}
		hosts = append(hosts, namecheapHost{
			Name:    r.PostForm.Get("HostName" + n),
			Type:    r.PostForm.Get("RecordType" + n),
			Address: r.PostForm.Get("Address" + n),
			MXPref:  r.PostForm.Get("MXPref" + n),
			TTL:     r.PostForm.Get("TTL" + n),
		})
	}
	z.hosts = hosts
	if et := r.PostForm.Get("EmailType"); et != "" {
		z.emailType = et
	}

	a.write(w, http.StatusOK,
		`<ApiResponse Status="OK" xmlns="http://api.namecheap.com/xml.response"><Errors/><CommandResponse Type="namecheap.domains.dns.setHosts"><DomainDNSSetHostsResult Domain="`+key+`" IsSuccess="true"/></CommandResponse></ApiResponse>`)
}

func (a *namecheapAPI) writeErr(w http.ResponseWriter, number, desc string) {
	a.write(w, http.StatusOK,
		fmt.Sprintf(`<ApiResponse Status="ERROR" xmlns="http://api.namecheap.com/xml.response"><Errors><Error Number="%s">%s</Error></Errors><CommandResponse/></ApiResponse>`, number, desc))
}

func (a *namecheapAPI) write(w http.ResponseWriter, status int, body string) {
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
}

func (a *namecheapAPI) issued(cmd string) bool { return slices.Contains(a.requests, cmd) }

// namecheapRecord is the challenge the tests publish.
func namecheapRecord() Record {
	return Record{Name: "_acme-challenge.vallet.example.com", Value: "digest-value-one"}
}

// findHost returns the record with the given name and type, or false.
func findHost(hosts []namecheapHost, name, typ string) (namecheapHost, bool) {
	for _, h := range hosts {
		if strings.EqualFold(h.Name, name) && strings.EqualFold(h.Type, typ) {
			return h, true
		}
	}
	return namecheapHost{}, false
}

// singleZone builds an account holding example.com with the given host set and
// Namecheap as its DNS.
func singleZone(hosts ...namecheapHost) ([]string, map[string]*namecheapZone) {
	return []string{"example.com"}, map[string]*namecheapZone{
		"example.com": {emailType: "MX", usingOurDNS: true, hosts: hosts},
	}
}

// TestNamecheapPublishesAndRemovesTheChallengeRecord is the happy path: the value
// is published at the right host label and the cleanup takes it away again.
func TestNamecheapPublishesAndRemovesTheChallengeRecord(t *testing.T) {
	domains, zones := singleZone()
	_, provider := newNamecheapAPI(t, domains, zones)

	cleanup, err := provider.Present(t.Context(), namecheapRecord())
	if err != nil {
		t.Fatalf("Present: %v", err)
	}

	h, ok := findHost(zones["example.com"].hosts, "_acme-challenge.vallet", "TXT")
	if !ok {
		t.Fatalf("challenge TXT not published; host set = %+v", zones["example.com"].hosts)
	}
	if h.Address != "digest-value-one" {
		t.Errorf("published value = %q, want the challenge digest", h.Address)
	}
	if h.TTL != namecheapChallengeTTL {
		t.Errorf("TTL = %q, want %q: a long TTL keeps resolvers serving a withdrawn answer", h.TTL, namecheapChallengeTTL)
	}

	if err := cleanup(t.Context()); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if _, ok := findHost(zones["example.com"].hosts, "_acme-challenge.vallet", "TXT"); ok {
		t.Errorf("cleanup left the challenge record behind: %+v", zones["example.com"].hosts)
	}
}

// TestNamecheapPreservesExistingRecordsOnSetAndCleanup is the most important test
// in the file. Namecheap's setHosts REPLACES the whole host set, so publishing or
// removing one TXT means re-submitting every other record. If the provider drops
// one, or mangles its MXPref or TTL, the record is silently gone.
//
// Both directions are asserted: the A and MX records survive the publish AND the
// cleanup, byte for byte, including the MX priority that a dropped MXPref would
// break.
func TestNamecheapPreservesExistingRecordsOnSetAndCleanup(t *testing.T) {
	a := namecheapHost{Name: "www", Type: "A", Address: "198.51.100.10", MXPref: "10", TTL: "1800"}
	mx := namecheapHost{Name: "@", Type: "MX", Address: "mail.example.com", MXPref: "5", TTL: "3600"}
	domains, zones := singleZone(a, mx)
	_, provider := newNamecheapAPI(t, domains, zones)

	assertPreserved := func(t *testing.T, phase string) {
		t.Helper()
		gotA, ok := findHost(zones["example.com"].hosts, "www", "A")
		if !ok || gotA != a {
			t.Errorf("%s: A record not preserved: got %+v, want %+v", phase, gotA, a)
		}
		gotMX, ok := findHost(zones["example.com"].hosts, "@", "MX")
		if !ok || gotMX != mx {
			t.Errorf("%s: MX record not preserved (MXPref/TTL must survive): got %+v, want %+v", phase, gotMX, mx)
		}
		if et := zones["example.com"].emailType; et != "MX" {
			t.Errorf("%s: EmailType changed to %q, want MX", phase, et)
		}
	}

	cleanup, err := provider.Present(t.Context(), namecheapRecord())
	if err != nil {
		t.Fatalf("Present: %v", err)
	}
	assertPreserved(t, "after publish")
	if _, ok := findHost(zones["example.com"].hosts, "_acme-challenge.vallet", "TXT"); !ok {
		t.Fatal("challenge TXT was not added alongside the existing records")
	}

	if err := cleanup(t.Context()); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	assertPreserved(t, "after cleanup")
	if _, ok := findHost(zones["example.com"].hosts, "_acme-challenge.vallet", "TXT"); ok {
		t.Error("cleanup left the challenge behind")
	}
}

// TestNamecheapPreservesACoexistingChallengeValue is the wildcard-sibling case:
// a certificate covering both example.com and *.example.com puts two different
// digests at _acme-challenge.example.com. Removing one must leave the other, so
// the guarantee rests on matching the exact value rather than deleting by name.
func TestNamecheapPreservesACoexistingChallengeValue(t *testing.T) {
	domains, zones := singleZone()
	_, provider := newNamecheapAPI(t, domains, zones)

	first := Record{Name: "_acme-challenge.example.com", Value: "digest-value-one"}
	cleanupFirst, err := provider.Present(t.Context(), first)
	if err != nil {
		t.Fatalf("Present(first): %v", err)
	}
	second := Record{Name: "_acme-challenge.example.com", Value: "digest-value-two"}
	cleanupSecond, err := provider.Present(t.Context(), second)
	if err != nil {
		t.Fatalf("Present(second): %v", err)
	}

	values := namecheapTXTValues(zones["example.com"].hosts, "_acme-challenge")
	if !sameSet(values, []string{"digest-value-one", "digest-value-two"}) {
		t.Fatalf("after two challenges the name holds %v, want both digests: publishing the second must not discard the first", values)
	}

	if err := cleanupSecond(t.Context()); err != nil {
		t.Fatalf("cleanup(second): %v", err)
	}
	if values := namecheapTXTValues(zones["example.com"].hosts, "_acme-challenge"); !slices.Equal(values, []string{"digest-value-one"}) {
		t.Fatalf("after removing the second value the name holds %v, want only the first: cleanup must subtract its own value", values)
	}

	if err := cleanupFirst(t.Context()); err != nil {
		t.Fatalf("cleanup(first): %v", err)
	}
	if values := namecheapTXTValues(zones["example.com"].hosts, "_acme-challenge"); len(values) != 0 {
		t.Errorf("removing the last value left %v behind", values)
	}
}

func namecheapTXTValues(hosts []namecheapHost, name string) []string {
	var out []string
	for _, h := range hosts {
		if strings.EqualFold(h.Name, name) && strings.EqualFold(h.Type, "TXT") {
			out = append(out, h.Address)
		}
	}
	return out
}

// TestNamecheapAbortsSetHostsWhenGetHostsFails is the zone-safety test. A
// setHosts built on a failed read would replace the whole host set with a
// truncated one, so a getHosts failure must abort BEFORE any setHosts. This is
// the Namecheap analog of "cleanup after a failed publish submits no change".
func TestNamecheapAbortsSetHostsWhenGetHostsFails(t *testing.T) {
	a := namecheapHost{Name: "www", Type: "A", Address: "198.51.100.10", MXPref: "10", TTL: "1800"}
	domains, zones := singleZone(a)
	api, provider := newNamecheapAPI(t, domains, zones)
	api.getHostsErr = true

	_, err := provider.Present(t.Context(), namecheapRecord())
	if err == nil {
		t.Fatal("Present proceeded despite getHosts failing")
	}
	if !errors.Is(err, ErrNamecheapAPI) {
		t.Errorf("error = %v, want ErrNamecheapAPI", err)
	}
	if api.issued(namecheapCmdSetHosts) {
		t.Fatal("a setHosts was issued after getHosts failed; a partial read would wipe the zone")
	}
	if got := zones["example.com"].hosts; !slices.Equal(got, []namecheapHost{a}) {
		t.Errorf("the existing host set was disturbed: %+v", got)
	}
}

// TestNamecheapRefusesDomainNotUsingNamecheapDNS proves the provider will not
// rewrite the host set of a domain served elsewhere. setHosts there is
// destructive — it can switch the domain onto Namecheap DNS and drop every
// externally-served record — so it must refuse and issue no setHosts.
func TestNamecheapRefusesDomainNotUsingNamecheapDNS(t *testing.T) {
	domains := []string{"example.com"}
	zones := map[string]*namecheapZone{
		"example.com": {emailType: "MXE", usingOurDNS: false, hosts: nil},
	}
	api, provider := newNamecheapAPI(t, domains, zones)

	_, err := provider.Present(t.Context(), namecheapRecord())
	if err == nil {
		t.Fatal("Present rewrote a domain not using Namecheap DNS")
	}
	if !errors.Is(err, ErrNamecheapAPI) {
		t.Errorf("error = %v, want ErrNamecheapAPI", err)
	}
	if api.issued(namecheapCmdSetHosts) {
		t.Error("a setHosts was issued for a domain served by another DNS provider")
	}
}

// TestNamecheapPresentReportsAnAPIRejection checks the publish path fails loudly,
// carries the API's own error number, AND still hands back a cleanup.
//
// The cleanup is the security-relevant half: a failed write can still have
// applied — a lost response leaves the set replaced at Namecheap with nothing
// here knowing it — so returning nil would leak a standing challenge record.
func TestNamecheapPresentReportsAnAPIRejection(t *testing.T) {
	domains, zones := singleZone()
	api, provider := newNamecheapAPI(t, domains, zones)
	api.setHostsErr = true

	cleanup, err := provider.Present(t.Context(), namecheapRecord())
	if err == nil {
		t.Fatal("Present accepted a refused setHosts")
	}
	if !errors.Is(err, ErrNamecheapAPI) {
		t.Errorf("error = %v, want ErrNamecheapAPI", err)
	}
	if cleanup == nil {
		t.Fatal("Present returned no cleanup for a write that may still have applied")
	}
	if !strings.Contains(err.Error(), "2016166") {
		t.Errorf("error %v does not carry the API's own error number, which is the diagnostic", err)
	}
}

// TestNamecheapCleanupAfterAFailedPublishSubmitsNoSetHosts is the other half of
// the contract: the cleanup returned on the error path must be safe to run when
// the write genuinely never applied. Because cleanup reads before it writes, a
// value that was never created is absent and no setHosts is submitted — so a
// concurrent challenge at the same name is not disturbed.
func TestNamecheapCleanupAfterAFailedPublishSubmitsNoSetHosts(t *testing.T) {
	concurrent := namecheapHost{Name: "_acme-challenge.vallet", Type: "TXT", Address: "someone-elses-challenge", MXPref: "10", TTL: "60"}
	domains, zones := singleZone(concurrent)
	api, provider := newNamecheapAPI(t, domains, zones)

	api.setHostsErr = true
	cleanup, err := provider.Present(t.Context(), namecheapRecord())
	if err == nil {
		t.Fatal("Present accepted a refused setHosts")
	}
	if cleanup == nil {
		t.Fatal("Present returned no cleanup")
	}

	api.setHostsErr = false
	api.requests = nil
	if err := cleanup(t.Context()); err != nil {
		t.Fatalf("cleanup after a failed publish: %v, want nil", err)
	}
	if api.issued(namecheapCmdSetHosts) {
		t.Error("cleanup submitted a setHosts for a value that was never published")
	}
	if got := zones["example.com"].hosts; !slices.Equal(got, []namecheapHost{concurrent}) {
		t.Errorf("cleanup disturbed a concurrent challenge: %+v", got)
	}
}

// TestNamecheapCleanupIsIdempotent proves an already-removed value is not an
// error. Cleanup runs on retry and shutdown paths and may run twice; treating
// "already gone" as a failure would make a correct end state look like a leak.
func TestNamecheapCleanupIsIdempotent(t *testing.T) {
	domains, zones := singleZone()
	_, provider := newNamecheapAPI(t, domains, zones)

	cleanup, err := provider.Present(t.Context(), namecheapRecord())
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

// TestNamecheapCleanupReportsAFailure is the other half of idempotence: an
// already-gone record is success, but a REFUSED removal must be reported so the
// solver's loud operator-facing log line fires.
func TestNamecheapCleanupReportsAFailure(t *testing.T) {
	domains, zones := singleZone()
	api, provider := newNamecheapAPI(t, domains, zones)

	cleanup, err := provider.Present(t.Context(), namecheapRecord())
	if err != nil {
		t.Fatalf("Present: %v", err)
	}
	api.setHostsErr = true
	if err := cleanup(t.Context()); err == nil {
		t.Fatal("cleanup swallowed an API refusal; the record is still published and nothing would tell the operator")
	}
}

// TestNamecheapPrefersTheMostSpecificDomain checks a delegated subdomain wins
// over its parent. Writing to the parent would put the record in a domain that is
// not authoritative for the name.
func TestNamecheapPrefersTheMostSpecificDomain(t *testing.T) {
	domains := []string{"example.com", "eu.example.com"}
	zones := map[string]*namecheapZone{
		"example.com":    {emailType: "MX", usingOurDNS: true},
		"eu.example.com": {emailType: "MX", usingOurDNS: true},
	}
	_, provider := newNamecheapAPI(t, domains, zones)

	rec := Record{Name: "_acme-challenge.www.eu.example.com", Value: "digest-value-one"}
	if _, err := provider.Present(t.Context(), rec); err != nil {
		t.Fatalf("Present: %v", err)
	}

	if _, ok := findHost(zones["eu.example.com"].hosts, "_acme-challenge.www", "TXT"); !ok {
		t.Errorf("record not written to the delegated domain: %+v", zones["eu.example.com"].hosts)
	}
	if len(zones["example.com"].hosts) != 0 {
		t.Errorf("the parent domain was written to despite a delegated child existing: %+v", zones["example.com"].hosts)
	}
}

// TestNamecheapSplitsAMultiLabelTLD proves the SLD/TLD split is correct for a
// multi-label public suffix. If the split guessed "the last two labels" it would
// send SLD=co, TLD=uk and the getHosts would miss the zone, so a successful
// publish here is proof the registrable boundary came from the account listing.
func TestNamecheapSplitsAMultiLabelTLD(t *testing.T) {
	domains := []string{"example.co.uk"}
	zones := map[string]*namecheapZone{
		"example.co.uk": {emailType: "MX", usingOurDNS: true},
	}
	_, provider := newNamecheapAPI(t, domains, zones)

	rec := Record{Name: "_acme-challenge.example.co.uk", Value: "digest-value-one"}
	if _, err := provider.Present(t.Context(), rec); err != nil {
		t.Fatalf("Present: %v", err)
	}
	if _, ok := findHost(zones["example.co.uk"].hosts, "_acme-challenge", "TXT"); !ok {
		t.Errorf("record not written under example.co.uk: %+v", zones["example.co.uk"].hosts)
	}
}

// TestNamecheapRefusesWhenNoDomainMatches checks the account-holds-nothing case
// fails rather than writing somewhere arbitrary.
func TestNamecheapRefusesWhenNoDomainMatches(t *testing.T) {
	domains := []string{"unrelated.test"}
	zones := map[string]*namecheapZone{
		"unrelated.test": {usingOurDNS: true},
	}
	api, provider := newNamecheapAPI(t, domains, zones)

	_, err := provider.Present(t.Context(), namecheapRecord())
	if err == nil {
		t.Fatal("Present succeeded with no matching domain for the name")
	}
	if !errors.Is(err, ErrNamecheapAPI) {
		t.Errorf("error = %v, want ErrNamecheapAPI", err)
	}
	if api.issued(namecheapCmdSetHosts) {
		t.Error("a setHosts was issued despite no domain matching")
	}
}

// TestNamecheapRefusesMissingOrBlankCredential is the constructor gate: each of
// the four fields is required and non-blank, refused at startup rather than at
// the first renewal. The error must name the FIELD, never echo the value.
func TestNamecheapRefusesMissingOrBlankCredential(t *testing.T) {
	t.Parallel()

	full := map[string]string{
		"api_user":  testNCAPIUser,
		"api_key":   testNCAPIKey,
		"username":  testNCUserName,
		"client_ip": testNCClientIP,
	}

	tests := []struct {
		name   string
		field  string
		blank  string
		remove bool
	}{
		{"missing api_user", "api_user", "", true},
		{"blank api_user", "api_user", "   ", false},
		{"missing api_key", "api_key", "", true},
		{"blank api_key", "api_key", " \t\n ", false},
		{"missing username", "username", "", true},
		{"blank username", "username", "  ", false},
		{"missing client_ip", "client_ip", "", true},
		{"blank client_ip", "client_ip", "\n", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			creds := map[string]secrets.Redacted{}
			for k, v := range full {
				creds[k] = secrets.NewRedacted(v)
			}
			if tc.remove {
				delete(creds, tc.field)
			} else {
				creds[tc.field] = secrets.NewRedacted(tc.blank)
			}

			p, err := NewNamecheap(NewNamedCredentials(creds), nil)
			if !errors.Is(err, ErrNamecheapAPI) {
				t.Fatalf("err = %v, want ErrNamecheapAPI", err)
			}
			if p != nil {
				t.Fatal("a provider with an incomplete credential must not be returned")
			}
			if !strings.Contains(err.Error(), tc.field) {
				t.Errorf("error %q does not name the missing field %q", err, tc.field)
			}
			if strings.Contains(err.Error(), testNCAPIKey) {
				t.Error("error must never echo the api key")
			}
		})
	}
}

// TestNamecheapRefusesASingleCredential proves the named-only shape: a lone
// packed reference cannot satisfy the four required fields, so it is refused
// rather than mis-split.
func TestNamecheapRefusesASingleCredential(t *testing.T) {
	t.Parallel()

	p, err := NewNamecheap(NewSingleCredential(secrets.NewRedacted("just-one-value")), nil)
	if !errors.Is(err, ErrNamecheapAPI) {
		t.Fatalf("err = %v, want ErrNamecheapAPI", err)
	}
	if p != nil {
		t.Fatal("a single credential must not build a namecheap provider")
	}
}

// TestNamecheapCredentialNeverAppearsInOutput checks every rendering path the key
// could escape through. The %+v case is the one that fails without the Format
// method: fmt walks a struct's unexported fields by reflection and does not call
// their redaction methods, so a secrets.Redacted in an unexported field is
// printed verbatim unless the CONTAINING type implements fmt.Formatter.
func TestNamecheapCredentialNeverAppearsInOutput(t *testing.T) {
	t.Parallel()

	provider, err := NewNamecheap(testNamecheapCreds(), nil)
	if err != nil {
		t.Fatalf("NewNamecheap: %v", err)
	}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
		rendered := fmt.Sprintf(verb, provider)
		if strings.Contains(rendered, testNCAPIKey) {
			t.Errorf("fmt %s of the provider prints the api key: %s", verb, rendered)
		}
	}
}

// TestNamecheapErrorsNeverCarryTheCredential checks the failure paths, which are
// where a credential most plausibly reaches a log.
func TestNamecheapErrorsNeverCarryTheCredential(t *testing.T) {
	domains, zones := singleZone()
	api, provider := newNamecheapAPI(t, domains, zones)

	api.setHostsErr = true
	_, presentErr := provider.Present(t.Context(), namecheapRecord())

	api.setHostsErr = false
	cleanup, err := provider.Present(t.Context(), namecheapRecord())
	if err != nil {
		t.Fatalf("Present: %v", err)
	}
	api.getHostsErr = true
	cleanupErr := cleanup(t.Context())

	for _, e := range []error{presentErr, cleanupErr} {
		if e == nil {
			t.Fatal("expected an error to inspect")
		}
		if strings.Contains(e.Error(), testNCAPIKey) {
			t.Errorf("error text carries the credential: %v", e)
		}
	}
}

// TestNamecheapIsRegisteredInTheSeam checks the provider is reachable through the
// registry, which is what config actually calls.
func TestNamecheapIsRegisteredInTheSeam(t *testing.T) {
	t.Parallel()

	p, err := NewAPIProvider("namecheap", testNamecheapCreds(), nil)
	if err != nil {
		t.Fatalf("NewAPIProvider(namecheap): %v", err)
	}
	if got := p.Name(); got != "namecheap" {
		t.Errorf("Name() = %q, want %q", got, "namecheap")
	}
}

// TestNamecheapErrorMessageTruncationKeepsValidUTF8 pins the bound applied to the
// API's own error text. The message is remote input cut at a fixed BYTE count, so
// a multi-byte rune straddling the boundary would leave a fragment that is not
// valid UTF-8, which the JSON log encoder downstream then mangles.
func TestNamecheapErrorMessageTruncationKeepsValidUTF8(t *testing.T) {
	t.Parallel()

	// One byte of "世" sits before the bound and two after it.
	msg := strings.Repeat("a", maxAPIMessageBytes-1) + "世" + strings.Repeat("b", 50)
	if utf8.ValidString(msg[:maxAPIMessageBytes]) {
		t.Fatalf("fixture no longer splits a rune at the %d-byte cut", maxAPIMessageBytes)
	}

	err := namecheapError([]namecheapAPIError{{Number: "2011166", Description: msg}})
	if err == nil {
		t.Fatal("namecheapError returned nil")
	}
	if !utf8.ValidString(err.Error()) {
		t.Errorf("error text is not valid UTF-8: %q", err.Error())
	}
}
