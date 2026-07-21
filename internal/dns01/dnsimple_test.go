package dns01

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"unicode/utf8"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/secrets"
)

// dsTestToken is the credential every test in this file hands the provider. It
// is a distinctive string so a leak into any output is unmistakable.
const dsTestToken = "ds-token-DO-NOT-LEAK-9f31ab7c"

// dsAccountID is the account whoami reports. The fake REFUSES any other account
// in a request path, which is what makes "the provider actually resolved the
// account" an assertion rather than an assumption.
const dsAccountID = 4021

// dsChallengeValue is this process's published digest.
const dsChallengeValue = "ZG5zaW1wbGVjaGFsbGVuZ2V2YWx1ZS1vbmUtaGVyZQ"

// dsRecord is one stored TXT record in the fake. The tests own this map and seed
// it directly, so every assertion about what survived a cleanup is read from
// state the TEST established rather than from anything the provider computed.
type dsRecord struct {
	name    string // relative, as DNSimple stores it
	content string
}

// dnsimpleAPI is a local stand-in for the DNSimple v2 API. No test in this
// package contacts DNSimple.
type dnsimpleAPI struct {
	t *testing.T

	// mu guards every mutable field below. The concurrency test drives this
	// handler from several goroutines at once, and an unguarded fake would race
	// on its own bookkeeping and report the provider as the culprit.
	mu sync.Mutex

	// requests records every method+path the provider issued, which is how the
	// tests assert what the provider did NOT do -- no delete on the failed
	// publish path, no delete addressed at a sibling challenge.
	requests []string

	// zones is the set of zone names the account holds.
	zones map[string]bool
	// records is the record store, keyed by ID. Seeded by tests.
	records map[int64]dsRecord
	// nextID is the ID handed to the next create.
	nextID int64

	// created holds the body of the last create, so a test can check the record
	// the provider actually asked for.
	created map[string]any

	// nullAccount makes whoami answer as a USER token does: no account.
	nullAccount bool
	// zeroAccount makes whoami answer with an account object carrying no usable
	// id, which is how a broken or impersonating identity endpoint would answer.
	zeroAccount bool
	// createFails makes the create call return an API-level rejection.
	createFails bool
	// ignoreNameFilter makes the listing return every TXT record in the zone
	// regardless of the name filter, which is how a remote service that does not
	// honor the filter -- or something impersonating it -- would answer.
	ignoreNameFilter bool
	// quoteStored wraps stored content in double quotes when it is listed, which
	// is the presentation form DNS uses on the wire and which DNSimple's
	// reference does not rule out.
	quoteStored bool
}

func newDNSimpleAPI(t *testing.T) (*dnsimpleAPI, Provider) {
	t.Helper()

	api := &dnsimpleAPI{
		t:       t,
		zones:   map[string]bool{"example.com": true},
		records: map[int64]dsRecord{},
		nextID:  700,
	}
	srv := httptest.NewServer(api)
	t.Cleanup(srv.Close)

	provider, err := NewDNSimple(secrets.NewRedacted(dsTestToken), srv.Client())
	if err != nil {
		t.Fatalf("NewDNSimple: %v", err)
	}
	// The API base is a constant by design, so the test rewrites the request host
	// in the transport instead of making the endpoint configurable -- making it
	// configurable to suit a test would be exactly the setting that lets a
	// misconfiguration point the token at another host.
	provider.(*dnsimpleProvider).client = &http.Client{
		Transport: dsRewriteHost{srv.URL, srv.Client().Transport},
	}
	return api, provider
}

// dsRewriteHost redirects requests for the real API base at the local fake.
type dsRewriteHost struct {
	base string
	next http.RoundTripper
}

func (r dsRewriteHost) RoundTrip(req *http.Request) (*http.Response, error) {
	target := r.base + strings.TrimPrefix(req.URL.String(), dnsimpleAPIBase)
	clone := req.Clone(req.Context())
	u, err := req.URL.Parse(target)
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

func (a *dnsimpleAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.requests = append(a.requests, r.Method+" "+r.URL.Path+"?"+r.URL.RawQuery)

	if got := r.Header.Get("Authorization"); got != "Bearer "+dsTestToken {
		a.t.Errorf("Authorization header = %q, want the bearer token", got)
	}
	w.Header().Set("Content-Type", "application/json")

	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/"), "/")
	if len(parts) == 1 && parts[0] == "whoami" {
		a.whoami(w)
		return
	}
	// Every other path is account-scoped, and the account must be the one whoami
	// reported. A provider that skipped the resolution, or invented an id, is
	// refused here rather than quietly served -- writing into another account is
	// the silent misroute this scoping exists to prevent.
	if len(parts) < 3 || parts[0] != strconv.Itoa(dsAccountID) || parts[1] != "zones" {
		a.t.Errorf("request %s %s is not scoped to account %d", r.Method, r.URL.Path, dsAccountID)
		a.write(w, http.StatusNotFound, `{"message":"not found"}`)
		return
	}
	zone := parts[2]

	switch {
	case r.Method == http.MethodGet && len(parts) == 3:
		a.getZone(w, zone)

	case r.Method == http.MethodGet && len(parts) == 4 && parts[3] == "records":
		a.listRecords(w, r, zone)

	case r.Method == http.MethodPost && len(parts) == 4 && parts[3] == "records":
		a.createRecord(w, r, zone)

	case r.Method == http.MethodDelete && len(parts) == 5 && parts[3] == "records":
		a.deleteRecord(w, parts[4])

	default:
		a.t.Errorf("unexpected request %s %s", r.Method, r.URL)
		a.write(w, http.StatusBadRequest, `{"message":"unexpected"}`)
	}
}

func (a *dnsimpleAPI) whoami(w http.ResponseWriter) {
	if a.nullAccount {
		// A USER token: DNSimple answers with the user and a null account.
		a.write(w, http.StatusOK, `{"data":{"user":{"id":9},"account":null}}`)
		return
	}
	if a.zeroAccount {
		a.write(w, http.StatusOK, `{"data":{"user":null,"account":{"id":0}}}`)
		return
	}
	a.write(w, http.StatusOK, fmt.Sprintf(`{"data":{"user":null,"account":{"id":%d}}}`, dsAccountID))
}

func (a *dnsimpleAPI) getZone(w http.ResponseWriter, zone string) {
	if !a.zones[zone] {
		a.write(w, http.StatusNotFound, `{"message":"not found"}`)
		return
	}
	a.write(w, http.StatusOK, fmt.Sprintf(`{"data":{"name":%q}}`, zone))
}

func (a *dnsimpleAPI) listRecords(w http.ResponseWriter, r *http.Request, zone string) {
	if !a.zones[zone] {
		a.write(w, http.StatusNotFound, `{"message":"not found"}`)
		return
	}
	// The fake honors the documented RELATIVE, exact name filter, so a provider
	// that sent the FQDN here would get an empty list rather than a lucky match.
	want := r.URL.Query().Get("name")

	type wire struct {
		ID      int64  `json:"id"`
		Type    string `json:"type"`
		Name    string `json:"name"`
		Content string `json:"content"`
	}
	out := []wire{}
	for id, rec := range a.records {
		if !a.ignoreNameFilter && rec.name != want {
			continue
		}
		content := rec.content
		if a.quoteStored {
			content = `"` + content + `"`
		}
		out = append(out, wire{ID: id, Type: "TXT", Name: rec.name, Content: content})
	}
	// Sorted so the listing order is deterministic. Map order would otherwise
	// make the scoping tests flaky in the direction that matters: a provider that
	// dropped its value or name filter would pick whichever record came back
	// first, so it would sometimes pick the right one by luck and the test would
	// pass on a broken implementation. Tests that must observe a WRONG record
	// being chosen seed it with a low ID, so it sorts first.
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	body, err := json.Marshal(map[string]any{"data": out})
	if err != nil {
		a.t.Fatalf("marshal records: %v", err)
	}
	a.write(w, http.StatusOK, string(body))
}

func (a *dnsimpleAPI) createRecord(w http.ResponseWriter, r *http.Request, zone string) {
	if a.createFails {
		a.write(w, http.StatusBadRequest, `{"message":"Validation failed"}`)
		return
	}
	if !a.zones[zone] {
		a.write(w, http.StatusNotFound, `{"message":"not found"}`)
		return
	}
	a.created = map[string]any{}
	if err := json.NewDecoder(r.Body).Decode(&a.created); err != nil {
		a.t.Fatalf("decode create body: %v", err)
	}
	name, _ := a.created["name"].(string)
	// Read through the API's OWN field name. A provider sending DigitalOcean's
	// "data" instead stores an empty TXT record here, which is exactly the silent
	// failure the real API would produce.
	content, _ := a.created["content"].(string)

	id := a.nextID
	a.nextID++
	a.records[id] = dsRecord{name: name, content: content}
	a.write(w, http.StatusCreated, fmt.Sprintf(`{"data":{"id":%d,"type":"TXT","name":%q,"content":%q}}`,
		id, name, content))
}

func (a *dnsimpleAPI) deleteRecord(w http.ResponseWriter, rawID string) {
	id, err := strconv.ParseInt(rawID, 10, 64)
	if err != nil {
		a.t.Errorf("delete with non-numeric id %q", rawID)
		a.write(w, http.StatusBadRequest, `{"message":"bad"}`)
		return
	}
	if _, ok := a.records[id]; !ok {
		a.write(w, http.StatusNotFound, `{"message":"not found"}`)
		return
	}
	delete(a.records, id)
	w.WriteHeader(http.StatusNoContent)
}

func (a *dnsimpleAPI) write(w http.ResponseWriter, status int, body string) {
	w.WriteHeader(status)
	if _, err := w.Write([]byte(body)); err != nil {
		a.t.Errorf("write response: %v", err)
	}
}

// deletes returns the DELETE requests the provider issued.
func (a *dnsimpleAPI) deletes() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []string
	for _, req := range a.requests {
		if strings.HasPrefix(req, http.MethodDelete+" ") {
			out = append(out, req)
		}
	}
	return out
}

// whoamiCount returns how many account lookups the provider issued.
func (a *dnsimpleAPI) whoamiCount() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	var n int
	for _, req := range a.requests {
		if strings.HasPrefix(req, http.MethodGet+" /whoami") {
			n++
		}
	}
	return n
}

func TestDNSimplePresentPublishesRelativeNameAndCleansUp(t *testing.T) {
	api, provider := newDNSimpleAPI(t)
	rec := Record{Name: ChallengeRecordName("vallet.example.com"), Value: dsChallengeValue}

	cleanup, err := provider.Present(t.Context(), rec)
	if err != nil {
		t.Fatalf("Present: %v", err)
	}
	if cleanup == nil {
		t.Fatal("Present returned a nil cleanup")
	}

	// The record name must be RELATIVE to the zone. DNSimple appends the domain
	// itself, so sending the FQDN would create
	// _acme-challenge.vallet.example.com.example.com, which the API accepts and
	// the CA never queries.
	if got := api.created["name"]; got != "_acme-challenge.vallet" {
		t.Errorf("create name = %v, want %q", got, "_acme-challenge.vallet")
	}
	// The value must travel in "content". DigitalOcean's "data" would be ignored
	// by the API and the record would be published empty.
	if got := api.created["content"]; got != dsChallengeValue {
		t.Errorf("create content = %v, want the challenge value", got)
	}
	if _, ok := api.created["data"]; ok {
		t.Error("create body carries a \"data\" field: that is DigitalOcean's " +
			"content field, and DNSimple ignores it")
	}
	if got := api.created["type"]; got != "TXT" {
		t.Errorf("create type = %v, want TXT", got)
	}

	// Read from the fake's own store: exactly one record exists and it is ours.
	if len(api.records) != 1 {
		t.Fatalf("records after publish = %d, want 1", len(api.records))
	}
	for _, stored := range api.records {
		if stored.content != dsChallengeValue {
			t.Errorf("stored content = %q, want the challenge value", stored.content)
		}
	}

	if err := cleanup(t.Context()); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if len(api.records) != 0 {
		t.Errorf("records after cleanup = %d, want 0", len(api.records))
	}
}

// TestDNSimpleCleanupFiltersOnTheRelativeName pins the READ half of the
// relative/FQDN split. DNSimple's name filter matches the record's own relative
// name exactly, so a cleanup that queried the FQDN would get an empty list, find
// nothing, report success, and LEAK the record.
func TestDNSimpleCleanupFiltersOnTheRelativeName(t *testing.T) {
	api, provider := newDNSimpleAPI(t)
	rec := Record{Name: ChallengeRecordName("vallet.example.com"), Value: dsChallengeValue}

	cleanup, err := provider.Present(t.Context(), rec)
	if err != nil {
		t.Fatalf("Present: %v", err)
	}
	if err := cleanup(t.Context()); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if len(api.records) != 0 {
		t.Fatal("cleanup left the record standing: the list filter did not match, " +
			"which is what sending the FQDN instead of the relative name produces")
	}

	var listed string
	for _, req := range api.requests {
		if strings.HasPrefix(req, http.MethodGet+" ") && strings.Contains(req, "/records?") {
			listed = req
		}
	}
	if !strings.Contains(listed, "name=_acme-challenge.vallet&") {
		t.Errorf("list request %q did not filter on the relative name", listed)
	}
	if strings.Contains(listed, "example.com&") || strings.Contains(listed, "example.com%") {
		t.Errorf("list request %q filtered on a fully qualified name", listed)
	}
}

// TestDNSimpleCleanupMatchesQuotedStoredContent covers the read-path tolerance.
// DNSimple's reference does not say whether a TXT value is stored verbatim or in
// the quoted presentation form, and an exact-only comparison against the quoted
// form would find nothing and leak the record.
func TestDNSimpleCleanupMatchesQuotedStoredContent(t *testing.T) {
	api, provider := newDNSimpleAPI(t)
	api.quoteStored = true

	rec := Record{Name: ChallengeRecordName("example.com"), Value: dsChallengeValue}
	cleanup, err := provider.Present(t.Context(), rec)
	if err != nil {
		t.Fatalf("Present: %v", err)
	}
	if err := cleanup(t.Context()); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if len(api.records) != 0 {
		t.Error("cleanup did not remove a record whose content came back quoted")
	}
}

func TestDNSimpleCleanupIsIdempotent(t *testing.T) {
	api, provider := newDNSimpleAPI(t)
	rec := Record{Name: ChallengeRecordName("example.com"), Value: dsChallengeValue}

	cleanup, err := provider.Present(t.Context(), rec)
	if err != nil {
		t.Fatalf("Present: %v", err)
	}
	if err := cleanup(t.Context()); err != nil {
		t.Fatalf("first cleanup: %v", err)
	}
	before := len(api.deletes())
	if err := cleanup(t.Context()); err != nil {
		t.Fatalf("second cleanup on an already-removed record: %v", err)
	}
	if got := len(api.deletes()); got != before {
		t.Errorf("second cleanup issued %d deletes, want none beyond the first %d", got-before, before)
	}
}

// TestDNSimpleCleanupAfterFailedPublishRemovesNothing pins the seam's contract:
// a cleanup MUST come back even when Present fails, and calling it when nothing
// was created must not issue a destructive request.
func TestDNSimpleCleanupAfterFailedPublishRemovesNothing(t *testing.T) {
	api, provider := newDNSimpleAPI(t)
	// A sibling record the test seeds itself. If the failed-publish cleanup were
	// to fall back to deleting by name, this is what it would destroy.
	api.records[100] = dsRecord{name: "_acme-challenge", content: "someone-elses-value"}
	api.createFails = true

	rec := Record{Name: ChallengeRecordName("example.com"), Value: dsChallengeValue}
	cleanup, err := provider.Present(t.Context(), rec)
	if err == nil {
		t.Fatal("Present succeeded, want the API rejection")
	}
	if cleanup == nil {
		t.Fatal("Present returned a nil cleanup on the failure path: a create whose " +
			"response was lost would leak a standing _acme-challenge record")
	}

	if err := cleanup(t.Context()); err != nil {
		t.Fatalf("cleanup after a failed publish: %v", err)
	}
	if got := api.deletes(); len(got) != 0 {
		t.Errorf("cleanup issued destructive requests %v, want none", got)
	}
	if _, ok := api.records[100]; !ok {
		t.Error("cleanup removed the unrelated record it never created")
	}
}

// TestDNSimpleCleanupAfterFailedPublishRemovesARecordThatWasCreated is the other
// half of the contract: when the create DID apply but its response was lost, the
// cleanup handed back from the failing Present must still remove the record.
func TestDNSimpleCleanupAfterFailedPublishRemovesARecordThatWasCreated(t *testing.T) {
	api, provider := newDNSimpleAPI(t)
	api.createFails = true
	// The record the lost-response create left standing, seeded by the test at
	// the exact name and value this challenge publishes.
	api.records[100] = dsRecord{name: "_acme-challenge", content: dsChallengeValue}

	rec := Record{Name: ChallengeRecordName("example.com"), Value: dsChallengeValue}
	cleanup, err := provider.Present(t.Context(), rec)
	if err == nil {
		t.Fatal("Present succeeded, want the API rejection")
	}
	if cleanup == nil {
		t.Fatal("Present returned a nil cleanup on the failure path")
	}
	if err := cleanup(t.Context()); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if _, ok := api.records[100]; ok {
		t.Error("the cleanup from a failed publish left the created record standing")
	}
}

func TestDNSimplePresentSurfacesAPIRejection(t *testing.T) {
	api, provider := newDNSimpleAPI(t)
	api.createFails = true

	rec := Record{Name: ChallengeRecordName("example.com"), Value: dsChallengeValue}
	_, err := provider.Present(t.Context(), rec)
	if err == nil {
		t.Fatal("Present succeeded, want the API rejection")
	}
	if !strings.Contains(err.Error(), "400") {
		t.Errorf("error %q does not name the API fault", err)
	}
	if strings.Contains(err.Error(), dsTestToken) {
		t.Fatal("error carries the API token")
	}
}

// TestDNSimpleWildcardCleanupRemovesOnlyItsOwnValue is the scoping test. A
// certificate covering example.com and *.example.com puts TWO challenges at the
// same name with different digests, so cleanup must remove one value and leave
// the other.
//
// The sibling is seeded by the test with a known ID, and the survivor is checked
// against that seeded state -- never against anything the provider computed.
func TestDNSimpleWildcardCleanupRemovesOnlyItsOwnValue(t *testing.T) {
	api, provider := newDNSimpleAPI(t)

	const siblingID = 100
	const siblingValue = "c2libGluZ3dpbGRjYXJkZG5zaW1wbGV2YWx1ZS10d28"
	api.records[siblingID] = dsRecord{name: "_acme-challenge", content: siblingValue}

	rec := Record{Name: ChallengeRecordName("*.example.com"), Value: dsChallengeValue}
	if rec.Name != "_acme-challenge.example.com" {
		t.Fatalf("fixture: challenge name = %q", rec.Name)
	}

	cleanup, err := provider.Present(t.Context(), rec)
	if err != nil {
		t.Fatalf("Present: %v", err)
	}
	// Both values now sit at the one name, which is what makes the value filter
	// in findRecord load-bearing: without it the listing is ambiguous by ID.
	if len(api.records) != 2 {
		t.Fatalf("records after publish = %d, want 2 (ours and the sibling)", len(api.records))
	}

	if err := cleanup(t.Context()); err != nil {
		t.Fatalf("cleanup: %v", err)
	}

	survivor, ok := api.records[siblingID]
	if !ok {
		t.Fatal("cleanup removed the sibling wildcard challenge, which is still in flight")
	}
	if survivor.content != siblingValue {
		t.Errorf("sibling content = %q, want it untouched", survivor.content)
	}
	if len(api.records) != 1 {
		t.Errorf("records after cleanup = %d, want only the sibling", len(api.records))
	}
	// Exactly one delete, and it named the ID of OUR record -- not the sibling's.
	dels := api.deletes()
	if len(dels) != 1 {
		t.Fatalf("deletes = %v, want exactly one", dels)
	}
	if strings.Contains(dels[0], strconv.Itoa(siblingID)) {
		t.Errorf("delete %q addressed the sibling record", dels[0])
	}
}

// TestDNSimpleCleanupDoesNotTrustTheRemoteNameFilter drives an API that ignores
// the name filter, which is how a broken or impersonating service would answer.
// The provider re-checks the record name in code, so a record at an UNRELATED
// name must survive even when it carries the same value.
func TestDNSimpleCleanupDoesNotTrustTheRemoteNameFilter(t *testing.T) {
	api, provider := newDNSimpleAPI(t)
	api.ignoreNameFilter = true

	const strayID = 100
	api.records[strayID] = dsRecord{name: "unrelated", content: dsChallengeValue}

	rec := Record{Name: ChallengeRecordName("example.com"), Value: dsChallengeValue}
	cleanup, err := provider.Present(t.Context(), rec)
	if err != nil {
		t.Fatalf("Present: %v", err)
	}
	if err := cleanup(t.Context()); err != nil {
		t.Fatalf("cleanup: %v", err)
	}

	if _, ok := api.records[strayID]; !ok {
		t.Error("cleanup deleted a record at an unrelated name: the provider trusted " +
			"the API's name filter instead of re-checking the name itself")
	}
	if len(api.records) != 1 {
		t.Errorf("records after cleanup = %d, want only the unrelated one", len(api.records))
	}
}

// TestDNSimpleResolvesTheAccountFromTheToken pins where the account id comes
// from. Every zone and record path is account-scoped, and the id is taken from
// whoami -- the account the PRESENTED TOKEN belongs to -- so no configured
// number can point a credentialed write at another account.
func TestDNSimpleResolvesTheAccountFromTheToken(t *testing.T) {
	api, provider := newDNSimpleAPI(t)
	rec := Record{Name: ChallengeRecordName("example.com"), Value: dsChallengeValue}

	if _, err := provider.Present(t.Context(), rec); err != nil {
		t.Fatalf("Present: %v", err)
	}
	if len(api.requests) == 0 || !strings.HasPrefix(api.requests[0], http.MethodGet+" /whoami") {
		t.Fatalf("first request = %v, want the whoami that resolves the account", api.requests)
	}
	// The fake refuses any path not scoped to dsAccountID, so reaching a create
	// at all proves the resolved id was used. Checked explicitly anyway.
	for _, req := range api.requests[1:] {
		if !strings.Contains(req, "/"+strconv.Itoa(dsAccountID)+"/zones/") {
			t.Errorf("request %q is not scoped to the resolved account", req)
		}
	}
}

// TestDNSimpleResolvesTheAccountOnlyOnce pins the caching. whoami is per
// provider, not per issuance.
func TestDNSimpleResolvesTheAccountOnlyOnce(t *testing.T) {
	api, provider := newDNSimpleAPI(t)
	rec := Record{Name: ChallengeRecordName("example.com"), Value: dsChallengeValue}

	for range 2 {
		if _, err := provider.Present(t.Context(), rec); err != nil {
			t.Fatalf("Present: %v", err)
		}
	}
	var whoamis int
	for _, req := range api.requests {
		if strings.HasPrefix(req, http.MethodGet+" /whoami") {
			whoamis++
		}
	}
	if whoamis != 1 {
		t.Errorf("whoami calls = %d, want 1: the resolved account must be cached", whoamis)
	}
}

// TestDNSimpleAccountResolutionIsConcurrencySafe drives the account resolution
// from several goroutines at once, which is the shape a multi-name order takes:
// one provider, several challenges in flight.
//
// Run under -race, it covers the reason the whoami call is NOT made under the
// mutex. Racers may each issue their own lookup -- that is the accepted cost of
// not holding a lock across a network call -- but every one of them must leave
// with the SAME non-zero id, because the first write wins and the losers return
// the cached value rather than their own.
func TestDNSimpleAccountResolutionIsConcurrencySafe(t *testing.T) {
	api, provider := newDNSimpleAPI(t)

	const goroutines = 8
	// Each round races a FRESH provider, because the cache is written exactly
	// once per provider. Reusing one provider would put every caller's read
	// before that single early write, so no read would ever overlap it: the race
	// detector would see nothing and the test would pass whether or not the
	// cache is guarded at all. Measured -- with a single shared provider,
	// removing the mutex from cachedAccount survives every run. Many rounds give
	// many first-writes, and a goroutine still arriving at its read while a
	// faster sibling has already published is the interleaving that trips the
	// detector.
	const rounds = 40

	for range rounds {
		// A fresh provider over the SAME fake, so the cache starts empty while
		// the request-counting stays cumulative.
		p := &dnsimpleProvider{
			token:  secrets.NewRedacted(dsTestToken),
			client: provider.(*dnsimpleProvider).client,
		}

		var start sync.WaitGroup
		var done sync.WaitGroup
		start.Add(1)
		ids := make([]int64, goroutines)
		errs := make([]error, goroutines)

		for i := range goroutines {
			done.Add(1)
			go func() {
				defer done.Done()
				// Released together, so the callers genuinely contend for the
				// first resolution instead of arriving one after another.
				start.Wait()
				ids[i], errs[i] = p.account(t.Context())
			}()
		}
		start.Done()
		done.Wait()

		for i := range goroutines {
			if errs[i] != nil {
				t.Fatalf("goroutine %d: account: %v", i, errs[i])
			}
			if ids[i] == 0 {
				t.Fatalf("goroutine %d observed account 0: a racer read the cache "+
					"before it was published", i)
			}
			if ids[i] != dsAccountID {
				t.Fatalf("goroutine %d got account %d, want %d", i, ids[i], dsAccountID)
			}
		}
		// Once resolved, the cache serves every later caller on this provider.
		before := api.whoamiCount()
		if id, err := p.account(t.Context()); err != nil || id != dsAccountID {
			t.Fatalf("account after the race = %d, %v; want the cached id", id, err)
		}
		if got := api.whoamiCount(); got != before {
			t.Fatalf("a call after the race issued another whoami (%d -> %d)", before, got)
		}
	}
}

// TestDNSimpleUserTokenRefusalIsNotCached pins that the refusal stays reachable.
// It is returned before the cache is written, so it must fire on EVERY call --
// a one-shot error that a later call skipped past would let a user token through
// on a retry.
func TestDNSimpleUserTokenRefusalIsNotCached(t *testing.T) {
	api, provider := newDNSimpleAPI(t)
	api.nullAccount = true
	p := provider.(*dnsimpleProvider)

	for i := range 3 {
		id, err := p.account(t.Context())
		if err == nil {
			t.Fatalf("call %d: account succeeded for a user token", i)
		}
		if id != 0 {
			t.Errorf("call %d: account = %d alongside an error, want 0", i, id)
		}
		if !strings.Contains(err.Error(), "account token") {
			t.Errorf("call %d: error %q is not the user-token refusal", i, err)
		}
	}
	if got := api.whoamiCount(); got != 3 {
		t.Errorf("whoami calls = %d, want 3: a failed resolution must not be cached", got)
	}
}

// TestDNSimpleErrorMessageTruncationKeepsValidUTF8 pins that bounding the API's
// own message cannot leave a partial rune. A fixed byte cut can land inside a
// multi-byte sequence, and the invalid UTF-8 that results is mangled by whatever
// encodes the log record downstream.
func TestDNSimpleErrorMessageTruncationKeepsValidUTF8(t *testing.T) {
	// One byte of "世" sits before the bound and two after it.
	msg := strings.Repeat("a", maxAPIMessageBytes-1) + "世" + strings.Repeat("b", 50)
	if utf8.ValidString(msg[:maxAPIMessageBytes]) {
		t.Fatalf("fixture no longer splits a rune at the %d-byte cut", maxAPIMessageBytes)
	}

	raw, err := json.Marshal(map[string]any{"message": msg})
	if err != nil {
		t.Fatalf("marshal error body: %v", err)
	}

	got := dnsimpleError(http.StatusBadRequest, raw)
	if got == nil {
		t.Fatal("dnsimpleError returned nil")
	}
	if !utf8.ValidString(got.Error()) {
		t.Errorf("error text is not valid UTF-8: %q", got.Error())
	}
	// The repair must cost at most the bytes a partial rune can be, so the
	// diagnostic is not silently gutted.
	if len(got.Error()) < maxAPIMessageBytes-utf8.UTFMax {
		t.Errorf("truncation discarded more than a partial rune: %d bytes", len(got.Error()))
	}
}

// TestDNSimpleRefusesAUserToken pins the loud refusal. DNSimple issues both
// account and user tokens, and whoami answers a user token with a NULL account.
// A user may belong to several accounts, so there is no account this token
// means, and picking one would decide on the program's own initiative which of
// the operator's accounts gets written to.
func TestDNSimpleRefusesAUserToken(t *testing.T) {
	api, provider := newDNSimpleAPI(t)
	api.nullAccount = true

	rec := Record{Name: ChallengeRecordName("example.com"), Value: dsChallengeValue}
	_, err := provider.Present(t.Context(), rec)
	if err == nil {
		t.Fatal("Present succeeded with a token that resolves to no account")
	}
	if !strings.Contains(err.Error(), "account token") {
		t.Errorf("error %q does not name the user-vs-account token fault", err)
	}
	if len(api.requests) != 1 {
		t.Errorf("requests = %v, want only the whoami: nothing may be written "+
			"before the account is known", api.requests)
	}
}

// TestDNSimpleRefusesAnAccountWithoutAUsableID covers the other half of the
// account guard. An identity endpoint that is broken -- or impersonating -- can
// answer with an account object carrying no usable id, and accepting it would
// scope every later write to account "0": a path that addresses nothing, failing
// later and further away as a missing zone rather than here as the unusable
// identity it is.
func TestDNSimpleRefusesAnAccountWithoutAUsableID(t *testing.T) {
	api, provider := newDNSimpleAPI(t)
	api.zeroAccount = true

	rec := Record{Name: ChallengeRecordName("example.com"), Value: dsChallengeValue}
	_, err := provider.Present(t.Context(), rec)
	if err == nil {
		t.Fatal("Present succeeded with an account carrying no usable id")
	}
	if len(api.requests) != 1 {
		t.Errorf("requests = %v, want only the whoami: nothing may be written "+
			"before a usable account is known", api.requests)
	}
}

func TestDNSimpleUnknownZoneRefuses(t *testing.T) {
	api, provider := newDNSimpleAPI(t)
	api.zones = map[string]bool{} // the account holds nothing

	rec := Record{Name: ChallengeRecordName("vallet.example.com"), Value: dsChallengeValue}
	_, err := provider.Present(t.Context(), rec)
	if err == nil {
		t.Fatal("Present succeeded with no matching zone, want a refusal")
	}
	if !strings.Contains(err.Error(), "no zone found") {
		t.Errorf("error %q does not name the missing zone as the fault", err)
	}
	if len(api.deletes()) != 0 {
		t.Error("a failed zone lookup issued a destructive request")
	}
}

// TestDNSimplePrefersTheMostSpecificZone pins the walk order. Writing to the
// parent of a delegated subdomain puts the record in a zone that is not
// authoritative for the name.
func TestDNSimplePrefersTheMostSpecificZone(t *testing.T) {
	api, provider := newDNSimpleAPI(t)
	api.zones = map[string]bool{"example.com": true, "eu.example.com": true}

	rec := Record{Name: ChallengeRecordName("vallet.eu.example.com"), Value: dsChallengeValue}
	if _, err := provider.Present(t.Context(), rec); err != nil {
		t.Fatalf("Present: %v", err)
	}
	if got := api.created["name"]; got != "_acme-challenge.vallet" {
		t.Errorf("create name = %v, want the name relative to eu.example.com", got)
	}
	var createdUnder string
	for _, req := range api.requests {
		if strings.HasPrefix(req, http.MethodPost+" ") {
			createdUnder = req
		}
	}
	if !strings.Contains(createdUnder, "/zones/eu.example.com/records") {
		t.Errorf("create went to %q, want the delegated eu.example.com", createdUnder)
	}
}

// TestDNSimpleRefusesAMalformedZoneCandidate pins the check that keeps a value
// derived from the certificate request from reaching a request path as anything
// other than a domain name.
func TestDNSimpleRefusesAMalformedZoneCandidate(t *testing.T) {
	api, provider := newDNSimpleAPI(t)

	rec := Record{Name: "_acme-challenge.ev/il.com", Value: dsChallengeValue}
	_, err := provider.Present(t.Context(), rec)
	if err == nil {
		t.Fatal("Present succeeded for a malformed zone candidate")
	}
	if !strings.Contains(err.Error(), "malformed zone candidate") {
		t.Errorf("error %q is not the refusal: the candidate reached the API", err)
	}
	// Only the whoami may have been issued; no zone lookup for the crafted name.
	for _, req := range api.requests {
		if strings.Contains(req, "/zones/") {
			t.Errorf("a malformed candidate produced a zone request %q", req)
		}
	}
}

func TestDNSimpleMissingCredentialRefused(t *testing.T) {
	if _, err := NewDNSimple(secrets.NewRedacted(""), nil); err == nil {
		t.Error("NewDNSimple with an empty token succeeded, want a refusal at construction")
	}
	if _, err := NewDNSimple(secrets.NewRedacted(dsTestToken), nil); err != nil {
		t.Errorf("NewDNSimple with a token: %v", err)
	}
}

// TestDNSimpleRecordNameUsesTheEmptyApexEncoding pins the one place DNSimple's
// relative form differs from DigitalOcean's: the apex is the empty string, not
// "@". The shared label-boundary rule is reused; only the encoding is
// translated.
func TestDNSimpleRecordNameUsesTheEmptyApexEncoding(t *testing.T) {
	for _, tc := range []struct {
		fqdn, zone, want string
		wantErr          bool
	}{
		{fqdn: "_acme-challenge.example.com", zone: "example.com", want: "_acme-challenge"},
		{fqdn: "_acme-challenge.a.b.example.com", zone: "example.com", want: "_acme-challenge.a.b"},
		{fqdn: "_acme-challenge.example.com.", zone: "example.com", want: "_acme-challenge"},
		{fqdn: "example.com", zone: "example.com", want: ""},
		// A suffix match that is not a LABEL boundary must not be accepted:
		// "notexample.com" ends with "example.com" as a string.
		{fqdn: "_acme-challenge.notexample.com", zone: "example.com", wantErr: true},
		{fqdn: "_acme-challenge.other.org", zone: "example.com", wantErr: true},
	} {
		got, err := dnsimpleRecordName(tc.fqdn, tc.zone)
		if tc.wantErr {
			if err == nil {
				t.Errorf("dnsimpleRecordName(%q, %q) = %q, want an error", tc.fqdn, tc.zone, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("dnsimpleRecordName(%q, %q): %v", tc.fqdn, tc.zone, err)
			continue
		}
		if got != tc.want {
			t.Errorf("dnsimpleRecordName(%q, %q) = %q, want %q", tc.fqdn, tc.zone, got, tc.want)
		}
	}
}

// TestDNSimpleProviderNeverFormatsItsToken covers the mechanism, not a string:
// fmt walks unexported struct fields by reflection and does NOT call
// secrets.Redacted's redaction methods, so without Format on the containing type
// "%+v" prints the bearer token in full.
func TestDNSimpleProviderNeverFormatsItsToken(t *testing.T) {
	provider, err := NewDNSimple(secrets.NewRedacted(dsTestToken), nil)
	if err != nil {
		t.Fatalf("NewDNSimple: %v", err)
	}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
		if rendered := fmt.Sprintf(verb, provider); strings.Contains(rendered, dsTestToken) {
			t.Errorf("fmt %s of the provider leaked the token: %s", verb, rendered)
		}
	}
}

func TestNewAPIProviderBuildsDNSimple(t *testing.T) {
	provider, err := NewAPIProvider("dnsimple", secrets.NewRedacted(dsTestToken), nil)
	if err != nil {
		t.Fatalf("NewAPIProvider: %v", err)
	}
	if got := provider.Name(); got != "dnsimple" {
		t.Errorf("Name() = %q, want %q", got, "dnsimple")
	}
}

// TestDNSimpleDoesNotPollForPropagation pins the seam's division of labor: the
// solver polls the authoritative nameservers, so a provider must not add a
// redundant, weaker wait of its own.
func TestDNSimpleDoesNotPollForPropagation(t *testing.T) {
	api, provider := newDNSimpleAPI(t)
	rec := Record{Name: ChallengeRecordName("example.com"), Value: dsChallengeValue}

	if _, err := provider.Present(context.Background(), rec); err != nil {
		t.Fatalf("Present: %v", err)
	}
	// A whoami, one zone lookup and one create. Any read-back of the record after
	// the create would be a propagation poll.
	for _, req := range api.requests {
		if strings.HasPrefix(req, http.MethodGet+" ") && strings.Contains(req, "/records") {
			t.Errorf("Present read records back (%q), which is a propagation poll", req)
		}
	}
}
