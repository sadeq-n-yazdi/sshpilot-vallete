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
	"testing"
	"unicode/utf8"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/secrets"
)

// doTestToken is the credential every test in this file hands the provider. It
// is a distinctive string so a leak into any output is unmistakable.
const doTestToken = "do-token-DO-NOT-LEAK-4c71e9b0"

// doRecord is one stored TXT record in the fake. The tests own this map and
// seed it directly, so every assertion about what survived a cleanup is read
// from state the TEST established rather than from anything the provider
// computed.
type doRecord struct {
	name string // relative, as DigitalOcean stores it
	data string
}

// digitalOceanAPI is a local stand-in for the DigitalOcean v2 API. No test in
// this package contacts DigitalOcean.
type digitalOceanAPI struct {
	t *testing.T

	// requests records every method+path the provider issued, which is how the
	// tests assert what the provider did NOT do -- no delete on the failed
	// publish path, no delete addressed at a sibling challenge.
	requests []string

	// domains is the set of domain names the account holds.
	domains map[string]bool
	// records is the record store, keyed by ID. Seeded by tests.
	records map[int64]doRecord
	// nextID is the ID handed to the next create.
	nextID int64

	// created holds the body of the last create, so a test can check the record
	// the provider actually asked for.
	created map[string]any

	// createFails makes the create call return an API-level rejection.
	createFails bool
	// ignoreNameFilter makes the listing return every TXT record in the domain
	// regardless of the name filter, which is how a remote service that does not
	// honor the filter -- or something impersonating it -- would answer.
	ignoreNameFilter bool
	// deleteStatus overrides the response code for a delete.
	deleteStatus int
}

func newDigitalOceanAPI(t *testing.T) (*digitalOceanAPI, Provider) {
	t.Helper()

	api := &digitalOceanAPI{
		t:            t,
		domains:      map[string]bool{"example.com": true},
		records:      map[int64]doRecord{},
		nextID:       500,
		deleteStatus: http.StatusNoContent,
	}
	srv := httptest.NewServer(api)
	t.Cleanup(srv.Close)

	provider, err := NewDigitalOcean(NewSingleCredential(secrets.NewRedacted(doTestToken)), srv.Client())
	if err != nil {
		t.Fatalf("NewDigitalOcean: %v", err)
	}
	// The API base is a constant by design, so the test rewrites the request
	// host in the transport instead of making the endpoint configurable --
	// making it configurable to suit a test would be exactly the setting that
	// lets a misconfiguration point the token at another host.
	provider.(*digitalOceanProvider).client = &http.Client{
		Transport: doRewriteHost{srv.URL, srv.Client().Transport},
	}
	return api, provider
}

// doRewriteHost redirects requests for the real API base at the local fake.
type doRewriteHost struct {
	base string
	next http.RoundTripper
}

func (r doRewriteHost) RoundTrip(req *http.Request) (*http.Response, error) {
	target := r.base + strings.TrimPrefix(req.URL.String(), digitalOceanAPIBase)
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

func (a *digitalOceanAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.requests = append(a.requests, r.Method+" "+r.URL.Path+"?"+r.URL.RawQuery)

	if got := r.Header.Get("Authorization"); got != "Bearer "+doTestToken {
		a.t.Errorf("Authorization header = %q, want the bearer token", got)
	}
	w.Header().Set("Content-Type", "application/json")

	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/"), "/")
	switch {
	case r.Method == http.MethodGet && len(parts) == 2 && parts[0] == "domains":
		a.getDomain(w, parts[1])

	case r.Method == http.MethodGet && len(parts) == 3 && parts[2] == "records":
		a.listRecords(w, r, parts[1])

	case r.Method == http.MethodPost && len(parts) == 3 && parts[2] == "records":
		a.createRecord(w, r, parts[1])

	case r.Method == http.MethodDelete && len(parts) == 4 && parts[2] == "records":
		a.deleteRecord(w, parts[3])

	default:
		a.t.Errorf("unexpected request %s %s", r.Method, r.URL)
		a.write(w, http.StatusBadRequest, `{"id":"unexpected","message":"unexpected"}`)
	}
}

func (a *digitalOceanAPI) getDomain(w http.ResponseWriter, name string) {
	if !a.domains[name] {
		a.write(w, http.StatusNotFound, `{"id":"not_found","message":"not found"}`)
		return
	}
	a.write(w, http.StatusOK, fmt.Sprintf(`{"domain":{"name":%q}}`, name))
}

func (a *digitalOceanAPI) listRecords(w http.ResponseWriter, r *http.Request, domain string) {
	if !a.domains[domain] {
		a.write(w, http.StatusNotFound, `{"id":"not_found","message":"not found"}`)
		return
	}
	// The fake honors the documented FQDN name filter, so a provider that sent
	// the relative name here would get an empty list rather than a lucky match.
	want := strings.TrimSuffix(r.URL.Query().Get("name"), ".")

	type wire struct {
		ID   int64  `json:"id"`
		Type string `json:"type"`
		Name string `json:"name"`
		Data string `json:"data"`
	}
	out := []wire{}
	for id, rec := range a.records {
		if !a.ignoreNameFilter && rec.name+"."+domain != want {
			continue
		}
		out = append(out, wire{ID: id, Type: "TXT", Name: rec.name, Data: rec.data})
	}
	// Sorted so the listing order is deterministic. Map order would otherwise
	// make the scoping tests flaky in the direction that matters: a provider
	// that dropped its value or name filter would pick whichever record came
	// back first, so it would sometimes pick the right one by luck and the test
	// would pass on a broken implementation. Tests that must observe a WRONG
	// record being chosen seed it with a low ID, so it sorts first.
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	body, err := json.Marshal(map[string]any{"domain_records": out})
	if err != nil {
		a.t.Fatalf("marshal records: %v", err)
	}
	a.write(w, http.StatusOK, string(body))
}

func (a *digitalOceanAPI) createRecord(w http.ResponseWriter, r *http.Request, domain string) {
	if a.createFails {
		a.write(w, http.StatusUnprocessableEntity, `{"id":"unprocessable_entity","message":"quota exceeded"}`)
		return
	}
	if !a.domains[domain] {
		a.write(w, http.StatusNotFound, `{"id":"not_found","message":"not found"}`)
		return
	}
	a.created = map[string]any{}
	if err := json.NewDecoder(r.Body).Decode(&a.created); err != nil {
		a.t.Fatalf("decode create body: %v", err)
	}
	name, _ := a.created["name"].(string)
	data, _ := a.created["data"].(string)

	id := a.nextID
	a.nextID++
	a.records[id] = doRecord{name: name, data: data}
	a.write(w, http.StatusCreated, fmt.Sprintf(`{"domain_record":{"id":%d,"type":"TXT","name":%q,"data":%q}}`,
		id, name, data))
}

func (a *digitalOceanAPI) deleteRecord(w http.ResponseWriter, rawID string) {
	id, err := strconv.ParseInt(rawID, 10, 64)
	if err != nil {
		a.t.Errorf("delete with non-numeric id %q", rawID)
		a.write(w, http.StatusBadRequest, `{"id":"bad","message":"bad"}`)
		return
	}
	if a.deleteStatus != http.StatusNoContent {
		a.write(w, a.deleteStatus, `{"id":"server_error","message":"nope"}`)
		return
	}
	if _, ok := a.records[id]; !ok {
		a.write(w, http.StatusNotFound, `{"id":"not_found","message":"not found"}`)
		return
	}
	delete(a.records, id)
	w.WriteHeader(http.StatusNoContent)
}

func (a *digitalOceanAPI) write(w http.ResponseWriter, status int, body string) {
	w.WriteHeader(status)
	if _, err := w.Write([]byte(body)); err != nil {
		a.t.Errorf("write response: %v", err)
	}
}

// deletes returns the DELETE requests the provider issued.
func (a *digitalOceanAPI) deletes() []string {
	var out []string
	for _, req := range a.requests {
		if strings.HasPrefix(req, http.MethodDelete+" ") {
			out = append(out, req)
		}
	}
	return out
}

const doChallengeValue = "aXpsSGdZQlB2c3NlY2hhbGxlbmdldmFsdWUtb25l"

func TestDigitalOceanPresentPublishesRelativeNameAndCleansUp(t *testing.T) {
	api, provider := newDigitalOceanAPI(t)
	rec := Record{Name: ChallengeRecordName("vallet.example.com"), Value: doChallengeValue}

	cleanup, err := provider.Present(t.Context(), rec)
	if err != nil {
		t.Fatalf("Present: %v", err)
	}
	if cleanup == nil {
		t.Fatal("Present returned a nil cleanup")
	}

	// The record name must be RELATIVE to the domain. Sending the FQDN would
	// create _acme-challenge.vallet.example.com.example.com, which the API
	// accepts and the CA never queries.
	if got := api.created["name"]; got != "_acme-challenge.vallet" {
		t.Errorf("create name = %v, want %q", got, "_acme-challenge.vallet")
	}
	if got := api.created["data"]; got != doChallengeValue {
		t.Errorf("create data = %v, want the challenge value", got)
	}
	if got := api.created["type"]; got != "TXT" {
		t.Errorf("create type = %v, want TXT", got)
	}

	// Read from the fake's own store: exactly one record exists and it is ours.
	if len(api.records) != 1 {
		t.Fatalf("records after publish = %d, want 1", len(api.records))
	}

	if err := cleanup(t.Context()); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if len(api.records) != 0 {
		t.Errorf("records after cleanup = %d, want 0", len(api.records))
	}
}

func TestDigitalOceanCleanupIsIdempotent(t *testing.T) {
	api, provider := newDigitalOceanAPI(t)
	rec := Record{Name: ChallengeRecordName("example.com"), Value: doChallengeValue}

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

// TestDigitalOceanCleanupAfterFailedPublishRemovesNothing pins the seam's
// contract: a cleanup MUST come back even when Present fails, and calling it
// when nothing was created must not issue a destructive request.
func TestDigitalOceanCleanupAfterFailedPublishRemovesNothing(t *testing.T) {
	api, provider := newDigitalOceanAPI(t)
	// A sibling record the test seeds itself. If the failed-publish cleanup were
	// to fall back to deleting by name, this is what it would destroy.
	api.records[100] = doRecord{name: "_acme-challenge", data: "someone-elses-value"}
	api.createFails = true

	rec := Record{Name: ChallengeRecordName("example.com"), Value: doChallengeValue}
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

func TestDigitalOceanPresentSurfacesAPIRejection(t *testing.T) {
	api, provider := newDigitalOceanAPI(t)
	api.createFails = true

	rec := Record{Name: ChallengeRecordName("example.com"), Value: doChallengeValue}
	_, err := provider.Present(t.Context(), rec)
	if err == nil {
		t.Fatal("Present succeeded, want the API rejection")
	}
	if !strings.Contains(err.Error(), "422") {
		t.Errorf("error %q does not name the API fault", err)
	}
	if strings.Contains(err.Error(), doTestToken) {
		t.Fatal("error carries the API token")
	}
}

// TestDigitalOceanWildcardCleanupRemovesOnlyItsOwnValue is the scoping test. A
// certificate covering example.com and *.example.com puts TWO challenges at the
// same name with different digests, so cleanup must remove one value and leave
// the other.
//
// The sibling is seeded by the test with a known ID, and the survivor is checked
// against that seeded state -- never against anything the provider computed.
func TestDigitalOceanWildcardCleanupRemovesOnlyItsOwnValue(t *testing.T) {
	api, provider := newDigitalOceanAPI(t)

	const siblingID = 100
	const siblingValue = "c2libGluZ3dpbGRjYXJkY2hhbGxlbmdldmFsdWUtdHdv"
	api.records[siblingID] = doRecord{name: "_acme-challenge", data: siblingValue}

	rec := Record{Name: ChallengeRecordName("*.example.com"), Value: doChallengeValue}
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
	if survivor.data != siblingValue {
		t.Errorf("sibling data = %q, want it untouched", survivor.data)
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

// TestDigitalOceanCleanupDoesNotTrustTheRemoteNameFilter drives an API that
// ignores the name filter, which is how a broken or impersonating service would
// answer. The provider re-checks the record name in code, so a record at an
// UNRELATED name must survive even when it carries the same value.
//
// The fixture keeps the challenge name unambiguous -- our own record is present
// and deletable -- so the assertion that fires is the one about the unrelated
// record, not an incidental "nothing to delete" path.
func TestDigitalOceanCleanupDoesNotTrustTheRemoteNameFilter(t *testing.T) {
	api, provider := newDigitalOceanAPI(t)
	api.ignoreNameFilter = true

	const strayID = 100
	api.records[strayID] = doRecord{name: "unrelated", data: doChallengeValue}

	rec := Record{Name: ChallengeRecordName("example.com"), Value: doChallengeValue}
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

// TestDigitalOceanRefusesAMalformedDomainCandidate pins the check that keeps a
// value derived from the certificate request from reaching a request path as
// anything other than a domain name.
//
// The assertion is on the SPECIFIC refusal, because without the check the walk
// still ends in an error -- an escaped candidate merely 404s and the walk runs
// out. Only the message distinguishes "refused before the request" from "asked
// the API about a crafted name".
func TestDigitalOceanRefusesAMalformedDomainCandidate(t *testing.T) {
	api, provider := newDigitalOceanAPI(t)

	rec := Record{Name: "_acme-challenge.ev/il.com", Value: doChallengeValue}
	_, err := provider.Present(t.Context(), rec)
	if err == nil {
		t.Fatal("Present succeeded for a malformed domain candidate")
	}
	if !strings.Contains(err.Error(), "malformed domain candidate") {
		t.Errorf("error %q is not the refusal: the candidate reached the API", err)
	}
	if len(api.requests) != 0 {
		t.Errorf("a malformed candidate produced requests %v, want none", api.requests)
	}
}

func TestDigitalOceanUnknownDomainRefuses(t *testing.T) {
	api, provider := newDigitalOceanAPI(t)
	api.domains = map[string]bool{} // the account holds nothing

	rec := Record{Name: ChallengeRecordName("vallet.example.com"), Value: doChallengeValue}
	_, err := provider.Present(t.Context(), rec)
	if err == nil {
		t.Fatal("Present succeeded with no matching domain, want a refusal")
	}
	if !strings.Contains(err.Error(), "no domain found") {
		t.Errorf("error %q does not name the missing domain as the fault", err)
	}
	if len(api.deletes()) != 0 {
		t.Error("a failed domain lookup issued a destructive request")
	}
}

// TestDigitalOceanPrefersTheMostSpecificDomain pins the walk order. Writing to
// the parent of a delegated subdomain puts the record in a zone that is not
// authoritative for the name.
func TestDigitalOceanPrefersTheMostSpecificDomain(t *testing.T) {
	api, provider := newDigitalOceanAPI(t)
	api.domains = map[string]bool{"example.com": true, "eu.example.com": true}

	rec := Record{Name: ChallengeRecordName("vallet.eu.example.com"), Value: doChallengeValue}
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
	if !strings.Contains(createdUnder, "/domains/eu.example.com/records") {
		t.Errorf("create went to %q, want the delegated eu.example.com", createdUnder)
	}
}

func TestDigitalOceanMissingCredentialRefused(t *testing.T) {
	if _, err := NewDigitalOcean(NewSingleCredential(secrets.NewRedacted("")), nil); err == nil {
		t.Error("NewDigitalOcean with an empty token succeeded, want a refusal at construction")
	}
	if _, err := NewDigitalOcean(NewSingleCredential(secrets.NewRedacted(doTestToken)), nil); err != nil {
		t.Errorf("NewDigitalOcean with a token: %v", err)
	}
}

// TestRelativeRecordNameRejectsNamesOutsideTheDomain pins the split that decides
// where the record is written. A wrong split is silent: DigitalOcean accepts an
// unsuffixed name as a subdomain prefix.
func TestRelativeRecordNameRejectsNamesOutsideTheDomain(t *testing.T) {
	for _, tc := range []struct {
		fqdn, domain, want string
		wantErr            bool
	}{
		{fqdn: "_acme-challenge.example.com", domain: "example.com", want: "_acme-challenge"},
		{fqdn: "_acme-challenge.a.b.example.com", domain: "example.com", want: "_acme-challenge.a.b"},
		{fqdn: "_acme-challenge.example.com.", domain: "example.com", want: "_acme-challenge"},
		{fqdn: "example.com", domain: "example.com", want: "@"},
		// A suffix match that is not a LABEL boundary must not be accepted:
		// "notexample.com" ends with "example.com" as a string.
		{fqdn: "_acme-challenge.notexample.com", domain: "example.com", wantErr: true},
		{fqdn: "_acme-challenge.other.org", domain: "example.com", wantErr: true},
		{fqdn: "example.com", domain: "vallet.example.com", wantErr: true},
	} {
		got, err := relativeRecordName(tc.fqdn, tc.domain)
		if tc.wantErr {
			if err == nil {
				t.Errorf("relativeRecordName(%q, %q) = %q, want an error", tc.fqdn, tc.domain, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("relativeRecordName(%q, %q): %v", tc.fqdn, tc.domain, err)
			continue
		}
		if got != tc.want {
			t.Errorf("relativeRecordName(%q, %q) = %q, want %q", tc.fqdn, tc.domain, got, tc.want)
		}
	}
}

// TestDigitalOceanProviderNeverFormatsItsToken covers the mechanism, not a
// string: fmt walks unexported struct fields by reflection and does NOT call
// secrets.Redacted's redaction methods, so without Format on the containing type
// "%+v" prints the bearer token in full.
func TestDigitalOceanProviderNeverFormatsItsToken(t *testing.T) {
	provider, err := NewDigitalOcean(NewSingleCredential(secrets.NewRedacted(doTestToken)), nil)
	if err != nil {
		t.Fatalf("NewDigitalOcean: %v", err)
	}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
		if rendered := fmt.Sprintf(verb, provider); strings.Contains(rendered, doTestToken) {
			t.Errorf("fmt %s of the provider leaked the token: %s", verb, rendered)
		}
	}
}

func TestNewAPIProviderBuildsDigitalOcean(t *testing.T) {
	provider, err := NewAPIProvider("digitalocean", NewSingleCredential(secrets.NewRedacted(doTestToken)), nil)
	if err != nil {
		t.Fatalf("NewAPIProvider: %v", err)
	}
	if got := provider.Name(); got != "digitalocean" {
		t.Errorf("Name() = %q, want %q", got, "digitalocean")
	}
}

// TestDigitalOceanDoesNotPollForPropagation pins the seam's division of labor:
// the solver polls the authoritative nameservers, so a provider must not add a
// redundant, weaker wait of its own.
func TestDigitalOceanDoesNotPollForPropagation(t *testing.T) {
	api, provider := newDigitalOceanAPI(t)
	rec := Record{Name: ChallengeRecordName("example.com"), Value: doChallengeValue}

	if _, err := provider.Present(context.Background(), rec); err != nil {
		t.Fatalf("Present: %v", err)
	}
	// One domain lookup and one create. Any read-back of the record after the
	// create would be a propagation poll.
	for _, req := range api.requests {
		if strings.HasPrefix(req, http.MethodGet+" ") && strings.Contains(req, "/records") {
			t.Errorf("Present read records back (%q), which is a propagation poll", req)
		}
	}
}

// TestDigitalOceanErrorMessageTruncationKeepsValidUTF8 pins the bound applied
// to the API's own error text.
//
// The message is remote input cut at a fixed BYTE count, so a multi-byte rune
// straddling the boundary would leave a fragment that is not valid UTF-8. That
// reaches the JSON log encoder, which mangles it.
//
// The first assertion proves a NAIVE cut of this fixture would be invalid. It
// is not decoration: the original fix for this defect elsewhere in the tree
// shipped with a test whose hand-computed offset landed on a character
// boundary, so it passed against unfixed code. Without this precondition the
// fixture could quietly stop exercising the case it exists for.
func TestDigitalOceanErrorMessageTruncationKeepsValidUTF8(t *testing.T) {
	// One byte of "世" sits before the bound and two after it.
	msg := strings.Repeat("a", maxAPIMessageBytes-1) + "世" + strings.Repeat("b", 50)
	if utf8.ValidString(msg[:maxAPIMessageBytes]) {
		t.Fatalf("fixture no longer splits a rune at the %d-byte cut", maxAPIMessageBytes)
	}

	raw, err := json.Marshal(map[string]any{"id": "unprocessable_entity", "message": msg})
	if err != nil {
		t.Fatalf("marshal error body: %v", err)
	}

	got := digitalOceanError(http.StatusUnprocessableEntity, raw)
	if got == nil {
		t.Fatal("digitalOceanError returned nil")
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
