package dns01

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/secrets"
)

// acTestToken is the credential every test in this file hands the provider. It
// is a distinctive string so a leak into any output is unmistakable.
const acTestToken = "arvan-key-DO-NOT-LEAK-7f31a2c9"

// acChallengeValue is the digest a real challenge would publish. It is an
// unforgeable base64url string; the tests treat it as the value to be scoped to.
const acChallengeValue = "YXJ2YW5jaGFsbGVuZ2V2YWx1ZS1vbmUtNGM3MWU5YjA"

// acRecord is one stored TXT record in the fake. The tests own this map and seed
// it directly, so every assertion about what survived a cleanup is read from
// state the TEST established rather than from anything the provider computed.
type acRecord struct {
	name string // relative, as ArvanCloud stores it
	text string
}

// arvanCloudAPI is a local stand-in for the ArvanCloud CDN 4.0 DNS API. No test
// in this package contacts ArvanCloud.
type arvanCloudAPI struct {
	t *testing.T

	// requests records every method+path the provider issued, in order, which is
	// how the tests assert what the provider did NOT do — no delete on the failed
	// publish path, no delete addressed at a sibling challenge.
	requests []string

	// domains is the set of domain names the account holds.
	domains map[string]bool
	// records is the record store, keyed by ID. Seeded by tests.
	records map[string]acRecord
	// nextID feeds the ID handed to the next create.
	nextID int

	// created holds the decoded body of the last create, so a test can check the
	// record the provider actually asked for.
	created map[string]any

	// createPersistsThenFails persists the record and THEN returns an error, the
	// shape of a create applied at ArvanCloud whose success response was lost.
	createPersistsThenFails bool
}

func newArvanCloudAPI(t *testing.T) (*arvanCloudAPI, Provider) {
	t.Helper()

	api := &arvanCloudAPI{
		t:       t,
		domains: map[string]bool{"example.com": true},
		records: map[string]acRecord{},
		nextID:  500,
	}
	srv := httptest.NewServer(api)
	t.Cleanup(srv.Close)

	provider, err := NewArvanCloud(NewSingleCredential(secrets.NewRedacted(acTestToken)), srv.Client())
	if err != nil {
		t.Fatalf("NewArvanCloud: %v", err)
	}
	// The API base is a constant by design, so the test rewrites the request host
	// in the transport instead of making the endpoint configurable — making it
	// configurable to suit a test would be exactly the setting that lets a
	// misconfiguration point the key at another host.
	provider.(*arvanCloudProvider).client = &http.Client{
		Transport: acRewriteHost{srv.URL, srv.Client().Transport},
	}
	return api, provider
}

// acRewriteHost redirects requests for the real API base at the local fake.
type acRewriteHost struct {
	base string
	next http.RoundTripper
}

func (r acRewriteHost) RoundTrip(req *http.Request) (*http.Response, error) {
	target := r.base + strings.TrimPrefix(req.URL.String(), arvanCloudAPIBase)
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

func (a *arvanCloudAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.requests = append(a.requests, r.Method+" "+r.URL.Path+"?"+r.URL.RawQuery)

	if got := r.Header.Get("Authorization"); got != "Apikey "+acTestToken {
		a.t.Errorf("Authorization header = %q, want %q", got, "Apikey "+acTestToken)
	}
	w.Header().Set("Content-Type", "application/json")

	// Paths are /domains/{domain}/dns-records[/{id}]. A domain absent from the
	// account answers 404 for every method, which is what the domain walk keys on.
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/"), "/")
	if len(parts) < 3 || parts[0] != "domains" || parts[2] != "dns-records" {
		a.t.Errorf("unexpected request %s %s", r.Method, r.URL)
		a.write(w, http.StatusBadRequest, `{"message":"unexpected"}`)
		return
	}
	if !a.domains[parts[1]] {
		a.write(w, http.StatusNotFound, `{"message":"not found"}`)
		return
	}
	switch {
	case r.Method == http.MethodGet && len(parts) == 3:
		a.listRecords(w, r)
	case r.Method == http.MethodPost && len(parts) == 3:
		a.createRecord(w, r)
	case r.Method == http.MethodDelete && len(parts) == 4:
		a.deleteRecord(w, parts[3])
	default:
		a.t.Errorf("unexpected request %s %s", r.Method, r.URL)
		a.write(w, http.StatusBadRequest, `{"message":"unexpected"}`)
	}
}

func (a *arvanCloudAPI) listRecords(w http.ResponseWriter, r *http.Request) {
	// ArvanCloud's search does not match underscores, so the provider strips them
	// from the term; the fake compares the same way, so a provider that sent a
	// term the record name cannot contain would get an empty list — the happy path
	// therefore proves the search term the provider sends actually matches.
	search := r.URL.Query().Get("search")

	type wireVal struct {
		Text string `json:"text"`
	}
	type wire struct {
		ID    string  `json:"id"`
		Type  string  `json:"type"`
		Name  string  `json:"name"`
		Value wireVal `json:"value"`
	}
	out := []wire{}
	for id, rec := range a.records {
		if search != "" && !strings.Contains(strings.ReplaceAll(rec.name, "_", ""), search) {
			continue
		}
		out = append(out, wire{ID: id, Type: "txt", Name: rec.name, Value: wireVal{Text: rec.text}})
	}
	// Sorted so listing order is deterministic. Map order would otherwise make the
	// scoping test flaky in the direction that matters: a provider that dropped its
	// value filter would pick whichever record came back first, so it would
	// sometimes pick the right one by luck. The sibling is seeded with a low ID so
	// it sorts first.
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	body, err := json.Marshal(map[string]any{"data": out})
	if err != nil {
		a.t.Fatalf("marshal records: %v", err)
	}
	a.write(w, http.StatusOK, string(body))
}

func (a *arvanCloudAPI) createRecord(w http.ResponseWriter, r *http.Request) {
	a.created = map[string]any{}
	if err := json.NewDecoder(r.Body).Decode(&a.created); err != nil {
		a.t.Fatalf("decode create body: %v", err)
	}
	name, _ := a.created["name"].(string)
	text := ""
	if v, ok := a.created["value"].(map[string]any); ok {
		text, _ = v["text"].(string)
	}

	id := fmt.Sprintf("rec-%d", a.nextID)
	a.nextID++
	a.records[id] = acRecord{name: name, text: text}

	if a.createPersistsThenFails {
		// The record is now stored, but the caller sees an error: the shape of a
		// create that applied at ArvanCloud whose success response never arrived.
		a.write(w, http.StatusInternalServerError, `{"message":"backend error"}`)
		return
	}
	a.write(w, http.StatusCreated,
		fmt.Sprintf(`{"data":{"id":%q,"type":"txt","name":%q,"value":{"text":%q}}}`, id, name, text))
}

func (a *arvanCloudAPI) deleteRecord(w http.ResponseWriter, id string) {
	if _, ok := a.records[id]; !ok {
		a.write(w, http.StatusNotFound, `{"message":"not found"}`)
		return
	}
	delete(a.records, id)
	w.WriteHeader(http.StatusOK)
}

func (a *arvanCloudAPI) write(w http.ResponseWriter, status int, body string) {
	w.WriteHeader(status)
	if _, err := w.Write([]byte(body)); err != nil {
		a.t.Errorf("write response: %v", err)
	}
}

// deletes returns the DELETE requests the provider issued.
func (a *arvanCloudAPI) deletes() []string {
	var out []string
	for _, req := range a.requests {
		if strings.HasPrefix(req, http.MethodDelete+" ") {
			out = append(out, req)
		}
	}
	return out
}

// TestArvanCloudCleanupAfterPersistedCreateThatErrored is mandatory test #2: a
// create that APPLIED but returned an error must still hand back a cleanup, and
// that cleanup must delete the standing record. It also carries the wire-shape
// checks and mandatory #5's second half:
//
//   - The ArvanCloud protocol facts verified against the docs — TXT type is the
//     lowercase "txt", the name is RELATIVE to the domain (a subdomain here, so
//     the split is exercised), the value is the nested {"value":{"text":...}}
//     object, and the TTL is the 600s floor the API enforces. Sending the FQDN
//     would create _acme-challenge.vallet.example.com.example.com, which the API
//     accepts and no CA ever queries.
//   - An API-error path must never carry the credential.
func TestArvanCloudCleanupAfterPersistedCreateThatErrored(t *testing.T) {
	api, provider := newArvanCloudAPI(t)
	api.createPersistsThenFails = true

	rec := Record{Name: ChallengeRecordName("vallet.example.com"), Value: acChallengeValue}
	cleanup, err := provider.Present(t.Context(), rec)
	if err == nil {
		t.Fatal("Present succeeded, want the API error the persisted create returned")
	}
	if strings.Contains(err.Error(), acTestToken) {
		t.Fatal("the API-error path carried the API key")
	}
	if cleanup == nil {
		t.Fatal("Present returned a nil cleanup after a create that applied: the standing " +
			"_acme-challenge record could never be withdrawn")
	}

	// The create body ArvanCloud actually received: relative subdomain name,
	// lowercase type, nested value object, 600s TTL.
	if got := api.created["name"]; got != "_acme-challenge.vallet" {
		t.Errorf("create name = %v, want %q", got, "_acme-challenge.vallet")
	}
	if got := api.created["type"]; got != "txt" {
		t.Errorf("create type = %v, want lowercase txt", got)
	}
	if val, ok := api.created["value"].(map[string]any); !ok || val["text"] != acChallengeValue {
		t.Errorf("create value = %v, want nested {text: %q}", api.created["value"], acChallengeValue)
	}
	if got := api.created["ttl"]; got != float64(arvanCloudChallengeTTL) {
		t.Errorf("create ttl = %v, want %d", got, arvanCloudChallengeTTL)
	}
	if len(api.records) != 1 {
		t.Fatalf("records after the persisted create = %d, want 1", len(api.records))
	}

	if err := cleanup(t.Context()); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if len(api.records) != 0 {
		t.Errorf("records after cleanup = %d, want 0: the leaked record was not withdrawn", len(api.records))
	}
	if len(api.deletes()) != 1 {
		t.Errorf("cleanup issued %d deletes, want exactly one", len(api.deletes()))
	}
}

// TestArvanCloudCleanupIsIdempotent is mandatory test #3: a record already absent
// is a success and issues NO destructive request.
func TestArvanCloudCleanupIsIdempotent(t *testing.T) {
	api, provider := newArvanCloudAPI(t)
	rec := Record{Name: ChallengeRecordName("example.com"), Value: acChallengeValue}

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

// TestArvanCloudWildcardCleanupRemovesOnlyItsOwnValue is mandatory test #4, the
// scoping test. A certificate covering example.com and *.example.com puts TWO
// challenges at the same name with different digests, so cleanup must remove one
// value and leave the other. The sibling is seeded by the test with a known ID,
// and the survivor is checked against that seeded state.
func TestArvanCloudWildcardCleanupRemovesOnlyItsOwnValue(t *testing.T) {
	api, provider := newArvanCloudAPI(t)

	const siblingID = "100"
	const siblingValue = "YXJ2YW5zaWJsaW5nd2lsZGNhcmR2YWx1ZS10d28tOTk5"
	api.records[siblingID] = acRecord{name: "_acme-challenge", text: siblingValue}

	rec := Record{Name: ChallengeRecordName("*.example.com"), Value: acChallengeValue}
	if rec.Name != "_acme-challenge.example.com" {
		t.Fatalf("fixture: challenge name = %q", rec.Name)
	}

	cleanup, err := provider.Present(t.Context(), rec)
	if err != nil {
		t.Fatalf("Present: %v", err)
	}
	// Both values now sit at the one name, which is what makes the value filter in
	// findRecord load-bearing: without it the listing is ambiguous by ID.
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
	if survivor.text != siblingValue {
		t.Errorf("sibling value = %q, want it untouched", survivor.text)
	}
	if len(api.records) != 1 {
		t.Errorf("records after cleanup = %d, want only the sibling", len(api.records))
	}
	dels := api.deletes()
	if len(dels) != 1 {
		t.Fatalf("deletes = %v, want exactly one", dels)
	}
	if strings.Contains(dels[0], siblingID) {
		t.Errorf("delete %q addressed the sibling record", dels[0])
	}
}

// TestArvanCloudRefusesAMalformedDomainCandidate is mandatory test #6: a value
// derived from the certificate request must not reach a request path as anything
// other than a domain name. The assertion is on the SPECIFIC refusal, because
// without the check the walk still ends in an error — an escaped candidate merely
// 404s and the walk runs out. Only the message distinguishes "refused before the
// request" from "asked the API about a crafted name".
func TestArvanCloudRefusesAMalformedDomainCandidate(t *testing.T) {
	api, provider := newArvanCloudAPI(t)

	rec := Record{Name: "_acme-challenge.ev/il.com", Value: acChallengeValue}
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

// TestArvanCloudProviderNeverFormatsItsToken is mandatory test #5: fmt walks
// unexported struct fields by reflection and does NOT call secrets.Redacted's
// redaction methods, so without Format on the containing type "%+v" prints the
// API key in full.
func TestArvanCloudProviderNeverFormatsItsToken(t *testing.T) {
	provider, err := NewArvanCloud(NewSingleCredential(secrets.NewRedacted(acTestToken)), nil)
	if err != nil {
		t.Fatalf("NewArvanCloud: %v", err)
	}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
		rendered := fmt.Sprintf(verb, provider)
		if strings.Contains(rendered, acTestToken) {
			t.Errorf("fmt %s of the provider leaked the key: %s", verb, rendered)
		}
		if !strings.Contains(rendered, "[REDACTED]") {
			t.Errorf("fmt %s did not render the redaction marker: %s", verb, rendered)
		}
	}
}
