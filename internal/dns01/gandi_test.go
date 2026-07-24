package dns01

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/secrets"
)

// gandiTestToken is the credential every test in this file hands the provider.
// It is a distinctive string so a leak into any output is unmistakable.
const gandiTestToken = "gandi-pat-DO-NOT-LEAK-7f13ac02"

// gandiChallengeValue is the value this process publishes. Like a real ACME
// digest it is bare base64url, so raw and quote-normalized forms are equal.
const gandiChallengeValue = "Z2FuZGljaGFsbGVuZ2V2YWx1ZS1vbmUtNDMtY2hhcnM"

// gandiAPI is a local stand-in for the Gandi LiveDNS v5 API. No test in this
// package contacts Gandi. It stores TXT rrsets keyed by the relative record
// name, which is how Gandi addresses them.
type gandiAPI struct {
	t *testing.T

	// requests records every method+path the provider issued, which is how the
	// tests assert what the provider did NOT do -- no delete/clobbering PUT on
	// the failed-publish path, no rrset delete that discards a sibling value.
	requests []string

	// domains is the set of domain names the account holds.
	domains map[string]bool
	// rrsets is the TXT store, keyed by relative record name. Seeded by tests.
	rrsets map[string]gandiRRSet

	// putStoresThenFails makes a PUT apply its change AND then answer an
	// API-level rejection. This is the "create errored after it was written"
	// shape: a naive cleanup that trusted the error and did nothing would leak
	// the standing record, so the delete on the cleanup path must be observable.
	putStoresThenFails bool
}

func newGandiAPI(t *testing.T) (*gandiAPI, Provider) {
	t.Helper()

	api := &gandiAPI{
		t:       t,
		domains: map[string]bool{"example.com": true},
		rrsets:  map[string]gandiRRSet{},
	}
	srv := httptest.NewServer(api)
	t.Cleanup(srv.Close)

	provider, err := NewGandi(NewSingleCredential(secrets.NewRedacted(gandiTestToken)), srv.Client())
	if err != nil {
		t.Fatalf("NewGandi: %v", err)
	}
	// The API base is a constant by design, so the test rewrites the request
	// host in the transport instead of making the endpoint configurable --
	// making it configurable to suit a test would be exactly the setting that
	// lets a misconfiguration point the token at another host.
	provider.(*gandiProvider).client = &http.Client{
		Transport: gandiRewriteHost{srv.URL, srv.Client().Transport},
	}
	return api, provider
}

// gandiRewriteHost redirects requests for the real API base at the local fake.
type gandiRewriteHost struct {
	base string
	next http.RoundTripper
}

func (r gandiRewriteHost) RoundTrip(req *http.Request) (*http.Response, error) {
	target := r.base + strings.TrimPrefix(req.URL.String(), gandiAPIBase)
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

func (a *gandiAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.requests = append(a.requests, r.Method+" "+r.URL.Path)

	if got := r.Header.Get("Authorization"); got != "Bearer "+gandiTestToken {
		a.t.Errorf("Authorization header = %q, want the bearer token", got)
	}
	w.Header().Set("Content-Type", "application/json")

	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/"), "/")
	switch {
	case r.Method == http.MethodGet && len(parts) == 2 && parts[0] == "domains":
		a.getDomain(w, parts[1])

	case len(parts) == 5 && parts[0] == "domains" && parts[2] == "records" && parts[4] == "TXT":
		a.rrset(w, r, parts[1], parts[3])

	default:
		a.t.Errorf("unexpected request %s %s", r.Method, r.URL)
		a.write(w, http.StatusBadRequest, `{"message":"unexpected"}`)
	}
}

func (a *gandiAPI) getDomain(w http.ResponseWriter, name string) {
	if !a.domains[name] {
		// Gandi answers 404 "Unknown domain" for a domain absent from the
		// account, which is the signal the walk uses to try the parent.
		a.write(w, http.StatusNotFound, `{"message":"Unknown domain"}`)
		return
	}
	a.write(w, http.StatusOK, fmt.Sprintf(`{"fqdn":%q}`, name))
}

func (a *gandiAPI) rrset(w http.ResponseWriter, r *http.Request, domain, name string) {
	if !a.domains[domain] {
		a.write(w, http.StatusNotFound, `{"message":"Unknown domain"}`)
		return
	}
	switch r.Method {
	case http.MethodGet:
		set, ok := a.rrsets[name]
		if !ok {
			a.write(w, http.StatusNotFound, `{"message":"Can't find the TXT record"}`)
			return
		}
		body, err := json.Marshal(set)
		if err != nil {
			a.t.Fatalf("marshal rrset: %v", err)
		}
		a.write(w, http.StatusOK, string(body))

	case http.MethodPut:
		var set gandiRRSet
		if err := json.NewDecoder(r.Body).Decode(&set); err != nil {
			a.t.Fatalf("decode put body: %v", err)
		}
		if set.TTL < gandiChallengeTTL {
			// Real Gandi rejects a TTL below 300, so a provider that sent 60
			// would fail here rather than pass on a fake that tolerated it.
			a.t.Errorf("PUT rrset_ttl = %d, below Gandi's 300 floor", set.TTL)
		}
		a.rrsets[name] = set
		if a.putStoresThenFails {
			a.write(w, http.StatusInternalServerError, `{"message":"stored then failed"}`)
			return
		}
		a.write(w, http.StatusCreated, `{"message":"DNS Record Created"}`)

	case http.MethodDelete:
		if _, ok := a.rrsets[name]; !ok {
			a.write(w, http.StatusNotFound, `{"message":"Can't find the TXT record"}`)
			return
		}
		delete(a.rrsets, name)
		w.WriteHeader(http.StatusNoContent)

	default:
		a.t.Errorf("unexpected rrset method %s", r.Method)
		a.write(w, http.StatusMethodNotAllowed, `{"message":"nope"}`)
	}
}

func (a *gandiAPI) write(w http.ResponseWriter, status int, body string) {
	w.WriteHeader(status)
	if _, err := w.Write([]byte(body)); err != nil {
		a.t.Errorf("write response: %v", err)
	}
}

// destructive returns the DELETE and PUT requests the provider issued -- the
// writes a cleanup on a no-op path must not make.
func (a *gandiAPI) destructive() []string {
	var out []string
	for _, req := range a.requests {
		if strings.HasPrefix(req, http.MethodDelete+" ") || strings.HasPrefix(req, http.MethodPut+" ") {
			out = append(out, req)
		}
	}
	return out
}

func TestGandiPresentPublishesRelativeNameAndCleansUp(t *testing.T) {
	api, provider := newGandiAPI(t)
	rec := Record{Name: ChallengeRecordName("vallet.example.com"), Value: gandiChallengeValue}

	cleanup, err := provider.Present(t.Context(), rec)
	if err != nil {
		t.Fatalf("Present: %v", err)
	}
	if cleanup == nil {
		t.Fatal("Present returned a nil cleanup")
	}

	// The rrset must be stored under the RELATIVE name. Sending the FQDN would
	// create _acme-challenge.vallet.example.com under example.com, which no CA
	// queries.
	set, ok := api.rrsets["_acme-challenge.vallet"]
	if !ok {
		t.Fatalf("no rrset at the relative name; store = %v", api.rrsets)
	}
	if !slices.Equal(set.Values, []string{gandiChallengeValue}) {
		t.Errorf("rrset values = %v, want the challenge value", set.Values)
	}

	if err := cleanup(t.Context()); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if _, ok := api.rrsets["_acme-challenge.vallet"]; ok {
		t.Errorf("rrset survived cleanup: %v", api.rrsets)
	}
}

func TestGandiCleanupIsIdempotent(t *testing.T) {
	api, provider := newGandiAPI(t)
	rec := Record{Name: ChallengeRecordName("example.com"), Value: gandiChallengeValue}

	cleanup, err := provider.Present(t.Context(), rec)
	if err != nil {
		t.Fatalf("Present: %v", err)
	}
	if err := cleanup(t.Context()); err != nil {
		t.Fatalf("first cleanup: %v", err)
	}
	before := len(api.destructive())
	if err := cleanup(t.Context()); err != nil {
		t.Fatalf("second cleanup on an already-removed record: %v", err)
	}
	if got := len(api.destructive()); got != before {
		t.Errorf("second cleanup issued %d destructive requests, want none beyond the first %d",
			got-before, before)
	}
}

// TestGandiCleanupAfterStoredButFailedPublish pins the seam's non-nil-on-failure
// contract in the case that most needs it: the PUT APPLIED and then errored, so
// the record is standing and only the returned cleanup can withdraw it.
func TestGandiCleanupAfterStoredButFailedPublish(t *testing.T) {
	api, provider := newGandiAPI(t)
	api.putStoresThenFails = true

	rec := Record{Name: ChallengeRecordName("example.com"), Value: gandiChallengeValue}
	cleanup, err := provider.Present(t.Context(), rec)
	if err == nil {
		t.Fatal("Present succeeded, want the API rejection")
	}
	if cleanup == nil {
		t.Fatal("Present returned a nil cleanup on the failure path: the record was " +
			"written before the error, so a nil cleanup leaks a standing _acme-challenge record")
	}
	// The record really is standing in the zone.
	if _, ok := api.rrsets["_acme-challenge"]; !ok {
		t.Fatal("fixture: the PUT did not store the record before failing")
	}

	// Let the retry PUT succeed so cleanup can complete, and prove it removed it.
	api.putStoresThenFails = false
	if err := cleanup(t.Context()); err != nil {
		t.Fatalf("cleanup after a stored-but-failed publish: %v", err)
	}
	if _, ok := api.rrsets["_acme-challenge"]; ok {
		t.Error("cleanup did not remove the record the failed publish left standing")
	}
}

// TestGandiCleanupAfterUnappliedPublishRemovesNothing is the other failure
// shape: the PUT never applied, so the returned cleanup must find nothing and
// issue NO destructive request, and must not disturb an unrelated value seeded
// at the same name.
func TestGandiCleanupAfterUnappliedPublishRemovesNothing(t *testing.T) {
	api, provider := newGandiAPI(t)
	// A sibling value the test seeds itself. Publishing our value fails before
	// it is written, so cleanup must leave this untouched.
	api.rrsets["_acme-challenge"] = gandiRRSet{TTL: 600, Values: []string{"someone-elses-value"}}
	api.domains = map[string]bool{} // force domainFor to refuse, so no PUT is issued

	rec := Record{Name: ChallengeRecordName("example.com"), Value: gandiChallengeValue}
	cleanup, err := provider.Present(t.Context(), rec)
	if err == nil {
		t.Fatal("Present succeeded, want the refusal")
	}
	if cleanup != nil {
		// domainFor failed before anything could be created, so per the seam a
		// nil cleanup is correct here -- there is nothing to withdraw.
		t.Fatal("Present returned a cleanup though nothing was created")
	}
	if got := api.destructive(); len(got) != 0 {
		t.Errorf("a refused publish issued destructive requests %v, want none", got)
	}
	if set := api.rrsets["_acme-challenge"]; !slices.Equal(set.Values, []string{"someone-elses-value"}) {
		t.Errorf("the unrelated value was disturbed: %v", set.Values)
	}
}

// TestGandiWildcardCleanupRemovesOnlyItsOwnValue is the security-critical
// scoping test. A certificate covering example.com and *.example.com puts TWO
// TXT values at one name; cleanup must remove ours and PUT BACK the sibling,
// never DELETE the whole rrset. A decoy operator value at the same name must
// also survive.
func TestGandiWildcardCleanupRemovesOnlyItsOwnValue(t *testing.T) {
	api, provider := newGandiAPI(t)

	const siblingValue = "c2libGluZ3dpbGRjYXJkY2hhbGxlbmdldmFsdWUtdHdv"
	const operatorValue = "v=spf1 -all"
	// Seed the sibling wildcard challenge and an operator record already at the
	// challenge name, with an operator-chosen TTL.
	api.rrsets["_acme-challenge"] = gandiRRSet{TTL: 900, Values: []string{siblingValue, operatorValue}}

	rec := Record{Name: ChallengeRecordName("*.example.com"), Value: gandiChallengeValue}
	if rec.Name != "_acme-challenge.example.com" {
		t.Fatalf("fixture: challenge name = %q", rec.Name)
	}

	cleanup, err := provider.Present(t.Context(), rec)
	if err != nil {
		t.Fatalf("Present: %v", err)
	}
	// The merge added ours without discarding the pre-existing values.
	set := api.rrsets["_acme-challenge"]
	if !slices.Contains(set.Values, gandiChallengeValue) || !slices.Contains(set.Values, siblingValue) ||
		!slices.Contains(set.Values, operatorValue) || len(set.Values) != 3 {
		t.Fatalf("after publish rrset = %v, want ours merged with both pre-existing values", set.Values)
	}
	if set.TTL != 900 {
		t.Errorf("merge rewrote the operator's TTL to %d, want 900 preserved", set.TTL)
	}

	if err := cleanup(t.Context()); err != nil {
		t.Fatalf("cleanup: %v", err)
	}

	survivor, ok := api.rrsets["_acme-challenge"]
	if !ok {
		t.Fatal("cleanup DELETEd the whole rrset, discarding the sibling challenge and the operator record")
	}
	if !slices.Contains(survivor.Values, siblingValue) || !slices.Contains(survivor.Values, operatorValue) {
		t.Errorf("survivors = %v, want the sibling and operator values intact", survivor.Values)
	}
	if slices.Contains(survivor.Values, gandiChallengeValue) {
		t.Errorf("cleanup left our own value behind: %v", survivor.Values)
	}
	// No rrset DELETE was issued -- the set still had other members.
	for _, req := range api.requests {
		if strings.HasPrefix(req, http.MethodDelete+" ") {
			t.Errorf("cleanup issued an rrset delete %q while other values remained", req)
		}
	}
}

func TestGandiPresentSurfacesAPIRejection(t *testing.T) {
	api, provider := newGandiAPI(t)
	api.putStoresThenFails = true

	rec := Record{Name: ChallengeRecordName("example.com"), Value: gandiChallengeValue}
	_, err := provider.Present(t.Context(), rec)
	if err == nil {
		t.Fatal("Present succeeded, want the API rejection")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("error %q does not name the API fault", err)
	}
	if strings.Contains(err.Error(), gandiTestToken) {
		t.Fatal("error carries the API token")
	}
}

// TestGandiRefusesAMalformedDomainCandidate pins the check that keeps a value
// derived from the certificate request from reaching a request path as anything
// other than a domain name. The assertion is on the SPECIFIC refusal, because
// without the check the walk still ends in an error -- an escaped candidate
// merely 404s and the walk runs out.
func TestGandiRefusesAMalformedDomainCandidate(t *testing.T) {
	api, provider := newGandiAPI(t)

	rec := Record{Name: "_acme-challenge.ev/il.com", Value: gandiChallengeValue}
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

func TestGandiUnknownDomainRefuses(t *testing.T) {
	api, provider := newGandiAPI(t)
	api.domains = map[string]bool{} // the account holds nothing

	rec := Record{Name: ChallengeRecordName("vallet.example.com"), Value: gandiChallengeValue}
	_, err := provider.Present(t.Context(), rec)
	if err == nil {
		t.Fatal("Present succeeded with no matching domain, want a refusal")
	}
	if !strings.Contains(err.Error(), "no domain found") {
		t.Errorf("error %q does not name the missing domain as the fault", err)
	}
	if len(api.destructive()) != 0 {
		t.Error("a failed domain lookup issued a destructive request")
	}
}

// TestGandiPrefersTheMostSpecificDomain pins the walk order. Writing to the
// parent of a delegated subdomain puts the record in a zone that is not
// authoritative for the name.
func TestGandiPrefersTheMostSpecificDomain(t *testing.T) {
	api, provider := newGandiAPI(t)
	api.domains = map[string]bool{"example.com": true, "eu.example.com": true}

	rec := Record{Name: ChallengeRecordName("vallet.eu.example.com"), Value: gandiChallengeValue}
	if _, err := provider.Present(t.Context(), rec); err != nil {
		t.Fatalf("Present: %v", err)
	}
	if _, ok := api.rrsets["_acme-challenge.vallet"]; !ok {
		t.Fatalf("rrset not stored relative to eu.example.com; store = %v", api.rrsets)
	}
	var putUnder string
	for _, req := range api.requests {
		if strings.HasPrefix(req, http.MethodPut+" ") {
			putUnder = req
		}
	}
	if !strings.Contains(putUnder, "/domains/eu.example.com/records") {
		t.Errorf("write went to %q, want the delegated eu.example.com", putUnder)
	}
}

func TestGandiMissingCredentialRefused(t *testing.T) {
	if _, err := NewGandi(NewSingleCredential(secrets.NewRedacted("")), nil); err == nil {
		t.Error("NewGandi with an empty token succeeded, want a refusal at construction")
	}
	if _, err := NewGandi(NewSingleCredential(secrets.NewRedacted("   ")), nil); err == nil {
		t.Error("NewGandi with a whitespace-only token succeeded, want a refusal at construction")
	}
	if _, err := NewGandi(NewSingleCredential(secrets.NewRedacted(gandiTestToken)), nil); err != nil {
		t.Errorf("NewGandi with a token: %v", err)
	}
}

// TestGandiProviderNeverFormatsItsToken covers the mechanism, not a string: fmt
// walks unexported struct fields by reflection and does NOT call
// secrets.Redacted's redaction methods, so without Format on the containing type
// "%+v" prints the bearer token in full.
func TestGandiProviderNeverFormatsItsToken(t *testing.T) {
	provider, err := NewGandi(NewSingleCredential(secrets.NewRedacted(gandiTestToken)), nil)
	if err != nil {
		t.Fatalf("NewGandi: %v", err)
	}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
		rendered := fmt.Sprintf(verb, provider)
		if strings.Contains(rendered, gandiTestToken) {
			t.Errorf("fmt %s of the provider leaked the token: %s", verb, rendered)
		}
		if !strings.Contains(rendered, "[REDACTED]") {
			t.Errorf("fmt %s of the provider = %q, want it to render the redaction marker", verb, rendered)
		}
	}
}

func TestNewAPIProviderBuildsGandi(t *testing.T) {
	provider, err := NewAPIProvider("gandi", NewSingleCredential(secrets.NewRedacted(gandiTestToken)), nil)
	if err != nil {
		t.Fatalf("NewAPIProvider: %v", err)
	}
	if got := provider.Name(); got != "gandi" {
		t.Errorf("Name() = %q, want %q", got, "gandi")
	}
}

// TestGandiDoesNotPollForPropagation pins the seam's division of labor: the
// solver polls the authoritative nameservers, so a provider must not add a
// redundant, weaker wait of its own. Present may read the rrset once (to merge),
// but must not read it BACK after the write.
func TestGandiDoesNotPollForPropagation(t *testing.T) {
	api, provider := newGandiAPI(t)
	rec := Record{Name: ChallengeRecordName("example.com"), Value: gandiChallengeValue}

	if _, err := provider.Present(context.Background(), rec); err != nil {
		t.Fatalf("Present: %v", err)
	}
	var sawWrite bool
	for _, req := range api.requests {
		if strings.HasPrefix(req, http.MethodPut+" ") {
			sawWrite = true
		}
		if sawWrite && strings.HasPrefix(req, http.MethodGet+" ") && strings.Contains(req, "/records/") {
			t.Errorf("Present read the rrset back after writing (%q), which is a propagation poll", req)
		}
	}
}
