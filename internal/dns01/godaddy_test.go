package dns01

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/secrets"
)

// The credential halves and the packed form every test in this file hands the
// provider. They are distinctive strings so a leak into any output is
// unmistakable, and they are colon-free so packing them is unambiguous — the
// same property the "sso-key KEY:SECRET" header depends on.
const (
	godaddyTestKey    = "gd-key-DO-NOT-LEAK-3f9a21"
	godaddyTestSecret = "gd-secret-DO-NOT-LEAK-77c0b4"
	godaddyTestCred   = godaddyTestKey + ":" + godaddyTestSecret
)

// godaddyChallengeValue is the value this process publishes. Like a real ACME
// digest it is bare base64url, so it carries no quoting to normalize.
const godaddyChallengeValue = "Z29kYWRkeWNoYWxsZW5nZXZhbHVlLW9uZS00My1jaGFycw"

// godaddyAPI is a local stand-in for the GoDaddy Domains v1 API. No test in this
// package contacts GoDaddy. It stores TXT records keyed by the relative record
// name, which is how GoDaddy addresses them within a domain.
type godaddyAPI struct {
	t *testing.T

	// requests records every method+path the provider issued, which is how the
	// tests assert what the provider did NOT do -- no delete/clobbering PUT on
	// the failed-publish path, no whole-set delete that discards a sibling
	// value.
	requests []string

	// domains is the set of domain names the account holds.
	domains map[string]bool
	// records is the TXT store, keyed by relative record name. Seeded by tests.
	records map[string][]godaddyRecord

	// putStoresThenFails makes a PUT apply its change AND then answer an
	// API-level rejection. This is the "create errored after it was written"
	// shape: a naive cleanup that trusted the error and did nothing would leak
	// the standing record, so the delete on the cleanup path must be observable.
	putStoresThenFails bool
}

func newGoDaddyAPI(t *testing.T) (*godaddyAPI, Provider) {
	t.Helper()

	api := &godaddyAPI{
		t:       t,
		domains: map[string]bool{"example.com": true},
		records: map[string][]godaddyRecord{},
	}
	srv := httptest.NewServer(api)
	t.Cleanup(srv.Close)

	provider, err := NewGoDaddy(NewNamedCredentials(map[string]secrets.Redacted{
		"api_key":    secrets.NewRedacted(godaddyTestKey),
		"api_secret": secrets.NewRedacted(godaddyTestSecret),
	}), srv.Client())
	if err != nil {
		t.Fatalf("NewGoDaddy: %v", err)
	}
	// The API base is a constant by design, so the test rewrites the request
	// host in the transport instead of making the endpoint configurable --
	// making it configurable to suit a test would be exactly the setting that
	// lets a misconfiguration point the credential at another host.
	provider.(*godaddyProvider).client = &http.Client{
		Transport: godaddyRewriteHost{srv.URL, srv.Client().Transport},
	}
	return api, provider
}

// godaddyRewriteHost redirects requests for the real API base at the local fake.
type godaddyRewriteHost struct {
	base string
	next http.RoundTripper
}

func (r godaddyRewriteHost) RoundTrip(req *http.Request) (*http.Response, error) {
	target := r.base + strings.TrimPrefix(req.URL.String(), godaddyAPIBase)
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

func (a *godaddyAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.requests = append(a.requests, r.Method+" "+r.URL.Path)

	if got := r.Header.Get("Authorization"); got != "sso-key "+godaddyTestCred {
		a.t.Errorf("Authorization header = %q, want the sso-key credential", got)
	}
	w.Header().Set("Content-Type", "application/json")

	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/"), "/")
	switch {
	case r.Method == http.MethodGet && len(parts) == 2 && parts[0] == "domains":
		a.getDomain(w, parts[1])

	case len(parts) == 5 && parts[0] == "domains" && parts[2] == "records" && parts[3] == "TXT":
		a.record(w, r, parts[1], parts[4])

	default:
		a.t.Errorf("unexpected request %s %s", r.Method, r.URL)
		a.write(w, http.StatusBadRequest, `{"code":"INVALID","message":"unexpected"}`)
	}
}

func (a *godaddyAPI) getDomain(w http.ResponseWriter, name string) {
	if !a.domains[name] {
		// GoDaddy answers 404 for a domain absent from the account, which is the
		// signal the walk uses to try the parent. A credential problem would be
		// 401/403, which the walk must NOT treat as a miss.
		a.write(w, http.StatusNotFound, `{"code":"NOT_FOUND","message":"domain not found"}`)
		return
	}
	a.write(w, http.StatusOK, fmt.Sprintf(`{"domain":%q}`, name))
}

func (a *godaddyAPI) record(w http.ResponseWriter, r *http.Request, domain, name string) {
	if !a.domains[domain] {
		a.write(w, http.StatusNotFound, `{"code":"NOT_FOUND","message":"domain not found"}`)
		return
	}
	switch r.Method {
	case http.MethodGet:
		// GoDaddy answers a name with no records with 200 and an EMPTY ARRAY,
		// not a 404, so the fake does the same to exercise that path.
		body, err := json.Marshal(a.records[name])
		if err != nil {
			a.t.Fatalf("marshal records: %v", err)
		}
		if a.records[name] == nil {
			body = []byte("[]")
		}
		a.write(w, http.StatusOK, string(body))

	case http.MethodPut:
		var recs []godaddyRecord
		if err := json.NewDecoder(r.Body).Decode(&recs); err != nil {
			a.t.Fatalf("decode put body: %v", err)
		}
		for _, rec := range recs {
			if rec.TTL < godaddyChallengeTTL {
				// Real GoDaddy rejects a TTL below 600, so a provider that sent
				// 60 would fail here rather than pass on a fake that tolerated
				// it.
				a.t.Errorf("PUT ttl = %d, below GoDaddy's 600 floor", rec.TTL)
			}
		}
		a.records[name] = recs
		if a.putStoresThenFails {
			a.write(w, http.StatusInternalServerError, `{"code":"INTERNAL","message":"stored then failed"}`)
			return
		}
		w.WriteHeader(http.StatusOK)

	case http.MethodDelete:
		if _, ok := a.records[name]; !ok {
			a.write(w, http.StatusNotFound, `{"code":"NOT_FOUND","message":"record not found"}`)
			return
		}
		delete(a.records, name)
		w.WriteHeader(http.StatusNoContent)

	default:
		a.t.Errorf("unexpected record method %s", r.Method)
		a.write(w, http.StatusMethodNotAllowed, `{"code":"METHOD","message":"nope"}`)
	}
}

func (a *godaddyAPI) write(w http.ResponseWriter, status int, body string) {
	w.WriteHeader(status)
	if _, err := w.Write([]byte(body)); err != nil {
		a.t.Errorf("write response: %v", err)
	}
}

// destructive returns the DELETE and PUT requests the provider issued -- the
// writes a cleanup on a no-op path must not make.
func (a *godaddyAPI) destructive() []string {
	var out []string
	for _, req := range a.requests {
		if strings.HasPrefix(req, http.MethodDelete+" ") || strings.HasPrefix(req, http.MethodPut+" ") {
			out = append(out, req)
		}
	}
	return out
}

// values is a test helper returning the stored data values at a relative name.
func (a *godaddyAPI) values(name string) []string {
	out := make([]string, 0, len(a.records[name]))
	for _, r := range a.records[name] {
		out = append(out, r.Data)
	}
	return out
}

func TestGoDaddyPresentPublishesRelativeNameAndCleansUp(t *testing.T) {
	api, provider := newGoDaddyAPI(t)
	rec := Record{Name: ChallengeRecordName("vallet.example.com"), Value: godaddyChallengeValue}

	cleanup, err := provider.Present(t.Context(), rec)
	if err != nil {
		t.Fatalf("Present: %v", err)
	}
	if cleanup == nil {
		t.Fatal("Present returned a nil cleanup")
	}

	// The record must be stored under the RELATIVE name. Sending the FQDN would
	// create _acme-challenge.vallet.example.com under example.com, which no CA
	// queries.
	got := api.values("_acme-challenge.vallet")
	if !slices.Equal(got, []string{godaddyChallengeValue}) {
		t.Fatalf("record values = %v, want the challenge value; store = %v", got, api.records)
	}

	if err := cleanup(t.Context()); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if _, ok := api.records["_acme-challenge.vallet"]; ok {
		t.Errorf("record survived cleanup: %v", api.records)
	}
}

func TestGoDaddyCleanupIsIdempotent(t *testing.T) {
	api, provider := newGoDaddyAPI(t)
	rec := Record{Name: ChallengeRecordName("example.com"), Value: godaddyChallengeValue}

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

// TestGoDaddyCleanupAfterStoredButFailedPublish pins the seam's
// non-nil-on-failure contract in the case that most needs it: the PUT APPLIED
// and then errored, so the record is standing and only the returned cleanup can
// withdraw it.
func TestGoDaddyCleanupAfterStoredButFailedPublish(t *testing.T) {
	api, provider := newGoDaddyAPI(t)
	api.putStoresThenFails = true

	rec := Record{Name: ChallengeRecordName("example.com"), Value: godaddyChallengeValue}
	cleanup, err := provider.Present(t.Context(), rec)
	if err == nil {
		t.Fatal("Present succeeded, want the API rejection")
	}
	if cleanup == nil {
		t.Fatal("Present returned a nil cleanup on the failure path: the record was " +
			"written before the error, so a nil cleanup leaks a standing _acme-challenge record")
	}
	if _, ok := api.records["_acme-challenge"]; !ok {
		t.Fatal("fixture: the PUT did not store the record before failing")
	}

	// Let the retry PUT succeed so cleanup can complete, and prove it removed it.
	api.putStoresThenFails = false
	if err := cleanup(t.Context()); err != nil {
		t.Fatalf("cleanup after a stored-but-failed publish: %v", err)
	}
	if _, ok := api.records["_acme-challenge"]; ok {
		t.Error("cleanup did not remove the record the failed publish left standing")
	}
}

// TestGoDaddyCleanupAfterUnappliedPublishRemovesNothing is the other failure
// shape: the PUT never applied, so the returned cleanup must find nothing and
// issue NO destructive request, and must not disturb an unrelated value seeded
// at the same name.
func TestGoDaddyCleanupAfterUnappliedPublishRemovesNothing(t *testing.T) {
	api, provider := newGoDaddyAPI(t)
	// A sibling value the test seeds itself. Publishing our value fails before
	// it is written, so cleanup must leave this untouched.
	api.records["_acme-challenge"] = []godaddyRecord{{Data: "someone-elses-value", TTL: 600}}
	api.domains = map[string]bool{} // force domainFor to refuse, so no PUT is issued

	rec := Record{Name: ChallengeRecordName("example.com"), Value: godaddyChallengeValue}
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
	if got := api.values("_acme-challenge"); !slices.Equal(got, []string{"someone-elses-value"}) {
		t.Errorf("the unrelated value was disturbed: %v", got)
	}
}

// TestGoDaddyWildcardCleanupRemovesOnlyItsOwnValue is the security-critical
// scoping test. A certificate covering example.com and *.example.com puts TWO
// TXT values at one name; cleanup must remove ours and PUT BACK the sibling,
// never DELETE the whole record set. A decoy operator value at the same name
// must also survive.
func TestGoDaddyWildcardCleanupRemovesOnlyItsOwnValue(t *testing.T) {
	api, provider := newGoDaddyAPI(t)

	const siblingValue = "c2libGluZ3dpbGRjYXJkY2hhbGxlbmdldmFsdWUtdHdv"
	const operatorValue = "v=spf1 -all"
	// Seed the sibling wildcard challenge and an operator record already at the
	// challenge name, with an operator-chosen TTL above the floor.
	api.records["_acme-challenge"] = []godaddyRecord{
		{Data: siblingValue, TTL: 900},
		{Data: operatorValue, TTL: 900},
	}

	rec := Record{Name: ChallengeRecordName("*.example.com"), Value: godaddyChallengeValue}
	if rec.Name != "_acme-challenge.example.com" {
		t.Fatalf("fixture: challenge name = %q", rec.Name)
	}

	cleanup, err := provider.Present(t.Context(), rec)
	if err != nil {
		t.Fatalf("Present: %v", err)
	}
	// The merge added ours without discarding the pre-existing values.
	got := api.values("_acme-challenge")
	if !slices.Contains(got, godaddyChallengeValue) || !slices.Contains(got, siblingValue) ||
		!slices.Contains(got, operatorValue) || len(got) != 3 {
		t.Fatalf("after publish records = %v, want ours merged with both pre-existing values", got)
	}
	// The operator's TTL is preserved on the merge, not rewritten to the floor.
	if ttl := api.records["_acme-challenge"][0].TTL; ttl != 900 {
		t.Errorf("merge rewrote the operator's TTL to %d, want 900 preserved", ttl)
	}

	if err := cleanup(t.Context()); err != nil {
		t.Fatalf("cleanup: %v", err)
	}

	survivors, ok := api.records["_acme-challenge"]
	if !ok {
		t.Fatal("cleanup DELETEd the whole record set, discarding the sibling challenge and the operator record")
	}
	got = api.values("_acme-challenge")
	if !slices.Contains(got, siblingValue) || !slices.Contains(got, operatorValue) {
		t.Errorf("survivors = %v, want the sibling and operator values intact", survivors)
	}
	if slices.Contains(got, godaddyChallengeValue) {
		t.Errorf("cleanup left our own value behind: %v", got)
	}
	// No whole-set DELETE was issued -- other values remained.
	for _, req := range api.requests {
		if strings.HasPrefix(req, http.MethodDelete+" ") {
			t.Errorf("cleanup issued a record delete %q while other values remained", req)
		}
	}
}

func TestGoDaddyPresentSurfacesAPIRejection(t *testing.T) {
	api, provider := newGoDaddyAPI(t)
	api.putStoresThenFails = true

	rec := Record{Name: ChallengeRecordName("example.com"), Value: godaddyChallengeValue}
	_, err := provider.Present(t.Context(), rec)
	if err == nil {
		t.Fatal("Present succeeded, want the API rejection")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("error %q does not name the API fault", err)
	}
	if strings.Contains(err.Error(), godaddyTestKey) || strings.Contains(err.Error(), godaddyTestSecret) {
		t.Fatal("error carries a credential half")
	}
}

// TestGoDaddyRefusesAMalformedDomainCandidate pins the check that keeps a value
// derived from the certificate request from reaching a request path as anything
// other than a domain name. The assertion is on the SPECIFIC refusal, because
// without the check the walk still ends in an error -- an escaped candidate
// merely 404s and the walk runs out.
func TestGoDaddyRefusesAMalformedDomainCandidate(t *testing.T) {
	api, provider := newGoDaddyAPI(t)

	rec := Record{Name: "_acme-challenge.ev/il.com", Value: godaddyChallengeValue}
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

// TestGoDaddyRefusesDomainLookupMismatch pins the check that the lookup's own
// answer is for the domain that was asked for. A redirected or impersonated
// response naming a different domain must not substitute that domain for the one
// this lookup resolved, because the challenge would then be written into a zone
// the walk never selected.
func TestGoDaddyRefusesDomainLookupMismatch(t *testing.T) {
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Method+" "+r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		// Answer any domain lookup 200 but name a DIFFERENT domain.
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"domain":"attacker-example.net"}`))
	}))
	t.Cleanup(srv.Close)

	provider, err := NewGoDaddy(NewSingleCredential(secrets.NewRedacted(godaddyTestCred)), srv.Client())
	if err != nil {
		t.Fatalf("NewGoDaddy: %v", err)
	}
	provider.(*godaddyProvider).client = &http.Client{
		Transport: godaddyRewriteHost{srv.URL, srv.Client().Transport},
	}

	rec := Record{Name: ChallengeRecordName("vallet.example.com"), Value: godaddyChallengeValue}
	_, err = provider.Present(t.Context(), rec)
	if err == nil {
		t.Fatal("Present succeeded despite a domain lookup answering for a different domain")
	}
	if !strings.Contains(err.Error(), "different domain") {
		t.Errorf("error %q is not the mismatch refusal", err)
	}
	for _, req := range seen {
		if strings.HasPrefix(req, http.MethodPut+" ") || strings.HasPrefix(req, http.MethodDelete+" ") {
			t.Errorf("a mismatched lookup issued a destructive request %q", req)
		}
	}
}

// TestGoDaddyErrorWithoutStructuredCode covers the fallback in
// godaddyError: a rejection whose body has a message but no code, and one with
// no parseable body at all, must still surface the HTTP status rather than an
// empty error.
func TestGoDaddyErrorWithoutStructuredCode(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{"message without code", `{"message":"quota exceeded"}`},
		{"unparseable body", `<html>gateway</html>`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			api, provider := newGoDaddyAPI(t)
			// Fail the PUT with a 429 carrying the test's body.
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				api.requests = append(api.requests, r.Method+" "+r.URL.Path)
				w.Header().Set("Content-Type", "application/json")
				if r.Method == http.MethodGet && strings.Count(r.URL.Path, "/") == 2 {
					_, _ = w.Write([]byte(`{"domain":"example.com"}`))
					return
				}
				if r.Method == http.MethodGet {
					_, _ = w.Write([]byte(`[]`))
					return
				}
				w.WriteHeader(http.StatusTooManyRequests)
				_, _ = w.Write([]byte(tt.body))
			}))
			t.Cleanup(srv.Close)
			provider.(*godaddyProvider).client = &http.Client{
				Transport: godaddyRewriteHost{srv.URL, srv.Client().Transport},
			}

			rec := Record{Name: ChallengeRecordName("example.com"), Value: godaddyChallengeValue}
			_, err := provider.Present(t.Context(), rec)
			if err == nil {
				t.Fatal("Present succeeded, want the 429 surfaced")
			}
			if !strings.Contains(err.Error(), "429") {
				t.Errorf("error %q does not surface the HTTP status", err)
			}
		})
	}
}

func TestGoDaddyUnknownDomainRefuses(t *testing.T) {
	api, provider := newGoDaddyAPI(t)
	api.domains = map[string]bool{} // the account holds nothing

	rec := Record{Name: ChallengeRecordName("vallet.example.com"), Value: godaddyChallengeValue}
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

// TestGoDaddyDomainWalkSurfacesCredentialFault proves a 403 on a candidate is
// surfaced rather than swallowed as "try the parent". Treating it as a miss
// would turn a bad or under-privileged credential into a misleading
// "no domain found" after walking the whole name.
func TestGoDaddyDomainWalkSurfacesCredentialFault(t *testing.T) {
	api := &godaddyAPI{t: t, domains: map[string]bool{}, records: map[string][]godaddyRecord{}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		api.requests = append(api.requests, r.Method+" "+r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"code":"ACCESS_DENIED","message":"not entitled"}`))
	}))
	t.Cleanup(srv.Close)

	provider, err := NewGoDaddy(NewSingleCredential(secrets.NewRedacted(godaddyTestCred)), srv.Client())
	if err != nil {
		t.Fatalf("NewGoDaddy: %v", err)
	}
	provider.(*godaddyProvider).client = &http.Client{
		Transport: godaddyRewriteHost{srv.URL, srv.Client().Transport},
	}

	rec := Record{Name: ChallengeRecordName("vallet.example.com"), Value: godaddyChallengeValue}
	_, err = provider.Present(t.Context(), rec)
	if err == nil {
		t.Fatal("Present succeeded despite a 403 on the domain lookup")
	}
	if strings.Contains(err.Error(), "no domain found") {
		t.Errorf("a 403 was swallowed as a miss: %v", err)
	}
	if !strings.Contains(err.Error(), "403") {
		t.Errorf("error %q does not surface the credential fault", err)
	}
	// The walk must stop at the first 403, not keep trying parents.
	if len(api.requests) != 1 {
		t.Errorf("walk issued %d requests after a 403, want it to stop at the first", len(api.requests))
	}
}

// TestGoDaddyPrefersTheMostSpecificDomain pins the walk order. Writing to the
// parent of a delegated subdomain puts the record in a zone that is not
// authoritative for the name.
func TestGoDaddyPrefersTheMostSpecificDomain(t *testing.T) {
	api, provider := newGoDaddyAPI(t)
	api.domains = map[string]bool{"example.com": true, "eu.example.com": true}

	rec := Record{Name: ChallengeRecordName("vallet.eu.example.com"), Value: godaddyChallengeValue}
	if _, err := provider.Present(t.Context(), rec); err != nil {
		t.Fatalf("Present: %v", err)
	}
	if _, ok := api.records["_acme-challenge.vallet"]; !ok {
		t.Fatalf("record not stored relative to eu.example.com; store = %v", api.records)
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

// TestGoDaddyProviderNeverFormatsItsCredential covers the mechanism, not a
// string: fmt walks unexported struct fields by reflection and does NOT call
// secrets.Redacted's redaction methods, so without Format on the containing type
// "%+v" prints the packed key and secret in full.
func TestGoDaddyProviderNeverFormatsItsCredential(t *testing.T) {
	provider, err := NewGoDaddy(NewSingleCredential(secrets.NewRedacted(godaddyTestCred)), nil)
	if err != nil {
		t.Fatalf("NewGoDaddy: %v", err)
	}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
		rendered := fmt.Sprintf(verb, provider)
		if strings.Contains(rendered, godaddyTestKey) || strings.Contains(rendered, godaddyTestSecret) {
			t.Errorf("fmt %s of the provider leaked a credential half: %s", verb, rendered)
		}
		if !strings.Contains(rendered, "[REDACTED]") {
			t.Errorf("fmt %s of the provider = %q, want it to render the redaction marker", verb, rendered)
		}
	}
}

func TestNewAPIProviderBuildsGoDaddy(t *testing.T) {
	provider, err := NewAPIProvider("godaddy", NewSingleCredential(secrets.NewRedacted(godaddyTestCred)), nil)
	if err != nil {
		t.Fatalf("NewAPIProvider: %v", err)
	}
	if got := provider.Name(); got != "godaddy" {
		t.Errorf("Name() = %q, want %q", got, "godaddy")
	}
}

// TestGoDaddyDoesNotPollForPropagation pins the seam's division of labor: the
// solver polls the authoritative nameservers, so a provider must not add a
// redundant, weaker wait of its own. Present may read the record set once (to
// merge), but must not read it BACK after the write.
func TestGoDaddyDoesNotPollForPropagation(t *testing.T) {
	api, provider := newGoDaddyAPI(t)
	rec := Record{Name: ChallengeRecordName("example.com"), Value: godaddyChallengeValue}

	if _, err := provider.Present(context.Background(), rec); err != nil {
		t.Fatalf("Present: %v", err)
	}
	var sawWrite bool
	for _, req := range api.requests {
		if strings.HasPrefix(req, http.MethodPut+" ") {
			sawWrite = true
		}
		if sawWrite && strings.HasPrefix(req, http.MethodGet+" ") && strings.Contains(req, "/records/") {
			t.Errorf("Present read the record back after writing (%q), which is a propagation poll", req)
		}
	}
}

// TestGoDaddyAcceptsNamedCredentials proves the named form (api_key + api_secret)
// builds a provider, and that it normalizes to EXACTLY the packed "KEY:SECRET"
// credential the single unwrap site consumes -- so the named path inherits the
// request path's coverage rather than duplicating the fake-API harness.
func TestGoDaddyAcceptsNamedCredentials(t *testing.T) {
	t.Parallel()

	named, err := NewGoDaddy(NewNamedCredentials(map[string]secrets.Redacted{
		"api_key":    secrets.NewRedacted(godaddyTestKey),
		"api_secret": secrets.NewRedacted(godaddyTestSecret),
	}), nil)
	if err != nil {
		t.Fatalf("NewGoDaddy(named): %v", err)
	}
	packed, err := NewGoDaddy(NewSingleCredential(secrets.NewRedacted(godaddyTestCred)), nil)
	if err != nil {
		t.Fatalf("NewGoDaddy(packed): %v", err)
	}

	gotNamed := named.(*godaddyProvider).credential.Reveal()
	wantPacked := packed.(*godaddyProvider).credential.Reveal()
	if gotNamed != wantPacked {
		t.Error("named credentials did not normalize to the packed KEY:SECRET form")
	}
}

// TestGoDaddyAcceptsSingleEntryNamedCredentialsAsPacked confirms a lone named
// entry falls through Single() and is treated as the packed single form, so an
// operator who put the packed pair under one arbitrary key still works.
func TestGoDaddyAcceptsSingleEntryNamedCredentialsAsPacked(t *testing.T) {
	t.Parallel()

	p, err := NewGoDaddy(NewNamedCredentials(map[string]secrets.Redacted{
		"credentials": secrets.NewRedacted(godaddyTestCred),
	}), nil)
	if err != nil {
		t.Fatalf("NewGoDaddy(one named entry): %v", err)
	}
	if p == nil {
		t.Fatal("provider must not be nil")
	}
}

// TestGoDaddyRejectsPartialNamedCredentials is the multi-field abuse case:
// exactly one named half present must REFUSE, not silently colon-split the lone
// value into the wrong parts. The error must name neither half.
func TestGoDaddyRejectsPartialNamedCredentials(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		creds map[string]secrets.Redacted
	}{
		{"only api_key", map[string]secrets.Redacted{
			"api_key": secrets.NewRedacted(godaddyTestKey),
		}},
		{"only api_secret", map[string]secrets.Redacted{
			"api_secret": secrets.NewRedacted(godaddyTestSecret),
		}},
		// The dangerous case the explicit partial guard exists for: an operator
		// pastes the packed "key:secret" pair into api_key and leaves the secret
		// unset. Without the guard this lone entry would fall through to the
		// single-value path and be colon-split and silently accepted. It must be
		// refused.
		{"packed pair pasted into api_key", map[string]secrets.Redacted{
			"api_key": secrets.NewRedacted(godaddyTestCred),
		}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p, err := NewGoDaddy(NewNamedCredentials(tc.creds), nil)
			if !errors.Is(err, ErrGoDaddyAPI) {
				t.Fatalf("err = %v, want ErrGoDaddyAPI", err)
			}
			if p != nil {
				t.Fatal("a provider with an incomplete credential must not be returned")
			}
			if strings.Contains(err.Error(), godaddyTestKey) || strings.Contains(err.Error(), godaddyTestSecret) {
				t.Error("error must never echo a credential half")
			}
		})
	}
}

// TestGoDaddyRejectsBlankCredentialHalves covers the blank shape the packed pair
// allows: a credential can be blank in a HALF while the whole string is not
// blank at all. It mirrors the route53 sibling case.
func TestGoDaddyRejectsBlankCredentialHalves(t *testing.T) {
	t.Parallel()

	tests := []struct{ name, credential string }{
		{"both halves blank", "  :  "},
		{"key blank", "  :" + godaddyTestSecret},
		{"secret blank", godaddyTestKey + ":  "},
		{"secret is a newline", godaddyTestKey + ":\n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			p, err := NewGoDaddy(NewSingleCredential(secrets.NewRedacted(tt.credential)), nil)
			if !errors.Is(err, ErrGoDaddyAPI) {
				t.Fatalf("err = %v, want ErrGoDaddyAPI", err)
			}
			if p != nil {
				t.Fatal("a provider with no usable credential must not be returned")
			}
			if strings.Contains(err.Error(), godaddyTestKey) || strings.Contains(err.Error(), godaddyTestSecret) {
				t.Error("error must never echo either half of the credential")
			}
		})
	}
}
