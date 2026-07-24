package dns01

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"unicode/utf8"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/secrets"
)

// The credential fields every test in this file hands the provider. Each is a
// distinctive string so a leak into any output is unmistakable. azureClientSecret
// is the only field that is truly secret — the application password — so it is
// the one the non-leak tests target, alongside the bearer token the fake issues.
const (
	azureTenantID       = "tenant-PUBLIC-11111111-2222-3333"
	azureClientID       = "client-PUBLIC-44444444-5555-6666"
	azureClientSecret   = "azure-secret-DO-NOT-LEAK-9f31ab7c"
	azureSubscriptionID = "sub-PUBLIC-77777777-8888-9999"

	// azureAccessToken is what the fake token endpoint issues. Every management
	// call must carry it in the Authorization header, and it must never appear in
	// any error: it is a zone-rewriting secret for its lifetime.
	azureAccessToken = "azure-bearer-token-DO-NOT-LEAK-4d7b1e93"
)

// azureChallenge is this process's published digest, and azureSibling is the
// OTHER challenge of a wildcard order: a different digest at the same name that
// cleanup must leave untouched.
const (
	azureChallenge = "digest-value-one"
	azureSibling   = "digest-value-two"
)

// azureRecordSetKey identifies one TXT record set in the fake's store.
type azureRecordSetKey struct {
	group, zone, relative string
}

// azureFakeZone is one DNS zone in the fake subscription.
type azureFakeZone struct {
	name  string
	group string
	// idOverride, when set, is returned verbatim as the zone's resource id so a
	// test can feed a malformed id (a traversal sequence in the resource-group
	// segment) through the response-validation path.
	idOverride string
}

// azureAPI is a local stand-in for the Entra ID token endpoint and the Azure DNS
// management API. No test in this package contacts Azure.
//
// It holds real state and APPLIES the writes it receives rather than only
// recording them: the union-on-publish and subtract-on-cleanup logic is the part
// of this provider most likely to be wrong, and a fake that merely recorded
// requests would let a provider that clobbers a co-existing value pass.
type azureAPI struct {
	t *testing.T

	mu sync.Mutex

	zones []azureFakeZone

	// records maps a record set to the TXT values currently published at it.
	records map[azureRecordSetKey][]string
	ttls    map[azureRecordSetKey]int

	// requests records every method+path issued, so a test can assert what the
	// provider did NOT do.
	requests []string

	// tokenFails makes the token endpoint reject with an OAuth2 error.
	tokenFails bool
	// putStatus overrides the response to a record-set PUT, so the publish- and
	// cleanup-rejection paths can be driven.
	putStatus int
	// deleteStatus overrides the response to a record-set DELETE.
	deleteStatus int
	// paginate splits the zone list across two pages, so the pagination walk is
	// exercised: the only zone appears on the SECOND page.
	paginate bool
	// putMessage overrides the message text in a PUT rejection body, so a test can
	// drive remote-controlled message content through the error path.
	putMessage string
}

func newAzureAPI(t *testing.T, zones ...azureFakeZone) (*azureAPI, *azureProvider) {
	t.Helper()

	if len(zones) == 0 {
		zones = []azureFakeZone{{name: "example.com", group: "rg-prod"}}
	}
	api := &azureAPI{
		t:       t,
		zones:   zones,
		records: map[azureRecordSetKey][]string{},
		ttls:    map[azureRecordSetKey]int{},
	}
	srv := httptest.NewServer(api)
	t.Cleanup(srv.Close)

	provider, err := NewAzure(azureCreds(nil), srv.Client())
	if err != nil {
		t.Fatalf("NewAzure: %v", err)
	}
	p := provider.(*azureProvider)
	// Both the login host and the management host are constants by design, so the
	// test rewrites the request host in the transport rather than making either
	// endpoint configurable — a settable endpoint is exactly the setting that lets
	// a misconfiguration point the client secret or the bearer token at another
	// host.
	p.client = &http.Client{Transport: rewriteAzureHost{srv.URL, srv.Client().Transport}}
	return api, p
}

// azureCreds builds the named credential set, applying any overrides. A nil
// override yields the full, valid set.
func azureCreds(overrides map[string]string) Credentials {
	fields := map[string]string{
		"tenant_id":       azureTenantID,
		"client_id":       azureClientID,
		"client_secret":   azureClientSecret,
		"subscription_id": azureSubscriptionID,
	}
	for k, v := range overrides {
		if v == azureDelete {
			delete(fields, k)
			continue
		}
		fields[k] = v
	}
	named := make(map[string]secrets.Redacted, len(fields))
	for k, v := range fields {
		named[k] = secrets.NewRedacted(v)
	}
	return NewNamedCredentials(named)
}

// azureDelete is a sentinel override meaning "remove this field entirely".
const azureDelete = "\x00delete\x00"

// rewriteAzureHost redirects requests for either fixed Azure host at the local
// fake, preserving the path and query.
type rewriteAzureHost struct {
	base string
	next http.RoundTripper
}

func (r rewriteAzureHost) RoundTrip(req *http.Request) (*http.Response, error) {
	s := req.URL.String()
	switch {
	case strings.HasPrefix(s, azureLoginBase):
		s = r.base + strings.TrimPrefix(s, azureLoginBase)
	case strings.HasPrefix(s, azureManagementBase):
		s = r.base + strings.TrimPrefix(s, azureManagementBase)
	}
	clone := req.Clone(req.Context())
	u, err := req.URL.Parse(s)
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

func (a *azureAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)

	a.mu.Lock()
	defer a.mu.Unlock()
	a.requests = append(a.requests, r.Method+" "+r.URL.Path)

	if strings.HasSuffix(r.URL.Path, "/oauth2/v2.0/token") {
		a.serveToken(w, r, body)
		return
	}

	// Every management call must carry the bearer token the token endpoint
	// issued, and it must be the token — the client secret must never appear here.
	auth := r.Header.Get("Authorization")
	if auth != "Bearer "+azureAccessToken {
		a.t.Errorf("Authorization = %q, want the issued bearer token", auth)
	}
	if strings.Contains(auth, azureClientSecret) {
		a.t.Errorf("the client secret appears in the Authorization header: %q", auth)
	}

	w.Header().Set("Content-Type", "application/json")
	segments := strings.Split(strings.TrimPrefix(r.URL.Path, "/"), "/")
	switch {
	case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/providers/Microsoft.Network/dnszones"):
		a.listZones(w, r)
	case len(segments) == 10 && segments[8] == "TXT":
		a.recordSet(w, r, segments, body)
	default:
		a.t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		a.write(w, http.StatusNotFound, `{"error":{"code":"NotFound","message":"no"}}`)
	}
}

// serveToken mimics the Entra ID client-credentials token endpoint. It checks
// the tenant is in the path and the client id, secret, grant type and scope are
// in the form, then issues the fixed bearer token.
func (a *azureAPI) serveToken(w http.ResponseWriter, r *http.Request, body []byte) {
	if got := strings.Split(strings.TrimPrefix(r.URL.Path, "/"), "/")[0]; got != azureTenantID {
		a.t.Errorf("token URL tenant = %q, want the tenant id", got)
	}
	if a.tokenFails {
		a.write(w, http.StatusUnauthorized,
			`{"error":"invalid_client","error_description":"AADSTS7000215: Invalid client secret provided"}`)
		return
	}
	form, err := url.ParseQuery(string(body))
	if err != nil {
		a.t.Errorf("token body did not parse: %v", err)
	}
	if form.Get("grant_type") != "client_credentials" {
		a.t.Errorf("grant_type = %q, want client_credentials", form.Get("grant_type"))
	}
	if form.Get("client_id") != azureClientID {
		a.t.Errorf("client_id = %q, want the client id", form.Get("client_id"))
	}
	if form.Get("client_secret") != azureClientSecret {
		a.t.Errorf("client_secret = %q, want the client secret", form.Get("client_secret"))
	}
	if form.Get("scope") != azureScope {
		a.t.Errorf("scope = %q, want %q", form.Get("scope"), azureScope)
	}
	w.Header().Set("Content-Type", "application/json")
	a.write(w, http.StatusOK, fmt.Sprintf(
		`{"token_type":"Bearer","expires_in":3599,"access_token":%q}`, azureAccessToken))
}

// listZones mimics GET .../dnszones, optionally across two pages.
func (a *azureAPI) listZones(w http.ResponseWriter, r *http.Request) {
	page := r.URL.Query().Get("page")
	if a.paginate && page != "2" {
		// The first page carries no zones and a continuation link to the second.
		// A provider that reads only the first page finds nothing.
		next := azureManagementBase + "/subscriptions/" + azureSubscriptionID +
			"/providers/Microsoft.Network/dnszones?api-version=" + azureAPIVersion + "&page=2"
		a.write(w, http.StatusOK, fmt.Sprintf(`{"value":[],"nextLink":%q}`, next))
		return
	}

	items := make([]string, 0, len(a.zones))
	for _, z := range a.zones {
		id := z.idOverride
		if id == "" {
			id = "/subscriptions/" + azureSubscriptionID + "/resourceGroups/" + z.group +
				"/providers/Microsoft.Network/dnszones/" + z.name
		}
		items = append(items, fmt.Sprintf(`{"id":%q,"name":%q,"type":"Microsoft.Network/dnszones"}`, id, z.name))
	}
	a.write(w, http.StatusOK, fmt.Sprintf(`{"value":[%s]}`, strings.Join(items, ",")))
}

// recordSet handles GET, PUT and DELETE on one TXT record set, applying the
// change to the fake's state.
func (a *azureAPI) recordSet(w http.ResponseWriter, r *http.Request, segments []string, body []byte) {
	key := azureRecordSetKey{group: segments[3], zone: segments[7], relative: segments[9]}

	switch r.Method {
	case http.MethodGet:
		values, ok := a.records[key]
		if !ok {
			a.write(w, http.StatusNotFound, `{"error":{"code":"NotFound","message":"record set not found"}}`)
			return
		}
		a.write(w, http.StatusOK, a.recordSetJSON(values, a.ttls[key]))

	case http.MethodPut:
		if a.putStatus != 0 {
			msg := a.putMessage
			if msg == "" {
				msg = "the record set was refused"
			}
			raw, err := json.Marshal(map[string]any{"error": map[string]any{"code": "BadRequest", "message": msg}})
			if err != nil {
				a.t.Fatalf("marshal error body: %v", err)
			}
			a.write(w, a.putStatus, string(raw))
			return
		}
		var in azureRecordSet
		if err := json.Unmarshal(body, &in); err != nil {
			a.t.Errorf("put body did not parse: %v", err)
			a.write(w, http.StatusBadRequest, `{"error":{"code":"BadRequest","message":"bad body"}}`)
			return
		}
		values := make([]string, 0, len(in.Properties.TXTRecords))
		for _, rec := range in.Properties.TXTRecords {
			if len(rec.Value) == 0 {
				a.t.Error("PUT carried a TXT record with an empty value array, which Azure rejects")
			}
			values = append(values, strings.Join(rec.Value, ""))
		}
		a.records[key] = values
		a.ttls[key] = in.Properties.TTL
		a.write(w, http.StatusOK, a.recordSetJSON(values, in.Properties.TTL))

	case http.MethodDelete:
		if a.deleteStatus != 0 {
			a.write(w, a.deleteStatus, `{"error":{"code":"BadRequest","message":"delete refused"}}`)
			return
		}
		delete(a.records, key)
		delete(a.ttls, key)
		a.write(w, http.StatusOK, `{}`)

	default:
		a.t.Errorf("unexpected method %s on record set", r.Method)
		a.write(w, http.StatusMethodNotAllowed, `{"error":{"code":"NotAllowed","message":"no"}}`)
	}
}

func (a *azureAPI) recordSetJSON(values []string, ttl int) string {
	records := make([]string, 0, len(values))
	for _, v := range values {
		records = append(records, fmt.Sprintf(`{"value":[%q]}`, v))
	}
	return fmt.Sprintf(`{"properties":{"TTL":%d,"TXTRecords":[%s]}}`, ttl, strings.Join(records, ","))
}

func (a *azureAPI) write(w http.ResponseWriter, status int, body string) {
	w.WriteHeader(status)
	_, _ = io.WriteString(w, body)
}

// seed adds a stored TXT value directly, so assertions about what survived a
// cleanup read from state the TEST established.
func (a *azureAPI) seed(group, zone, relative string, values ...string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	key := azureRecordSetKey{group: group, zone: zone, relative: relative}
	a.records[key] = values
	a.ttls[key] = 300
}

func (a *azureAPI) stored(group, zone, relative string) []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return slices.Clone(a.records[azureRecordSetKey{group: group, zone: zone, relative: relative}])
}

func (a *azureAPI) methodsIssued() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return slices.Clone(a.requests)
}

func azureRecord() Record {
	return Record{Name: "_acme-challenge.example.com", Value: azureChallenge}
}

// TestAzurePublishesAndRemovesTheChallengeRecord is the happy path: the value is
// published at the right record set with a low TTL and the cleanup takes it away.
func TestAzurePublishesAndRemovesTheChallengeRecord(t *testing.T) {
	t.Parallel()
	api, provider := newAzureAPI(t)

	cleanup, err := provider.Present(context.Background(), azureRecord())
	if err != nil {
		t.Fatalf("Present: %v", err)
	}
	if cleanup == nil {
		t.Fatal("Present returned a nil cleanup")
	}

	if got := api.stored("rg-prod", "example.com", "_acme-challenge"); !slices.Equal(got, []string{azureChallenge}) {
		t.Fatalf("published values = %v, want the challenge digest", got)
	}
	key := azureRecordSetKey{"rg-prod", "example.com", "_acme-challenge"}
	if got := api.ttls[key]; got != azureChallengeTTL {
		t.Errorf("TTL = %d, want %d: a long TTL keeps resolvers serving a withdrawn "+
			"challenge answer", got, azureChallengeTTL)
	}

	if err := cleanup(context.Background()); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if got := api.stored("rg-prod", "example.com", "_acme-challenge"); got != nil {
		t.Errorf("cleanup left the record set behind: %v", got)
	}
}

// TestAzurePreservesACoexistingValue is the multi-value test.
//
// A certificate covering both example.com and *.example.com puts two different
// digests at _acme-challenge.example.com, because ChallengeRecordName strips the
// wildcard prefix. Azure keys a record set by (name, type) and holds a SET of
// values, so a PUT that writes only the new value silently discards the other
// challenge. Both directions are asserted: publishing the second value must keep
// the first, and cleaning up the second must leave the first standing.
func TestAzurePreservesACoexistingValue(t *testing.T) {
	t.Parallel()
	api, provider := newAzureAPI(t)

	cleanupFirst, err := provider.Present(context.Background(), azureRecord())
	if err != nil {
		t.Fatalf("Present(first): %v", err)
	}
	second := Record{Name: "_acme-challenge.example.com", Value: azureSibling}
	cleanupSecond, err := provider.Present(context.Background(), second)
	if err != nil {
		t.Fatalf("Present(second): %v", err)
	}

	if got := api.stored("rg-prod", "example.com", "_acme-challenge"); !sameSet(got, []string{azureChallenge, azureSibling}) {
		t.Fatalf("after two challenges the record set holds %v, want both digests: "+
			"publishing the second must not discard the first", got)
	}

	if err := cleanupSecond(context.Background()); err != nil {
		t.Fatalf("cleanup(second): %v", err)
	}
	if got := api.stored("rg-prod", "example.com", "_acme-challenge"); !slices.Equal(got, []string{azureChallenge}) {
		t.Fatalf("after removing the second value the set holds %v, want only the first: "+
			"cleanup must subtract its own value, not delete the set", got)
	}

	if err := cleanupFirst(context.Background()); err != nil {
		t.Fatalf("cleanup(first): %v", err)
	}
	if got := api.stored("rg-prod", "example.com", "_acme-challenge"); got != nil {
		t.Errorf("removing the last value left a record set behind: %v", got)
	}
}

// TestAzureCleanupLeavesAnUnrelatedValueAlone is the scoping test. An operator's
// own TXT value at the same name must survive both the publish and the cleanup,
// because the guarantee rests on set subtraction rather than an opaque id.
func TestAzureCleanupLeavesAnUnrelatedValueAlone(t *testing.T) {
	t.Parallel()
	api, provider := newAzureAPI(t)
	api.seed("rg-prod", "example.com", "_acme-challenge", "operator-owned-value")

	cleanup, err := provider.Present(context.Background(), azureRecord())
	if err != nil {
		t.Fatalf("Present: %v", err)
	}
	if got := api.stored("rg-prod", "example.com", "_acme-challenge"); !sameSet(got, []string{"operator-owned-value", azureChallenge}) {
		t.Fatalf("publish produced %v, want the operator's value kept alongside ours", got)
	}

	if err := cleanup(context.Background()); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if got := api.stored("rg-prod", "example.com", "_acme-challenge"); !slices.Equal(got, []string{"operator-owned-value"}) {
		t.Errorf("cleanup produced %v, want the operator's value untouched: the provider "+
			"must not remove a value it did not publish", got)
	}
}

// TestAzureCleanupIsIdempotent proves a second cleanup, and a cleanup for a value
// that was never created, are both a no-op success — the path a cleanup returned
// from a failed publish takes.
func TestAzureCleanupIsIdempotent(t *testing.T) {
	t.Parallel()
	api, provider := newAzureAPI(t)

	cleanup, err := provider.Present(context.Background(), azureRecord())
	if err != nil {
		t.Fatalf("Present: %v", err)
	}
	if err := cleanup(context.Background()); err != nil {
		t.Fatalf("first cleanup: %v", err)
	}
	if err := cleanup(context.Background()); err != nil {
		t.Errorf("second cleanup: %v, want nil", err)
	}
	// The second cleanup read an absent record set and must not have issued a
	// destructive call.
	deletes := 0
	for _, req := range api.methodsIssued() {
		if strings.HasPrefix(req, http.MethodDelete) {
			deletes++
		}
	}
	if deletes != 1 {
		t.Errorf("saw %d DELETE calls, want exactly one: the idempotent second cleanup "+
			"must not delete again", deletes)
	}
}

// TestAzureCleanupReportsAFailure is the other half of idempotence: an
// already-gone value is success, but a REFUSED removal must be reported, or an
// _acme-challenge record is left standing with the solver believing it withdrawn.
func TestAzureCleanupReportsAFailure(t *testing.T) {
	t.Parallel()
	api, provider := newAzureAPI(t)

	cleanup, err := provider.Present(context.Background(), azureRecord())
	if err != nil {
		t.Fatalf("Present: %v", err)
	}
	api.deleteStatus = http.StatusForbidden
	if err := cleanup(context.Background()); err == nil {
		t.Fatal("cleanup swallowed an API refusal; the record is still published and " +
			"nothing would tell the operator")
	}
}

// TestAzurePresentReportsAnAPIRejection checks the publish path fails loudly AND
// still hands back a cleanup, because a failed write can still have applied.
func TestAzurePresentReportsAnAPIRejection(t *testing.T) {
	t.Parallel()
	api, provider := newAzureAPI(t)
	api.putStatus = http.StatusBadRequest
	api.putMessage = "InvalidRecordSet"

	cleanup, err := provider.Present(context.Background(), azureRecord())
	if err == nil {
		t.Fatal("Present accepted a refused write")
	}
	if !errors.Is(err, ErrAzureAPI) {
		t.Errorf("error = %v, want ErrAzureAPI", err)
	}
	if cleanup == nil {
		t.Fatal("Present returned no cleanup for a write that may still have applied: a " +
			"lost response leaves the record published with nothing able to remove it")
	}
	if !strings.Contains(err.Error(), "InvalidRecordSet") {
		t.Errorf("error %v does not carry the API's own message, which is the diagnostic", err)
	}
	assertNoAzureSecret(t, err)
}

// TestAzureCleanupAfterAFailedPublishSubmitsNoChange proves the cleanup returned
// on the error path is safe to run when the write genuinely never applied: it
// reads first, finds its value absent, and makes no destructive call — leaving a
// concurrent challenge at the same name untouched.
func TestAzureCleanupAfterAFailedPublishSubmitsNoChange(t *testing.T) {
	t.Parallel()
	api, provider := newAzureAPI(t)
	api.seed("rg-prod", "example.com", "_acme-challenge", "someone-elses-challenge")

	api.putStatus = http.StatusBadRequest
	cleanup, err := provider.Present(context.Background(), azureRecord())
	if err == nil {
		t.Fatal("Present accepted a refused write")
	}
	if cleanup == nil {
		t.Fatal("Present returned no cleanup")
	}

	api.putStatus = 0
	if err := cleanup(context.Background()); err != nil {
		t.Fatalf("cleanup after a failed publish: %v, want nil", err)
	}
	if got := api.stored("rg-prod", "example.com", "_acme-challenge"); !slices.Equal(got, []string{"someone-elses-challenge"}) {
		t.Errorf("cleanup disturbed a concurrent challenge: record set = %v", got)
	}
}

// TestAzureRefusesAmbiguousZone proves two zones with the same name in different
// resource groups are refused rather than guessed between. Writing to the wrong
// one succeeds at the API and is never seen by the CA.
func TestAzureRefusesAmbiguousZone(t *testing.T) {
	t.Parallel()
	api, provider := newAzureAPI(t,
		azureFakeZone{name: "example.com", group: "rg-a"},
		azureFakeZone{name: "example.com", group: "rg-b"},
	)

	_, err := provider.Present(context.Background(), azureRecord())
	if err == nil {
		t.Fatal("Present picked one of two identically named zones")
	}
	if !errors.Is(err, ErrAzureAmbiguousZone) {
		t.Errorf("error = %v, want ErrAzureAmbiguousZone", err)
	}
	for _, req := range api.methodsIssued() {
		if strings.HasPrefix(req, http.MethodPut) {
			t.Errorf("a record set was written despite the zone being ambiguous: %q", req)
		}
	}
}

// TestAzurePrefersTheMostSpecificZone checks a delegated subdomain wins over its
// parent. Writing to the parent would put the record in a zone that is not
// authoritative for the name, so the CA would never see it.
func TestAzurePrefersTheMostSpecificZone(t *testing.T) {
	t.Parallel()
	api, provider := newAzureAPI(t,
		azureFakeZone{name: "example.com", group: "rg-parent"},
		azureFakeZone{name: "eu.example.com", group: "rg-child"},
	)

	rec := Record{Name: "_acme-challenge.eu.example.com", Value: azureChallenge}
	if _, err := provider.Present(context.Background(), rec); err != nil {
		t.Fatalf("Present: %v", err)
	}
	if got := api.stored("rg-child", "eu.example.com", "_acme-challenge"); !slices.Equal(got, []string{azureChallenge}) {
		t.Fatalf("record written to %v, want the delegated child zone", got)
	}
	if got := api.stored("rg-parent", "example.com", "_acme-challenge.eu"); got != nil {
		t.Errorf("the parent zone was written to despite a delegated child existing: %v", got)
	}
}

// TestAzureRefusesWhenNoZoneMatches checks the subscription-holds-nothing case
// fails rather than writing somewhere arbitrary.
func TestAzureRefusesWhenNoZoneMatches(t *testing.T) {
	t.Parallel()
	_, provider := newAzureAPI(t, azureFakeZone{name: "unrelated.test", group: "rg-x"})

	_, err := provider.Present(context.Background(), azureRecord())
	if err == nil {
		t.Fatal("Present succeeded with no zone for the name")
	}
	if !errors.Is(err, ErrAzureAPI) {
		t.Errorf("error = %v, want ErrAzureAPI", err)
	}
}

// TestAzureFollowsZoneListPagination proves a zone on the second page of the
// subscription listing is found. A provider reading only the first page would
// see no zone and fail closed, silently breaking issuance for that domain.
func TestAzureFollowsZoneListPagination(t *testing.T) {
	t.Parallel()
	api, provider := newAzureAPI(t)
	api.paginate = true

	cleanup, err := provider.Present(context.Background(), azureRecord())
	if err != nil {
		t.Fatalf("Present with a paginated zone list: %v", err)
	}
	if got := api.stored("rg-prod", "example.com", "_acme-challenge"); !slices.Equal(got, []string{azureChallenge}) {
		t.Fatalf("published values = %v, want the challenge found on the second page", got)
	}
	if cleanup == nil {
		t.Fatal("Present returned a nil cleanup")
	}
}

// TestAzureRejectsMalformedResourceGroupFromAPI checks that a resource group
// parsed out of a zone's resource id is validated before it is interpolated into
// a request path.
//
// The resource group is taken from the API's own response and reaches the path
// of a subsequent credentialed PUT. A hostile or confused response returning a
// traversal sequence there could steer that write at another resource, so the
// value is checked against the shape Azure documents.
func TestAzureRejectsMalformedResourceGroupFromAPI(t *testing.T) {
	t.Parallel()
	api, provider := newAzureAPI(t, azureFakeZone{
		name:       "example.com",
		idOverride: "/subscriptions/" + azureSubscriptionID + "/resourceGroups/../../evil/providers/Microsoft.Network/dnszones/example.com",
	})

	_, err := provider.Present(context.Background(), azureRecord())
	if err == nil {
		t.Fatal("Present accepted a malformed resource group from the API")
	}
	if !errors.Is(err, ErrAzureAPI) {
		t.Errorf("error = %v, want ErrAzureAPI", err)
	}
	for _, req := range api.methodsIssued() {
		if strings.HasPrefix(req, http.MethodPut) {
			t.Errorf("a write was issued despite the malformed resource group: %q", req)
		}
	}
}

// TestAzureTokenEndpointErrorSurfaces proves a token-endpoint rejection becomes
// an ErrAzureAPI, no record is written, and the client secret does not leak into
// the error even though the endpoint's own message is carried.
func TestAzureTokenEndpointErrorSurfaces(t *testing.T) {
	t.Parallel()
	api, provider := newAzureAPI(t)
	api.tokenFails = true

	_, err := provider.Present(context.Background(), azureRecord())
	if !errors.Is(err, ErrAzureAPI) {
		t.Fatalf("err = %v, want ErrAzureAPI", err)
	}
	assertNoAzureSecret(t, err)
	for _, req := range api.methodsIssued() {
		if strings.HasPrefix(req, http.MethodPut) || strings.HasPrefix(req, http.MethodGet) && strings.Contains(req, "/TXT/") {
			t.Errorf("a management call was made despite the token request failing: %q", req)
		}
	}
}

// TestAzureRejectsIncompleteCredentials is the construction-time gate. Each of
// the four required fields, when missing or blank, must refuse with ErrAzureAPI
// and return no provider, and no error may echo the client secret.
func TestAzureRejectsIncompleteCredentials(t *testing.T) {
	t.Parallel()

	blank := []string{"", " ", "   ", "\t", "\n", " \t\r\n "}
	for _, field := range []string{"tenant_id", "client_id", "client_secret", "subscription_id"} {
		t.Run("missing "+field, func(t *testing.T) {
			t.Parallel()
			p, err := NewAzure(azureCreds(map[string]string{field: azureDelete}), nil)
			if !errors.Is(err, ErrAzureAPI) {
				t.Fatalf("err = %v, want ErrAzureAPI", err)
			}
			if p != nil {
				t.Fatal("a provider with an incomplete credential must not be returned")
			}
			assertNoAzureSecret(t, err)
		})
		for _, b := range blank {
			t.Run("blank "+field+" "+strconv.Quote(b), func(t *testing.T) {
				t.Parallel()
				p, err := NewAzure(azureCreds(map[string]string{field: b}), nil)
				if !errors.Is(err, ErrAzureAPI) {
					t.Fatalf("err = %v, want ErrAzureAPI", err)
				}
				if p != nil {
					t.Fatal("a provider with a blank credential must not be returned")
				}
				assertNoAzureSecret(t, err)
			})
		}
	}
}

// TestAzureRejectsSingleCredential proves Azure refuses the single-value form the
// token providers use: it needs four named values and will not guess them from
// one.
func TestAzureRejectsSingleCredential(t *testing.T) {
	t.Parallel()

	p, err := NewAzure(NewSingleCredential(secrets.NewRedacted(azureClientSecret)), nil)
	if !errors.Is(err, ErrAzureAPI) {
		t.Fatalf("err = %v, want ErrAzureAPI", err)
	}
	if p != nil {
		t.Fatal("a single credential must not build an Azure provider")
	}
	assertNoAzureSecret(t, err)
}

// TestAzureProviderFormatRedacts is the leak gate on the struct itself: no fmt
// verb may print any credential field. Without the Format method, "%+v" walks the
// unexported fields by reflection and prints all four in full.
func TestAzureProviderFormatRedacts(t *testing.T) {
	t.Parallel()

	p, err := NewAzure(azureCreds(nil), nil)
	if err != nil {
		t.Fatalf("NewAzure: %v", err)
	}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
		out := fmt.Sprintf(verb, p)
		for _, secret := range []string{azureTenantID, azureClientID, azureClientSecret, azureSubscriptionID} {
			if strings.Contains(out, secret) {
				t.Errorf("%s of provider leaked a credential field: %q", verb, out)
			}
		}
	}
}

// TestAzureCredentialNeverAppearsInFailurePaths checks the error paths, which are
// where a credential or the bearer token most plausibly reaches a log.
func TestAzureCredentialNeverAppearsInFailurePaths(t *testing.T) {
	t.Parallel()
	api, provider := newAzureAPI(t)

	api.putStatus = http.StatusForbidden
	_, presentErr := provider.Present(context.Background(), azureRecord())

	api.putStatus = 0
	cleanup, err := provider.Present(context.Background(), azureRecord())
	if err != nil {
		t.Fatalf("Present: %v", err)
	}
	api.deleteStatus = http.StatusForbidden
	cleanupErr := cleanup(context.Background())

	for _, e := range []error{presentErr, cleanupErr} {
		if e == nil {
			t.Fatal("expected an error to inspect")
		}
		assertNoAzureSecret(t, e)
	}
}

// TestAzureNamedProviderThroughSeam proves the registry builds Azure from a named
// credential set, so a deployer selecting "azure" reaches this provider.
func TestAzureNamedProviderThroughSeam(t *testing.T) {
	t.Parallel()

	p, err := NewAPIProvider("azure", azureCreds(nil), nil)
	if err != nil {
		t.Fatalf("NewAPIProvider(azure): %v", err)
	}
	if p == nil || p.Name() != "azure" {
		t.Fatalf("provider = %v, want a provider named azure", p)
	}
}

// TestAzureErrorMessageTruncationKeepsValidUTF8 pins the bound applied to the
// API's own error text.
//
// The message is remote input cut at a fixed BYTE count, so a multi-byte rune
// straddling the boundary would leave a fragment that is not valid UTF-8, which
// the JSON log encoder downstream then mangles. The first assertion proves a
// NAIVE cut of this fixture would be invalid, so the fixture cannot quietly stop
// exercising the case it exists for.
func TestAzureErrorMessageTruncationKeepsValidUTF8(t *testing.T) {
	t.Parallel()

	// One byte of "世" sits before the bound and two after it.
	msg := strings.Repeat("a", maxAPIMessageBytes-1) + "世" + strings.Repeat("b", 50)
	if utf8.ValidString(msg[:maxAPIMessageBytes]) {
		t.Fatalf("fixture no longer splits a rune at the %d-byte cut", maxAPIMessageBytes)
	}

	raw, err := json.Marshal(map[string]any{"error": map[string]any{"code": "BadRequest", "message": msg}})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	e := azureError(http.StatusBadRequest, raw)
	if e == nil {
		t.Fatal("azureError returned nil")
	}
	if !utf8.ValidString(e.Error()) {
		t.Errorf("error text is not valid UTF-8: %q", e.Error())
	}
	if got := e.Error(); len(got) < maxAPIMessageBytes-utf8.UTFMax {
		t.Errorf("truncation discarded more than a partial rune: %d bytes", len(got))
	}
}

// assertNoAzureSecret fails if the client secret or the issued bearer token
// appears anywhere in err.
func assertNoAzureSecret(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		return
	}
	if strings.Contains(err.Error(), azureClientSecret) {
		t.Errorf("error leaked the client secret: %v", err)
	}
	if strings.Contains(err.Error(), azureAccessToken) {
		t.Errorf("error leaked the bearer token: %v", err)
	}
}
