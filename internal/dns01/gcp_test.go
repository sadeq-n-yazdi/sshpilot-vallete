package dns01

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/secrets"
)

// gcpChallengeValue is the value this process publishes. Like a real ACME digest
// it is bare base64url, so the quote-normalized form round-trips cleanly.
const gcpChallengeValue = "Z2NwY2hhbGxlbmdldmFsdWUtb25lLTQzLWNoYXJhY3Rlcg"

const (
	gcpTestProjectID   = "example-project"
	gcpTestClientEmail = "vallet-dns-DO-NOT-LEAK@example-project.iam.gserviceaccount.com"
	gcpFakeAccessToken = "ya29.fake-access-token-value"
)

// gcpTestKey holds the generated service account key and the artifacts a test
// needs from it: the redacted JSON credential, the PEM private-key body (a leak
// sentinel — it must never appear in any output), and the public key the fake
// token endpoint verifies the JWT assertion against.
type gcpTestKey struct {
	credential secrets.Redacted
	pemBody    string
	public     *rsa.PublicKey
}

func newGCPTestKey(t *testing.T) gcpTestKey {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal pkcs8: %v", err)
	}
	pemBody := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}))

	blob, err := json.Marshal(map[string]string{
		"type":         "service_account",
		"project_id":   gcpTestProjectID,
		"client_email": gcpTestClientEmail,
		"private_key":  pemBody,
		// Present in real keys and deliberately ignored by the provider, which uses
		// the constant token endpoint.
		"token_uri": "https://oauth2.googleapis.com/token",
	})
	if err != nil {
		t.Fatalf("marshal service account json: %v", err)
	}
	return gcpTestKey{credential: secrets.NewRedacted(string(blob)), pemBody: pemBody, public: &key.PublicKey}
}

// gcpZoneFixture is one managed zone the fake account holds.
type gcpZoneFixture struct {
	name       string
	dnsName    string
	visibility string
}

// gcpAPI is a local stand-in for the Google OAuth token endpoint and the Cloud
// DNS v1 API. No test contacts Google. The token handler VERIFIES the RS256
// assertion, so a broken signing path fails here rather than passing silently.
type gcpAPI struct {
	t      *testing.T
	public *rsa.PublicKey
	now    time.Time

	// requests records every method+path the provider issued (DNS paths only),
	// which is how the tests assert what the provider did NOT do.
	requests []string

	zones  []gcpZoneFixture
	rrsets map[string]gcpRRSet // keyed by fqdn (trailing dot), rrdatas stored quoted

	// changeStoresThenFails makes a change apply AND then answer a rejection: the
	// "written before the error" shape a nil cleanup would leak.
	changeStoresThenFails bool
	// changeFails rejects a change without applying it.
	changeFails bool
	// apiErrMessage overrides the message text of a DNS API rejection.
	apiErrMessage string
}

func newGCPAPI(t *testing.T) (*gcpAPI, Provider) {
	t.Helper()

	key := newGCPTestKey(t)
	api := &gcpAPI{
		t:      t,
		public: key.public,
		now:    time.Date(2026, 7, 24, 12, 0, 0, 0, time.UTC),
		zones:  []gcpZoneFixture{{name: "zone-example-com", dnsName: "example.com.", visibility: "public"}},
		rrsets: map[string]gcpRRSet{},
	}
	srv := httptest.NewServer(api)
	t.Cleanup(srv.Close)

	provider, err := NewGCP(NewSingleCredential(key.credential), srv.Client())
	if err != nil {
		t.Fatalf("NewGCP: %v", err)
	}
	gp := provider.(*gcpProvider)
	// The clock is pinned so the JWT iat/exp are deterministic and the fake can
	// assert the window.
	gp.now = func() time.Time { return api.now }
	// The API bases are constants by design, so the test rewrites the request host
	// in the transport instead of making the endpoints configurable.
	base, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse server url: %v", err)
	}
	gp.client = &http.Client{Transport: gcpRewriteHost{base: base, next: srv.Client().Transport}}
	return api, provider
}

// gcpRewriteHost redirects requests for the real Google hosts at the local fake,
// preserving the path so the fake routes on the real /token and /dns/v1 paths.
type gcpRewriteHost struct {
	base *url.URL
	next http.RoundTripper
}

func (r gcpRewriteHost) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	u := *req.URL
	u.Scheme = r.base.Scheme
	u.Host = r.base.Host
	clone.URL = &u
	clone.Host = u.Host
	next := r.next
	if next == nil {
		next = http.DefaultTransport
	}
	return next.RoundTrip(clone)
}

func (a *gcpAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/token":
		a.token(w, r)
	case strings.HasPrefix(r.URL.Path, "/dns/v1/projects/"):
		a.requests = append(a.requests, r.Method+" "+r.URL.Path+"?"+r.URL.RawQuery)
		a.dns(w, r)
	default:
		a.t.Errorf("unexpected request %s %s", r.Method, r.URL)
		http.Error(w, "unexpected", http.StatusNotFound)
	}
}

// token verifies the signed assertion and issues the fake access token. The
// verification is the load-bearing half of the JWT test: it fails if the
// signature, the claims or the encoding are wrong.
func (a *gcpAPI) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		a.t.Fatalf("parse token form: %v", err)
	}
	if got := r.Form.Get("grant_type"); got != gcpGrantType {
		a.t.Errorf("grant_type = %q, want %q", got, gcpGrantType)
	}
	if ct := r.Header.Get("Content-Type"); ct != "application/x-www-form-urlencoded" {
		a.t.Errorf("token Content-Type = %q, want form encoding", ct)
	}

	assertion := r.Form.Get("assertion")
	parts := strings.Split(assertion, ".")
	if len(parts) != 3 {
		a.t.Fatalf("assertion has %d segments, want 3", len(parts))
	}

	var header gcpJWTHeader
	a.decodeSegment(parts[0], &header)
	if header.Algorithm != "RS256" || header.Type != "JWT" {
		a.t.Errorf("jwt header = %+v, want RS256/JWT", header)
	}

	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		a.t.Fatalf("decode signature: %v", err)
	}
	if err := rsa.VerifyPKCS1v15(a.public, crypto.SHA256, digest[:], sig); err != nil {
		a.t.Fatalf("jwt signature does not verify: %v", err)
	}

	var claims gcpJWTClaims
	a.decodeSegment(parts[1], &claims)
	if claims.Issuer != gcpTestClientEmail {
		a.t.Errorf("iss = %q, want the client_email", claims.Issuer)
	}
	if claims.Audience != gcpTokenEndpoint {
		a.t.Errorf("aud = %q, want the constant token endpoint", claims.Audience)
	}
	if claims.Scope != gcpDNSScope {
		a.t.Errorf("scope = %q, want the clouddns scope", claims.Scope)
	}
	if claims.IssuedAt != a.now.Unix() {
		a.t.Errorf("iat = %d, want %d", claims.IssuedAt, a.now.Unix())
	}
	if claims.Expiry <= claims.IssuedAt {
		a.t.Errorf("exp %d not after iat %d", claims.Expiry, claims.IssuedAt)
	}

	a.write(w, http.StatusOK, fmt.Sprintf(`{"access_token":%q,"expires_in":3600,"token_type":"Bearer"}`, gcpFakeAccessToken))
}

func (a *gcpAPI) decodeSegment(seg string, out any) {
	a.t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		a.t.Fatalf("decode jwt segment: %v", err)
	}
	if err := json.Unmarshal(raw, out); err != nil {
		a.t.Fatalf("unmarshal jwt segment: %v", err)
	}
}

func (a *gcpAPI) dns(w http.ResponseWriter, r *http.Request) {
	if got := r.Header.Get("Authorization"); got != "Bearer "+gcpFakeAccessToken {
		a.t.Errorf("Authorization = %q, want the fake access token", got)
	}
	w.Header().Set("Content-Type", "application/json")

	rest := strings.TrimPrefix(r.URL.Path, "/dns/v1/projects/"+gcpTestProjectID+"/")
	switch {
	case r.Method == http.MethodGet && rest == "managedZones":
		a.listZones(w, r)
	case r.Method == http.MethodGet && strings.HasSuffix(rest, "/rrsets"):
		a.listRRSets(w, r)
	case r.Method == http.MethodPost && strings.HasSuffix(rest, "/changes"):
		a.createChange(w, r)
	default:
		a.t.Errorf("unexpected dns request %s %s", r.Method, r.URL)
		a.write(w, http.StatusNotFound, `{"error":{"message":"not found"}}`)
	}
}

func (a *gcpAPI) listZones(w http.ResponseWriter, r *http.Request) {
	want := r.URL.Query().Get("dnsName")
	var out gcpManagedZonesListResponse
	for _, z := range a.zones {
		if z.dnsName != want {
			continue
		}
		out.ManagedZones = append(out.ManagedZones, struct {
			Name       string `json:"name"`
			DNSName    string `json:"dnsName"`
			Visibility string `json:"visibility"`
		}{Name: z.name, DNSName: z.dnsName, Visibility: z.visibility})
	}
	body, err := json.Marshal(out)
	if err != nil {
		a.t.Fatalf("marshal zones: %v", err)
	}
	a.write(w, http.StatusOK, string(body))
}

func (a *gcpAPI) listRRSets(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	var out gcpResourceRecordSetsListResponse
	if set, ok := a.rrsets[name]; ok {
		out.RRSets = []gcpRRSet{set}
	}
	body, err := json.Marshal(out)
	if err != nil {
		a.t.Fatalf("marshal rrsets: %v", err)
	}
	a.write(w, http.StatusOK, string(body))
}

func (a *gcpAPI) createChange(w http.ResponseWriter, r *http.Request) {
	var change gcpChange
	if err := json.NewDecoder(r.Body).Decode(&change); err != nil {
		a.t.Fatalf("decode change: %v", err)
	}
	if a.changeFails {
		a.writeErr(w)
		return
	}
	for _, del := range change.Deletions {
		delete(a.rrsets, del.Name)
	}
	for _, add := range change.Additions {
		a.rrsets[add.Name] = add
	}
	if a.changeStoresThenFails {
		a.writeErr(w)
		return
	}
	a.write(w, http.StatusOK, `{"status":"pending"}`)
}

func (a *gcpAPI) writeErr(w http.ResponseWriter) {
	msg := a.apiErrMessage
	if msg == "" {
		msg = "quota exceeded"
	}
	body, err := json.Marshal(map[string]any{"error": map[string]any{"message": msg}})
	if err != nil {
		a.t.Fatalf("marshal error body: %v", err)
	}
	a.write(w, http.StatusBadRequest, string(body))
}

func (a *gcpAPI) write(w http.ResponseWriter, status int, body string) {
	w.WriteHeader(status)
	if _, err := w.Write([]byte(body)); err != nil {
		a.t.Errorf("write response: %v", err)
	}
}

// destructive returns the change requests the provider issued. A cleanup on a
// no-op path must issue none.
func (a *gcpAPI) destructive() []string {
	var out []string
	for _, req := range a.requests {
		if strings.HasPrefix(req, http.MethodPost+" ") && strings.Contains(req, "/changes") {
			out = append(out, req)
		}
	}
	return out
}

func TestGCPPresentPublishesAndCleansUp(t *testing.T) {
	api, provider := newGCPAPI(t)
	rec := Record{Name: ChallengeRecordName("vallet.example.com"), Value: gcpChallengeValue}

	cleanup, err := provider.Present(t.Context(), rec)
	if err != nil {
		t.Fatalf("Present: %v", err)
	}
	if cleanup == nil {
		t.Fatal("Present returned a nil cleanup")
	}

	set, ok := api.rrsets["_acme-challenge.vallet.example.com."]
	if !ok {
		t.Fatalf("no rrset at the fqdn; store = %v", api.rrsets)
	}
	if !slices.Equal(set.Rrdatas, []string{quoteTXT(gcpChallengeValue)}) {
		t.Errorf("stored rrdatas = %v, want the quoted challenge value", set.Rrdatas)
	}
	if set.TTL != gcpChallengeTTL {
		t.Errorf("stored ttl = %d, want %d", set.TTL, gcpChallengeTTL)
	}

	if err := cleanup(t.Context()); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if _, ok := api.rrsets["_acme-challenge.vallet.example.com."]; ok {
		t.Errorf("rrset survived cleanup: %v", api.rrsets)
	}
}

func TestGCPCleanupIsIdempotent(t *testing.T) {
	api, provider := newGCPAPI(t)
	rec := Record{Name: ChallengeRecordName("example.com"), Value: gcpChallengeValue}

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
		t.Errorf("second cleanup issued %d changes, want none beyond the first %d", got-before, before)
	}
}

// TestGCPCleanupAfterStoredButFailedPublish pins the seam's non-nil-on-failure
// contract in the case that most needs it: the change APPLIED and then errored,
// so the record is standing and only the returned cleanup can withdraw it.
func TestGCPCleanupAfterStoredButFailedPublish(t *testing.T) {
	api, provider := newGCPAPI(t)
	api.changeStoresThenFails = true

	rec := Record{Name: ChallengeRecordName("example.com"), Value: gcpChallengeValue}
	cleanup, err := provider.Present(t.Context(), rec)
	if err == nil {
		t.Fatal("Present succeeded, want the API rejection")
	}
	if cleanup == nil {
		t.Fatal("Present returned a nil cleanup though the record was written before the error")
	}
	if _, ok := api.rrsets["_acme-challenge.example.com."]; !ok {
		t.Fatal("fixture: the change did not store the record before failing")
	}

	api.changeStoresThenFails = false
	if err := cleanup(t.Context()); err != nil {
		t.Fatalf("cleanup after a stored-but-failed publish: %v", err)
	}
	if _, ok := api.rrsets["_acme-challenge.example.com."]; ok {
		t.Error("cleanup did not remove the record the failed publish left standing")
	}
}

// TestGCPCleanupAfterUnappliedPublishRemovesNothing is the other failure shape:
// the publish never applied, so the returned cleanup must find nothing, issue no
// change, and leave an unrelated value at the same name untouched.
func TestGCPCleanupAfterUnappliedPublishRemovesNothing(t *testing.T) {
	api, provider := newGCPAPI(t)
	api.rrsets["_acme-challenge.example.com."] = gcpRRSet{
		Name: "_acme-challenge.example.com.", Type: "TXT", TTL: 600, Rrdatas: []string{quoteTXT("someone-elses-value")},
	}
	api.zones = nil // force zone discovery to refuse, so no change is issued

	rec := Record{Name: ChallengeRecordName("example.com"), Value: gcpChallengeValue}
	cleanup, err := provider.Present(t.Context(), rec)
	if err == nil {
		t.Fatal("Present succeeded, want the refusal")
	}
	if cleanup != nil {
		t.Fatal("Present returned a cleanup though nothing was created")
	}
	if got := api.destructive(); len(got) != 0 {
		t.Errorf("a refused publish issued changes %v, want none", got)
	}
	if set := api.rrsets["_acme-challenge.example.com."]; !slices.Equal(set.Rrdatas, []string{quoteTXT("someone-elses-value")}) {
		t.Errorf("the unrelated value was disturbed: %v", set.Rrdatas)
	}
}

// TestGCPWildcardCleanupRemovesOnlyItsOwnValue is the security-critical scoping
// test: a certificate covering example.com and *.example.com puts TWO TXT values
// at one name; cleanup must remove ours and keep the sibling and an operator
// value, never delete the whole rrset.
func TestGCPWildcardCleanupRemovesOnlyItsOwnValue(t *testing.T) {
	api, provider := newGCPAPI(t)

	const siblingValue = "c2libGluZ3dpbGRjYXJkY2hhbGxlbmdldmFsdWUtdHdvLTQz"
	const operatorValue = "v=spf1 -all"
	api.rrsets["_acme-challenge.example.com."] = gcpRRSet{
		Name: "_acme-challenge.example.com.", Type: "TXT", TTL: 900,
		Rrdatas: []string{quoteTXT(siblingValue), quoteTXT(operatorValue)},
	}

	rec := Record{Name: ChallengeRecordName("*.example.com"), Value: gcpChallengeValue}
	if rec.Name != "_acme-challenge.example.com" {
		t.Fatalf("fixture: challenge name = %q", rec.Name)
	}

	cleanup, err := provider.Present(t.Context(), rec)
	if err != nil {
		t.Fatalf("Present: %v", err)
	}
	set := api.rrsets["_acme-challenge.example.com."]
	if len(set.Rrdatas) != 3 || !slices.Contains(set.Rrdatas, quoteTXT(gcpChallengeValue)) ||
		!slices.Contains(set.Rrdatas, quoteTXT(siblingValue)) || !slices.Contains(set.Rrdatas, quoteTXT(operatorValue)) {
		t.Fatalf("after publish rrdatas = %v, want ours merged with both pre-existing values", set.Rrdatas)
	}
	if set.TTL != 900 {
		t.Errorf("merge rewrote the operator's TTL to %d, want 900 preserved", set.TTL)
	}

	if err := cleanup(t.Context()); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	survivor, ok := api.rrsets["_acme-challenge.example.com."]
	if !ok {
		t.Fatal("cleanup deleted the whole rrset, discarding the sibling challenge and the operator record")
	}
	if !slices.Contains(survivor.Rrdatas, quoteTXT(siblingValue)) || !slices.Contains(survivor.Rrdatas, quoteTXT(operatorValue)) {
		t.Errorf("survivors = %v, want the sibling and operator values intact", survivor.Rrdatas)
	}
	if slices.Contains(survivor.Rrdatas, quoteTXT(gcpChallengeValue)) {
		t.Errorf("cleanup left our own value behind: %v", survivor.Rrdatas)
	}
}

func TestGCPPresentSurfacesAPIRejection(t *testing.T) {
	api, provider := newGCPAPI(t)
	api.changeFails = true
	api.apiErrMessage = "insufficient permissions on managed zone"

	rec := Record{Name: ChallengeRecordName("example.com"), Value: gcpChallengeValue}
	_, err := provider.Present(t.Context(), rec)
	if err == nil {
		t.Fatal("Present succeeded, want the API rejection")
	}
	if !strings.Contains(err.Error(), "400") || !strings.Contains(err.Error(), "insufficient permissions") {
		t.Errorf("error %q does not carry the API fault", err)
	}
}

// TestGCPAmbiguousZoneRefused pins the refusal when two public zones share a DNS
// name: writing to the wrong one is accepted by the API and never seen by the CA.
func TestGCPAmbiguousZoneRefused(t *testing.T) {
	api, provider := newGCPAPI(t)
	api.zones = []gcpZoneFixture{
		{name: "zone-a", dnsName: "example.com.", visibility: "public"},
		{name: "zone-b", dnsName: "example.com.", visibility: "public"},
	}

	rec := Record{Name: ChallengeRecordName("vallet.example.com"), Value: gcpChallengeValue}
	_, err := provider.Present(t.Context(), rec)
	if !errors.Is(err, ErrGCPAmbiguousZone) {
		t.Errorf("err = %v, want ErrGCPAmbiguousZone", err)
	}
	if len(api.destructive()) != 0 {
		t.Error("an ambiguous-zone refusal issued a change")
	}
}

// TestGCPPrivateZoneIgnored proves a private zone is not selected: the CA queries
// the public internet and a private zone is never seen.
func TestGCPPrivateZoneIgnored(t *testing.T) {
	api, provider := newGCPAPI(t)
	api.zones = []gcpZoneFixture{{name: "zone-private", dnsName: "example.com.", visibility: "private"}}

	rec := Record{Name: ChallengeRecordName("vallet.example.com"), Value: gcpChallengeValue}
	_, err := provider.Present(t.Context(), rec)
	if err == nil || errors.Is(err, ErrGCPAmbiguousZone) {
		t.Fatalf("err = %v, want a plain no-zone refusal", err)
	}
	if !strings.Contains(err.Error(), "no public managed zone") {
		t.Errorf("error %q does not name the missing public zone", err)
	}
}

func TestGCPNoZoneRefuses(t *testing.T) {
	api, provider := newGCPAPI(t)
	api.zones = nil

	rec := Record{Name: ChallengeRecordName("vallet.example.com"), Value: gcpChallengeValue}
	_, err := provider.Present(t.Context(), rec)
	if err == nil {
		t.Fatal("Present succeeded with no matching zone")
	}
	if !strings.Contains(err.Error(), "no public managed zone") {
		t.Errorf("error %q does not name the missing zone", err)
	}
	if len(api.destructive()) != 0 {
		t.Error("a failed zone lookup issued a change")
	}
}

// TestGCPPrefersTheMostSpecificZone pins the walk order: writing to the parent of
// a delegated subdomain puts the record in a zone that is not authoritative.
func TestGCPPrefersTheMostSpecificZone(t *testing.T) {
	api, provider := newGCPAPI(t)
	api.zones = []gcpZoneFixture{
		{name: "zone-example-com", dnsName: "example.com.", visibility: "public"},
		{name: "zone-eu-example-com", dnsName: "eu.example.com.", visibility: "public"},
	}

	rec := Record{Name: ChallengeRecordName("vallet.eu.example.com"), Value: gcpChallengeValue}
	if _, err := provider.Present(t.Context(), rec); err != nil {
		t.Fatalf("Present: %v", err)
	}
	var change string
	for _, req := range api.requests {
		if strings.Contains(req, "/changes") {
			change = req
		}
	}
	if !strings.Contains(change, "zone-eu-example-com") {
		t.Errorf("change went to %q, want the delegated eu.example.com zone", change)
	}
}

func TestGCPRefusesAMalformedZoneCandidate(t *testing.T) {
	api, provider := newGCPAPI(t)

	rec := Record{Name: "_acme-challenge.ev/il.com", Value: gcpChallengeValue}
	_, err := provider.Present(t.Context(), rec)
	if err == nil {
		t.Fatal("Present succeeded for a malformed zone candidate")
	}
	if !strings.Contains(err.Error(), "malformed zone candidate") {
		t.Errorf("error %q is not the refusal", err)
	}
	for _, req := range api.requests {
		if strings.HasPrefix(req, "GET /dns/v1/projects/"+gcpTestProjectID+"/managedZones?") {
			t.Errorf("malformed candidate reached the zone lookup: %q", req)
		}
	}
}

// TestGCPRejectsMalformedServiceAccountKey is the negative construction path: a
// key that is not valid JSON, or missing fields, or carrying a non-RSA/non-PEM
// key, is refused at startup with a credential-free error.
func TestGCPRejectsMalformedServiceAccountKey(t *testing.T) {
	t.Parallel()

	good := newGCPTestKey(t)
	tests := []struct{ name, cred string }{
		{"not json", "this is not json"},
		{"empty json object", "{}"},
		{"missing private key", `{"project_id":"example-project","client_email":"a@b.iam.gserviceaccount.com"}`},
		{"private key not pem", `{"project_id":"example-project","client_email":"a@b.iam.gserviceaccount.com","private_key":"not-a-pem-block"}`},
		{"bad project id", `{"project_id":"X","client_email":"a@b.iam.gserviceaccount.com","private_key":"` + strings.ReplaceAll(good.pemBody, "\n", `\n`) + `"}`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p, err := NewGCP(NewSingleCredential(secrets.NewRedacted(tc.cred)), nil)
			if !errors.Is(err, ErrGCPAPI) {
				t.Fatalf("err = %v, want ErrGCPAPI", err)
			}
			if p != nil {
				t.Fatal("a provider with an unusable key must not be returned")
			}
			if strings.Contains(err.Error(), "PRIVATE KEY") || strings.Contains(err.Error(), good.pemBody) {
				t.Error("error echoed the credential")
			}
		})
	}
}

func TestGCPMissingCredentialRefused(t *testing.T) {
	t.Parallel()

	if _, err := NewGCP(Credentials{}, nil); !errors.Is(err, ErrGCPAPI) {
		t.Error("NewGCP with an empty set succeeded, want a refusal")
	}
	if _, err := NewGCP(NewSingleCredential(secrets.NewRedacted("   ")), nil); !errors.Is(err, ErrGCPAPI) {
		t.Error("NewGCP with a whitespace-only credential succeeded, want a refusal")
	}
}

// TestGCPProviderNeverRevealsItsKey covers the mechanism and the artifact: fmt
// walks unexported struct fields by reflection and does NOT call
// secrets.Redacted's redaction methods, so without Format on the containing type
// "%+v" would print the JSON key — including the RSA private key — in full.
func TestGCPProviderNeverRevealsItsKey(t *testing.T) {
	key := newGCPTestKey(t)
	provider, err := NewGCP(NewSingleCredential(key.credential), nil)
	if err != nil {
		t.Fatalf("NewGCP: %v", err)
	}

	encoded, err := json.Marshal(provider)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	renders := map[string]string{
		"%v": fmt.Sprintf("%v", provider), "%+v": fmt.Sprintf("%+v", provider),
		"%#v": fmt.Sprintf("%#v", provider), "%s": fmt.Sprintf("%s", provider),
		"json": string(encoded), "name": provider.Name(),
	}
	for label, rendered := range renders {
		if strings.Contains(rendered, key.pemBody) || strings.Contains(rendered, "PRIVATE KEY") ||
			strings.Contains(rendered, gcpTestClientEmail) {
			t.Errorf("%s leaked the credential: %s", label, rendered)
		}
	}
	if !strings.Contains(fmt.Sprintf("%+v", provider), "[REDACTED]") {
		t.Error("provider does not render the redaction marker")
	}
}

// TestGCPErrorNeverCarriesTheKey drives a failing token exchange and asserts the
// error names the fault but not the credential.
func TestGCPErrorNeverCarriesTheKey(t *testing.T) {
	key := newGCPTestKey(t)
	// A server that rejects every token request, so accessToken fails inside
	// Present. No zone or DNS call is reached.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"account disabled"}`))
	}))
	t.Cleanup(srv.Close)

	provider, err := NewGCP(NewSingleCredential(key.credential), srv.Client())
	if err != nil {
		t.Fatalf("NewGCP: %v", err)
	}
	base, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	provider.(*gcpProvider).client = &http.Client{Transport: gcpRewriteHost{base: base, next: srv.Client().Transport}}

	_, err = provider.Present(t.Context(), Record{Name: ChallengeRecordName("example.com"), Value: gcpChallengeValue})
	if err == nil {
		t.Fatal("Present succeeded against a token endpoint that rejects everything")
	}
	if !strings.Contains(err.Error(), "invalid_grant") {
		t.Errorf("error %q does not name the token fault", err)
	}
	if strings.Contains(err.Error(), key.pemBody) || strings.Contains(err.Error(), "PRIVATE KEY") ||
		strings.Contains(err.Error(), gcpTestClientEmail) {
		t.Error("error carried the credential")
	}
}

func TestNewAPIProviderBuildsGCP(t *testing.T) {
	key := newGCPTestKey(t)
	provider, err := NewAPIProvider("gcp", NewSingleCredential(key.credential), nil)
	if err != nil {
		t.Fatalf("NewAPIProvider: %v", err)
	}
	if got := provider.Name(); got != "gcp" {
		t.Errorf("Name() = %q, want %q", got, "gcp")
	}
}

// TestGCPDoesNotPollForPropagation pins the seam's division of labor: the solver
// polls the authoritative nameservers, so a provider must not read the record
// back after writing it.
func TestGCPDoesNotPollForPropagation(t *testing.T) {
	api, provider := newGCPAPI(t)
	rec := Record{Name: ChallengeRecordName("example.com"), Value: gcpChallengeValue}

	if _, err := provider.Present(context.Background(), rec); err != nil {
		t.Fatalf("Present: %v", err)
	}
	var sawChange bool
	for _, req := range api.requests {
		if strings.Contains(req, "/changes") {
			sawChange = true
		}
		if sawChange && strings.Contains(req, "/rrsets?") {
			t.Errorf("Present read the rrset back after writing (%q), which is a propagation poll", req)
		}
	}
}
