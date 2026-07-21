package dns01

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/secrets"
)

// testToken is the credential every test in this file hands the provider. It is
// a distinctive string so a leak into any output is unmistakable, and it is
// never the ONLY thing asserted — see TestCloudflareTokenIsRevealedExactlyOnce
// for the mechanism-level check that does not depend on this value.
const testToken = "cf-token-DO-NOT-LEAK-8f3a91c2"

// cloudflareAPI is a local stand-in for the Cloudflare v4 API. No test in this
// package contacts Cloudflare.
type cloudflareAPI struct {
	t *testing.T

	// requests records every method+path the provider issued, which is how the
	// tests assert what the provider did NOT do — no zone-wide record listing,
	// no delete addressed by name.
	requests []string

	// recordID is handed out by create and is the only ID delete will accept.
	recordID string
	// created holds the body of the last create, so a test can check the record
	// the provider asked for.
	created map[string]any

	// deleteStatus overrides the response code for a delete, so the
	// already-gone and hard-failure paths can both be driven.
	deleteStatus int
	// createFails makes the create call return an API-level rejection.
	createFails bool
	// createErrMessage overrides the message text in the rejection body, so a
	// test can drive remote-controlled message content through the error path.
	createErrMessage string
}

func newCloudflareAPI(t *testing.T) (*cloudflareAPI, Provider) {
	t.Helper()

	api := &cloudflareAPI{t: t, recordID: "rec-abc123", deleteStatus: http.StatusOK}
	srv := httptest.NewServer(api)
	t.Cleanup(srv.Close)

	provider, err := NewCloudflare(secrets.NewRedacted(testToken), srv.Client())
	if err != nil {
		t.Fatalf("NewCloudflare: %v", err)
	}
	// The API base is a constant by design, so the test rewrites the request
	// host in the transport instead of making the endpoint configurable —
	// making it configurable to suit a test would be exactly the setting that
	// lets a misconfiguration point the token at another host.
	provider.(*cloudflareProvider).client = &http.Client{Transport: rewriteHost{srv.URL, srv.Client().Transport}}
	return api, provider
}

// rewriteHost redirects requests for the real API base at the local fake.
type rewriteHost struct {
	base string
	next http.RoundTripper
}

func (r rewriteHost) RoundTrip(req *http.Request) (*http.Response, error) {
	target := r.base + strings.TrimPrefix(req.URL.String(), cloudflareAPIBase)
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

func (a *cloudflareAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.requests = append(a.requests, r.Method+" "+r.URL.Path+"?"+r.URL.RawQuery)

	if got := r.Header.Get("Authorization"); got != "Bearer "+testToken {
		a.t.Errorf("Authorization header = %q, want the bearer token", got)
	}

	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/zones":
		if r.URL.Query().Get("name") != "example.com" {
			a.write(w, http.StatusOK, `{"success":true,"result":[]}`)
			return
		}
		a.write(w, http.StatusOK, `{"success":true,"result":[{"id":"zone-1"}]}`)

	case r.Method == http.MethodPost && r.URL.Path == "/zones/zone-1/dns_records":
		if a.createFails {
			msg := a.createErrMessage
			if msg == "" {
				msg = "quota exceeded"
			}
			body, err := json.Marshal(map[string]any{
				"success": false,
				"errors":  []map[string]any{{"code": 9999, "message": msg}},
			})
			if err != nil {
				a.t.Fatalf("marshal error body: %v", err)
			}
			a.write(w, http.StatusBadRequest, string(body))
			return
		}
		_ = json.NewDecoder(r.Body).Decode(&a.created)
		a.write(w, http.StatusOK, fmt.Sprintf(`{"success":true,"result":{"id":%q}}`, a.recordID))

	case r.Method == http.MethodDelete && r.URL.Path == "/zones/zone-1/dns_records/"+a.recordID:
		if a.deleteStatus != http.StatusOK {
			a.write(w, a.deleteStatus, `{"success":false,"errors":[{"code":1000,"message":"nope"}]}`)
			return
		}
		a.write(w, http.StatusOK, fmt.Sprintf(`{"success":true,"result":{"id":%q}}`, a.recordID))

	default:
		a.t.Errorf("unexpected request %s %s", r.Method, r.URL)
		a.write(w, http.StatusNotFound, `{"success":false,"errors":[]}`)
	}
}

func (a *cloudflareAPI) write(w http.ResponseWriter, status int, body string) {
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
}

func testRecord() Record {
	return Record{Name: "_acme-challenge.vallet.example.com", Value: "digest-value"}
}

// TestCloudflareCreatesAndDeletesTheChallengeRecord is the happy path: the
// record is created with the right type, name and value, and the cleanup
// removes it.
func TestCloudflareCreatesAndDeletesTheChallengeRecord(t *testing.T) {
	api, provider := newCloudflareAPI(t)

	cleanup, err := provider.Present(t.Context(), testRecord())
	if err != nil {
		t.Fatalf("Present: %v", err)
	}

	for field, want := range map[string]any{
		"type":    "TXT",
		"name":    "_acme-challenge.vallet.example.com",
		"content": "digest-value",
	} {
		if got := api.created[field]; got != want {
			t.Errorf("created record %s = %v, want %v", field, got, want)
		}
	}

	if err := cleanup(t.Context()); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if !slicesContains(api.requests, "DELETE /zones/zone-1/dns_records/rec-abc123?") {
		t.Errorf("cleanup did not delete the created record; requests: %v", api.requests)
	}
}

// TestCloudflareDeletesOnlyTheRecordItCreated is the scoping test.
//
// The guarantee is structural: the cleanup closure captures the record ID the
// create call returned, so there is no code path from a record NAME to a set of
// records to delete. This asserts the observable consequence — the provider
// never issues a listing or a search before deleting, so it cannot discover,
// and therefore cannot destroy, a record it did not create. A delete-by-name
// implementation would have to list first, and would fail here.
func TestCloudflareDeletesOnlyTheRecordItCreated(t *testing.T) {
	api, provider := newCloudflareAPI(t)

	cleanup, err := provider.Present(t.Context(), testRecord())
	if err != nil {
		t.Fatalf("Present: %v", err)
	}
	before := len(api.requests)
	if err := cleanup(t.Context()); err != nil {
		t.Fatalf("cleanup: %v", err)
	}

	cleanupRequests := api.requests[before:]
	if len(cleanupRequests) != 1 {
		t.Fatalf("cleanup made %d requests, want exactly one delete: %v",
			len(cleanupRequests), cleanupRequests)
	}
	if !strings.HasPrefix(cleanupRequests[0], "DELETE /zones/zone-1/dns_records/rec-abc123") {
		t.Errorf("cleanup request = %q; a lookup before deleting would mean the "+
			"provider can address records it did not create", cleanupRequests[0])
	}
}

// TestCloudflareCleanupIsIdempotent proves an already-removed record is not an
// error. Cleanup runs on retry and shutdown paths and may run twice; treating
// "already gone" as a failure would make a correct end state look like a leak.
func TestCloudflareCleanupIsIdempotent(t *testing.T) {
	api, provider := newCloudflareAPI(t)

	cleanup, err := provider.Present(t.Context(), testRecord())
	if err != nil {
		t.Fatalf("Present: %v", err)
	}

	api.deleteStatus = http.StatusNotFound
	if err := cleanup(t.Context()); err != nil {
		t.Errorf("cleanup of an already-removed record: %v, want nil", err)
	}
}

// TestCloudflareTokenNeverAppearsInOutput checks every rendering path a
// credential could escape through.
//
// This is the artifact-level half of the token-secrecy assertion; the
// mechanism-level half is the next test, which does not depend on the token
// having a recognizable value.
func TestCloudflareTokenNeverAppearsInOutput(t *testing.T) {
	api, provider := newCloudflareAPI(t)
	api.createFails = true

	_, err := provider.Present(t.Context(), testRecord())
	if err == nil {
		t.Fatal("Present succeeded against a failing api")
	}

	encoded, marshalErr := json.Marshal(provider)
	if marshalErr != nil {
		t.Fatalf("json.Marshal: %v", marshalErr)
	}

	for name, rendered := range map[string]string{
		"error":     err.Error(),
		"%v":        fmt.Sprintf("%v", provider),
		"%+v":       fmt.Sprintf("%+v", provider),
		"%#v":       fmt.Sprintf("%#v", provider),
		"%s":        fmt.Sprintf("%s", provider),
		"json":      string(encoded),
		"name":      provider.Name(),
		"error %+v": fmt.Sprintf("%+v", err),
	} {
		if strings.Contains(rendered, testToken) {
			t.Errorf("token leaked through %s: %s", name, rendered)
		}
	}
}

// TestCloudflareTokenIsRevealedExactlyOnce asserts the MECHANISM rather than
// the artifact.
//
// A test that greps one rendered string for one sample token proves only that
// the paths it happened to exercise are clean today. The property that actually
// holds the guarantee is that the plaintext token is unwrapped in exactly one
// place in the package — inside the function that writes the Authorization
// header — so no other code can put it anywhere. This pins that by reading the
// package's own source: a second Reveal call, wherever it is added and whatever
// it does with the value, fails this test.
func TestCloudflareTokenIsRevealedExactlyOnce(t *testing.T) {
	t.Parallel()

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}

	reveals := map[string]int{}
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(filepath.Clean(name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if n := strings.Count(string(src), ".Reveal()"); n > 0 {
			reveals[name] = n
		}
	}

	// One Reveal per provider file, and no Reveal anywhere else in the package.
	//
	//   - cloudflare.go: in do, where the token is written into the
	//     Authorization header. The constructor's emptiness check deliberately
	//     compares the wrapped value against "" rather than revealing it, so no
	//     second site exists.
	//   - route53.go: in splitAWSCredential, which is the single place the
	//     packed "keyID:secret" pair is unwrapped. It is called from the
	//     constructor (to fail a malformed credential at startup) and from do
	//     (to sign), but there is still exactly one line of source that can
	//     produce plaintext, which is the property this test defends.
	//   - digitalocean.go: in do, where the bearer token is written into the
	//     Authorization header. Its constructor's emptiness check compares the
	//     wrapped value against "" for the same reason Cloudflare's does.
	//   - dnsimple.go: in do, where the bearer token is written into the
	//     Authorization header. Its constructor's emptiness check compares the
	//     wrapped value against "" for the same reason Cloudflare's does.
	//   - gandi.go: in do, where the bearer PAT is written into the
	//   - arvancloud.go: in do, where the API key is written into the
	//     Authorization header. Its constructor's emptiness check compares the
	//     wrapped value against "" for the same reason Cloudflare's does.
	//
	// Any other file, or a second site in any of these, means a new path to
	// plaintext and must be justified by editing this list.
	want := map[string]int{
		"cloudflare.go": 1, "route53.go": 1, "digitalocean.go": 1, "dnsimple.go": 1,
		"gandi.go": 1, "arvancloud.go": 1,
	}
	if !maps.Equal(reveals, want) {
		t.Errorf("Reveal() call sites = %v, want %v: the plaintext credential must "+
			"be unwrapped only where it is written into the outbound request", reveals, want)
	}
}

// TestCloudflareRefusesAnEmptyToken proves the provider will not start without
// a credential. Starting without one would make every issuance attempt fail at
// the API with a 401, which reads like a Cloudflare outage rather than like the
// unresolved secret reference it is.
func TestCloudflareRefusesAnEmptyToken(t *testing.T) {
	t.Parallel()

	if _, err := NewCloudflare(secrets.NewRedacted(""), nil); !errors.Is(err, ErrCloudflareAPI) {
		t.Errorf("NewCloudflare with an empty token: %v, want ErrCloudflareAPI", err)
	}
}

// TestUnsupportedProviderIsRefused proves the registry fails closed. A provider
// name this build does not implement must not fall through to another
// provider's credentials or to a different challenge type.
func TestUnsupportedProviderIsRefused(t *testing.T) {
	t.Parallel()

	// Names are chosen to stay unimplemented as E6-E16 land providers, plus
	// the two shapes that must never be accepted: the empty name, and a
	// correct name in the wrong case. Matching is exact, so "CLOUDFLARE" and
	// "ROUTE53" are refusals rather than case-insensitive hits.
	for _, name := range []string{"ovh", "rfc2136", "", "CLOUDFLARE", "ROUTE53"} {
		if _, err := NewAPIProvider(name, secrets.NewRedacted(testToken), nil); !errors.Is(err, ErrUnsupportedProvider) {
			t.Errorf("NewAPIProvider(%q) = %v, want ErrUnsupportedProvider", name, err)
		}
	}
}

func slicesContains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

// TestCloudflareErrorMessageTruncationKeepsValidUTF8 pins the bound applied to
// the API's own error text.
//
// The message is remote input cut at a fixed BYTE count, so a multi-byte rune
// straddling the boundary would leave a fragment that is not valid UTF-8. That
// reaches the JSON log encoder, which mangles it, so a party choosing message
// lengths could corrupt this server's log encoding.
//
// The first assertion proves a NAIVE cut of this fixture would be invalid. It
// is not decoration: an earlier fix for this same defect shipped with a test
// whose hand-computed offset landed on a character boundary, so the test passed
// against unfixed code. Without this precondition the fixture could quietly
// stop exercising the case it exists for.
func TestCloudflareErrorMessageTruncationKeepsValidUTF8(t *testing.T) {
	api, provider := newCloudflareAPI(t)
	api.createFails = true
	// One byte of "世" sits before the 200-byte bound and two after it.
	api.createErrMessage = strings.Repeat("a", maxAPIMessageBytes-1) + "世" + strings.Repeat("b", 50)

	if utf8.ValidString(api.createErrMessage[:maxAPIMessageBytes]) {
		t.Fatalf("fixture no longer splits a rune at the %d-byte cut", maxAPIMessageBytes)
	}

	_, err := provider.Present(t.Context(), Record{
		Name:  ChallengeRecordName("example.com"),
		Value: "challenge-value",
	})
	if err == nil {
		t.Fatal("Present succeeded, want the API rejection")
	}
	if !utf8.ValidString(err.Error()) {
		t.Errorf("error text is not valid UTF-8: %q", err.Error())
	}
	// The repair must cost at most the bytes a partial rune can be, so the
	// diagnostic is not silently gutted.
	if got := err.Error(); len(got) < maxAPIMessageBytes-utf8.UTFMax {
		t.Errorf("truncation discarded more than a partial rune: %d bytes", len(got))
	}
}

// TestCloudflareZoneLookupEscapesTheNameParameter pins that the zone-lookup
// query parameter is encoded rather than concatenated.
//
// A candidate containing "&" would otherwise split the query into extra
// parameters, and one containing "#" would truncate it — either way the zone
// lookup is answered for a name nobody asked about, and the challenge record
// could be written into the wrong zone.
//
// The assertion is that the parameter DECODES BACK to the intended name. That
// is derived independently, from the record name the test itself supplied, and
// not from anything the provider computed.
func TestCloudflareZoneLookupEscapesTheNameParameter(t *testing.T) {
	var gotNames []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/zones" {
			// r.URL.Query() decodes; a correctly encoded "&" survives as part
			// of the single name value, a raw one becomes a separate parameter.
			gotNames = append(gotNames, r.URL.Query().Get("name"))
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte(`{"success":true,"result":[]}`)); err != nil {
			t.Errorf("write: %v", err)
		}
	}))
	t.Cleanup(srv.Close)

	provider, err := NewCloudflare(secrets.NewRedacted(testToken), srv.Client())
	if err != nil {
		t.Fatalf("NewCloudflare: %v", err)
	}
	provider.(*cloudflareProvider).client = &http.Client{
		Transport: rewriteHost{srv.URL, srv.Client().Transport},
	}

	// The zone walk strips the leftmost label, so this candidate is the one the
	// lookup asks about.
	const hostile = "evil&status=inactive.example.com"
	_, _ = provider.Present(t.Context(), Record{
		Name:  ChallengeRecordName(hostile),
		Value: "challenge-value",
	})

	if len(gotNames) == 0 {
		t.Fatal("no zone lookup was issued")
	}
	if gotNames[0] != hostile {
		t.Errorf("name parameter decoded to %q, want %q: an unescaped %q splits "+
			"the query into separate parameters", gotNames[0], hostile, "&")
	}
}
