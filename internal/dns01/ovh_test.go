package dns01

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/secrets"
)

// The credential fields every test in this file hands the provider. Each is a
// distinctive string so a leak into any output is unmistakable. ovhAppSecret is
// the field OVH NEVER transmits — it is only ever the SHA-1 signing key — so it
// is the one the non-leak tests target.
const (
	ovhAppKey      = "ovh-app-key-PUBLIC-abc123"
	ovhAppSecret   = "ovh-app-secret-DO-NOT-LEAK-9f31ab7c"
	ovhConsumerKey = "ovh-consumer-key-PUBLIC-def456"
)

// ovhServerTime is the unix time the fake's /auth/time reports. It is far from
// any plausible local clock so the delta-adjustment test can prove the provider
// used SERVER time rather than its own.
const ovhServerTime int64 = 1_700_000_000

// ovhChallenge is this process's published digest, and ovhSibling is the OTHER
// challenge of a wildcard order: a different digest at the same name that cleanup
// must leave untouched.
const (
	ovhChallenge = "b3ZoY2hhbGxlbmdldmFsdWUtb25lLWZvci10ZXN0aW5n"
	ovhSibling   = "b3Zoc2libGluZ3ZhbHVlLXR3by1mb3ItdGVzdGluZ3g"
)

// ovhStored is one stored TXT record in the fake.
type ovhStored struct {
	subDomain string
	target    string
}

// ovhAPI is a local stand-in for the OVHcloud API v1. No test in this package
// contacts OVH. It verifies the request signature on every authenticated call,
// which is what makes "the signature is computed and correct" an assertion rather
// than an assumption.
type ovhAPI struct {
	t *testing.T

	// mu guards every mutable field below.
	mu sync.Mutex

	// requests records every method+path the provider issued.
	requests []string
	// signedCalls counts authenticated calls whose signature the fake verified.
	signedCalls int
	// lastTimestamp is the X-Ovh-Timestamp of the last signed call.
	lastTimestamp int64

	// zones is the set of zone names the account holds.
	zones map[string]bool
	// records is the record store, keyed by ID.
	records map[int64]ovhStored
	// nextID is the ID handed to the next create.
	nextID int64
	// refreshes counts zone-refresh calls.
	refreshes int

	// createFails makes the create call return an API-level rejection carrying a
	// message, so a test can assert the error path and that no secret leaks into
	// it.
	createFails bool
	// quoteStored wraps a stored target in double quotes when it is read back,
	// which is the presentation form DNS uses on the wire.
	quoteStored bool
}

func newOVHAPI(t *testing.T) (*ovhAPI, Provider) {
	t.Helper()

	api := &ovhAPI{
		t:       t,
		zones:   map[string]bool{"example.com": true},
		records: map[int64]ovhStored{},
		nextID:  900,
	}
	srv := httptest.NewServer(api)
	t.Cleanup(srv.Close)

	provider, err := NewOVH(ovhCreds(nil), srv.Client())
	if err != nil {
		t.Fatalf("NewOVH: %v", err)
	}
	// The API base is chosen from a fixed allowlist by design, so the test
	// rewrites the request host in the transport instead of making the endpoint a
	// free-form URL -- a settable base would be exactly the misconfiguration that
	// lets a credential be pointed at another host. The full path (including the
	// /1.0 prefix) is preserved so the fake can reconstruct the URL that was
	// signed.
	provider.(*ovhProvider).client = &http.Client{
		Transport: ovhRewriteHost{srv.URL, srv.Client().Transport},
	}
	// A fixed local clock makes the timestamp deterministic. It is set well away
	// from ovhServerTime so a provider that ignored the server delta would produce
	// a timestamp the delta test can catch.
	provider.(*ovhProvider).now = func() time.Time { return time.Unix(1_000_000_000, 0) }
	return api, provider
}

// ovhCreds builds a named credential set, applying any overrides. A nil override
// yields the full, valid set.
func ovhCreds(overrides map[string]string) Credentials {
	fields := map[string]string{
		"application_key":    ovhAppKey,
		"application_secret": ovhAppSecret,
		"consumer_key":       ovhConsumerKey,
	}
	for k, v := range overrides {
		if v == ovhDelete {
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

// ovhDelete is a sentinel override value meaning "remove this field entirely".
const ovhDelete = "\x00delete\x00"

// ovhRewriteHost redirects requests for the real API base at the local fake,
// preserving the path and query so the signed URL can be reconstructed.
type ovhRewriteHost struct {
	base string
	next http.RoundTripper
}

func (r ovhRewriteHost) RoundTrip(req *http.Request) (*http.Response, error) {
	base := ovhEndpoints[ovhDefaultEndpoint]
	target := r.base + strings.TrimPrefix(req.URL.String(), base)
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

func (a *ovhAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)

	a.mu.Lock()
	defer a.mu.Unlock()
	a.requests = append(a.requests, r.Method+" "+r.URL.Path+"?"+r.URL.RawQuery)

	// /auth/time is unauthenticated and answers with plain-text unix seconds. The
	// rewrite transport strips the base (including the /1.0 version segment), so
	// the fake sees paths relative to it.
	if r.URL.Path == "/auth/time" {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = fmt.Fprintf(w, "%d", ovhServerTime)
		return
	}

	a.verifySignature(r, body)

	w.Header().Set("Content-Type", "application/json")
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/"), "/")

	// domain/zone/{zone}[/record[/{id}] | /refresh]
	if len(parts) < 3 || parts[0] != "domain" || parts[1] != "zone" {
		a.t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		a.write(w, http.StatusBadRequest, `{"message":"unexpected"}`)
		return
	}
	zone := parts[2]

	switch {
	case r.Method == http.MethodGet && len(parts) == 3:
		a.getZone(w, zone)
	case r.Method == http.MethodPost && len(parts) == 4 && parts[3] == "refresh":
		a.refresh(w, zone)
	case r.Method == http.MethodPost && len(parts) == 4 && parts[3] == "record":
		a.createRecord(w, zone, body)
	case r.Method == http.MethodGet && len(parts) == 4 && parts[3] == "record":
		a.listRecords(w, r, zone)
	case r.Method == http.MethodGet && len(parts) == 5 && parts[3] == "record":
		a.getRecord(w, parts[4])
	case r.Method == http.MethodDelete && len(parts) == 5 && parts[3] == "record":
		a.deleteRecord(w, parts[4])
	default:
		a.t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		a.write(w, http.StatusBadRequest, `{"message":"unexpected"}`)
	}
}

// verifySignature recomputes the OVH request signature exactly as the provider
// must have, and asserts the header matches. This is the signature-correctness
// gate: a wrong algorithm, a mismatched timestamp, or a signed URL that differs
// from the sent one all fail here rather than passing silently.
func (a *ovhAPI) verifySignature(r *http.Request, body []byte) {
	a.t.Helper()

	app := r.Header.Get("X-Ovh-Application")
	consumer := r.Header.Get("X-Ovh-Consumer")
	ts := r.Header.Get("X-Ovh-Timestamp")
	sig := r.Header.Get("X-Ovh-Signature")

	if app != ovhAppKey {
		a.t.Errorf("X-Ovh-Application = %q, want the application key", app)
	}
	if consumer != ovhConsumerKey {
		a.t.Errorf("X-Ovh-Consumer = %q, want the consumer key", consumer)
	}
	if !strings.HasPrefix(sig, "$1$") {
		a.t.Errorf("X-Ovh-Signature = %q, want the $1$ scheme prefix", sig)
	}
	if ts == "" {
		a.t.Error("X-Ovh-Timestamp is missing")
	}

	// The URL that was signed is the real OVH URL, reconstructed from the fixed
	// base plus the path+query the fake received (the rewrite transport preserved
	// both).
	fullURL := ovhEndpoints[ovhDefaultEndpoint] + r.URL.RequestURI()
	h := sha1.New()
	_, _ = fmt.Fprintf(h, "%s+%s+%s+%s+%s+%s",
		ovhAppSecret, consumer, r.Method, fullURL, string(body), ts)
	want := "$1$" + hex.EncodeToString(h.Sum(nil))
	if sig != want {
		a.t.Errorf("X-Ovh-Signature = %q, want %q (method=%s url=%s bodylen=%d ts=%s)",
			sig, want, r.Method, fullURL, len(body), ts)
	}

	a.signedCalls++
	if n, err := strconv.ParseInt(ts, 10, 64); err == nil {
		a.lastTimestamp = n
	}
}

func (a *ovhAPI) getZone(w http.ResponseWriter, zone string) {
	if !a.zones[zone] {
		a.write(w, http.StatusNotFound, `{"message":"This service does not exist"}`)
		return
	}
	a.write(w, http.StatusOK, fmt.Sprintf(`{"name":%q}`, zone))
}

func (a *ovhAPI) refresh(w http.ResponseWriter, zone string) {
	if !a.zones[zone] {
		a.write(w, http.StatusNotFound, `{"message":"This service does not exist"}`)
		return
	}
	a.refreshes++
	a.write(w, http.StatusOK, `null`)
}

func (a *ovhAPI) createRecord(w http.ResponseWriter, zone string, body []byte) {
	if !a.zones[zone] {
		a.write(w, http.StatusNotFound, `{"message":"This service does not exist"}`)
		return
	}
	if a.createFails {
		a.write(w, http.StatusBadRequest, `{"message":"the target is not a valid TXT value"}`)
		return
	}
	var in ovhRecordCreate
	if err := json.Unmarshal(body, &in); err != nil {
		a.t.Errorf("create body did not parse: %v", err)
		a.write(w, http.StatusBadRequest, `{"message":"bad body"}`)
		return
	}
	if in.FieldType != "TXT" {
		a.t.Errorf("create fieldType = %q, want TXT", in.FieldType)
	}
	id := a.nextID
	a.nextID++
	a.records[id] = ovhStored{subDomain: in.SubDomain, target: in.Target}
	a.write(w, http.StatusOK, fmt.Sprintf(
		`{"id":%d,"fieldType":%q,"subDomain":%q,"target":%q,"zone":%q}`,
		id, in.FieldType, in.SubDomain, in.Target, zone))
}

func (a *ovhAPI) listRecords(w http.ResponseWriter, r *http.Request, zone string) {
	if !a.zones[zone] {
		a.write(w, http.StatusNotFound, `{"message":"This service does not exist"}`)
		return
	}
	sub := r.URL.Query().Get("subDomain")
	var ids []int64
	for id, rec := range a.records {
		if rec.subDomain == sub {
			ids = append(ids, id)
		}
	}
	raw, _ := json.Marshal(ids)
	a.write(w, http.StatusOK, string(raw))
}

func (a *ovhAPI) getRecord(w http.ResponseWriter, idStr string) {
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		a.write(w, http.StatusBadRequest, `{"message":"bad id"}`)
		return
	}
	rec, ok := a.records[id]
	if !ok {
		a.write(w, http.StatusNotFound, `{"message":"This service does not exist"}`)
		return
	}
	target := rec.target
	if a.quoteStored {
		target = `"` + rec.target + `"`
	}
	a.write(w, http.StatusOK, fmt.Sprintf(
		`{"id":%d,"fieldType":"TXT","subDomain":%q,"target":%q}`, id, rec.subDomain, target))
}

func (a *ovhAPI) deleteRecord(w http.ResponseWriter, idStr string) {
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		a.write(w, http.StatusBadRequest, `{"message":"bad id"}`)
		return
	}
	if _, ok := a.records[id]; !ok {
		a.write(w, http.StatusNotFound, `{"message":"This service does not exist"}`)
		return
	}
	delete(a.records, id)
	a.write(w, http.StatusOK, `null`)
}

func (a *ovhAPI) write(w http.ResponseWriter, status int, body string) {
	w.WriteHeader(status)
	_, _ = io.WriteString(w, body)
}

// seed adds a stored record directly, so assertions about what survived a cleanup
// read from state the TEST established.
func (a *ovhAPI) seed(id int64, sub, target string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.records[id] = ovhStored{subDomain: sub, target: target}
}

func (a *ovhAPI) storedTargets(sub string) []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []string
	for _, rec := range a.records {
		if rec.subDomain == sub {
			out = append(out, rec.target)
		}
	}
	return out
}

// TestOVHPresentCreatesRefreshesAndCleansUp is the happy path: create the record,
// refresh, and on cleanup delete the exact value and refresh again. It also
// proves the signature was verified on every authenticated call and that a
// sibling challenge at the same name survives.
func TestOVHPresentCreatesRefreshesAndCleansUp(t *testing.T) {
	t.Parallel()
	api, provider := newOVHAPI(t)

	// A sibling wildcard challenge already sits at the same name with a different
	// digest. Cleanup must not touch it.
	api.seed(42, "_acme-challenge", ovhSibling)

	rec := Record{Name: "_acme-challenge.example.com", Value: ovhChallenge}
	cleanup, err := provider.Present(context.Background(), rec)
	if err != nil {
		t.Fatalf("Present: %v", err)
	}
	if cleanup == nil {
		t.Fatal("Present returned a nil cleanup")
	}

	if got := api.storedTargets("_acme-challenge"); len(got) != 2 {
		t.Fatalf("after Present, stored targets = %v, want the challenge and the sibling", got)
	}
	if api.refreshes < 1 {
		t.Error("Present did not refresh the zone; OVH would never serve the record")
	}

	if err := cleanup(context.Background()); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	remaining := api.storedTargets("_acme-challenge")
	if len(remaining) != 1 || remaining[0] != ovhSibling {
		t.Fatalf("after cleanup, stored targets = %v, want only the sibling", remaining)
	}
	if api.refreshes < 2 {
		t.Error("cleanup did not refresh the zone after deleting")
	}
	if api.signedCalls == 0 {
		t.Error("no authenticated call was signature-verified")
	}
}

// TestOVHCleanupIsIdempotent proves a second cleanup, and a cleanup for a value
// that was never created, are both a no-op success -- the path a cleanup returned
// from a failed publish takes.
func TestOVHCleanupIsIdempotent(t *testing.T) {
	t.Parallel()
	api, provider := newOVHAPI(t)

	cleanup := provider.(*ovhProvider).removeValue("example.com", "_acme-challenge", ovhChallenge)
	if err := cleanup(context.Background()); err != nil {
		t.Fatalf("cleanup of a never-created value: %v", err)
	}
	// Nothing was deleted, so nothing was refreshed.
	if api.refreshes != 0 {
		t.Errorf("idempotent cleanup refreshed the zone %d times, want 0", api.refreshes)
	}
}

// TestOVHReadsQuotedTargets proves cleanup still matches its own value when OVH
// echoes the target in the quoted presentation form.
func TestOVHReadsQuotedTargets(t *testing.T) {
	t.Parallel()
	api, provider := newOVHAPI(t)
	api.quoteStored = true

	rec := Record{Name: "_acme-challenge.example.com", Value: ovhChallenge}
	cleanup, err := provider.Present(context.Background(), rec)
	if err != nil {
		t.Fatalf("Present: %v", err)
	}
	if err := cleanup(context.Background()); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if got := api.storedTargets("_acme-challenge"); len(got) != 0 {
		t.Fatalf("after cleanup, stored targets = %v, want none", got)
	}
}

// TestOVHTimestampUsesServerDelta proves the provider stamps requests with OVH's
// clock, not its own: the fixed local clock is 700M seconds behind the fake's
// /auth/time, and the timestamp actually sent must track the server.
func TestOVHTimestampUsesServerDelta(t *testing.T) {
	t.Parallel()
	api, provider := newOVHAPI(t)

	rec := Record{Name: "_acme-challenge.example.com", Value: ovhChallenge}
	if _, err := provider.Present(context.Background(), rec); err != nil {
		t.Fatalf("Present: %v", err)
	}
	// The local clock is 1e9; the server is 1.7e9. The stamped timestamp must be
	// the server time, not the local one.
	if api.lastTimestamp != ovhServerTime {
		t.Errorf("stamped timestamp = %d, want the server-adjusted %d", api.lastTimestamp, ovhServerTime)
	}
}

// TestOVHAPIErrorSurfaces proves an API-level create rejection becomes an
// ErrOVHAPI, that a cleanup still comes back, and that the API's message is
// carried without leaking any credential.
func TestOVHAPIErrorSurfaces(t *testing.T) {
	t.Parallel()
	api, provider := newOVHAPI(t)
	api.createFails = true

	rec := Record{Name: "_acme-challenge.example.com", Value: ovhChallenge}
	cleanup, err := provider.Present(context.Background(), rec)
	if !errors.Is(err, ErrOVHAPI) {
		t.Fatalf("err = %v, want ErrOVHAPI", err)
	}
	if cleanup == nil {
		t.Fatal("a cleanup must be returned even when Present fails")
	}
	assertNoOVHSecret(t, err)

	// The returned cleanup finds nothing and succeeds without a destructive call.
	if err := cleanup(context.Background()); err != nil {
		t.Fatalf("cleanup after failed publish: %v", err)
	}
}

// TestOVHRejectsIncompleteCredentials is the construction-time gate. Each of the
// three required fields, when missing or blank, must refuse with ErrOVHAPI and
// return no provider, and no error may echo the application secret.
func TestOVHRejectsIncompleteCredentials(t *testing.T) {
	t.Parallel()

	blank := []string{"", " ", "   ", "\t", "\n", " \t\r\n "}

	for _, field := range []string{"application_key", "application_secret", "consumer_key"} {
		t.Run("missing "+field, func(t *testing.T) {
			t.Parallel()
			p, err := NewOVH(ovhCreds(map[string]string{field: ovhDelete}), nil)
			if !errors.Is(err, ErrOVHAPI) {
				t.Fatalf("err = %v, want ErrOVHAPI", err)
			}
			if p != nil {
				t.Fatal("a provider with an incomplete credential must not be returned")
			}
			assertNoOVHSecret(t, err)
		})
		for _, b := range blank {
			t.Run("blank "+field+" "+strconv.Quote(b), func(t *testing.T) {
				t.Parallel()
				p, err := NewOVH(ovhCreds(map[string]string{field: b}), nil)
				if !errors.Is(err, ErrOVHAPI) {
					t.Fatalf("err = %v, want ErrOVHAPI", err)
				}
				if p != nil {
					t.Fatal("a provider with a blank credential must not be returned")
				}
				assertNoOVHSecret(t, err)
			})
		}
	}
}

// TestOVHRejectsSingleCredential proves OVH refuses the single-value form the
// token providers use: it needs three named values and will not guess them from
// one.
func TestOVHRejectsSingleCredential(t *testing.T) {
	t.Parallel()

	p, err := NewOVH(NewSingleCredential(secrets.NewRedacted(ovhAppSecret)), nil)
	if !errors.Is(err, ErrOVHAPI) {
		t.Fatalf("err = %v, want ErrOVHAPI", err)
	}
	if p != nil {
		t.Fatal("a single credential must not build an OVH provider")
	}
	assertNoOVHSecret(t, err)
}

// TestOVHEndpointSelection proves each allowlisted region resolves to its own
// base URL, the default is EU, and an unknown region is refused.
func TestOVHEndpointSelection(t *testing.T) {
	t.Parallel()

	cases := []struct {
		endpoint string
		wantBase string
	}{
		{"", "https://eu.api.ovh.com/1.0"},
		{"ovh-eu", "https://eu.api.ovh.com/1.0"},
		{"ovh-ca", "https://ca.api.ovh.com/1.0"},
		{"ovh-us", "https://api.us.ovhcloud.com/1.0"},
	}
	for _, tc := range cases {
		t.Run("endpoint "+strconv.Quote(tc.endpoint), func(t *testing.T) {
			t.Parallel()
			overrides := map[string]string{}
			if tc.endpoint == "" {
				overrides["endpoint"] = ovhDelete
			} else {
				overrides["endpoint"] = tc.endpoint
			}
			p, err := NewOVH(ovhCreds(overrides), nil)
			if err != nil {
				t.Fatalf("NewOVH(%q): %v", tc.endpoint, err)
			}
			if got := p.(*ovhProvider).baseURL; got != tc.wantBase {
				t.Errorf("baseURL = %q, want %q", got, tc.wantBase)
			}
		})
	}

	t.Run("unknown endpoint refused", func(t *testing.T) {
		t.Parallel()
		p, err := NewOVH(ovhCreds(map[string]string{"endpoint": "https://evil.example.com"}), nil)
		if !errors.Is(err, ErrOVHAPI) {
			t.Fatalf("err = %v, want ErrOVHAPI", err)
		}
		if p != nil {
			t.Fatal("an unknown endpoint must not build a provider")
		}
	})
}

// TestOVHProviderFormatRedacts is the leak gate on the struct itself: no fmt verb
// may print any credential field. Without the Format method, "%+v" walks the
// unexported fields by reflection and prints all three in full.
func TestOVHProviderFormatRedacts(t *testing.T) {
	t.Parallel()

	p, err := NewOVH(ovhCreds(nil), nil)
	if err != nil {
		t.Fatalf("NewOVH: %v", err)
	}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
		out := fmt.Sprintf(verb, p)
		for _, secret := range []string{ovhAppKey, ovhAppSecret, ovhConsumerKey} {
			if strings.Contains(out, secret) {
				t.Errorf("%s of provider leaked a credential field: %q", verb, out)
			}
		}
	}
}

// TestOVHNamedProviderThroughSeam proves the registry builds OVH from a named
// credential set, so a deployer selecting "ovh" reaches this provider.
func TestOVHNamedProviderThroughSeam(t *testing.T) {
	t.Parallel()

	p, err := NewAPIProvider("ovh", ovhCreds(nil), nil)
	if err != nil {
		t.Fatalf("NewAPIProvider(ovh): %v", err)
	}
	if p == nil || p.Name() != "ovh" {
		t.Fatalf("provider = %v, want a provider named ovh", p)
	}
}

// assertNoOVHSecret fails if the application secret appears anywhere in err.
func assertNoOVHSecret(t *testing.T, err error) {
	t.Helper()
	if err != nil && strings.Contains(err.Error(), ovhAppSecret) {
		t.Errorf("error leaked the application secret: %v", err)
	}
}
