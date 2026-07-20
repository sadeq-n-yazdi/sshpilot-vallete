package httpserver_test

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/audit"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/auth"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/config"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/service/device"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/service/publickey"
	httpserver "github.com/sadeq-n-yazdi/sshpilot-vallete/internal/transport/http"
)

// Every test in this file drives the handler built by NewHandler, over the real
// Guard and the real services, and asserts on the STATUS the route table
// produces. That is the point of the file rather than a stylistic choice: a
// test that called managementRateLimit directly would stay green if the mgmt(…)
// wrap were deleted from a mux.Handle line, which is exactly the mutant that
// survived on PR #56. Nothing below can pass unless the limiter is actually
// mounted on the route being exercised.

const keysRoutePath = "/api/v1/keys"

// mgmtEnv is the wired system under test with a configured management tier.
type mgmtEnv struct {
	handler http.Handler
	signer  *auth.AccessTokenSigner
	devices *memDeviceRepo
	now     time.Time
}

// newMgmtEnv builds a handler whose management tier permits limit requests per
// minute per credential.
//
// The window is a full minute and every test fires its requests in one tight
// loop, so all of them land inside a single window without a clock seam and
// without a sleep -- the boundary under test is the COUNT, not the passage of
// time. Retry-After values are therefore asserted as a range within the window
// rather than as an exact integer; the exact-value assertions live in the
// unit-level tests, which do drive a hand-wound clock.
func newMgmtEnv(t *testing.T, limit int) *mgmtEnv {
	t.Helper()

	env := &mgmtEnv{now: time.Now().UTC(), devices: newMemDeviceRepo()}

	store, err := newTestCounterStore(func() time.Time { return env.now })
	if err != nil {
		t.Fatalf("counter store: %v", err)
	}
	denylist, err := auth.NewDenylist(store)
	if err != nil {
		t.Fatalf("NewDenylist: %v", err)
	}
	if env.signer, err = auth.NewAccessTokenSigner([]byte(strings.Repeat("k", auth.MinSigningKeyLen))); err != nil {
		t.Fatalf("NewAccessTokenSigner: %v", err)
	}
	guard, err := auth.NewGuard(env.signer, denylist)
	if err != nil {
		t.Fatalf("NewGuard: %v", err)
	}

	sink := &memAuditSink{}
	emitter, err := audit.NewEmitter(sink, audit.WithClock(func() time.Time { return env.now }))
	if err != nil {
		t.Fatalf("audit.NewEmitter: %v", err)
	}
	devSvc, err := device.New(env.devices, emitter, device.WithClock(func() time.Time { return env.now }))
	if err != nil {
		t.Fatalf("device.New: %v", err)
	}
	keySvc, err := publickey.New(newMemPublicKeyRepo(), env.devices, emitter,
		publickey.WithClock(func() time.Time { return env.now }))
	if err != nil {
		t.Fatalf("publickey.New: %v", err)
	}

	cfg := config.Default()
	cfg.RateLimit.Tiers.Management = config.Tier{Requests: limit, Window: config.Duration(time.Minute)}
	env.handler = httpserver.NewHandler(&cfg, slog.New(slog.DiscardHandler), devicePinger{}, devicePublisher{},
		httpserver.WithAuthorizer(guard), httpserver.WithDeviceService(devSvc),
		httpserver.WithPublicKeyService(keySvc))
	return env
}

// token mints a real token for owner, minted from credential cred. The
// credential is a parameter because it is the rate-limit KEY: a test that could
// not vary it independently of the owner could not tell per-credential keying
// from per-owner keying.
func (e *mgmtEnv) token(t *testing.T, owner domain.OwnerID, cred string) string {
	t.Helper()

	tok, err := e.signer.Issue(domain.AccessToken{
		ID:                  "jti-" + cred,
		OwnerID:             owner,
		RefreshCredentialID: domain.RefreshCredentialID(cred),
		Scopes:              []domain.Scope{{Kind: domain.ScopeFullOwner}},
		IssuedAt:            e.now,
		ExpiresAt:           e.now.Add(auth.AccessTokenLifetime),
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	return tok.Reveal()
}

func (e *mgmtEnv) do(method, target, token, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	e.handler.ServeHTTP(rec, req)
	return rec
}

// mgmtRoute is one management route, as a client addresses it.
type mgmtRoute struct {
	name   string
	method string
	target string
	body   string
}

// managementRoutes is every route the management tier is mounted on. The table
// is exhaustive on purpose: with one route per case, deleting the mgmt wrap
// from any SINGLE mux.Handle line turns exactly that case red, where a test
// covering only one route would catch only the wholesale removal of the tier.
func managementRoutes() []mgmtRoute {
	return []mgmtRoute{
		{"register device", http.MethodPost, devicesPath, `{"name":"laptop"}`},
		{"list devices", http.MethodGet, devicesPath, ""},
		{"revoke device", http.MethodDelete, devicesPath + "/dev-absent", ""},
		{"add key", http.MethodPost, keysRoutePath, `{"device_id":"dev-absent","public_key":"ssh-ed25519 AAAA x"}`},
		{"list keys", http.MethodGet, keysRoutePath, ""},
		{"revoke key", http.MethodDelete, keysRoutePath + "/key-absent", ""},
	}
}

// TestEveryManagementRouteIsRateLimited is the mounting test.
//
// The assertion is deliberately only "the (limit+1)th request is 429": several
// of these routes address resources that do not exist, so their SUCCESS status
// varies (201, 200, 204, 404 …). What must not vary is that the limiter refuses
// past the limit, and that is a property of the route table rather than of any
// handler -- which is what makes it the test that a deleted wrap fails.
func TestEveryManagementRouteIsRateLimited(t *testing.T) {
	t.Parallel()

	const limit = 3
	for _, route := range managementRoutes() {
		t.Run(route.name, func(t *testing.T) {
			t.Parallel()

			// A fresh env per route, so a route's budget is its own and one
			// case cannot pass by spending another's.
			env := newMgmtEnv(t, limit)
			token := env.token(t, "owner-a", "cred-a")

			for i := 1; i <= limit; i++ {
				rec := env.do(route.method, route.target, token, route.body)
				if rec.Code == http.StatusTooManyRequests {
					t.Fatalf("request #%d of %d was refused as over-limit", i, limit)
				}
			}

			rec := env.do(route.method, route.target, token, route.body)
			if rec.Code != http.StatusTooManyRequests {
				t.Fatalf("request #%d = %d, want 429 (is the management tier mounted on this route?)",
					limit+1, rec.Code)
			}
			assertRetryAfterWithinWindow(t, rec, time.Minute)
		})
	}
}

// assertRetryAfterWithinWindow checks that a 429 names a delay a client can act
// on: present, positive, and no longer than the window it is waiting out.
func assertRetryAfterWithinWindow(t *testing.T, rec *httptest.ResponseRecorder, window time.Duration) {
	t.Helper()

	raw := rec.Header().Get("Retry-After")
	if raw == "" {
		t.Fatal("429 carried no Retry-After header")
	}
	secs, err := strconv.Atoi(raw)
	if err != nil {
		t.Fatalf("Retry-After = %q, want an integer delta-seconds", raw)
	}
	// Zero would invite an immediate retry that is certain to fail; more than
	// the window would be a delay the caller never actually owes.
	if secs < 1 || time.Duration(secs)*time.Second > window {
		t.Fatalf("Retry-After = %ds, want 1..%d", secs, int(window.Seconds()))
	}
}

// TestManagementLimitDoesNotLeakAcrossCredentials pins the isolation ADR-0023
// asks for. One credential exhausting its budget must not spend another's --
// neither another owner's (which would be a cross-tenant denial of service one
// account could inflict on every other) nor a second credential of the SAME
// owner, since the ADR keys this tier per credential.
func TestManagementLimitDoesNotLeakAcrossCredentials(t *testing.T) {
	t.Parallel()

	const limit = 2
	env := newMgmtEnv(t, limit)
	victimA := env.token(t, "owner-a", "cred-a1")
	sameOwner := env.token(t, "owner-a", "cred-a2")
	otherOwner := env.token(t, "owner-b", "cred-b1")

	// Exhaust cred-a1 and confirm it is actually refused, so the rest of the
	// test is not asserting isolation from a limit that never engaged.
	for range limit {
		env.do(http.MethodGet, devicesPath, victimA, "")
	}
	if rec := env.do(http.MethodGet, devicesPath, victimA, ""); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("cred-a1 over its limit = %d, want 429", rec.Code)
	}

	for _, tc := range []struct {
		name  string
		token string
	}{
		{"second credential of the same owner", sameOwner},
		{"another owner", otherOwner},
	} {
		if rec := env.do(http.MethodGet, devicesPath, tc.token, ""); rec.Code != http.StatusOK {
			t.Errorf("%s = %d, want 200: an exhausted credential spent a budget that was not its own",
				tc.name, rec.Code)
		}
	}
}

// TestManagementRateLimitIsNotAnExistenceOracle: a 429 must be the same
// response whether the target exists or not.
//
// The property is structural -- the limiter keys on the caller's credential and
// runs before any handler, so it has never consulted storage when it writes --
// and this test documents it against the route that makes it easiest to get
// wrong: DELETE of a device addressed by id. If the refusal ever varied with
// the target, an attacker holding one valid credential could enumerate device
// ids by reading existence off the difference.
func TestManagementRateLimitIsNotAnExistenceOracle(t *testing.T) {
	t.Parallel()

	const limit = 1
	env := newMgmtEnv(t, limit)
	token := env.token(t, "owner-a", "cred-a")

	// A device that really exists, created through the route itself.
	rec := env.do(http.MethodPost, devicesPath, token, `{"name":"laptop"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("register = %d (%s), want 201", rec.Code, rec.Body.String())
	}
	var created deviceJSON
	decodeInto(t, rec, &created)

	// Both of the following are now over the limit. The existing id belongs to
	// this very owner; the absent one is well formed and belongs to nobody.
	existing := env.do(http.MethodDelete, devicesPath+"/"+created.ID, token, "")
	absent := env.do(http.MethodDelete, devicesPath+"/dev-does-not-exist", token, "")

	for _, rr := range []*httptest.ResponseRecorder{existing, absent} {
		if rr.Code != http.StatusTooManyRequests {
			t.Fatalf("over-limit delete = %d, want 429", rr.Code)
		}
	}
	if existing.Body.String() != absent.Body.String() {
		t.Errorf("429 bodies differ: existing %q, absent %q", existing.Body.String(), absent.Body.String())
	}
	if got, want := existing.Header().Get("Retry-After"), absent.Header().Get("Retry-After"); got != want {
		t.Errorf("Retry-After differs: existing %q, absent %q", got, want)
	}
	// Header SETS, not just the two values above: a header present on one
	// response and absent on the other is the same oracle in a subtler form.
	if got, want := headerNames(existing), headerNames(absent); got != want {
		t.Errorf("429 header sets differ: existing %q, absent %q", got, want)
	}
}

// headerNames renders a response's header names as one comparable string.
func headerNames(rec *httptest.ResponseRecorder) string {
	names := make([]string, 0, len(rec.Header()))
	for name := range rec.Header() {
		names = append(names, name)
	}
	// Sorted, because map iteration order is randomized and an unsorted
	// comparison would fail at random rather than on a real difference.
	slices.Sort(names)
	return strings.Join(names, ",")
}

// TestManagementLimitLeavesUnauthenticatedRefusalsUnchanged records the tier's
// boundary rather than a behavior to preserve for its own sake.
//
// The limiter sits INSIDE Protect, so a caller with no valid credential never
// reaches it and never spends anything. That is a deliberate consequence of
// per-credential keying and not an oversight: there is no credential to key on
// before the token verifies. Defending that surface is the AUTH tier's job, and
// it is unmounted because no auth route exists yet -- so this test exists to
// make the gap visible in the suite rather than only in a comment.
func TestManagementLimitLeavesUnauthenticatedRefusalsUnchanged(t *testing.T) {
	t.Parallel()

	env := newMgmtEnv(t, 1)
	for i := range 4 {
		rec := env.do(http.MethodGet, devicesPath, "not-a-real-token", "")
		if rec.Code == http.StatusTooManyRequests {
			t.Fatalf("request #%d: an unauthenticated caller reached the management tier", i+1)
		}
	}
}
