package httpserver_test

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/auth"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/config"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/secrets"
	httpserver "github.com/sadeq-n-yazdi/sshpilot-vallete/internal/transport/http"
)

// fakeEnroll is a programmable EnrollmentService. Every method returns what the
// test set and records what it was handed, so a test can assert both the wire
// response and that the verified owner (never a request field) reached the
// service.
type fakeEnroll struct {
	startGrant *auth.Grant
	startErr   error
	mintGrant  *auth.Grant
	mintErr    error
	approveErr error
	pollErr    error
	redeem     *auth.Issued
	redeemErr  error

	startCalls   int
	redeemCalls  int
	pollCalls    int
	mintOwner    domain.OwnerID
	approveOwner domain.OwnerID
	approveCode  string
}

func (f *fakeEnroll) StartDeviceGrant(_ context.Context, _ string, _ []domain.Scope) (*auth.Grant, error) {
	f.startCalls++
	return f.startGrant, f.startErr
}

func (f *fakeEnroll) Mint(_ context.Context, ownerID domain.OwnerID, _ string, _ []domain.Scope) (*auth.Grant, error) {
	f.mintOwner = ownerID
	return f.mintGrant, f.mintErr
}

func (f *fakeEnroll) Approve(_ context.Context, ownerID domain.OwnerID, userCode string) error {
	f.approveOwner = ownerID
	f.approveCode = userCode
	return f.approveErr
}

func (f *fakeEnroll) Poll(_ context.Context, _ secrets.Redacted) error {
	f.pollCalls++
	return f.pollErr
}

func (f *fakeEnroll) Redeem(_ context.Context, _ secrets.Redacted) (*auth.Issued, error) {
	f.redeemCalls++
	return f.redeem, f.redeemErr
}

// fakeIssuer is a programmable TokenIssuer.
type fakeIssuer struct {
	issued  *auth.Issued
	err     error
	calls   int
	lastNow time.Time
}

func (f *fakeIssuer) Exchange(_ context.Context, _ secrets.Redacted, now time.Time) (*auth.Issued, error) {
	f.calls++
	f.lastNow = now
	return f.issued, f.err
}

// enrollEnv is the system under test: the real router with the enrollment and
// token services faked, a real Guard as the authorizer (so guarded routes get a
// genuine owner from a minted token), and a breakable counter store so the
// fail-closed AUTH path can be exercised.
type enrollEnv struct {
	handler http.Handler
	enroll  *fakeEnroll
	issuer  *fakeIssuer
	store   *breakableStore
	signer  *auth.AccessTokenSigner
	now     time.Time
}

// newEnrollEnv wires the env. authRequests, when positive, overrides the AUTH
// tier's free budget so a lockout can be provoked in a handful of requests; zero
// keeps the shipped default.
func newEnrollEnv(t *testing.T, authRequests int) *enrollEnv {
	t.Helper()
	// The wall clock, not a pinned instant: NewHandler's guardian verifies
	// tokens against time.Now, so a token minted at a fixed past/future instant
	// would fail its validity window for a reason unrelated to the test.
	e := &enrollEnv{now: time.Now().UTC(), enroll: &fakeEnroll{}, issuer: &fakeIssuer{}}

	store, err := newTestCounterStore(func() time.Time { return e.now })
	if err != nil {
		t.Fatalf("counter store: %v", err)
	}
	e.store = store
	denylist, err := auth.NewDenylist(store)
	if err != nil {
		t.Fatalf("NewDenylist: %v", err)
	}
	if e.signer, err = auth.NewAccessTokenSigner([]byte(strings.Repeat("k", auth.MinSigningKeyLen))); err != nil {
		t.Fatalf("NewAccessTokenSigner: %v", err)
	}
	guard, err := auth.NewGuard(e.signer, denylist)
	if err != nil {
		t.Fatalf("NewGuard: %v", err)
	}

	cfg := config.Default()
	if authRequests > 0 {
		cfg.RateLimit.Tiers.Auth = config.Tier{Requests: authRequests, Window: config.Duration(time.Minute)}
	}
	e.handler = httpserver.NewHandler(&cfg, slog.New(slog.DiscardHandler), devicePinger{}, devicePublisher{},
		httpserver.WithAuthorizer(guard),
		httpserver.WithEnrollmentService(e.enroll),
		httpserver.WithTokenService(e.issuer),
		httpserver.WithCounterStore(store))
	return e
}

// token mints a real full-owner access token signed by the env's signer, so a
// guarded route resolves a genuine owner. Nothing here fabricates an
// auth.Authorization.
func (e *enrollEnv) token(t *testing.T, owner domain.OwnerID) string {
	t.Helper()
	tok, err := e.signer.Issue(domain.AccessToken{
		ID:                  "jti-" + string(owner),
		OwnerID:             owner,
		RefreshCredentialID: domain.RefreshCredentialID("cred-" + string(owner)),
		Scopes:              []domain.Scope{{Kind: domain.ScopeFullOwner}},
		IssuedAt:            e.now,
		ExpiresAt:           e.now.Add(auth.AccessTokenLifetime),
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	return tok.Reveal()
}

// do issues one request. remoteAddr, when set, overrides the default peer so a
// test can key the AUTH limiter on a chosen address (or an unparseable one).
func (e *enrollEnv) do(t *testing.T, method, target, token, body, remoteAddr string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	if remoteAddr != "" {
		req.RemoteAddr = remoteAddr
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	e.handler.ServeHTTP(rec, req)
	return rec
}
