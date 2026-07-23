package httpserver_test

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/auth"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/secrets"
	httpserver "github.com/sadeq-n-yazdi/sshpilot-vallete/internal/transport/http"
)

const (
	deviceCodeBody = `{"device_code":"whatever"}`
	startBody      = `{"client_label":"laptop","scopes":[{"kind":"read-only"}]}`
)

func sampleGrant(userCode string) *auth.Grant {
	return &auth.Grant{
		PairingID:    "pair-1",
		DeviceCode:   secrets.NewRedacted("device-secret-xyz"),
		UserCode:     secrets.NewRedacted(userCode),
		ExpiresAt:    time.Now().Add(10 * time.Minute).UTC(),
		PollInterval: 5 * time.Second,
	}
}

func sampleIssued() *auth.Issued {
	return &auth.Issued{
		RefreshToken:     secrets.NewRedacted("refresh-abc"),
		RefreshExpiresAt: time.Now().Add(24 * time.Hour).UTC(),
		AccessToken:      secrets.NewRedacted("access-def"),
		AccessExpiresAt:  time.Now().Add(15 * time.Minute).UTC(),
		OwnerID:          "owner-1",
		LineageID:        "lin-1",
		Scopes:           []domain.Scope{{Kind: domain.ScopeReadOnly}},
	}
}

func decodeBody(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatalf("decoding response body %q: %v", rec.Body.String(), err)
	}
	return m
}

// TestStartDeviceGrantDisclosesCodes: the start endpoint reveals both codes
// exactly once. A body that carried [REDACTED] instead would mean the response
// struct embedded auth.Grant rather than revealing its fields deliberately.
func TestStartDeviceGrantDisclosesCodes(t *testing.T) {
	t.Parallel()
	e := newEnrollEnv(t, 0)
	e.enroll.startGrant = sampleGrant("WDJB-MJHT")

	rec := e.do(t, http.MethodPost, "/api/v1/enroll/device", "", startBody, "")
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body %q", rec.Code, rec.Body.String())
	}
	body := decodeBody(t, rec)
	if body["device_code"] != "device-secret-xyz" {
		t.Errorf("device_code = %v, want the revealed secret", body["device_code"])
	}
	if body["user_code"] != "WDJB-MJHT" {
		t.Errorf("user_code = %v", body["user_code"])
	}
	if body["poll_interval_seconds"] != float64(5) {
		t.Errorf("poll_interval_seconds = %v, want 5", body["poll_interval_seconds"])
	}
}

// TestStartDeviceGrantScopeErrorIsBadRequest: a rejected scope is a 400 built
// from the caller's own input, never a 500.
func TestStartDeviceGrantScopeErrorIsBadRequest(t *testing.T) {
	t.Parallel()
	e := newEnrollEnv(t, 0)
	e.enroll.startErr = domain.ErrInvalidInput

	rec := e.do(t, http.MethodPost, "/api/v1/enroll/device", "", startBody, "")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

// TestStartMalformedBodyIsBadRequest: a body the strict decoder rejects (an
// unknown field) is a 400 and the service is never called.
func TestStartMalformedBodyIsBadRequest(t *testing.T) {
	t.Parallel()
	e := newEnrollEnv(t, 0)

	rec := e.do(t, http.MethodPost, "/api/v1/enroll/device", "", `{"client_label":"x","owner_id":"victim"}`, "")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if e.enroll.startCalls != 0 {
		t.Errorf("service called %d times on a malformed body, want 0", e.enroll.startCalls)
	}
}

// TestPollApprovedAndRefused: approved is a 200 and a refused poll is a uniform
// 401. The third outcome, pending -> 202, rides the real service's unexported
// errPollPending sentinel and so is exercised end-to-end in the e2e test rather
// than here, where a fake cannot fabricate that sentinel.
func TestPollApprovedAndRefused(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		err  error
		want int
	}{
		{"approved", nil, http.StatusOK},
		{"refused", auth.ErrAuthFailed, http.StatusUnauthorized},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			e := newEnrollEnv(t, 0)
			e.enroll.pollErr = tc.err
			rec := e.do(t, http.MethodPost, "/api/v1/enroll/poll", "", deviceCodeBody, "")
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d", rec.Code, tc.want)
			}
		})
	}
}

// TestRedeemDisclosesTokensOnSuccess: a successful redemption reveals the token
// pair; RecordSuccess is exercised by the clean 200.
func TestRedeemDisclosesTokensOnSuccess(t *testing.T) {
	t.Parallel()
	e := newEnrollEnv(t, 0)
	e.enroll.redeem = sampleIssued()

	rec := e.do(t, http.MethodPost, "/api/v1/enroll/redeem", "", deviceCodeBody, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %q", rec.Code, rec.Body.String())
	}
	body := decodeBody(t, rec)
	if body["refresh_token"] != "refresh-abc" || body["access_token"] != "access-def" {
		t.Errorf("tokens not revealed: %v", body)
	}
	if strings.Contains(rec.Body.String(), "REDACTED") {
		t.Error("response carried a [REDACTED] marker; a secret field was embedded, not revealed")
	}
}

// TestRedeemUniformRejection: an auth failure is a bare 401 with the uniform
// body, so unknown/expired/unapproved are one indistinguishable answer.
func TestRedeemUniformRejection(t *testing.T) {
	t.Parallel()
	e := newEnrollEnv(t, 0)
	e.enroll.redeemErr = auth.ErrAuthFailed

	rec := e.do(t, http.MethodPost, "/api/v1/enroll/redeem", "", deviceCodeBody, "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if got := rec.Body.String(); got != "{\"status\":\"error\"}\n" {
		t.Errorf("body = %q, want the uniform error", got)
	}
}

// TestRedeemBruteForceClimbsBackoff is the AUTH-tier mutation guard for the
// minting path. With one free failure, the third attempt from an IP must be a
// 429: that only happens if RecordFailure ran on each rejection (so the count
// grew) AND the Check honored the resulting lockout. Deleting RecordFailure
// leaves every attempt a 401; flipping the Check deny to allow leaves the third
// a 401. Either mutation turns the wanted slice below wrong.
func TestRedeemBruteForceClimbsBackoff(t *testing.T) {
	t.Parallel()
	e := newEnrollEnv(t, 1)
	e.enroll.redeemErr = auth.ErrAuthFailed

	want := []int{http.StatusUnauthorized, http.StatusUnauthorized, http.StatusTooManyRequests}
	for i, w := range want {
		rec := e.do(t, http.MethodPost, "/api/v1/enroll/redeem", "", deviceCodeBody, "198.51.100.7:2200")
		if rec.Code != w {
			t.Fatalf("attempt %d: status = %d, want %d", i+1, rec.Code, w)
		}
	}
}

// TestRedeemSuccessClearsFailureCount is the RecordSuccess mutation guard. A
// success between failures resets the counter, so it takes two more failures to
// arm the lockout. If RecordSuccess is removed the count survives the success
// and the fourth request (the second failure after it) is already a 429 -- so
// asserting the fourth is a 401 kills that mutant.
func TestRedeemSuccessClearsFailureCount(t *testing.T) {
	t.Parallel()
	e := newEnrollEnv(t, 1)
	const ip = "198.51.100.9:2200"

	step := func(fail bool) int {
		if fail {
			e.enroll.redeem, e.enroll.redeemErr = nil, auth.ErrAuthFailed
		} else {
			e.enroll.redeem, e.enroll.redeemErr = sampleIssued(), nil
		}
		return e.do(t, http.MethodPost, "/api/v1/enroll/redeem", "", deviceCodeBody, ip).Code
	}

	got := []int{step(true), step(false), step(true), step(true), step(true)}
	want := []int{
		http.StatusUnauthorized, http.StatusOK,
		http.StatusUnauthorized, http.StatusUnauthorized, http.StatusTooManyRequests,
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("step %d: status = %d, want %d (full: %v)", i+1, got[i], want[i], got)
		}
	}
}

// TestRedeemFailsClosedOnStoreOutage: when the counter store cannot answer, the
// Check refuses and the credential is never verified. This is the AUTH tier's
// fail-closed posture -- serving an unmetered guessing oracle during an outage
// is the failure it exists to prevent.
func TestRedeemFailsClosedOnStoreOutage(t *testing.T) {
	t.Parallel()
	e := newEnrollEnv(t, 0)
	e.enroll.redeem = sampleIssued()
	e.store.down = true

	rec := e.do(t, http.MethodPost, "/api/v1/enroll/redeem", "", deviceCodeBody, "")
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", rec.Code)
	}
	if e.enroll.redeemCalls != 0 {
		t.Errorf("redeem verified during a store outage (%d calls); Check must gate first", e.enroll.redeemCalls)
	}
}

// TestRedeemRefusesUnresolvableClient: an address the limiter cannot key on is
// refused, never waved through -- the one caller we cannot identify must not be
// the one caller exempt from the limit.
func TestRedeemRefusesUnresolvableClient(t *testing.T) {
	t.Parallel()
	e := newEnrollEnv(t, 0)
	e.enroll.redeem = sampleIssued()

	rec := e.do(t, http.MethodPost, "/api/v1/enroll/redeem", "", deviceCodeBody, "not-an-address")
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", rec.Code)
	}
	if e.enroll.redeemCalls != 0 {
		t.Errorf("redeem ran for an unresolvable client (%d calls)", e.enroll.redeemCalls)
	}
}

// TestStartAndPollDoNotCountFailures: neither un-guarded read records a failure,
// so repeated calls never climb the backoff curve even under a one-failure
// budget. Counting them would penalize an honest, eager client.
func TestStartAndPollDoNotCountFailures(t *testing.T) {
	t.Parallel()
	e := newEnrollEnv(t, 1)
	e.enroll.startGrant = sampleGrant("WDJB-MJHT")
	e.enroll.pollErr = auth.ErrAuthFailed // a "wrong or too-soon" poll

	for i := range 6 {
		if rec := e.do(t, http.MethodPost, "/api/v1/enroll/device", "", startBody, "203.0.113.20:1"); rec.Code != http.StatusCreated {
			t.Fatalf("start %d: status = %d, want 201 (start must never self-lock)", i+1, rec.Code)
		}
		if rec := e.do(t, http.MethodPost, "/api/v1/enroll/poll", "", deviceCodeBody, "203.0.113.20:1"); rec.Code != http.StatusUnauthorized {
			t.Fatalf("poll %d: status = %d, want 401 (poll must not count too-soon as a failure)", i+1, rec.Code)
		}
	}
}

// TestStartRespectsSharedIPLockout: start carries no credential but still checks
// the shared IP lockout, so an address locked out for spraying redeem cannot
// open fresh pairings.
func TestStartRespectsSharedIPLockout(t *testing.T) {
	t.Parallel()
	e := newEnrollEnv(t, 1)
	e.enroll.redeemErr = auth.ErrAuthFailed
	e.enroll.startGrant = sampleGrant("WDJB-MJHT")
	const ip = "203.0.113.30:1"

	// Two failed redeems arm the lockout for this IP.
	for range 2 {
		e.do(t, http.MethodPost, "/api/v1/enroll/redeem", "", deviceCodeBody, ip)
	}
	if rec := e.do(t, http.MethodPost, "/api/v1/enroll/device", "", startBody, ip); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("start after lockout: status = %d, want 429", rec.Code)
	}
}

// TestMintDisclosesCodeForVerifiedOwner: mint runs behind the Guardian, takes
// the owner from the token, and omits the empty user code from the response.
func TestMintDisclosesCodeForVerifiedOwner(t *testing.T) {
	t.Parallel()
	e := newEnrollEnv(t, 0)
	e.enroll.mintGrant = sampleGrant("") // a mint has no user code

	rec := e.do(t, http.MethodPost, "/api/v1/enroll/mint", e.token(t, "owner-42"), startBody, "")
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body %q", rec.Code, rec.Body.String())
	}
	if e.enroll.mintOwner != "owner-42" {
		t.Errorf("mint owner = %q, want the token owner", e.enroll.mintOwner)
	}
	if _, present := decodeBody(t, rec)["user_code"]; present {
		t.Error("user_code present for a mint; the empty code must be omitted")
	}
}

// TestMintRequiresAuthorization: with no bearer, the Guardian refuses before the
// handler runs.
func TestMintRequiresAuthorization(t *testing.T) {
	t.Parallel()
	e := newEnrollEnv(t, 0)
	rec := e.do(t, http.MethodPost, "/api/v1/enroll/mint", "", startBody, "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

// TestApproveSucceeds: a valid approval is a 204, and the service is handed the
// verified owner plus the transcribed code.
func TestApproveSucceeds(t *testing.T) {
	t.Parallel()
	e := newEnrollEnv(t, 0)
	rec := e.do(t, http.MethodPost, "/api/v1/enroll/approve", e.token(t, "owner-7"), `{"user_code":"WDJB-MJHT"}`, "")
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204; body %q", rec.Code, rec.Body.String())
	}
	if e.enroll.approveOwner != "owner-7" || e.enroll.approveCode != "WDJB-MJHT" {
		t.Errorf("approve got owner=%q code=%q", e.enroll.approveOwner, e.enroll.approveCode)
	}
}

// TestApproveUniformRejection: a refused approval is a uniform 403 (the bearer
// already passed the Guardian, so this is a forbidden action, not a bad token).
func TestApproveUniformRejection(t *testing.T) {
	t.Parallel()
	e := newEnrollEnv(t, 0)
	e.enroll.approveErr = auth.ErrAuthFailed
	rec := e.do(t, http.MethodPost, "/api/v1/enroll/approve", e.token(t, "owner-7"), `{"user_code":"ZZZZ-ZZZZ"}`, "")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
}

// TestApproveBackoffIsKeyedByOwnerNotIP is the AUTH-tier mutation guard for the
// user-code oracle. Two owners spray the SAME IP: the first climbs to a lockout
// (proving RecordFailure ran on the owner key and the Check honored it), while
// the second -- same address, different owner -- is still merely refused. That
// simultaneously kills "drop RecordFailure on approve" (owner A never locks) and
// proves the key is the owner, not the address (owner B would 429 too if keyed
// by IP).
func TestApproveBackoffIsKeyedByOwnerNotIP(t *testing.T) {
	t.Parallel()
	e := newEnrollEnv(t, 1)
	e.enroll.approveErr = auth.ErrAuthFailed
	tokenA, tokenB := e.token(t, "owner-a"), e.token(t, "owner-b")
	const ip = "203.0.113.40:1"

	want := []int{http.StatusForbidden, http.StatusForbidden, http.StatusTooManyRequests}
	for i, w := range want {
		rec := e.do(t, http.MethodPost, "/api/v1/enroll/approve", tokenA, `{"user_code":"ZZZZ-ZZZZ"}`, ip)
		if rec.Code != w {
			t.Fatalf("owner-a attempt %d: status = %d, want %d", i+1, rec.Code, w)
		}
	}
	// Same IP, different owner: not locked, because the key is the owner.
	rec := e.do(t, http.MethodPost, "/api/v1/enroll/approve", tokenB, `{"user_code":"ZZZZ-ZZZZ"}`, ip)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("owner-b on the same IP: status = %d, want 403 (owner-keyed, not IP-keyed)", rec.Code)
	}
}

// TestEnrollmentRoutesRefuseWithoutServices: mounted-but-unwired routes answer
// 500, never 404 -- a wiring fault must read as a broken deployment, not an
// absent feature.
func TestEnrollmentRoutesRefuseWithoutServices(t *testing.T) {
	t.Parallel()
	signer, err := auth.NewAccessTokenSigner([]byte(strings.Repeat("k", auth.MinSigningKeyLen)))
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	store, err := newTestCounterStore(time.Now)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	denylist, err := auth.NewDenylist(store)
	if err != nil {
		t.Fatalf("denylist: %v", err)
	}
	guard, err := auth.NewGuard(signer, denylist)
	if err != nil {
		t.Fatalf("guard: %v", err)
	}
	h := httpserver.NewHandler(nil, slog.New(slog.DiscardHandler), devicePinger{}, devicePublisher{},
		httpserver.WithAuthorizer(guard)) // deliberately no enrollment/token service
	tok, err := signer.Issue(domain.AccessToken{
		ID: "jti", OwnerID: "owner-x", RefreshCredentialID: "cred",
		Scopes:   []domain.Scope{{Kind: domain.ScopeFullOwner}},
		IssuedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(auth.AccessTokenLifetime),
	})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	call := func(target, bearer, body string) int {
		req := httptest.NewRequest(http.MethodPost, target, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}

	unguarded := []string{"/api/v1/enroll/device", "/api/v1/enroll/poll", "/api/v1/enroll/redeem", "/api/v1/token"}
	for _, target := range unguarded {
		if got := call(target, "", deviceCodeBody); got != http.StatusInternalServerError {
			t.Errorf("%s without a service: status = %d, want 500", target, got)
		}
	}
	guarded := []string{"/api/v1/enroll/mint", "/api/v1/enroll/approve"}
	for _, target := range guarded {
		if got := call(target, tok.Reveal(), `{"user_code":"WDJB-MJHT"}`); got != http.StatusInternalServerError {
			t.Errorf("%s without a service: status = %d, want 500", target, got)
		}
	}
}
