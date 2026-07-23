package httpserver_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/auth"
)

const refreshBody = `{"refresh_token":"present-token"}`

// TestExchangeRotatesOnSuccess: a successful exchange reveals the fresh pair and
// hands the service a real clock -- the composition root's time.Now, not a zero
// value.
func TestExchangeRotatesOnSuccess(t *testing.T) {
	t.Parallel()
	e := newEnrollEnv(t, 0)
	e.issuer.issued = sampleIssued()

	rec := e.do(t, http.MethodPost, "/api/v1/token", "", refreshBody, "")
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
	if e.issuer.lastNow.IsZero() {
		t.Error("Exchange was handed the zero time; the handler must supply a clock")
	}
}

// TestExchangeUniformRejection: a rejected refresh token -- unknown, expired,
// revoked, or a replay that just burned its lineage inside the service -- is one
// indistinguishable 401, so a replayer cannot tell a live lineage it killed from
// a dead one.
func TestExchangeUniformRejection(t *testing.T) {
	t.Parallel()
	e := newEnrollEnv(t, 0)
	e.issuer.err = auth.ErrAuthFailed

	rec := e.do(t, http.MethodPost, "/api/v1/token", "", refreshBody, "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if got := rec.Body.String(); got != "{\"status\":\"error\"}\n" {
		t.Errorf("body = %q, want the uniform error", got)
	}
}

// TestExchangeMalformedBodyIsBadRequestNotCounted: a body the strict decoder
// rejects is a 400 and is not verified -- a parse failure is not a credential
// guess and must not climb the backoff curve.
func TestExchangeMalformedBodyIsBadRequestNotCounted(t *testing.T) {
	t.Parallel()
	e := newEnrollEnv(t, 0)
	rec := e.do(t, http.MethodPost, "/api/v1/token", "", `{"refresh_token":"x","extra":1}`, "")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if e.issuer.calls != 0 {
		t.Errorf("Exchange called %d times on a malformed body, want 0", e.issuer.calls)
	}
}

// TestExchangeBruteForceClimbsBackoff is the AUTH-tier mutation guard for the
// exchange path: with one free failure, the third attempt from an IP is a 429
// only if RecordFailure ran on each rejection and the Check honored the lockout.
func TestExchangeBruteForceClimbsBackoff(t *testing.T) {
	t.Parallel()
	e := newEnrollEnv(t, 1)
	e.issuer.err = auth.ErrAuthFailed

	want := []int{http.StatusUnauthorized, http.StatusUnauthorized, http.StatusTooManyRequests}
	for i, w := range want {
		rec := e.do(t, http.MethodPost, "/api/v1/token", "", refreshBody, "198.51.100.11:3000")
		if rec.Code != w {
			t.Fatalf("attempt %d: status = %d, want %d", i+1, rec.Code, w)
		}
	}
}

// TestExchangeSharesIPLockoutWithRedeem: exchange and redeem key the same IP
// space, so a campaign that sprays redeem is throttled when it pivots to
// exchange from the same address.
func TestExchangeSharesIPLockoutWithRedeem(t *testing.T) {
	t.Parallel()
	e := newEnrollEnv(t, 1)
	e.enroll.redeemErr = auth.ErrAuthFailed
	e.issuer.issued = sampleIssued()
	const ip = "198.51.100.13:3000"

	for range 2 {
		e.do(t, http.MethodPost, "/api/v1/enroll/redeem", "", deviceCodeBody, ip)
	}
	rec := e.do(t, http.MethodPost, "/api/v1/token", "", refreshBody, ip)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("exchange after redeem lockout on the same IP: status = %d, want 429", rec.Code)
	}
	if e.issuer.calls != 0 {
		t.Errorf("Exchange ran while the shared IP was locked out (%d calls)", e.issuer.calls)
	}
}

// TestExchangeFailsClosedOnStoreOutage: a counter-store outage refuses the
// exchange before the credential is verified.
func TestExchangeFailsClosedOnStoreOutage(t *testing.T) {
	t.Parallel()
	e := newEnrollEnv(t, 0)
	e.issuer.issued = sampleIssued()
	e.store.down = true

	rec := e.do(t, http.MethodPost, "/api/v1/token", "", refreshBody, "")
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", rec.Code)
	}
	if e.issuer.calls != 0 {
		t.Errorf("Exchange verified during a store outage (%d calls)", e.issuer.calls)
	}
}
