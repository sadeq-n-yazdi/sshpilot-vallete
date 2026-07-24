package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The enrollment and token-issuance surface (ADR-0032) exercised through the
// REAL production assembly: buildServer -> buildAPIDeps -> mountOwnerManagement
// -> NewHandler, the same chain run() runs. These tests are deliberately in
// cmd/valletd rather than the transport package because the property they defend
// is a WIRING one -- that the enrollment service, the token service, and the
// owner Guard share the ONE revocation denylist mountOwnerManagement builds
// (ADR-0032 decision). A transport-level test with hand-wired services could
// share a denylist correctly while production did not; only driving the actual
// composition can catch a second denylist slipping into either service.

// grantBody / issuedBody are the one-time disclosures the enrollment surface
// returns. They are decoded locally rather than imported from the transport
// package (whose wire structs are unexported) -- the field names are the wire
// contract, so pinning them here also guards against a silent rename.
type grantBody struct {
	PairingID  string `json:"pairing_id"`
	DeviceCode string `json:"device_code"`
	UserCode   string `json:"user_code"`
}

type issuedBody struct {
	RefreshToken string `json:"refresh_token"`
	AccessToken  string `json:"access_token"`
	OwnerID      string `json:"owner_id"`
}

func decodeGrant(t *testing.T, rr *httptest.ResponseRecorder) grantBody {
	t.Helper()
	var g grantBody
	if err := json.Unmarshal(rr.Body.Bytes(), &g); err != nil {
		t.Fatalf("decode grant: %v; body = %q", err, rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), "REDACTED") {
		t.Fatalf("grant body carried a [REDACTED] marker; a secret was not revealed: %q", rr.Body.String())
	}
	return g
}

func decodeIssued(t *testing.T, rr *httptest.ResponseRecorder) issuedBody {
	t.Helper()
	var i issuedBody
	if err := json.Unmarshal(rr.Body.Bytes(), &i); err != nil {
		t.Fatalf("decode issued: %v; body = %q", err, rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), "REDACTED") {
		t.Fatalf("issued body carried a [REDACTED] marker; a token was not revealed: %q", rr.Body.String())
	}
	return i
}

// TestEnrollmentDeviceGrantFlowThroughRealWiring drives the whole mode-1 flow --
// start, approve, poll, redeem, exchange -- and then the security assertion this
// task turns on: a refresh-token REPLAY revokes the whole lineage, and the
// access token minted by the intervening exchange is refused on the NEXT
// request because the token service's revocation and the owner Guard's check
// read the same denylist.
func TestEnrollmentDeviceGrantFlowThroughRealWiring(t *testing.T) {
	f := newMgmtFixture(t)
	alice := f.seedOwner("alice", "alice-key")
	h := f.handler()
	ownerToken := mintAccessToken(t, gateSigningKey, alice.OwnerID)

	// 1. An unauthenticated client opens a pending pairing.
	start := f.do(h, http.MethodPost, "/api/v1/enroll/device",
		`{"client_label":"ci runner","scopes":[{"kind":"full-owner"}]}`, "")
	if start.Code != http.StatusCreated {
		t.Fatalf("start status = %d, want 201; body = %q", start.Code, start.Body.String())
	}
	grant := decodeGrant(t, start)
	if grant.DeviceCode == "" || grant.UserCode == "" {
		t.Fatalf("start did not disclose both codes: %+v", grant)
	}

	// 2. The owner approves it with the transcribed user code, on an authenticated
	// session. The owner comes from ownerToken, never from the body.
	approve := f.do(h, http.MethodPost, "/api/v1/enroll/approve",
		`{"user_code":"`+grant.UserCode+`"}`, ownerToken)
	if approve.Code != http.StatusNoContent {
		t.Fatalf("approve status = %d, want 204; body = %q", approve.Code, approve.Body.String())
	}

	// 3. The client polls and now sees approval. This is the pairing's first poll,
	// so it is not throttled by the per-code cadence.
	poll := f.do(h, http.MethodPost, "/api/v1/enroll/poll",
		`{"device_code":"`+grant.DeviceCode+`"}`, "")
	if poll.Code != http.StatusOK {
		t.Fatalf("poll(approved) status = %d, want 200; body = %q", poll.Code, poll.Body.String())
	}
	if !strings.Contains(poll.Body.String(), "approved") {
		t.Errorf("poll body = %q, want approved", poll.Body.String())
	}

	// 4. Redeem exchanges the approved device code for the first credential pair.
	redeem := f.do(h, http.MethodPost, "/api/v1/enroll/redeem",
		`{"device_code":"`+grant.DeviceCode+`"}`, "")
	if redeem.Code != http.StatusOK {
		t.Fatalf("redeem status = %d, want 200; body = %q", redeem.Code, redeem.Body.String())
	}
	first := decodeIssued(t, redeem)
	if first.RefreshToken == "" || first.AccessToken == "" {
		t.Fatalf("redeem did not disclose a credential pair: %+v", first)
	}
	if domainOwner := string(alice.OwnerID); first.OwnerID != domainOwner {
		t.Errorf("redeemed credential owner = %q, want the approving owner %q", first.OwnerID, domainOwner)
	}

	// 5. The first access token is accepted by the owner Guard: it verifies and
	// carries full-owner scope, so an account-wide route answers it.
	if rr := f.do(h, http.MethodGet, "/api/v1/devices", "", first.AccessToken); rr.Code != http.StatusOK {
		t.Fatalf("first access token at /devices = %d, want 200; the redeemed token does not verify.\nbody = %q",
			rr.Code, rr.Body.String())
	}

	// 6. Exchange rotates the refresh token single-use, minting a fresh pair on the
	// SAME lineage.
	exchange := f.do(h, http.MethodPost, "/api/v1/token",
		`{"refresh_token":"`+first.RefreshToken+`"}`, "")
	if exchange.Code != http.StatusOK {
		t.Fatalf("exchange status = %d, want 200; body = %q", exchange.Code, exchange.Body.String())
	}
	second := decodeIssued(t, exchange)
	if second.AccessToken == "" || second.AccessToken == first.AccessToken {
		t.Fatalf("exchange did not rotate to a fresh access token: %+v", second)
	}

	// 7. The SECOND access token is live and accepted -- proven BEFORE the replay,
	// so the refusal in step 9 can only be the revocation, not a token that never
	// worked.
	if rr := f.do(h, http.MethodGet, "/api/v1/devices", "", second.AccessToken); rr.Code != http.StatusOK {
		t.Fatalf("second access token at /devices before replay = %d, want 200.\nbody = %q",
			rr.Code, rr.Body.String())
	}

	// 8. Replaying the already-rotated refresh token is reuse-theft: it is refused
	// 401, and inside the token service it revokes the whole lineage.
	replay := f.do(h, http.MethodPost, "/api/v1/token",
		`{"refresh_token":"`+first.RefreshToken+`"}`, "")
	if replay.Code != http.StatusUnauthorized {
		t.Fatalf("refresh replay status = %d, want 401 (reuse-theft); body = %q", replay.Code, replay.Body.String())
	}

	// 9. THE assertion. The second access token was accepted at step 7; it is now
	// refused, because the lineage the replay revoked lands in the SAME denylist
	// the owner Guard consults. A 200 here means the token service and the Guard
	// hold different denylists -- decision #2 broken -- so a revoked lineage's
	// access tokens would live out their fifteen minutes.
	revoked := f.do(h, http.MethodGet, "/api/v1/devices", "", second.AccessToken)
	if revoked.Code != http.StatusUnauthorized {
		t.Fatalf("second access token AFTER lineage revocation = %d, want 401.\n"+
			"The enrollment/token services and the owner Guard do not share one denylist (ADR-0032).\nbody = %q",
			revoked.Code, revoked.Body.String())
	}
}

// TestEnrollmentPollPendingThroughRealWiring covers the 202 pending outcome the
// transport unit test could not (the real errPollPending sentinel is unexported):
// a started-but-unapproved pairing polls as pending.
func TestEnrollmentPollPendingThroughRealWiring(t *testing.T) {
	f := newMgmtFixture(t)
	h := f.handler()

	start := f.do(h, http.MethodPost, "/api/v1/enroll/device",
		`{"client_label":"waiting","scopes":[{"kind":"full-owner"}]}`, "")
	if start.Code != http.StatusCreated {
		t.Fatalf("start status = %d, want 201; body = %q", start.Code, start.Body.String())
	}
	grant := decodeGrant(t, start)

	poll := f.do(h, http.MethodPost, "/api/v1/enroll/poll",
		`{"device_code":"`+grant.DeviceCode+`"}`, "")
	if poll.Code != http.StatusAccepted {
		t.Fatalf("poll(pending) status = %d, want 202; body = %q", poll.Code, poll.Body.String())
	}
	if !strings.Contains(poll.Body.String(), "pending") {
		t.Errorf("poll body = %q, want pending", poll.Body.String())
	}
}

// TestEnrollmentManualMintFlowThroughRealWiring covers mode 2: an authenticated
// owner mints a pre-approved pairing (no user code -- the mint IS the approval)
// and redeems it for a working credential pair.
func TestEnrollmentManualMintFlowThroughRealWiring(t *testing.T) {
	f := newMgmtFixture(t)
	alice := f.seedOwner("alice", "alice-key")
	h := f.handler()
	ownerToken := mintAccessToken(t, gateSigningKey, alice.OwnerID)

	mint := f.do(h, http.MethodPost, "/api/v1/enroll/mint",
		`{"client_label":"backup host","scopes":[{"kind":"full-owner"}]}`, ownerToken)
	if mint.Code != http.StatusCreated {
		t.Fatalf("mint status = %d, want 201; body = %q", mint.Code, mint.Body.String())
	}
	grant := decodeGrant(t, mint)
	if grant.DeviceCode == "" {
		t.Fatalf("mint did not disclose a device code: %+v", grant)
	}
	// Mode 2 has no user code: the mint itself is the approval, so there is nothing
	// for an operator to transcribe. A non-empty one would mean the mint left the
	// pairing pending.
	if grant.UserCode != "" {
		t.Errorf("mint disclosed a user code %q; a minted pairing is already approved", grant.UserCode)
	}

	redeem := f.do(h, http.MethodPost, "/api/v1/enroll/redeem",
		`{"device_code":"`+grant.DeviceCode+`"}`, "")
	if redeem.Code != http.StatusOK {
		t.Fatalf("redeem status = %d, want 200; body = %q", redeem.Code, redeem.Body.String())
	}
	issued := decodeIssued(t, redeem)
	if issued.AccessToken == "" {
		t.Fatalf("redeem did not disclose an access token: %+v", issued)
	}

	if rr := f.do(h, http.MethodGet, "/api/v1/devices", "", issued.AccessToken); rr.Code != http.StatusOK {
		t.Fatalf("minted-then-redeemed access token at /devices = %d, want 200.\nbody = %q",
			rr.Code, rr.Body.String())
	}
}
