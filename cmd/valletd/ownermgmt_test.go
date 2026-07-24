package main

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/auth"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/secrets"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/telemetry"
)

// gateSigningKey is the access-token signing key these tests configure the
// server with. Like gatePepper, a constant is correct: what is under test is
// whether the mounted surface VERIFIES a token minted by the same key, not the
// secrecy of this value. It is 36 bytes, comfortably past auth.MinSigningKeyLen.
const gateSigningKey = "0123456789abcdef0123456789abcdef0123"

// gateOtherSigningKey is a DIFFERENT adequate key, used only to mint a
// well-formed token the server must reject on signature.
const gateOtherSigningKey = "ffffffffffffffffffffffffffffffff1234"

// newMgmtFixture is newGateFixture plus a resolvable token signing key, so the
// server built through handler() mounts the owner management surface live. The
// access key pepper is deliberately left unset: the management routes do not
// depend on it, and leaving it out keeps this fixture on the development path.
func newMgmtFixture(t *testing.T) *gateFixture {
	t.Helper()

	t.Setenv("VALLET_TEST_SIGNING_KEY", gateSigningKey)
	f := newGateFixture(t, "")
	f.cfg.Auth.TokenSigningKeyRef = secrets.Ref("env:VALLET_TEST_SIGNING_KEY")
	return f
}

// mintAccessToken signs a full-owner access token for ownerID with the given
// key, valid at wall-clock time.
//
// The window is anchored to time.Now, not gateNow: the guardian supplies its
// own clock (time.Now) to Authorize, so a token stamped at the fixed seeding
// instant would verify as long expired. A full-owner scope is used on purpose;
// the cross-tenant test below depends on it to prove the 404 comes from the
// owner-scoped repository miss (ADR-0004) rather than from a scope check.
func mintAccessToken(t *testing.T, key string, ownerID domain.OwnerID) string {
	t.Helper()

	signer, err := auth.NewAccessTokenSigner([]byte(key))
	if err != nil {
		t.Fatalf("NewAccessTokenSigner: %v", err)
	}
	now := time.Now()
	tok, err := signer.Issue(domain.AccessToken{
		ID:                  "at-" + string(ownerID),
		OwnerID:             ownerID,
		RefreshCredentialID: domain.RefreshCredentialID("rc-" + string(ownerID)),
		Scopes:              []domain.Scope{{Kind: domain.ScopeFullOwner}},
		IssuedAt:            now.Add(-time.Minute),
		ExpiresAt:           now.Add(15 * time.Minute),
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	return tok.Reveal()
}

// do issues one management request through the built handler.
func (f *gateFixture) do(h http.Handler, method, target, body, bearer string) *httptest.ResponseRecorder {
	f.t.Helper()

	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, target, r)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

// TestOwnerManagementSurfaceVerifiesLive is THE positive test for this change:
// a server built through the production assembly must verify a signer-minted
// access token and answer the owner's own management request, where before the
// wiring every credential got the fail-closed 401.
//
// The 200 is load bearing. The previous, unwired state answered 401 to every
// credential, so a test that only asserted a refusal would pass against it
// unchanged. The only way the list below returns 200 with the owner's sets is
// if buildAPIDeps actually handed WithAuthorizer and WithKeySetService to the
// handler and the handler actually consulted them.
func TestOwnerManagementSurfaceVerifiesLive(t *testing.T) {
	f := newMgmtFixture(t)
	alice := f.seedOwner("alice", "public-key")
	h := f.handler()
	token := mintAccessToken(t, gateSigningKey, alice.OwnerID)

	t.Run("a valid access token lists the owner's key sets", func(t *testing.T) {
		rr := f.do(h, http.MethodGet, "/api/v1/keysets", "", token)
		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200; the management surface never verified the token.\nbody = %q",
				rr.Code, rr.Body.String())
		}
		// The result must be owner A's OWN set, not merely a well-formed empty
		// envelope: an empty {"key_sets":[]} also contains "key_sets", so
		// asserting the id is what proves the owner-scoped read came back with
		// Alice's data rather than nothing.
		if !strings.Contains(rr.Body.String(), string(alice.KeySetID)) {
			t.Errorf("body = %q, want owner A's own key set %q", rr.Body.String(), alice.KeySetID)
		}
	})

	t.Run("absent, malformed, and bad-signature tokens are refused 401", func(t *testing.T) {
		// A well-formed token signed by a DIFFERENT adequate key: the server
		// must reject it on the MAC, not merely on shape.
		badSig := mintAccessToken(t, gateOtherSigningKey, alice.OwnerID)
		for name, bearer := range map[string]string{
			"absent":        "",
			"garbage":       "not-a-token",
			"bad signature": badSig,
		} {
			rr := f.do(h, http.MethodGet, "/api/v1/keysets", "", bearer)
			if rr.Code != http.StatusUnauthorized {
				t.Errorf("%s: status = %d, want 401", name, rr.Code)
			}
		}
	})
}

// TestOwnerManagementCrossTenantIsNotFound is the security-critical case
// (ADR-0004). A full-owner token for Alice, aimed at Bob's key set, must get the
// same reasonless 404 a missing set gets -- never 403 and never any detail that
// would confirm Bob's set exists.
//
// The 404 rather than 403 is the whole point: the management routes take the
// owner from the token and address resources by id, so KeySetAccess names no
// owner and the guard's scope check PASSES for a full-owner token. Isolation is
// then structural -- the owner-scoped repository read for Alice simply does not
// find Bob's row -- and the service collapses that miss into ErrNotFound. A 403
// here would mean the boundary was a scope check that could be probed.
func TestOwnerManagementCrossTenantIsNotFound(t *testing.T) {
	f := newMgmtFixture(t)
	alice := f.seedOwner("alice", "alice-key")
	bob := f.seedOwner("bob", "bob-key")
	h := f.handler()
	aliceToken := mintAccessToken(t, gateSigningKey, alice.OwnerID)

	target := "/api/v1/keysets/" + string(bob.KeySetID)
	rr := f.do(h, http.MethodPatch, target, `{"name":"stolen"}`, aliceToken)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant rename status = %d, want 404 (never 403, never an existence leak).\nbody = %q",
			rr.Code, rr.Body.String())
	}
	body := strings.TrimSpace(rr.Body.String())
	if body != `{"status":"error"}` {
		t.Errorf("404 body = %q, want the reasonless uniform error; a reason field would leak Bob's set", body)
	}
	if strings.Contains(body, string(bob.KeySetID)) {
		t.Errorf("404 body leaked the target set id: %q", body)
	}
}

// TestOwnerManagementRejectsReservedNames proves the shared reserved-identifier
// guard is live on the MOUNTED service path -- both at create and at rename --
// and not merely at the bootstrap seam it used to reach only.
func TestOwnerManagementRejectsReservedNames(t *testing.T) {
	f := newMgmtFixture(t)
	alice := f.seedOwner("alice", "alice-key")
	h := f.handler()
	token := mintAccessToken(t, gateSigningKey, alice.OwnerID)

	t.Run("create with a reserved name is rejected 400", func(t *testing.T) {
		rr := f.do(h, http.MethodPost, "/api/v1/keysets", `{"name":"admin"}`, token)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("create reserved status = %d, want 400; policy.Guard is not live on create.\nbody = %q",
				rr.Code, rr.Body.String())
		}
	})

	t.Run("rename to a reserved name is rejected 400", func(t *testing.T) {
		create := f.do(h, http.MethodPost, "/api/v1/keysets", `{"name":"staging"}`, token)
		if create.Code != http.StatusCreated {
			t.Fatalf("setup create status = %d, want 201.\nbody = %q", create.Code, create.Body.String())
		}
		var created struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(create.Body.Bytes(), &created); err != nil {
			t.Fatalf("decode created set: %v", err)
		}

		rr := f.do(h, http.MethodPatch, "/api/v1/keysets/"+created.ID, `{"name":"admin"}`, token)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("rename to reserved status = %d, want 400; policy.Guard is not live on rename.\nbody = %q",
				rr.Code, rr.Body.String())
		}
	})
}

// TestOwnerManagementDisabledWithoutSigningKey pins the fail-closed development
// mode: with no token signing key configured, none of the four options mount,
// the routes stay at the refuse-everyone 401 stub, and startup warns loudly.
//
// The warning is part of the contract, not decoration: a management API that
// silently refuses every valid-looking token is the failure an operator debugs
// from the client side for an hour, so the log line must name the component and
// the config field to set.
func TestOwnerManagementDisabledWithoutSigningKey(t *testing.T) {
	f := newGateFixture(t, "") // development, no signing key ref, no pepper
	alice := f.seedOwner("alice", "alice-key")
	h := f.handler()

	// A token that WOULD verify had the surface been mounted, so the 401 is the
	// absent authorizer refusing rather than a bad credential.
	token := mintAccessToken(t, gateSigningKey, alice.OwnerID)
	rr := f.do(h, http.MethodGet, "/api/v1/keysets", "", token)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("management status with no signing key = %d, want 401 (fail-closed stub).\nbody = %q",
			rr.Code, rr.Body.String())
	}
	if !strings.Contains(f.logs.String(), "no access token signing key configured") {
		t.Errorf("startup did not warn that the owner management API is disabled.\nlogs:\n%s", f.logs.String())
	}
}

// TestProductionRefusesAnAbsentSigningKey pins the one place the absent
// reference is not a valid choice, the signing-key parallel to
// TestProductionRefusesAnAbsentPepper.
//
// In development an unset signing key disables the management API, which is
// safe. In production it is refused instead: a deployment that believes it
// serves an authenticated management API and answers 401 to everyone, with no
// complaint, is the silent failure this check exists to prevent. The refusal
// lives in buildAPIDeps's own path as well as in config.Validate, and this test
// drives the former.
func TestProductionRefusesAnAbsentSigningKey(t *testing.T) {
	f := newGateFixture(t, "env:VALLET_TEST_PROD_PEPPER") // a pepper so newPublisher is not the refusal
	t.Setenv("VALLET_TEST_PROD_PEPPER", gatePepper)
	f.cfg.Server.Environment = "production"

	logger := slog.New(slog.NewTextHandler(f.logs, nil))
	tel := telemetry.New(f.cfg, logger)
	t.Cleanup(func() { shutdownTelemetry(tel, logger) })

	_, _, err := buildAPIDeps(context.Background(), f.cfg, logger, f.store, tel, nil)
	if err == nil {
		t.Fatal("production built the API with no access token signing key")
	}
	if !strings.Contains(err.Error(), "auth.token_signing_key_ref") {
		t.Errorf("the refusal does not name the config field an operator must set: %v", err)
	}
}
