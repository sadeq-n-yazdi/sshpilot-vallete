package httpserver_test

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/audit"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	httpserver "github.com/sadeq-n-yazdi/sshpilot-vallete/internal/transport/http"
)

// Every test here drives the REAL handler built by NewHandler, over the REAL
// auth.Guard and the REAL device service. That is deliberate and is the whole
// point of the file: B5 shipped a Guardian that was defined and never mounted,
// and a test that called a handler function directly would have been perfectly
// green while the route table enforced nothing. Nothing below can pass unless
// the route is actually registered behind Protect.

const devicesPath = "/api/v1/devices"

func TestRegisterListRevokeRoundTrip(t *testing.T) {
	t.Parallel()

	env := newDeviceEnv(t)
	token := env.token(t, "owner-a", domain.Scope{Kind: domain.ScopeFullOwner})

	created := env.mustRegister(t, token, "work laptop")
	if created.Status != string(domain.DeviceStatusActive) {
		t.Errorf("status = %q, want active", created.Status)
	}
	if created.ID == "" {
		t.Fatal("register returned no device id")
	}

	list := env.mustList(t, token)
	if len(list) != 1 || list[0].ID != created.ID {
		t.Fatalf("list = %v, want the one device just created", list)
	}

	rr := env.do(t, http.MethodDelete, devicesPath+"/"+created.ID, token, "")
	if rr.Code != http.StatusNoContent {
		t.Fatalf("revoke = %d, want 204", rr.Code)
	}
	if rr.Body.Len() != 0 {
		t.Errorf("204 carried a %d-byte body, want none", rr.Body.Len())
	}

	after := env.mustList(t, token)
	if len(after) != 1 || after[0].Status != string(domain.DeviceStatusRevoked) {
		t.Fatalf("list after revoke = %v, want one revoked device", after)
	}
}

// TestResponsesCarryVaryOnAuthorization pins the header that keeps a shared
// cache from serving one owner's device list to another.
func TestResponsesCarryVaryOnAuthorization(t *testing.T) {
	t.Parallel()

	env := newDeviceEnv(t)
	token := env.token(t, "owner-a", domain.Scope{Kind: domain.ScopeFullOwner})
	env.mustRegister(t, token, "laptop")

	rr := env.do(t, http.MethodGet, devicesPath, token, "")
	if got := rr.Header().Get("Vary"); got != "Authorization" {
		t.Errorf("Vary = %q on a successful list, want Authorization", got)
	}
}

// TestOwnerComesFromTokenNotRequest is the core invariant. Owner B registers a
// device while trying every request-side channel to claim it belongs to owner
// A; the device must end up owned by B.
func TestOwnerComesFromTokenNotRequest(t *testing.T) {
	t.Parallel()

	env := newDeviceEnv(t)
	tokenB := env.token(t, "owner-b", domain.Scope{Kind: domain.ScopeFullOwner})

	// A body naming another owner must be refused outright, not silently
	// stripped. Silently stripping would be safe today and would make the
	// absence of an owner field a convention that a future decoder change could
	// undo without any test noticing.
	rr := env.do(t, http.MethodPost, devicesPath, tokenB, `{"name":"x","owner_id":"owner-a"}`)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("body asserting an owner = %d, want 400", rr.Code)
	}

	// Headers and query parameters are the other two channels. Neither may
	// redirect ownership.
	req := httptest.NewRequest(http.MethodPost, devicesPath+"?owner_id=owner-a&owner=owner-a",
		strings.NewReader(`{"name":"laptop"}`))
	req.Header.Set("Authorization", "Bearer "+tokenB)
	req.Header.Set("X-Owner-ID", "owner-a")
	rec := httptest.NewRecorder()
	env.handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("register = %d, want 201", rec.Code)
	}

	// The device must belong to owner B, checked at the repository rather than
	// through the response: the response deliberately does not echo an owner,
	// so the storage layer is the only honest witness.
	var got deviceJSON
	decodeInto(t, rec, &got)
	stored, err := env.repo.Get(t.Context(), "owner-b", domain.DeviceID(got.ID))
	if err != nil {
		t.Fatalf("device is not owned by the token's owner: %v", err)
	}
	if stored.OwnerID != "owner-b" {
		t.Fatalf("stored owner = %q, want owner-b", stored.OwnerID)
	}
}

// TestRevokeOwnerComesFromTokenNotRequest is the revoke route's version of the
// owner-boundary test, and it exists because a mutation survived without it:
// making the handler prefer an owner from a request header went undetected,
// since the cross-owner test below attacks with a token alone and never tries
// to ASSERT an owner. A 404 for a caller who did not claim to be someone else
// does not prove the handler would refuse one who did.
func TestRevokeOwnerComesFromTokenNotRequest(t *testing.T) {
	t.Parallel()

	env := newDeviceEnv(t)
	tokenA := env.token(t, "owner-a", domain.Scope{Kind: domain.ScopeFullOwner})
	tokenB := env.token(t, "owner-b", domain.Scope{Kind: domain.ScopeFullOwner})
	victim := env.mustRegister(t, tokenA, "owner a laptop")

	// Owner B, holding a valid token, addresses owner A's device and asserts
	// owner A through every channel a handler might be tempted to read.
	target := devicesPath + "/" + victim.ID + "?owner_id=owner-a&owner=owner-a"
	req := httptest.NewRequest(http.MethodDelete, target, nil)
	req.Header.Set("Authorization", "Bearer "+tokenB)
	req.Header.Set("X-Owner-ID", "owner-a")
	req.Header.Set("X-Owner", "owner-a")
	rec := httptest.NewRecorder()
	env.handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("revoke asserting another owner = %d, want 404", rec.Code)
	}
	stored, err := env.repo.Get(t.Context(), "owner-a", domain.DeviceID(victim.ID))
	if err != nil {
		t.Fatalf("owner A's device disappeared: %v", err)
	}
	if stored.Status != domain.DeviceStatusActive {
		t.Fatalf("owner A's device was revoked by owner B asserting an owner; status = %q", stored.Status)
	}
}

// TestRegisterOwnerAssertionIsIgnoredOnEveryChannel is the register route's
// equivalent, kept separate so a failure names which route leaked.
func TestRegisterOwnerAssertionIsIgnoredOnEveryChannel(t *testing.T) {
	t.Parallel()

	env := newDeviceEnv(t)
	tokenB := env.token(t, "owner-b", domain.Scope{Kind: domain.ScopeFullOwner})

	req := httptest.NewRequest(http.MethodPost, devicesPath+"?owner_id=owner-a",
		strings.NewReader(`{"name":"laptop"}`))
	req.Header.Set("Authorization", "Bearer "+tokenB)
	req.Header.Set("X-Owner-ID", "owner-a")
	rec := httptest.NewRecorder()
	env.handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("register = %d, want 201", rec.Code)
	}

	var got deviceJSON
	decodeInto(t, rec, &got)
	if _, err := env.repo.Get(t.Context(), "owner-a", domain.DeviceID(got.ID)); err == nil {
		t.Fatal("the device was created under the owner named by the request, not the token")
	}
	if _, err := env.repo.Get(t.Context(), "owner-b", domain.DeviceID(got.ID)); err != nil {
		t.Fatalf("the device is not owned by the token's owner: %v", err)
	}
}

// TestCrossOwnerIsIndistinguishableFromAbsent is the enumeration test required
// per endpoint. For every management route that names a device, owner B using
// owner A's id must get byte-for-byte what it gets for an id nobody owns.
func TestCrossOwnerIsIndistinguishableFromAbsent(t *testing.T) {
	t.Parallel()

	env := newDeviceEnv(t)
	tokenA := env.token(t, "owner-a", domain.Scope{Kind: domain.ScopeFullOwner})
	tokenB := env.token(t, "owner-b", domain.Scope{Kind: domain.ScopeFullOwner})
	victim := env.mustRegister(t, tokenA, "owner a laptop")

	crossOwner := env.do(t, http.MethodDelete, devicesPath+"/"+victim.ID, tokenB, "")
	absent := env.do(t, http.MethodDelete, devicesPath+"/ZZZZZZZZZZZZZZZZZZZZZZZZZZ", tokenB, "")
	assertIndistinguishable(t, "another owner's device", crossOwner, "a device that never existed", absent)

	if crossOwner.Code != http.StatusNotFound {
		t.Errorf("cross-owner revoke = %d, want 404", crossOwner.Code)
	}

	// And the refusal must be a refusal: owner A's device is untouched.
	stored, err := env.repo.Get(t.Context(), "owner-a", domain.DeviceID(victim.ID))
	if err != nil {
		t.Fatalf("owner A's device disappeared: %v", err)
	}
	if stored.Status != domain.DeviceStatusActive {
		t.Errorf("owner A's device status = %q after owner B's revoke, want active", stored.Status)
	}
}

// TestListNeverLeaksAnotherOwnersDevices is the list endpoint's cross-owner
// check. There is no id to probe with, so the leak would be in the collection
// itself.
func TestListNeverLeaksAnotherOwnersDevices(t *testing.T) {
	t.Parallel()

	env := newDeviceEnv(t)
	tokenA := env.token(t, "owner-a", domain.Scope{Kind: domain.ScopeFullOwner})
	tokenB := env.token(t, "owner-b", domain.Scope{Kind: domain.ScopeFullOwner})
	env.mustRegister(t, tokenA, "owner a laptop")

	// Owner B has registered nothing, so an empty list is the only correct
	// answer, and it must be an empty array rather than null.
	rr := env.do(t, http.MethodGet, devicesPath, tokenB, "")
	if rr.Code != http.StatusOK {
		t.Fatalf("list = %d, want 200", rr.Code)
	}
	if got := rr.Body.String(); !strings.Contains(got, `"devices":[]`) {
		t.Fatalf("owner B's list = %s, want an empty devices array", got)
	}
	if strings.Contains(rr.Body.String(), "owner a laptop") {
		t.Fatal("owner B's list disclosed owner A's device")
	}

	// Now owner B asks again while asserting that it is owner A. A 200 with an
	// empty list above does not prove the handler ignores an asserted owner,
	// because owner B never asserted one -- a mutation that preferred a header
	// survived precisely through that gap.
	req := httptest.NewRequest(http.MethodGet, devicesPath+"?owner_id=owner-a&owner=owner-a", nil)
	req.Header.Set("Authorization", "Bearer "+tokenB)
	req.Header.Set("X-Owner-ID", "owner-a")
	req.Header.Set("X-Owner", "owner-a")
	rec := httptest.NewRecorder()
	env.handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("list asserting another owner = %d, want 200", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "owner a laptop") {
		t.Fatalf("asserting an owner disclosed that owner's devices: %s", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"devices":[]`) {
		t.Fatalf("list asserting another owner = %s, want owner B's own empty list", rec.Body.String())
	}
}

// TestRevokeIsIdempotentSafeAndNotAnOracle proves the decision recorded in the
// service: the repeat, the stranger's id, and the nonexistent id are ONE
// response. If a repeat answered 204 while a stranger's id answered 404, the
// difference would report whether the caller had ever owned that device.
func TestRevokeIsIdempotentSafeAndNotAnOracle(t *testing.T) {
	t.Parallel()

	env := newDeviceEnv(t)
	tokenA := env.token(t, "owner-a", domain.Scope{Kind: domain.ScopeFullOwner})
	tokenB := env.token(t, "owner-b", domain.Scope{Kind: domain.ScopeFullOwner})

	mine := env.mustRegister(t, tokenA, "laptop")
	theirs := env.mustRegister(t, tokenB, "their laptop")

	if rr := env.do(t, http.MethodDelete, devicesPath+"/"+mine.ID, tokenA, ""); rr.Code != http.StatusNoContent {
		t.Fatalf("first revoke = %d, want 204", rr.Code)
	}

	repeat := env.do(t, http.MethodDelete, devicesPath+"/"+mine.ID, tokenA, "")
	stranger := env.do(t, http.MethodDelete, devicesPath+"/"+theirs.ID, tokenA, "")
	absent := env.do(t, http.MethodDelete, devicesPath+"/ZZZZZZZZZZZZZZZZZZZZZZZZZZ", tokenA, "")

	if repeat.Code != http.StatusNotFound {
		t.Errorf("repeat revoke = %d, want 404", repeat.Code)
	}
	assertIndistinguishable(t, "an already-revoked device", repeat, "another owner's device", stranger)
	assertIndistinguishable(t, "an already-revoked device", repeat, "a device that never existed", absent)

	// Idempotent-safe means the repeat changed nothing, which the 404 alone
	// does not prove.
	stored, err := env.repo.Get(t.Context(), "owner-a", domain.DeviceID(mine.ID))
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if stored.Status != domain.DeviceStatusRevoked {
		t.Errorf("status = %q after a repeat revoke, want still revoked", stored.Status)
	}
	// And it emitted no second audit record: the repeat was not an event.
	if got := env.auditCount(domain.AuditActionDeviceRevoked); got != 1 {
		t.Errorf("%d revocation audit records, want 1; the repeat must not be recorded as an event", got)
	}
}

// TestReadOnlyTokenCannotMutate is the scope test for the mutating routes. The
// verdict comes from auth.Guard via the route's AccessFunc, not from a check
// the handler performs, so this also proves the wiring rather than a duplicate.
func TestReadOnlyTokenCannotMutate(t *testing.T) {
	t.Parallel()

	env := newDeviceEnv(t)
	full := env.token(t, "owner-a", domain.Scope{Kind: domain.ScopeFullOwner})
	readOnly := env.token(t, "owner-a", domain.Scope{Kind: domain.ScopeReadOnly})
	existing := env.mustRegister(t, full, "laptop")

	t.Run("register", func(t *testing.T) {
		t.Parallel()

		rr := env.do(t, http.MethodPost, devicesPath, readOnly, `{"name":"sneaky"}`)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("register with a read-only token = %d, want 403", rr.Code)
		}
	})

	t.Run("revoke", func(t *testing.T) {
		t.Parallel()

		rr := env.do(t, http.MethodDelete, devicesPath+"/"+existing.ID, readOnly, "")
		if rr.Code != http.StatusForbidden {
			t.Fatalf("revoke with a read-only token = %d, want 403", rr.Code)
		}
	})

	t.Run("list is still permitted", func(t *testing.T) {
		t.Parallel()

		// The refusals above must come from the token being read-only, not from
		// a read-only token being rejected everywhere -- otherwise the two
		// subtests above would pass for the wrong reason.
		if rr := env.do(t, http.MethodGet, devicesPath, readOnly, ""); rr.Code != http.StatusOK {
			t.Fatalf("list with a read-only token = %d, want 200", rr.Code)
		}
	})
}

// TestSingleDeviceTokenIsConfinedToItsDevice is the scope test for the
// resource-bound kind.
func TestSingleDeviceTokenIsConfinedToItsDevice(t *testing.T) {
	t.Parallel()

	env := newDeviceEnv(t)
	full := env.token(t, "owner-a", domain.Scope{Kind: domain.ScopeFullOwner})
	mine := env.mustRegister(t, full, "bound device")
	other := env.mustRegister(t, full, "other device")

	bound := env.token(t, "owner-a", domain.Scope{Kind: domain.ScopeSingleDevice, ResourceID: mine.ID})

	t.Run("reaches its own device", func(t *testing.T) {
		t.Parallel()

		if rr := env.do(t, http.MethodDelete, devicesPath+"/"+mine.ID, bound, ""); rr.Code != http.StatusNoContent {
			t.Fatalf("revoking its own device = %d, want 204", rr.Code)
		}
	})

	t.Run("cannot reach another device of the same owner", func(t *testing.T) {
		t.Parallel()

		// Same owner, different device: the owner check passes and the scope
		// check is the only thing standing in the way, which is exactly what
		// this asserts.
		if rr := env.do(t, http.MethodDelete, devicesPath+"/"+other.ID, bound, ""); rr.Code != http.StatusForbidden {
			t.Fatalf("revoking a different device = %d, want 403", rr.Code)
		}
	})

	t.Run("cannot reach the account-wide list", func(t *testing.T) {
		t.Parallel()

		if rr := env.do(t, http.MethodGet, devicesPath, bound, ""); rr.Code != http.StatusForbidden {
			t.Fatalf("listing with a device-bound token = %d, want 403", rr.Code)
		}
	})

	t.Run("cannot register", func(t *testing.T) {
		t.Parallel()

		if rr := env.do(t, http.MethodPost, devicesPath, bound, `{"name":"new"}`); rr.Code != http.StatusForbidden {
			t.Fatalf("registering with a device-bound token = %d, want 403", rr.Code)
		}
	})
}

// TestRevokeActsOnExactlyTheDeviceItAuthorized closes the confused-deputy gap:
// the scope check reads the device id out of the path (DeviceAccess), so if the
// handler could be steered to a DIFFERENT device by any other part of the
// request, a token would authorize one resource while the server mutated
// another. The scope check would pass, honestly, on a device the caller never
// touched.
//
// This test exists because a mutation survived without it. The confinement test
// above only ever names one device per request, so it cannot tell "the handler
// used the path" from "the handler used something that happened to agree with
// the path".
func TestRevokeActsOnExactlyTheDeviceItAuthorized(t *testing.T) {
	t.Parallel()

	env := newDeviceEnv(t)
	full := env.token(t, "owner-a", domain.Scope{Kind: domain.ScopeFullOwner})
	authorized := env.mustRegister(t, full, "the authorized device")
	bystander := env.mustRegister(t, full, "the bystander")
	bound := env.token(t, "owner-a", domain.Scope{Kind: domain.ScopeSingleDevice, ResourceID: authorized.ID})

	// The path names the device the token is bound to, so authorization
	// legitimately succeeds. Every other channel names the bystander.
	target := devicesPath + "/" + authorized.ID + "?device=" + bystander.ID + "&id=" + bystander.ID
	req := httptest.NewRequest(http.MethodDelete, target, nil)
	req.Header.Set("Authorization", "Bearer "+bound)
	req.Header.Set("X-Device-ID", bystander.ID)
	req.Header.Set("X-Device", bystander.ID)
	rec := httptest.NewRecorder()
	env.handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("revoke of the authorized device = %d, want 204", rec.Code)
	}

	// The bystander must be untouched: it was never authorized, and nothing
	// outside the path may select what gets revoked.
	stored, err := env.repo.Get(t.Context(), "owner-a", domain.DeviceID(bystander.ID))
	if err != nil {
		t.Fatalf("Get bystander: %v", err)
	}
	if stored.Status != domain.DeviceStatusActive {
		t.Fatalf("the bystander was revoked; the handler acted on a device the scope check never authorized")
	}
	// And the device that WAS authorized is the one that changed.
	target2, err := env.repo.Get(t.Context(), "owner-a", domain.DeviceID(authorized.ID))
	if err != nil {
		t.Fatalf("Get authorized: %v", err)
	}
	if target2.Status != domain.DeviceStatusRevoked {
		t.Fatalf("the authorized device was not revoked; status = %q", target2.Status)
	}
}

// TestManagementRoutesRefuseWithoutACredential proves the routes are mounted
// behind Protect. An unmounted or unprotected route would answer 404 or 200
// here, never 401.
func TestManagementRoutesRefuseWithoutACredential(t *testing.T) {
	t.Parallel()

	env := newDeviceEnv(t)
	requests := map[string][2]string{
		"register": {http.MethodPost, devicesPath},
		"list":     {http.MethodGet, devicesPath},
		"revoke":   {http.MethodDelete, devicesPath + "/anything"},
	}
	for name, spec := range requests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			rr := env.do(t, spec[0], spec[1], "", `{"name":"x"}`)
			if rr.Code != http.StatusUnauthorized {
				t.Fatalf("unauthenticated %s = %d, want 401", name, rr.Code)
			}
			if got := rr.Header().Get("WWW-Authenticate"); got != "Bearer" {
				t.Errorf("WWW-Authenticate = %q, want Bearer", got)
			}
			if got := rr.Header().Get("Vary"); got != "Authorization" {
				t.Errorf("Vary = %q, want Authorization", got)
			}
		})
	}

	// Nothing was created by any of those requests.
	if n := env.repo.count(); n != 0 {
		t.Errorf("%d devices exist after only unauthenticated requests", n)
	}
}

// TestManagementRoutesFailClosedWithoutAnAuthorizer covers the wiring gap that
// exists in cmd/valletd today: a handler built without WithAuthorizer must
// refuse every management request rather than serve one, and must not answer
// 404 as though the feature were absent.
func TestManagementRoutesFailClosedWithoutAnAuthorizer(t *testing.T) {
	t.Parallel()

	handler := httpserver.NewHandler(nil, nil, devicePinger{}, devicePublisher{})
	for _, spec := range [][2]string{
		{http.MethodPost, devicesPath},
		{http.MethodGet, devicesPath},
		{http.MethodDelete, devicesPath + "/anything"},
	} {
		req := httptest.NewRequest(spec[0], spec[1], strings.NewReader(`{"name":"x"}`))
		// A well-formed credential, so the refusal cannot be blamed on parsing.
		req.Header.Set("Authorization", "Bearer "+strings.Repeat("t", 40))
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s %s with no authorizer wired = %d, want 401", spec[0], spec[1], rec.Code)
		}
	}
}

// TestManagementRoutesReturn500WhenTheServiceIsMissing pins the other half of
// the wiring story: authorization present, service absent. It must be a 500, not
// a 404 that reads as "no such device" and hides a broken deployment.
func TestManagementRoutesReturn500WhenTheServiceIsMissing(t *testing.T) {
	t.Parallel()

	env := newDeviceEnv(t)
	handler := httpserver.NewHandler(nil, nil, devicePinger{}, devicePublisher{},
		httpserver.WithAuthorizer(env.guard))
	token := env.token(t, "owner-a", domain.Scope{Kind: domain.ScopeFullOwner})

	req := httptest.NewRequest(http.MethodGet, devicesPath, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("list with no service wired = %d, want 500", rec.Code)
	}
}

// TestRegisterRejectsBadBodies checks the input surface. Each of these reports
// only on what the caller sent, which is why 400 is safe here while the device
// lookup path collapses to 404.
func TestRegisterRejectsBadBodies(t *testing.T) {
	t.Parallel()

	env := newDeviceEnv(t)
	token := env.token(t, "owner-a", domain.Scope{Kind: domain.ScopeFullOwner})

	bodies := map[string]string{
		"not json":          `{`,
		"unknown field":     `{"name":"x","admin":true}`,
		"missing name":      `{}`,
		"empty name":        `{"name":""}`,
		"control character": `{"name":"a\nb"}`,
		"over length":       `{"name":"` + strings.Repeat("a", 65) + `"}`,
		"two json values":   `{"name":"a"}{"name":"b"}`,
		"oversized":         `{"name":"` + strings.Repeat("a", 8192) + `"}`,
	}
	for name, body := range bodies {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			rr := env.do(t, http.MethodPost, devicesPath, token, body)
			if rr.Code != http.StatusBadRequest {
				t.Fatalf("got %d, want 400", rr.Code)
			}
			if got := rr.Body.String(); !strings.Contains(got, `"status":"error"`) {
				t.Errorf("body = %s, want the uniform error object", got)
			}
		})
	}
	if n := env.repo.count(); n != 0 {
		t.Errorf("%d devices created from rejected bodies", n)
	}
}

// TestDeviceNamesNeverReachTheRequestLog pins the logging prohibition. The
// audit record carries the name deliberately; the request log must not.
func TestDeviceNamesNeverReachTheRequestLog(t *testing.T) {
	t.Parallel()

	const secretName = "kitchen-nas-supersecret"
	var logs bytes.Buffer
	env := newDeviceEnvWithLogger(t, slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	token := env.token(t, "owner-a", domain.Scope{Kind: domain.ScopeFullOwner})

	created := env.mustRegister(t, token, secretName)
	if rr := env.do(t, http.MethodDelete, devicesPath+"/"+created.ID, token, ""); rr.Code != http.StatusNoContent {
		t.Fatalf("revoke = %d, want 204", rr.Code)
	}

	if strings.Contains(logs.String(), secretName) {
		t.Errorf("the device name reached the request log:\n%s", logs.String())
	}
	// The audit trail, which is access-controlled and retention-governed, is
	// where the name belongs -- so a test that merely found no name anywhere
	// would also pass if auditing had been dropped entirely.
	if !env.auditHasDetail(audit.DetailDeviceName, secretName) {
		t.Error("the device name is absent from the audit trail, where it belongs")
	}
}

// TestAuditRecordsAreEmittedForAccessAffectingChanges pins the audit
// requirement itself, at the transport level, so dropping the emit fails here
// and not only in the service's own tests.
func TestAuditRecordsAreEmittedForAccessAffectingChanges(t *testing.T) {
	t.Parallel()

	env := newDeviceEnv(t)
	token := env.token(t, "owner-a", domain.Scope{Kind: domain.ScopeFullOwner})
	created := env.mustRegister(t, token, "laptop")

	if got := env.auditCount(domain.AuditActionDeviceRegistered); got != 1 {
		t.Errorf("%d registration audit records, want 1", got)
	}
	if rr := env.do(t, http.MethodDelete, devicesPath+"/"+created.ID, token, ""); rr.Code != http.StatusNoContent {
		t.Fatalf("revoke = %d, want 204", rr.Code)
	}
	if got := env.auditCount(domain.AuditActionDeviceRevoked); got != 1 {
		t.Errorf("%d revocation audit records, want 1", got)
	}

	// A list is a read and must not be audited: an audit log that records reads
	// as access-affecting changes drowns the changes that matter.
	before := len(env.sink.records)
	if rr := env.do(t, http.MethodGet, devicesPath, token, ""); rr.Code != http.StatusOK {
		t.Fatalf("list = %d, want 200", rr.Code)
	}
	if len(env.sink.records) != before {
		t.Error("listing devices emitted an audit record")
	}
}

// assertIndistinguishable requires two responses to be identical in every
// channel a caller can observe: status, body, and the headers that could carry
// a difference.
func assertIndistinguishable(t *testing.T, aName string, a *httptest.ResponseRecorder, bName string, b *httptest.ResponseRecorder) {
	t.Helper()

	if a.Code != b.Code {
		t.Errorf("status differs: %s = %d, %s = %d", aName, a.Code, bName, b.Code)
	}
	if a.Body.String() != b.Body.String() {
		t.Errorf("body differs: %s = %q, %s = %q", aName, a.Body.String(), bName, b.Body.String())
	}
	for _, h := range []string{"Content-Type", "Cache-Control", "Vary", "WWW-Authenticate", "X-Content-Type-Options", "Content-Length"} {
		if a.Header().Get(h) != b.Header().Get(h) {
			t.Errorf("%s header differs: %s = %q, %s = %q", h, aName, a.Header().Get(h), bName, b.Header().Get(h))
		}
	}
}
