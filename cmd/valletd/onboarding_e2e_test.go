package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/secrets"
)

// Admin-provisioned owner onboarding (ADR-0033) exercised through the REAL
// production assembly: buildServer -> buildAPIDeps -> mountOwnerManagement ->
// NewHandler, the same chain run() runs. The property this defends is a WIRING
// one -- that the one-time code an administrator receives from
// POST /api/v1/admin/owners is an enrollment grant the owner can redeem at the
// SAME /enroll/redeem route to mint their own tokens, and that the admin gate on
// the provisioning route is real. A transport-level test with hand-wired fakes
// could satisfy each half while production connected them to different services;
// only driving the actual composition can catch that.

// provisionBody is the one-time disclosure the provisioning route returns. It is
// decoded locally rather than imported from the transport package (whose wire
// struct is unexported) -- the field names are the wire contract, so pinning
// them here also guards against a silent rename.
type provisionBody struct {
	OwnerID        string `json:"owner_id"`
	Handle         string `json:"handle"`
	SetName        string `json:"set_name"`
	EnrollmentCode string `json:"enrollment_code"`
	PairingID      string `json:"pairing_id"`
}

// newOnboardingE2EFixture is a gate fixture with BOTH signing keys resolvable:
// the owner key (so the onboarding and enrollment services are mounted) and the
// admin key (so the AdminIdentifier verifies the administrator's token). Both
// are required for this round trip, unlike the single-surface fixtures.
func newOnboardingE2EFixture(t *testing.T) *gateFixture {
	t.Helper()

	t.Setenv("VALLET_TEST_SIGNING_KEY", gateSigningKey)
	t.Setenv("VALLET_TEST_ADMIN_SIGNING_KEY", gateAdminSigningKey)
	f := newGateFixture(t, "")
	f.cfg.Auth.TokenSigningKeyRef = secrets.Ref("env:VALLET_TEST_SIGNING_KEY")
	f.cfg.Auth.AdminTokenSigningKeyRef = secrets.Ref("env:VALLET_TEST_ADMIN_SIGNING_KEY")
	return f
}

func decodeProvision(t *testing.T, rr *httptest.ResponseRecorder) provisionBody {
	t.Helper()
	var p provisionBody
	if err := json.Unmarshal(rr.Body.Bytes(), &p); err != nil {
		t.Fatalf("decode provision: %v; body = %q", err, rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), "REDACTED") {
		t.Fatalf("provision body carried a [REDACTED] marker; the enrollment code was not revealed: %q", rr.Body.String())
	}
	return p
}

// TestAdminProvisionsOwnerThenOwnerEnrollsThroughRealWiring is the whole slice:
// an administrator provisions an owner, and the returned one-time code is
// redeemed by the owner through the REAL /enroll/redeem route to mint tokens
// that a management route then accepts. Every hop travels the production
// assembly.
func TestAdminProvisionsOwnerThenOwnerEnrollsThroughRealWiring(t *testing.T) {
	f := newOnboardingE2EFixture(t)
	const admin = domain.AdministratorID("adm-onboarder")
	f.seedAdmin(admin, domain.AdminStatusActive)
	h := f.handler()
	adminToken := mintAdminBearer(t, gateAdminSigningKey, admin)

	// 1. The administrator provisions a brand-new owner. The 201 is load bearing:
	// the unwired state answers 500 (no service) or 403 (no admin identity), so
	// only a fully wired admin gate plus onboarding service produces it.
	provision := f.do(h, http.MethodPost, "/api/v1/admin/owners",
		`{"handle":"newbie","client_label":"first host"}`, adminToken)
	if provision.Code != http.StatusCreated {
		t.Fatalf("provision status = %d, want 201; body = %q", provision.Code, provision.Body.String())
	}
	owner := decodeProvision(t, provision)
	if owner.OwnerID == "" || owner.EnrollmentCode == "" {
		t.Fatalf("provision did not disclose an owner id and enrollment code: %+v", owner)
	}
	if owner.Handle != "newbie" || owner.SetName != "default" {
		t.Fatalf("provision body = %+v, want handle newbie / set default", owner)
	}

	// 2. The owner redeems the provisioning code at the SAME enrollment route the
	// device-grant and mint flows use. This is the wiring assertion: the code the
	// admin route handed out IS an enrollSvc.Mint device code.
	redeem := f.do(h, http.MethodPost, "/api/v1/enroll/redeem",
		`{"device_code":"`+owner.EnrollmentCode+`"}`, "")
	if redeem.Code != http.StatusOK {
		t.Fatalf("redeem status = %d, want 200; the provisioning code did not redeem.\nbody = %q",
			redeem.Code, redeem.Body.String())
	}
	issued := decodeIssued(t, redeem)
	if issued.AccessToken == "" || issued.RefreshToken == "" {
		t.Fatalf("redeem did not disclose a credential pair: %+v", issued)
	}
	if issued.OwnerID != owner.OwnerID {
		t.Fatalf("redeemed credential owner = %q, want the provisioned owner %q", issued.OwnerID, owner.OwnerID)
	}

	// 3. The owner's own access token is accepted by a management route: the
	// provisioned owner is real, active, and full-owner scoped.
	if rr := f.do(h, http.MethodGet, "/api/v1/devices", "", issued.AccessToken); rr.Code != http.StatusOK {
		t.Fatalf("provisioned owner's access token at /devices = %d, want 200.\nbody = %q",
			rr.Code, rr.Body.String())
	}

	// 4. The owner's public default key set is routable and serves (empty). The
	// provision opened it as a public default, so /{handle} answers 200 rather
	// than the 404 an unprovisioned name gets.
	if rr := f.do(h, http.MethodGet, "/newbie/default", "", ""); rr.Code != http.StatusOK {
		t.Fatalf("provisioned handle /newbie/default = %d, want 200.\nbody = %q", rr.Code, rr.Body.String())
	}
}

// TestAdminOwnerProvisioningRejectsANonAdminBearer proves the admin gate on the
// provisioning route is real in the production wiring: an OWNER's access token
// (valid on the management surface) is not an administrator and is refused 403,
// so no owner is created. It complements the transport unit test by driving the
// actual signed-admin identifier rather than a fake.
func TestAdminOwnerProvisioningRejectsANonAdminBearer(t *testing.T) {
	f := newOnboardingE2EFixture(t)
	alice := f.seedOwner("alice", "alice-key")
	h := f.handler()
	ownerToken := mintAccessToken(t, gateSigningKey, alice.OwnerID)

	rr := f.do(h, http.MethodPost, "/api/v1/admin/owners", `{"handle":"newbie"}`, ownerToken)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("owner token on the provisioning route = %d, want 403.\nbody = %q", rr.Code, rr.Body.String())
	}
	// The handle was not claimed: the refusal happened before any write.
	if got := f.do(h, http.MethodGet, "/newbie/default", "", ""); got.Code != http.StatusNotFound {
		t.Fatalf("a refused provision still claimed the handle: /newbie/default = %d, want 404", got.Code)
	}
}
