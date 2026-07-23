package main

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/auth"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/secrets"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/telemetry"
)

// gateAdminSigningKey is the admin-token signing key these tests configure the
// server with. Like gateSigningKey, a constant is correct: what is under test is
// whether the mounted admin surface VERIFIES a token minted by the same key, not
// the secrecy of this value. It is 36 bytes, past auth.MinSigningKeyLen.
const gateAdminSigningKey = "abcdef0123456789abcdef0123456789abcd"

// gateAdminOtherSigningKey is a DIFFERENT adequate key, used only to mint a
// well-formed admin token the server must reject on signature.
const gateAdminOtherSigningKey = "99999999999999999999999999999999beef"

// newAdminMgmtFixture is newGateFixture plus a resolvable admin token signing
// key, so the server built through handler() wires the administrator surface
// live. The pepper and owner signing key are left unset: the admin routes
// depend on neither, and leaving them out keeps this fixture on the development
// path.
func newAdminMgmtFixture(t *testing.T) *gateFixture {
	t.Helper()

	t.Setenv("VALLET_TEST_ADMIN_SIGNING_KEY", gateAdminSigningKey)
	f := newGateFixture(t, "")
	f.cfg.Auth.AdminTokenSigningKeyRef = secrets.Ref("env:VALLET_TEST_ADMIN_SIGNING_KEY")
	return f
}

// seedAdmin inserts an administrator row directly, the way bootstrap-admin does,
// so a minted token has a real row to be authorized against.
func (f *gateFixture) seedAdmin(id domain.AdministratorID, status domain.AdminStatus) {
	f.t.Helper()
	if err := f.store.Repos().Admins.Create(context.Background(), &domain.Administrator{
		ID:        id,
		Label:     "test-" + string(id),
		Status:    status,
		CreatedAt: gateNow,
		UpdatedAt: gateNow,
	}); err != nil {
		f.t.Fatalf("seed admin %q: %v", id, err)
	}
}

// mintAdminBearer signs an administrator token for id with key, valid at
// wall-clock time -- the guardian-less admin identifier uses time.Now, so a
// token stamped at the fixed seeding instant would verify as long expired.
func mintAdminBearer(t *testing.T, key string, id domain.AdministratorID) string {
	t.Helper()
	signer, err := auth.NewAdminTokenSigner([]byte(key))
	if err != nil {
		t.Fatalf("NewAdminTokenSigner: %v", err)
	}
	now := time.Now()
	tok, err := signer.Issue(id, "jti-"+string(id), now.Add(-time.Minute), now.Add(time.Hour))
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	return tok.Reveal()
}

// TestAdminSurfaceVerifiesLive is THE positive test for this change: a server
// built through the production assembly must verify a signer-minted admin token
// and APPLY the list edit (204), where before the wiring every credential got
// the fail-closed 403.
//
// The 204 is load bearing. The unwired state answered 403 to every credential,
// so a test that only asserted a refusal would pass against it unchanged. The
// only way an allowlist add returns 204 is if buildAPIDeps actually handed
// WithAdminIdentifier to the handler and the handler consulted it.
func TestAdminSurfaceVerifiesLive(t *testing.T) {
	f := newAdminMgmtFixture(t)
	const admin = domain.AdministratorID("adm-live")
	f.seedAdmin(admin, domain.AdminStatusActive)
	h := f.handler()

	t.Run("a valid admin token applies the edit 204", func(t *testing.T) {
		token := mintAdminBearer(t, gateAdminSigningKey, admin)
		rr := f.do(h, http.MethodPost, "/api/v1/admin/reserved/allowlist", `{"entry":"widget"}`, token)
		if rr.Code != http.StatusNoContent {
			t.Fatalf("status = %d, want 204; the admin surface never verified the token.\nbody = %q",
				rr.Code, rr.Body.String())
		}
	})

	t.Run("absent, garbage, and wrong-key tokens are refused 403", func(t *testing.T) {
		// A well-formed admin token signed by a DIFFERENT adequate key: rejected on
		// the MAC, not merely on shape.
		badSig := mintAdminBearer(t, gateAdminOtherSigningKey, admin)
		for name, bearer := range map[string]string{
			"absent":    "",
			"garbage":   "not-a-token",
			"wrong key": badSig,
		} {
			rr := f.do(h, http.MethodPost, "/api/v1/admin/reserved/blocklist", `{"entry":"frobnicate"}`, bearer)
			if rr.Code != http.StatusForbidden {
				t.Errorf("%s: status = %d, want 403", name, rr.Code)
			}
		}
	})
}

// TestAdminSurfaceRefusesDisabledAdmin is the revocation story of ADR-0031: a
// validly-signed token for an administrator whose row is disabled is refused,
// with no per-token revocation and no extra code -- listadmin's Get -> Active
// check does it. The 403 is identical to the unknown-admin 403, so a caller
// cannot tell a disabled admin from a nonexistent one.
func TestAdminSurfaceRefusesDisabledAdmin(t *testing.T) {
	f := newAdminMgmtFixture(t)
	const admin = domain.AdministratorID("adm-disabled")
	f.seedAdmin(admin, domain.AdminStatusDisabled)
	h := f.handler()

	token := mintAdminBearer(t, gateAdminSigningKey, admin)
	rr := f.do(h, http.MethodPost, "/api/v1/admin/reserved/allowlist", `{"entry":"widget"}`, token)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("disabled admin status = %d, want 403 (the row disable revokes the token).\nbody = %q",
			rr.Code, rr.Body.String())
	}
	body := strings.TrimSpace(rr.Body.String())
	if body != `{"status":"error"}` {
		t.Errorf("403 body = %q, want the reasonless uniform error", body)
	}
}

// TestAdminSurfaceDisabledWithoutSigningKey pins the fail-closed development
// mode: with no admin signing key configured, WithAdminIdentifier is not
// mounted, the routes stay at the denyAll stub, and startup warns loudly.
//
// The warning is part of the contract: an admin API that silently refuses every
// valid-looking token is the failure an operator debugs from the client side,
// so the log line must name the component and the config field to set.
func TestAdminSurfaceDisabledWithoutSigningKey(t *testing.T) {
	f := newGateFixture(t, "") // development, no admin signing key ref
	const admin = domain.AdministratorID("adm-live")
	f.seedAdmin(admin, domain.AdminStatusActive)
	h := f.handler()

	// A token that WOULD verify had the surface been mounted, so the 403 is the
	// absent identifier refusing rather than a bad credential.
	token := mintAdminBearer(t, gateAdminSigningKey, admin)
	rr := f.do(h, http.MethodPost, "/api/v1/admin/reserved/allowlist", `{"entry":"widget"}`, token)
	if rr.Code != http.StatusForbidden {
		t.Errorf("admin status with no signing key = %d, want 403 (fail-closed stub).\nbody = %q",
			rr.Code, rr.Body.String())
	}
	if !strings.Contains(f.logs.String(), "no admin token signing key configured") {
		t.Errorf("startup did not warn that the administrator API is disabled.\nlogs:\n%s", f.logs.String())
	}
}

// TestProductionRefusesAnAbsentAdminSigningKey pins the one place the absent
// reference is not a valid choice, the admin parallel to
// TestProductionRefusesAnAbsentSigningKey.
//
// The owner signing key AND the pepper are supplied, so the ONLY thing missing
// is the admin key: buildAPIDeps refuses on the first missing secret, and this
// test proves the refusal is the admin one -- it names admin_token_signing_key_ref,
// not a masked earlier failure.
func TestProductionRefusesAnAbsentAdminSigningKey(t *testing.T) {
	t.Setenv("VALLET_TEST_PROD_PEPPER", gatePepper)
	t.Setenv("VALLET_TEST_PROD_SIGNING_KEY", gateSigningKey)
	f := newGateFixture(t, "env:VALLET_TEST_PROD_PEPPER") // a pepper so newPublisher is not the refusal
	f.cfg.Server.Environment = "production"
	f.cfg.Auth.TokenSigningKeyRef = secrets.Ref("env:VALLET_TEST_PROD_SIGNING_KEY") // owner key present too
	// admin key deliberately left unset.

	logger := slog.New(slog.NewTextHandler(f.logs, nil))
	tel := telemetry.New(f.cfg, logger)
	t.Cleanup(func() { shutdownTelemetry(tel, logger) })

	_, _, err := buildAPIDeps(context.Background(), f.cfg, logger, f.store, tel, nil)
	if err == nil {
		t.Fatal("production built the API with no admin token signing key")
	}
	if !strings.Contains(err.Error(), "auth.admin_token_signing_key_ref") {
		t.Errorf("the refusal does not name the admin config field an operator must set: %v", err)
	}
}
