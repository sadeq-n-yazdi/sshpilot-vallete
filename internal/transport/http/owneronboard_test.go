package httpserver_test

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/config"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/secrets"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/service/onboarding"
	httpserver "github.com/sadeq-n-yazdi/sshpilot-vallete/internal/transport/http"
)

// These tests drive the REAL handler built by NewHandler over the owner
// provisioning route, so a route mounted without its fail-closed default, or
// wired without the ADMIN rate-limit tier, fails here rather than passing
// against a handler called directly.

const ownersPath = "/api/v1/admin/owners"

// enrollmentCodeSecret is the fixed code the fake service returns; the happy
// path asserts it reaches the response body, and the refusal paths assert it
// does not.
const enrollmentCodeSecret = "enrollment-code-xyz"

// fakeOwnerOnboarding mimics *onboarding.Service closely enough to test the
// transport: it authorizes the actor exactly as the real service does (empty or
// unknown refused ErrUnauthorized, disabled refused ErrForbidden), then maps a
// handful of sentinel handles to the sentinels the handler must translate.
type fakeOwnerOnboarding struct {
	mu     sync.Mutex
	actors []domain.AdministratorID
}

func (f *fakeOwnerOnboarding) ProvisionOwner(_ context.Context, actor domain.AdministratorID, req onboarding.Request) (onboarding.Result, error) {
	f.mu.Lock()
	f.actors = append(f.actors, actor)
	f.mu.Unlock()

	switch actor {
	case activeAdmin:
		// authorized below
	case disabledAdmin:
		return onboarding.Result{}, domain.ErrForbidden
	default:
		return onboarding.Result{}, domain.ErrUnauthorized
	}

	switch req.Handle {
	case "", "A B":
		return onboarding.Result{}, domain.ErrInvalidInput
	case "admin":
		return onboarding.Result{}, domain.ErrBlockedName
	case "taken":
		return onboarding.Result{}, domain.ErrConflict
	}

	setName := req.SetName
	if setName == "" {
		setName = onboarding.DefaultSetName
	}
	return onboarding.Result{
		OwnerID:        "owner-new",
		Handle:         req.Handle,
		SetName:        setName,
		EnrollmentCode: secrets.NewRedacted(enrollmentCodeSecret),
		ExpiresAt:      time.Date(2026, 7, 22, 12, 15, 0, 0, time.UTC),
		PairingID:      "pair-1",
	}, nil
}

func (f *fakeOwnerOnboarding) sawActors() []domain.AdministratorID {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]domain.AdministratorID(nil), f.actors...)
}

// TestProvisionOwnerFailsClosedWithoutAnIdentifier: a handler with the service
// but NO AdminIdentifier must refuse. The default denyAllAdminIdentifier
// resolves the empty actor, which the service refuses as unauthorized (403).
func TestProvisionOwnerFailsClosedWithoutAnIdentifier(t *testing.T) {
	t.Parallel()
	fake := &fakeOwnerOnboarding{}
	handler := httpserver.NewHandler(nil, nil, devicePinger{}, devicePublisher{},
		httpserver.WithOwnerOnboardingService(fake))

	rec := adminRequest(t, handler, http.MethodPost, ownersPath, `{"handle":"alice"}`)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("no identifier: status = %d, want 403", rec.Code)
	}
	// The empty actor reached the service; no owner was provisioned.
	if actors := fake.sawActors(); len(actors) != 1 || actors[0] != "" {
		t.Fatalf("actors = %v, want one empty actor", actors)
	}
	assertNoCodeLeak(t, rec.Body.String())
}

// TestProvisionOwnerRejectsNonAdministratorBearer: a request whose identity
// resolves to an id that is not an active administrator (an owner's token, an
// unknown id) is refused 403 — the same status a disabled administrator gets,
// so the two cannot be told apart.
func TestProvisionOwnerRejectsNonAdministratorBearer(t *testing.T) {
	t.Parallel()
	for _, id := range []domain.AdministratorID{"owner-holder", disabledAdmin} {
		fake := &fakeOwnerOnboarding{}
		handler := httpserver.NewHandler(nil, nil, devicePinger{}, devicePublisher{},
			httpserver.WithOwnerOnboardingService(fake),
			httpserver.WithAdminIdentifier(fixedAdminID(id)))

		rec := adminRequest(t, handler, http.MethodPost, ownersPath, `{"handle":"alice"}`)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("actor %q: status = %d, want 403", id, rec.Code)
		}
		assertNoCodeLeak(t, rec.Body.String())
	}
}

// TestProvisionOwnerMisconfiguredWithoutService: a handler with an
// AdminIdentifier but NO service answers 500 — a wiring fault, never a refusal.
func TestProvisionOwnerMisconfiguredWithoutService(t *testing.T) {
	t.Parallel()
	handler := httpserver.NewHandler(nil, nil, devicePinger{}, devicePublisher{},
		httpserver.WithAdminIdentifier(fixedAdminID(activeAdmin)))

	rec := adminRequest(t, handler, http.MethodPost, ownersPath, `{"handle":"alice"}`)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("no service: status = %d, want 500", rec.Code)
	}
}

// TestProvisionOwnerInvalidAndReservedHandle: a syntactically invalid handle and
// a reserved one both answer 400, rendered the same so nothing reveals which
// rule fired.
func TestProvisionOwnerInvalidAndReservedHandle(t *testing.T) {
	t.Parallel()
	handler := provisionHandler(t, &fakeOwnerOnboarding{}, nil)

	for _, handle := range []string{"A B", "admin"} {
		rec := adminRequest(t, handler, http.MethodPost, ownersPath, `{"handle":"`+handle+`"}`)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("handle %q: status = %d, want 400", handle, rec.Code)
		}
	}
}

// TestProvisionOwnerDuplicateHandleConflicts: a taken handle answers 409.
func TestProvisionOwnerDuplicateHandleConflicts(t *testing.T) {
	t.Parallel()
	handler := provisionHandler(t, &fakeOwnerOnboarding{}, nil)

	rec := adminRequest(t, handler, http.MethodPost, ownersPath, `{"handle":"taken"}`)
	if rec.Code != http.StatusConflict {
		t.Fatalf("duplicate handle: status = %d, want 409", rec.Code)
	}
}

// TestProvisionOwnerHappyPath: an active administrator provisions an owner and
// the response carries the owner id, handle, set name, and the one-time
// enrollment code.
func TestProvisionOwnerHappyPath(t *testing.T) {
	t.Parallel()
	handler := provisionHandler(t, &fakeOwnerOnboarding{}, nil)

	rec := adminRequest(t, handler, http.MethodPost, ownersPath, `{"handle":"alice"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("happy path: status = %d, want 201", rec.Code)
	}
	var body struct {
		OwnerID        string `json:"owner_id"`
		Handle         string `json:"handle"`
		SetName        string `json:"set_name"`
		EnrollmentCode string `json:"enrollment_code"`
		PairingID      string `json:"pairing_id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.OwnerID != "owner-new" || body.Handle != "alice" || body.SetName != "default" {
		t.Fatalf("body = %+v, want owner-new/alice/default", body)
	}
	if body.EnrollmentCode != enrollmentCodeSecret {
		t.Fatalf("enrollment_code = %q, want the minted code", body.EnrollmentCode)
	}
	if body.PairingID != "pair-1" {
		t.Fatalf("pairing_id = %q, want pair-1", body.PairingID)
	}
}

// TestProvisionOwnerIsAdminRateLimited: the ADMIN tier bounds the route. With a
// limit of one request per window, the second is refused 429 with a Retry-After.
func TestProvisionOwnerIsAdminRateLimited(t *testing.T) {
	t.Parallel()
	cfg := config.Default()
	cfg.RateLimit.Tiers.Admin = config.Tier{Requests: 1, Window: config.Duration(time.Minute)}
	handler := provisionHandler(t, &fakeOwnerOnboarding{}, &cfg)

	first := adminRequest(t, handler, http.MethodPost, ownersPath, `{"handle":"alice"}`)
	if first.Code != http.StatusCreated {
		t.Fatalf("first request: status = %d, want 201", first.Code)
	}
	second := adminRequest(t, handler, http.MethodPost, ownersPath, `{"handle":"bob"}`)
	if second.Code != http.StatusTooManyRequests {
		t.Fatalf("second request: status = %d, want 429", second.Code)
	}
	if second.Header().Get("Retry-After") == "" {
		t.Fatal("429 response is missing a Retry-After header")
	}
}

// provisionHandler builds a handler with the fake service and an identifier that
// resolves every request to the active administrator.
func provisionHandler(t *testing.T, svc httpserver.OwnerOnboardingService, cfg *config.Config) http.Handler {
	t.Helper()
	return httpserver.NewHandler(cfg, nil, devicePinger{}, devicePublisher{},
		httpserver.WithOwnerOnboardingService(svc),
		httpserver.WithAdminIdentifier(fixedAdminID(activeAdmin)))
}

// assertNoCodeLeak fails if a refusal body carries anything code-shaped. A
// refusal must never reveal a credential (there is none to reveal) or any
// diagnostic beyond the uniform error status.
func assertNoCodeLeak(t *testing.T, body string) {
	t.Helper()
	if body != "" && body != `{"status":"error"}`+"\n" && body != `{"status":"error"}` {
		t.Fatalf("refusal body = %q, want the uniform error status", body)
	}
}
