package httpserver_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	httpserver "github.com/sadeq-n-yazdi/sshpilot-vallete/internal/transport/http"
)

// TestDeviceAccessRefusesAnEmptySegment unit-tests the AccessFunc directly.
//
// The mux cannot currently produce an empty {deviceID} -- a DELETE to
// /api/v1/devices/ does not match the pattern -- so this branch is unreachable
// through the router today, and an end-to-end test cannot cover it. It is tested
// here anyway because the branch is what makes the route's confinement
// structural: if a future pattern change ever did admit an empty segment,
// returning a bare auth.Access{} would silently turn a device-scoped check into
// an account-wide one that a single-device token passes. The guarantee should
// not depend on a routing detail elsewhere continuing to hold.
func TestDeviceAccessRefusesAnEmptySegment(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/devices/", nil)
	// No SetPathValue call: PathValue returns "" exactly as it would for a
	// pattern that matched an empty segment.
	access, err := httpserver.DeviceAccess(req)
	if !errors.Is(err, domain.ErrInvalidInput) {
		t.Fatalf("DeviceAccess(empty id) error = %v, want ErrInvalidInput", err)
	}
	if access.Resource != "" || access.ResourceID != "" {
		t.Errorf("DeviceAccess returned a usable Access %+v alongside its error; an unbound Access here would widen the check", access)
	}
}

// TestDeviceAccessNamesTheDeviceFromThePath is the positive half: the AccessFunc
// binds to the path segment, which is what confines a single-device token.
func TestDeviceAccessNamesTheDeviceFromThePath(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/devices/dev-1", nil)
	req.SetPathValue("deviceID", "dev-1")
	access, err := httpserver.DeviceAccess(req)
	if err != nil {
		t.Fatalf("DeviceAccess = %v, want nil", err)
	}
	if access.ResourceID != "dev-1" {
		t.Errorf("ResourceID = %q, want %q", access.ResourceID, "dev-1")
	}
}

// failingDeviceService fails every operation with a plain error -- not
// ErrNotFound, not ErrInvalidInput -- so the default arm of writeDeviceError is
// what answers.
type failingDeviceService struct{ err error }

func (f failingDeviceService) Register(context.Context, domain.OwnerID, string, string) (*domain.Device, error) {
	return nil, f.err
}

func (f failingDeviceService) List(context.Context, domain.OwnerID) ([]domain.Device, error) {
	return nil, f.err
}

func (f failingDeviceService) Revoke(context.Context, domain.OwnerID, domain.DeviceID, string) error {
	return f.err
}

// TestUnexpectedServiceFailuresAre500AndSayNothing pins the default arm on every
// endpoint. Two things matter and both are asserted: the status is 500 (a
// storage fault must not masquerade as 404, which would tell an owner its device
// is gone), and the body is the same opaque {"status":"error"} every other
// refusal uses, carrying none of the internal error text.
func TestUnexpectedServiceFailuresAre500AndSayNothing(t *testing.T) {
	t.Parallel()

	// A distinctive string: if it ever reaches a client, the assertion below
	// finds it.
	boom := errors.New("dial tcp 10.0.0.5:5432: connection refused")

	for _, tc := range []struct {
		name   string
		method string
		path   string
		body   string
	}{
		{"register", http.MethodPost, devicesPath, `{"name":"laptop"}`},
		{"list", http.MethodGet, devicesPath, ""},
		{"revoke", http.MethodDelete, devicesPath + "/dev-1", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			env := newDeviceEnv(t)
			handler := httpserver.NewHandler(nil, nil, devicePinger{}, devicePublisher{},
				httpserver.WithAuthorizer(env.guard),
				httpserver.WithDeviceService(failingDeviceService{err: boom}))
			token := env.token(t, "owner-a", domain.Scope{Kind: domain.ScopeFullOwner})

			rec := doDeviceRequest(t, handler, tc.method, tc.path, tc.body, token)
			if rec.Code != http.StatusInternalServerError {
				t.Fatalf("%s with a failing service = %d, want 500", tc.name, rec.Code)
			}
			if got := rec.Body.String(); !isOpaqueErrorBody(got) {
				t.Errorf("body = %s, want the uniform opaque error body", got)
			}
			if strings.Contains(rec.Body.String(), "connection refused") ||
				strings.Contains(rec.Body.String(), "10.0.0.5") {
				t.Error("the internal error text reached the client")
			}
		})
	}
}

// TestMissingServiceIs500OnEveryEndpoint extends the existing list-only wiring
// test to register and revoke. A handler with no service behind it must be a
// loud misconfiguration on all three, never a plausible 404.
func TestMissingServiceIs500OnEveryEndpoint(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name   string
		method string
		path   string
		body   string
	}{
		{"register", http.MethodPost, devicesPath, `{"name":"laptop"}`},
		{"revoke", http.MethodDelete, devicesPath + "/dev-1", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			env := newDeviceEnv(t)
			handler := httpserver.NewHandler(nil, nil, devicePinger{}, devicePublisher{},
				httpserver.WithAuthorizer(env.guard))
			token := env.token(t, "owner-a", domain.Scope{Kind: domain.ScopeFullOwner})

			rec := doDeviceRequest(t, handler, tc.method, tc.path, tc.body, token)
			if rec.Code != http.StatusInternalServerError {
				t.Fatalf("%s with no service wired = %d, want 500", tc.name, rec.Code)
			}
		})
	}
}

func isOpaqueErrorBody(body string) bool {
	return body == "{\"status\":\"error\"}\n" || body == "{\"status\":\"error\"}"
}

func doDeviceRequest(t *testing.T, h http.Handler, method, path, body, token string) *httptest.ResponseRecorder {
	t.Helper()

	var req *http.Request
	if body == "" {
		req = httptest.NewRequest(method, path, nil)
	} else {
		req = httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}
