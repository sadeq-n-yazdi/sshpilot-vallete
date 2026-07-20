package httpserver_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	httpserver "github.com/sadeq-n-yazdi/sshpilot-vallete/internal/transport/http"
)

// This file pins the not-found mapping on the DOMAIN sentinel rather than on
// each service's own wrapper, across all three management surfaces the change
// touched.
//
// Every service defines its own ErrNotFound that wraps domain.ErrNotFound, and
// the handlers used to match only the wrapper. That is correct for every error
// the service maps on its way out — and silently wrong for one that is not
// mapped, because a bare domain.ErrNotFound then misses the arm and lands on
// the default, which answers 500.
//
// Why that matters here rather than being a cosmetic status difference: these
// surfaces answer a UNIFORM 404 precisely so that a row belonging to another
// owner is indistinguishable from a row that never existed. A path that answers
// 500 where its neighbors answer 404 is exactly the difference an observer
// needs to tell those two apart, so the fallthrough turns an unmapped error
// into a disclosure channel.
//
// Each fixture returns the BARE sentinel — the thing a repository yields and a
// service might forget to translate — so these tests fail if any handler goes
// back to matching only its own wrapper. There is one test per writer, because
// writeDeviceError, writeKeyError and writeKeySetError are three separate
// switches: a fix applied to one of them says nothing about the other two, and
// only a per-surface assertion catches the one that was missed.
//
// doDeviceRequest is reused throughout. Despite the name it is a plain
// handler-and-token request helper with nothing device-specific in it.

// failingKeyService fails every operation with whatever error it is given, so a
// test can drive a specific sentinel into writeKeyError.
type failingKeyService struct{ err error }

func (f failingKeyService) Add(context.Context, domain.OwnerID, domain.DeviceID, []byte, string) (*domain.PublicKey, error) {
	return nil, f.err
}

func (f failingKeyService) List(context.Context, domain.OwnerID) ([]domain.PublicKey, error) {
	return nil, f.err
}

func (f failingKeyService) Revoke(context.Context, domain.OwnerID, domain.PublicKeyID, string) error {
	return f.err
}

// failingKeySetService fails every operation with whatever error it is given,
// so a test can drive a specific sentinel into writeKeySetError.
type failingKeySetService struct{ err error }

func (f failingKeySetService) Create(context.Context, domain.OwnerID, string, string) (*domain.KeySet, error) {
	return nil, f.err
}

func (f failingKeySetService) List(context.Context, domain.OwnerID) ([]domain.KeySet, error) {
	return nil, f.err
}

func (f failingKeySetService) Rename(context.Context, domain.OwnerID, domain.KeySetID, string, string) (*domain.KeySet, error) {
	return nil, f.err
}

func (f failingKeySetService) Delete(context.Context, domain.OwnerID, domain.KeySetID, bool, string) error {
	return f.err
}

func (f failingKeySetService) SetDefault(context.Context, domain.OwnerID, domain.KeySetID, string) (*domain.KeySet, error) {
	return nil, f.err
}

func (f failingKeySetService) SetVisibility(context.Context, domain.OwnerID, domain.KeySetID, domain.Visibility, string) (*domain.KeySet, error) {
	return nil, f.err
}

// notFoundCase is one endpoint driven with a bare domain.ErrNotFound.
type notFoundCase struct {
	name   string
	method string
	path   string
	body   string
}

// assertNotFound drives one case and requires both the 404 and the uniform
// opaque body. The status alone is not the whole guarantee: a 404 that leaked a
// distinguishing message would defeat the same property the status protects.
func assertNotFound(t *testing.T, handler http.Handler, token string, tc notFoundCase) {
	t.Helper()

	rec := doDeviceRequest(t, handler, tc.method, tc.path, tc.body, token)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("%s with a bare domain.ErrNotFound = %d, want 404; "+
			"an unmapped domain sentinel must not fall through to the 500 arm",
			tc.name, rec.Code)
	}
	if got := rec.Body.String(); !isOpaqueErrorBody(got) {
		t.Errorf("%s body = %s, want the uniform opaque error body", tc.name, got)
	}
}

func TestBareDomainNotFoundAnswers404OnDevices(t *testing.T) {
	t.Parallel()

	for _, tc := range []notFoundCase{
		{"register", http.MethodPost, devicesPath, `{"name":"laptop"}`},
		{"list", http.MethodGet, devicesPath, ""},
		{"revoke", http.MethodDelete, devicesPath + "/dev-1", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			env := newDeviceEnv(t)
			handler := httpserver.NewHandler(nil, nil, devicePinger{}, devicePublisher{},
				httpserver.WithAuthorizer(env.guard),
				httpserver.WithDeviceService(failingDeviceService{err: domain.ErrNotFound}))
			token := env.token(t, "owner-a", domain.Scope{Kind: domain.ScopeFullOwner})

			assertNotFound(t, handler, token, tc)
		})
	}
}

func TestBareDomainNotFoundAnswers404OnKeys(t *testing.T) {
	t.Parallel()

	// A syntactically plausible submission. The fake never parses it; it is
	// here only so the handler's own decode succeeds and the request reaches
	// the service, which is the arm under test.
	const line = `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB3NzaC1lZDI1NTE5AAAAIExample user@host`

	for _, tc := range []notFoundCase{
		{"add", http.MethodPost, keysPath, `{"device_id":"dev-1","public_key":"` + line + `"}`},
		{"list", http.MethodGet, keysPath, ""},
		{"revoke", http.MethodDelete, keysPath + "/key-1", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			env := newKeyEnv(t)
			handler := httpserver.NewHandler(nil, nil, devicePinger{}, devicePublisher{},
				httpserver.WithAuthorizer(env.guard),
				httpserver.WithPublicKeyService(failingKeyService{err: domain.ErrNotFound}))
			token := env.fullToken(t, "owner-a")

			assertNotFound(t, handler, token, tc)
		})
	}
}

func TestBareDomainNotFoundAnswers404OnKeySets(t *testing.T) {
	t.Parallel()

	for _, tc := range []notFoundCase{
		{"create", http.MethodPost, keySetsPath, `{"name":"work"}`},
		{"list", http.MethodGet, keySetsPath, ""},
		{"rename", http.MethodPatch, keySetsPath + "/set-1", `{"name":"personal"}`},
		{"delete", http.MethodDelete, keySetsPath + "/set-1", `{"confirm":true}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			env := newSetEnv(t)
			handler := httpserver.NewHandler(nil, nil, devicePinger{}, devicePublisher{},
				httpserver.WithAuthorizer(env.authorizer),
				httpserver.WithKeySetService(failingKeySetService{err: domain.ErrNotFound}))
			token := env.fullToken(t, "owner-a")

			assertNotFound(t, handler, token, tc)
		})
	}
}
