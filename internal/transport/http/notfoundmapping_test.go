package httpserver_test

import (
	"net/http"
	"testing"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	httpserver "github.com/sadeq-n-yazdi/sshpilot-vallete/internal/transport/http"
)

// TestBareDomainNotFoundAnswers404 pins the mapping on the DOMAIN sentinel
// rather than on each service's wrapper.
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
// The fixture returns the bare sentinel — the thing a repository yields and a
// service might forget to translate — so this test fails if any handler goes
// back to matching only its own wrapper.
func TestBareDomainNotFoundAnswers404(t *testing.T) {
	t.Parallel()

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
				httpserver.WithDeviceService(failingDeviceService{err: domain.ErrNotFound}))
			token := env.token(t, "owner-a", domain.Scope{Kind: domain.ScopeFullOwner})

			rec := doDeviceRequest(t, handler, tc.method, tc.path, tc.body, token)
			if rec.Code != http.StatusNotFound {
				t.Fatalf("%s with a bare domain.ErrNotFound = %d, want 404; "+
					"an unmapped domain sentinel must not fall through to the 500 arm",
					tc.name, rec.Code)
			}
			if got := rec.Body.String(); !isOpaqueErrorBody(got) {
				t.Errorf("body = %s, want the uniform opaque error body", got)
			}
		})
	}
}
