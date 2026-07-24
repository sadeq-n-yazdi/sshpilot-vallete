package httpserver_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	httpserver "github.com/sadeq-n-yazdi/sshpilot-vallete/internal/transport/http"
)

// These tests drive the REAL handler built by NewHandler over the admin list
// routes, so a route that is registered without its fail-closed default, or not
// registered at all, fails here rather than passing against a handler called
// directly.

const (
	allowlistPath = "/api/v1/admin/reserved/allowlist"
	blocklistPath = "/api/v1/admin/reserved/blocklist"
)

// adminRoutes is every reserved-identifier edit route, so a test can assert a
// property across all of them at once.
var adminRoutes = [][2]string{
	{http.MethodPost, allowlistPath},
	{http.MethodDelete, allowlistPath},
	{http.MethodPost, blocklistPath},
	{http.MethodDelete, blocklistPath},
}

const (
	activeAdmin   = domain.AdministratorID("adm-active")
	disabledAdmin = domain.AdministratorID("adm-disabled")
)

// fakeListAdmin mimics *listadmin.Service closely enough to test the transport:
// it authorizes the actor exactly as the real service does (empty or unknown
// refused ErrUnauthorized, disabled refused ErrForbidden) before recording any
// effect, so a test can prove the handler both delegates and fails closed.
type fakeListAdmin struct {
	mu    sync.Mutex
	allow map[string]bool
	block map[string]bool
	calls []adminCall
}

type adminCall struct {
	op    string
	actor domain.AdministratorID
	entry string
}

func newFakeListAdmin() *fakeListAdmin {
	return &fakeListAdmin{allow: map[string]bool{}, block: map[string]bool{}}
}

func (f *fakeListAdmin) authorize(actor domain.AdministratorID) error {
	switch actor {
	case activeAdmin:
		return nil
	case disabledAdmin:
		return domain.ErrForbidden
	default:
		return domain.ErrUnauthorized
	}
}

func (f *fakeListAdmin) edit(op string, actor domain.AdministratorID, entry string, set map[string]bool, add bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, adminCall{op: op, actor: actor, entry: entry})
	// Authorization precedes any effect, exactly as listadmin.edit orders it.
	if err := f.authorize(actor); err != nil {
		return err
	}
	if add {
		if set[entry] {
			return domain.ErrConflict
		}
		set[entry] = true
		return nil
	}
	if !set[entry] {
		return domain.ErrNotFound
	}
	delete(set, entry)
	return nil
}

func (f *fakeListAdmin) AddAllowlistEntry(_ context.Context, a domain.AdministratorID, e string) error {
	return f.edit("allow_add", a, e, f.allow, true)
}
func (f *fakeListAdmin) RemoveAllowlistEntry(_ context.Context, a domain.AdministratorID, e string) error {
	return f.edit("allow_remove", a, e, f.allow, false)
}
func (f *fakeListAdmin) AddBlocklistTerm(_ context.Context, a domain.AdministratorID, e string) error {
	return f.edit("block_add", a, e, f.block, true)
}
func (f *fakeListAdmin) RemoveBlocklistTerm(_ context.Context, a domain.AdministratorID, e string) error {
	return f.edit("block_remove", a, e, f.block, false)
}

func (f *fakeListAdmin) snapshot() (allow, block int, calls []adminCall) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.allow), len(f.block), append([]adminCall(nil), f.calls...)
}

// fixedAdminID is an AdminIdentifier that resolves every request to one
// administrator, standing in for the authenticator that does not exist yet.
type fixedAdminID domain.AdministratorID

func (f fixedAdminID) AdministratorID(*http.Request) domain.AdministratorID {
	return domain.AdministratorID(f)
}

func adminRequest(t *testing.T, handler http.Handler, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

// TestAdminListRoutesFailClosedWithoutAnIdentifier is the counterpart to
// TestManagementRoutesFailClosedWithoutAnAuthorizer: a handler built with the
// list service but NO AdminIdentifier must refuse every edit and apply none.
// The default denyAllAdminIdentifier authenticates nobody, so the empty actor
// reaches the service and is refused.
func TestAdminListRoutesFailClosedWithoutAnIdentifier(t *testing.T) {
	t.Parallel()
	fake := newFakeListAdmin()
	handler := httpserver.NewHandler(nil, nil, devicePinger{}, devicePublisher{},
		httpserver.WithListAdminService(fake))

	for _, rt := range adminRoutes {
		rec := adminRequest(t, handler, rt[0], rt[1], `{"entry":"admin"}`)
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s %s with no identifier wired = %d, want 403", rt[0], rt[1], rec.Code)
		}
	}

	// Nothing was applied, and every delegated call carried the empty actor.
	allow, block, calls := fake.snapshot()
	if allow != 0 || block != 0 {
		t.Errorf("lists changed after refused edits: allow=%d block=%d, want 0/0", allow, block)
	}
	for _, c := range calls {
		if c.actor != "" {
			t.Errorf("delegated call %+v carried a non-empty actor, want empty from the deny-all default", c)
		}
	}
}

// TestAdminListRoutesReturn500WhenServiceMissing pins the other half of the
// wiring story: an identifier present, the service absent. It must be a 500,
// never a refusal that reads as "denied" and hides a broken deployment.
func TestAdminListRoutesReturn500WhenServiceMissing(t *testing.T) {
	t.Parallel()
	handler := httpserver.NewHandler(nil, nil, devicePinger{}, devicePublisher{},
		httpserver.WithAdminIdentifier(fixedAdminID(activeAdmin)))

	rec := adminRequest(t, handler, http.MethodPost, allowlistPath, `{"entry":"admin"}`)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("edit with no service wired = %d, want 500", rec.Code)
	}
}

// TestAdminListRoutesDelegateForAnIdentifiedAdmin proves the happy path: an
// identified active administrator's edits reach the service with the actor
// passed through, and succeed with 204.
func TestAdminListRoutesDelegateForAnIdentifiedAdmin(t *testing.T) {
	t.Parallel()
	fake := newFakeListAdmin()
	handler := httpserver.NewHandler(nil, nil, devicePinger{}, devicePublisher{},
		httpserver.WithListAdminService(fake),
		httpserver.WithAdminIdentifier(fixedAdminID(activeAdmin)))

	steps := []struct {
		method, path, entry, wantOp string
	}{
		{http.MethodPost, allowlistPath, "admin", "allow_add"},
		{http.MethodDelete, allowlistPath, "admin", "allow_remove"},
		{http.MethodPost, blocklistPath, "supportteam", "block_add"},
		{http.MethodDelete, blocklistPath, "supportteam", "block_remove"},
	}
	for _, s := range steps {
		rec := adminRequest(t, handler, s.method, s.path, `{"entry":"`+s.entry+`"}`)
		if rec.Code != http.StatusNoContent {
			t.Fatalf("%s %s = %d, want 204", s.method, s.path, rec.Code)
		}
	}

	_, _, calls := fake.snapshot()
	if len(calls) != len(steps) {
		t.Fatalf("delegated %d calls, want %d", len(calls), len(steps))
	}
	for i, s := range steps {
		if calls[i].op != s.wantOp || calls[i].actor != activeAdmin || calls[i].entry != s.entry {
			t.Errorf("call %d = %+v, want op=%s actor=%s entry=%s", i, calls[i], s.wantOp, activeAdmin, s.entry)
		}
	}
}

// TestAdminListRefusalRendersUniformly pins listadmin's BOUNDARY OBLIGATION: an
// unauthorized actor and a disabled one must be indistinguishable at the API, so
// neither can be used to enumerate which administrator IDs exist. Both answer
// 403 with no distinguishing body.
func TestAdminListRefusalRendersUniformly(t *testing.T) {
	t.Parallel()
	fake := newFakeListAdmin()
	disabled := httpserver.NewHandler(nil, nil, devicePinger{}, devicePublisher{},
		httpserver.WithListAdminService(fake),
		httpserver.WithAdminIdentifier(fixedAdminID(disabledAdmin)))
	unknown := httpserver.NewHandler(nil, nil, devicePinger{}, devicePublisher{},
		httpserver.WithListAdminService(fake),
		httpserver.WithAdminIdentifier(fixedAdminID("adm-nobody")))

	for _, h := range []http.Handler{disabled, unknown} {
		rec := adminRequest(t, h, http.MethodPost, allowlistPath, `{"entry":"admin"}`)
		if rec.Code != http.StatusForbidden {
			t.Errorf("refused edit = %d, want a uniform 403", rec.Code)
		}
	}
	if allow, block, _ := fake.snapshot(); allow != 0 || block != 0 {
		t.Errorf("a refused edit changed a list: allow=%d block=%d", allow, block)
	}
}

// TestAdminListRoutesRejectMalformedBodies checks the input surface. Each
// reports only on what the caller sent, so 400 is safe, and none applies an
// edit.
func TestAdminListRoutesRejectMalformedBodies(t *testing.T) {
	t.Parallel()
	fake := newFakeListAdmin()
	handler := httpserver.NewHandler(nil, nil, devicePinger{}, devicePublisher{},
		httpserver.WithListAdminService(fake),
		httpserver.WithAdminIdentifier(fixedAdminID(activeAdmin)))

	bodies := map[string]string{
		"not json":        `{`,
		"unknown field":   `{"entry":"x","actor":"root"}`,
		"two json values": `{"entry":"a"}{"entry":"b"}`,
		"oversized":       `{"entry":"` + strings.Repeat("a", 9000) + `"}`,
	}
	for name, body := range bodies {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			rec := adminRequest(t, handler, http.MethodPost, allowlistPath, body)
			if rec.Code != http.StatusBadRequest {
				t.Errorf("POST %s (%s) = %d, want 400", allowlistPath, name, rec.Code)
			}
		})
	}
}
