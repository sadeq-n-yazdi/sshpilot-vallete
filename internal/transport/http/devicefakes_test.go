package httpserver_test

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/audit"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/auth"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/service/device"
	httpserver "github.com/sadeq-n-yazdi/sshpilot-vallete/internal/transport/http"
)

// --- environment ---

// deviceEnv is the fully wired system under test: the real router, the real
// auth.Guard, the real device service, and an in-memory repository and audit
// sink.
type deviceEnv struct {
	handler http.Handler
	guard   *auth.Guard
	signer  *auth.AccessTokenSigner
	repo    *memDeviceRepo
	sink    *memAuditSink
	now     time.Time
}

func newDeviceEnv(t *testing.T) *deviceEnv {
	t.Helper()
	return newDeviceEnvWithLogger(t, slog.New(slog.DiscardHandler))
}

func newDeviceEnvWithLogger(t *testing.T, logger *slog.Logger) *deviceEnv {
	t.Helper()

	// The wall clock, not a fixed instant. The Guardian mounted by NewHandler
	// uses time.Now, so a token minted at a pinned timestamp would be outside
	// its validity window and every request would 401 for a reason that has
	// nothing to do with what is under test. Determinism is not lost: an access
	// token is valid for auth.AccessTokenLifetime from this instant, which no
	// test here comes close to exceeding.
	env := &deviceEnv{
		now:  time.Now().UTC(),
		repo: newMemDeviceRepo(),
		sink: &memAuditSink{},
	}

	store, err := newTestCounterStore(func() time.Time { return env.now })
	if err != nil {
		t.Fatalf("counter store: %v", err)
	}
	denylist, err := auth.NewDenylist(store)
	if err != nil {
		t.Fatalf("NewDenylist: %v", err)
	}
	if env.signer, err = auth.NewAccessTokenSigner([]byte(strings.Repeat("k", auth.MinSigningKeyLen))); err != nil {
		t.Fatalf("NewAccessTokenSigner: %v", err)
	}
	if env.guard, err = auth.NewGuard(env.signer, denylist); err != nil {
		t.Fatalf("NewGuard: %v", err)
	}

	emitter, err := audit.NewEmitter(env.sink, audit.WithClock(func() time.Time { return env.now }))
	if err != nil {
		t.Fatalf("audit.NewEmitter: %v", err)
	}
	svc, err := device.New(env.repo, emitter, device.WithClock(func() time.Time { return env.now }))
	if err != nil {
		t.Fatalf("device.New: %v", err)
	}

	env.handler = httpserver.NewHandler(nil, logger, devicePinger{}, devicePublisher{},
		httpserver.WithAuthorizer(env.guard), httpserver.WithDeviceService(svc))
	return env
}

// token mints a real access token, signed by the same signer the Guard
// verifies with. Nothing in these tests fabricates an auth.Authorization.
func (e *deviceEnv) token(t *testing.T, owner domain.OwnerID, scopes ...domain.Scope) string {
	t.Helper()

	tok, err := e.signer.Issue(domain.AccessToken{
		ID:                  "jti-" + string(owner),
		OwnerID:             owner,
		RefreshCredentialID: domain.RefreshCredentialID("cred-" + string(owner)),
		Scopes:              scopes,
		IssuedAt:            e.now,
		ExpiresAt:           e.now.Add(auth.AccessTokenLifetime),
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	return tok.Reveal()
}

func (e *deviceEnv) do(t *testing.T, method, target, token, body string) *httptest.ResponseRecorder {
	t.Helper()

	var reader *strings.Reader
	if body == "" {
		reader = strings.NewReader("")
	} else {
		reader = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, target, reader)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	e.handler.ServeHTTP(rec, req)
	return rec
}

func (e *deviceEnv) mustRegister(t *testing.T, token, name string) deviceJSON {
	t.Helper()

	payload, err := json.Marshal(map[string]string{"name": name})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	rr := e.do(t, http.MethodPost, devicesPath, token, string(payload))
	if rr.Code != http.StatusCreated {
		t.Fatalf("register = %d (%s), want 201", rr.Code, rr.Body.String())
	}
	var out deviceJSON
	decodeInto(t, rr, &out)
	return out
}

func (e *deviceEnv) mustList(t *testing.T, token string) []deviceJSON {
	t.Helper()

	rr := e.do(t, http.MethodGet, devicesPath, token, "")
	if rr.Code != http.StatusOK {
		t.Fatalf("list = %d (%s), want 200", rr.Code, rr.Body.String())
	}
	var out struct {
		Devices []deviceJSON `json:"devices"`
	}
	decodeInto(t, rr, &out)
	return out.Devices
}

func (e *deviceEnv) auditCount(action domain.AuditAction) int {
	n := 0
	for _, rec := range e.sink.records {
		if rec.Action == action {
			n++
		}
	}
	return n
}

func (e *deviceEnv) auditHasDetail(key audit.DetailKey, value string) bool {
	for _, rec := range e.sink.records {
		if rec.Metadata[string(key)] == value {
			return true
		}
	}
	return false
}

// deviceJSON is the wire shape a client sees. It is declared here rather than
// reusing the transport's unexported type so the test reads the JSON a consumer
// would, not the struct the server happens to marshal.
type deviceJSON struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Status    string `json:"status"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
	RevokedAt string `json:"revoked_at"`
	OwnerID   string `json:"owner_id"`
}

func decodeInto(t *testing.T, rr *httptest.ResponseRecorder, into any) {
	t.Helper()

	if err := json.Unmarshal(rr.Body.Bytes(), into); err != nil {
		t.Fatalf("decode %s: %v", rr.Body.String(), err)
	}
}

// memDeviceRepo is an in-memory DeviceRepository enforcing the owner scoping
// the real adapters promise.
type memDeviceRepo struct {
	mu      chan struct{}
	devices map[domain.DeviceID]*domain.Device
}

func newMemDeviceRepo() *memDeviceRepo {
	r := &memDeviceRepo{mu: make(chan struct{}, 1), devices: map[domain.DeviceID]*domain.Device{}}
	r.mu <- struct{}{}
	return r
}

func (r *memDeviceRepo) lock()   { <-r.mu }
func (r *memDeviceRepo) unlock() { r.mu <- struct{}{} }

func (r *memDeviceRepo) count() int {
	r.lock()
	defer r.unlock()
	return len(r.devices)
}

func (r *memDeviceRepo) Create(_ context.Context, d *domain.Device) error {
	r.lock()
	defer r.unlock()
	clone := *d
	r.devices[d.ID] = &clone
	return nil
}

func (r *memDeviceRepo) Get(_ context.Context, ownerID domain.OwnerID, id domain.DeviceID) (*domain.Device, error) {
	r.lock()
	defer r.unlock()
	d, ok := r.devices[id]
	if !ok || d.OwnerID != ownerID {
		return nil, domain.ErrNotFound
	}
	clone := *d
	return &clone, nil
}

func (r *memDeviceRepo) ListByOwner(_ context.Context, ownerID domain.OwnerID) ([]domain.Device, error) {
	r.lock()
	defer r.unlock()
	var out []domain.Device
	for _, d := range r.devices {
		if d.OwnerID == ownerID {
			out = append(out, *d)
		}
	}
	return out, nil
}

func (r *memDeviceRepo) Rename(_ context.Context, ownerID domain.OwnerID, id domain.DeviceID, name string, now time.Time) error {
	r.lock()
	defer r.unlock()
	d, ok := r.devices[id]
	if !ok || d.OwnerID != ownerID {
		return domain.ErrNotFound
	}
	d.Name, d.UpdatedAt = name, now
	return nil
}

func (r *memDeviceRepo) Revoke(_ context.Context, ownerID domain.OwnerID, id domain.DeviceID, now time.Time) error {
	r.lock()
	defer r.unlock()
	d, ok := r.devices[id]
	if !ok || d.OwnerID != ownerID {
		return domain.ErrNotFound
	}
	// Mirrors the SQLite adapter: no revoked_at filter, so a repeat succeeds at
	// the port. Collapsing it to 404 is the service's job, and this fake must
	// not do it for the service.
	d.Status, d.UpdatedAt, d.RevokedAt = domain.DeviceStatusRevoked, now, &now
	return nil
}

// memAuditSink captures appended audit records.
type memAuditSink struct {
	records []*domain.AuditRecord
}

func (s *memAuditSink) Append(_ context.Context, rec *domain.AuditRecord) error {
	s.records = append(s.records, rec)
	return nil
}

// devicePinger and devicePublisher satisfy the non-management dependencies of
// NewHandler. They are declared here because the equivalents used by the other
// tests live in the internal test package, which this external one cannot see.
type devicePinger struct{}

func (devicePinger) PingContext(context.Context) error { return nil }

type devicePublisher struct{}

func (devicePublisher) Resolve(context.Context, string, string) ([]byte, error) {
	return []byte("ssh-ed25519 AAAA x\n"), nil
}
