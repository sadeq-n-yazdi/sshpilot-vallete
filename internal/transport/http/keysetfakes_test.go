package httpserver_test

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/audit"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/auth"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/migrate"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/nameguard"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/repository"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/schema"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/service/keyset"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/storage/sqlite"
	httpserver "github.com/sadeq-n-yazdi/sshpilot-vallete/internal/transport/http"
)

// keySetsPath is the route constant, so a test cannot address a path the router
// does not serve while still passing.
const keySetsPath = "/api/v1/keysets"

// setEnv is the fully wired system under test: the real router, the real
// auth.Guard, the real keyset service, and a real migrated SQLite store behind
// it. Nothing here fabricates an auth.Authorization or short-circuits the
// Guardian -- the scope and owner checks under test are the real ones, and the
// owner_id predicates the cross-owner tests depend on are the adapter's own.
type setEnv struct {
	handler http.Handler
	signer  *auth.AccessTokenSigner
	store   repository.Store
	sink    *memAuditSink
	// authorizer is retained so a variant handler can be built with the same
	// real Guard but a different option set.
	authorizer httpserver.Authorizer
	now        time.Time
}

func newSetEnv(t *testing.T, opts ...keyset.Option) *setEnv {
	t.Helper()

	// The wall clock: the Guardian mounted by NewHandler uses time.Now, so a
	// token minted at a pinned timestamp would fall outside its validity window.
	env := &setEnv{now: time.Now().UTC(), sink: &memAuditSink{}}

	// A file-backed database rather than ":memory:", which pins the pool to one
	// connection. httptest drives requests through a real server goroutine, and
	// a single-connection pool would serialize them into a shape production
	// never has.
	db, err := sqlite.Open(sqlite.Options{Path: filepath.Join(t.TempDir(), "keysets.db")})
	if err != nil {
		t.Fatalf("sqlite.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	reg, err := schema.Registry()
	if err != nil {
		t.Fatalf("schema.Registry: %v", err)
	}
	runner, err := migrate.NewRunner(sqlite.NewMigrateDB(db), migrate.EngineSQLite, reg)
	if err != nil {
		t.Fatalf("migrate.NewRunner: %v", err)
	}
	if _, err := runner.Up(context.Background()); err != nil {
		t.Fatalf("migrate Up: %v", err)
	}
	env.store = sqlite.NewStore(db)

	counters, err := newTestCounterStore(func() time.Time { return env.now })
	if err != nil {
		t.Fatalf("counter store: %v", err)
	}
	denylist, err := auth.NewDenylist(counters)
	if err != nil {
		t.Fatalf("NewDenylist: %v", err)
	}
	if env.signer, err = auth.NewAccessTokenSigner([]byte(strings.Repeat("k", auth.MinSigningKeyLen))); err != nil {
		t.Fatalf("NewAccessTokenSigner: %v", err)
	}
	guard, err := auth.NewGuard(env.signer, denylist)
	if err != nil {
		t.Fatalf("NewGuard: %v", err)
	}

	emitter, err := audit.NewEmitter(env.sink, audit.WithClock(func() time.Time { return env.now }))
	if err != nil {
		t.Fatalf("audit.NewEmitter: %v", err)
	}
	nameGuard, err := nameguard.Default()
	if err != nil {
		t.Fatalf("nameguard.Default(): %v", err)
	}
	opts = append([]keyset.Option{keyset.WithClock(func() time.Time { return env.now })}, opts...)
	svc, err := keyset.New(env.store, nameGuard, emitter, opts...)
	if err != nil {
		t.Fatalf("keyset.New: %v", err)
	}

	env.authorizer = guard
	env.handler = httpserver.NewHandler(nil, slog.New(slog.DiscardHandler), devicePinger{}, devicePublisher{},
		httpserver.WithAuthorizer(guard), httpserver.WithKeySetService(svc))
	return env
}

// seedOwner inserts the owner row key_sets' foreign key requires.
func (e *setEnv) seedOwner(t *testing.T, owner domain.OwnerID) domain.OwnerID {
	t.Helper()
	if err := e.store.Repos().Owners.Create(context.Background(), &domain.Owner{
		ID: owner, Status: domain.OwnerStatusActive, CreatedAt: e.now, UpdatedAt: e.now,
	}); err != nil {
		t.Fatalf("seed owner %s: %v", owner, err)
	}
	return owner
}

// token mints a real access token, signed by the same signer the Guard
// verifies with.
func (e *setEnv) token(t *testing.T, owner domain.OwnerID, scopes ...domain.Scope) string {
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

// fullToken is the common case: a token that may do anything within its owner.
func (e *setEnv) fullToken(t *testing.T, owner domain.OwnerID) string {
	t.Helper()
	return e.token(t, owner, domain.Scope{Kind: domain.ScopeFullOwner})
}

// readOnlyToken may read and nothing else. The Guardian derives Mutating from
// the HTTP method, so this token must be refused by every write route without
// any route having to declare it.
func (e *setEnv) readOnlyToken(t *testing.T, owner domain.OwnerID) string {
	t.Helper()
	return e.token(t, owner, domain.Scope{Kind: domain.ScopeReadOnly})
}

// setBoundToken is confined to one key set.
func (e *setEnv) setBoundToken(t *testing.T, owner domain.OwnerID, id string) string {
	t.Helper()
	return e.token(t, owner, domain.Scope{Kind: domain.ScopeSingleSet, ResourceID: id})
}

func (e *setEnv) do(t *testing.T, method, target, token, body string) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequest(method, target, strings.NewReader(body))
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

// setJSON mirrors keySetResponse, declared here so the test asserts against the
// WIRE shape rather than against the server's own struct. A field renamed in
// the handler and here at once would otherwise pass unnoticed.
type setJSON struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Visibility string `json:"visibility"`
	IsDefault  bool   `json:"is_default"`
}

func nameBody(t *testing.T, name string) string {
	t.Helper()
	payload, err := json.Marshal(map[string]string{"name": name})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(payload)
}

func confirmBody(t *testing.T, confirm bool) string {
	t.Helper()
	payload, err := json.Marshal(map[string]bool{"confirm": confirm})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(payload)
}

func (e *setEnv) mustCreate(t *testing.T, token, name string) setJSON {
	t.Helper()

	rr := e.do(t, http.MethodPost, keySetsPath, token, nameBody(t, name))
	if rr.Code != http.StatusCreated {
		t.Fatalf("create = %d (%s), want 201", rr.Code, rr.Body.String())
	}
	var out setJSON
	decodeInto(t, rr, &out)
	return out
}

func (e *setEnv) mustList(t *testing.T, token string) []setJSON {
	t.Helper()

	rr := e.do(t, http.MethodGet, keySetsPath, token, "")
	if rr.Code != http.StatusOK {
		t.Fatalf("list = %d (%s), want 200", rr.Code, rr.Body.String())
	}
	var out struct {
		KeySets []setJSON `json:"key_sets"`
	}
	decodeInto(t, rr, &out)
	return out.KeySets
}

// setPath addresses one key set.
func setPath(id string) string { return keySetsPath + "/" + id }

// reason reads the conflict reason out of a response body, or "" if there is
// none. A 404 must never have one.
func reason(t *testing.T, rr *httptest.ResponseRecorder) string {
	t.Helper()
	var out struct {
		Reason string `json:"reason"`
	}
	decodeInto(t, rr, &out)
	return out.Reason
}

func (e *setEnv) auditRecords(action domain.AuditAction) []*domain.AuditRecord {
	var out []*domain.AuditRecord
	for _, rec := range e.sink.records {
		if rec.Action == action {
			out = append(out, rec)
		}
	}
	return out
}

// seedMember puts a key in a set so the set counts as non-empty, inserting the
// device and public key rows the composite foreign keys require. It goes
// straight to the repositories: this slice has no membership endpoint yet.
func (e *setEnv) seedMember(t *testing.T, owner domain.OwnerID, setID domain.KeySetID, keyID domain.PublicKeyID) {
	t.Helper()
	ctx := context.Background()
	r := e.store.Repos()

	deviceID := domain.DeviceID(string(keyID) + "-dev")
	if err := r.Devices.Create(ctx, &domain.Device{
		ID: deviceID, OwnerID: owner, Name: string(keyID) + " device",
		Status: domain.DeviceStatusActive, CreatedAt: e.now, UpdatedAt: e.now,
	}); err != nil {
		t.Fatalf("seed device: %v", err)
	}
	if err := r.PublicKeys.Create(ctx, &domain.PublicKey{
		ID: keyID, OwnerID: owner, DeviceID: deviceID,
		Algorithm: domain.AlgEd25519, Blob: []byte(keyID),
		Fingerprint: "SHA256:" + string(keyID), BitLen: 256,
		Status: domain.KeyStatusActive, CreatedAt: e.now, UpdatedAt: e.now,
	}); err != nil {
		t.Fatalf("seed key: %v", err)
	}
	if err := r.KeySets.AddMember(ctx, owner, setID, keyID, e.now); err != nil {
		t.Fatalf("AddMember: %v", err)
	}
}

// newSetEnvWithoutService builds the same environment with NO key set service,
// which is the interim production wiring: the routes are mounted regardless, so
// their shape does not depend on whether an embedder supplied a service.
func newSetEnvWithoutService(t *testing.T) *setEnv {
	t.Helper()
	env := newSetEnv(t)
	env.handler = httpserver.NewHandler(nil, slog.New(slog.DiscardHandler), devicePinger{}, devicePublisher{},
		httpserver.WithAuthorizer(env.authorizer))
	return env
}
