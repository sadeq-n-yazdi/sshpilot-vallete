package httpserver_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"encoding/pem"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/audit"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/auth"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/service/publickey"
	httpserver "github.com/sadeq-n-yazdi/sshpilot-vallete/internal/transport/http"
)

// Route constants, so a test cannot address a path the router does not serve
// while still passing.
const (
	keysPath = "/api/v1/keys"
)

// --- environment ---

// keyEnv is the fully wired system under test: the real router, the real
// auth.Guard, the real publickey service, and in-memory repositories and an
// audit sink. Nothing here fabricates an auth.Authorization or short-circuits
// the Guardian -- the scope and owner checks under test are the real ones.
//
// It shares memDeviceRepo, memAuditSink, decodeInto, and the pinger/publisher
// stubs with the device tests, which live in this same external test package.
type keyEnv struct {
	handler http.Handler
	guard   *auth.Guard
	signer  *auth.AccessTokenSigner
	keys    *memPublicKeyRepo
	devices *memDeviceRepo
	sink    *memAuditSink
	now     time.Time
}

func newKeyEnv(t *testing.T) *keyEnv {
	t.Helper()
	return newKeyEnvWithLogger(t, slog.New(slog.DiscardHandler))
}

func newKeyEnvWithLogger(t *testing.T, logger *slog.Logger) *keyEnv {
	t.Helper()

	// The wall clock, for the reason newDeviceEnvWithLogger gives: the Guardian
	// mounted by NewHandler uses time.Now, so a token minted at a pinned
	// timestamp would fall outside its validity window.
	env := &keyEnv{
		now:     time.Now().UTC(),
		keys:    newMemPublicKeyRepo(),
		devices: newMemDeviceRepo(),
		sink:    &memAuditSink{},
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
	svc, err := publickey.New(env.keys, env.devices, emitter,
		publickey.WithClock(func() time.Time { return env.now }))
	if err != nil {
		t.Fatalf("publickey.New: %v", err)
	}

	env.handler = httpserver.NewHandler(nil, logger, devicePinger{}, devicePublisher{},
		httpserver.WithAuthorizer(env.guard), httpserver.WithPublicKeyService(svc))
	return env
}

// token mints a real access token, signed by the same signer the Guard
// verifies with.
func (e *keyEnv) token(t *testing.T, owner domain.OwnerID, scopes ...domain.Scope) string {
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
func (e *keyEnv) fullToken(t *testing.T, owner domain.OwnerID) string {
	t.Helper()
	return e.token(t, owner, domain.Scope{Kind: domain.ScopeFullOwner})
}

func (e *keyEnv) do(t *testing.T, method, target, token, body string) *httptest.ResponseRecorder {
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

// seedDevice puts an active device straight into the repository, bypassing the
// device service, which this slice does not depend on.
func (e *keyEnv) seedDevice(t *testing.T, owner domain.OwnerID, id domain.DeviceID) domain.DeviceID {
	t.Helper()

	d := &domain.Device{
		ID: id, OwnerID: owner, Name: "seed", Status: domain.DeviceStatusActive,
		CreatedAt: e.now, UpdatedAt: e.now,
	}
	if err := e.devices.Create(context.Background(), d); err != nil {
		t.Fatalf("seed device: %v", err)
	}
	return id
}

// addBody builds the enrollment body.
func addBody(t *testing.T, deviceID domain.DeviceID, line string) string {
	t.Helper()

	payload, err := json.Marshal(map[string]string{"device_id": string(deviceID), "public_key": line})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(payload)
}

func (e *keyEnv) mustAdd(t *testing.T, token string, deviceID domain.DeviceID, line string) keyJSON {
	t.Helper()

	rr := e.do(t, http.MethodPost, keysPath, token, addBody(t, deviceID, line))
	if rr.Code != http.StatusCreated {
		t.Fatalf("add = %d (%s), want 201", rr.Code, rr.Body.String())
	}
	var out keyJSON
	decodeInto(t, rr, &out)
	return out
}

func (e *keyEnv) mustList(t *testing.T, token string) []keyJSON {
	t.Helper()

	rr := e.do(t, http.MethodGet, keysPath, token, "")
	if rr.Code != http.StatusOK {
		t.Fatalf("list = %d (%s), want 200", rr.Code, rr.Body.String())
	}
	var out struct {
		Keys []keyJSON `json:"keys"`
	}
	decodeInto(t, rr, &out)
	return out.Keys
}

func (e *keyEnv) auditRecords(action domain.AuditAction) []*domain.AuditRecord {
	var out []*domain.AuditRecord
	for _, rec := range e.sink.records {
		if rec.Action == action {
			out = append(out, rec)
		}
	}
	return out
}

// keyJSON is the wire shape a client sees. It is declared here rather than
// reusing the transport's unexported type so the test reads the JSON a consumer
// would, not the struct the server happens to marshal. OwnerID and Blob are
// declared precisely so a test can assert the server never sends them.
type keyJSON struct {
	ID          string `json:"id"`
	DeviceID    string `json:"device_id"`
	Algorithm   string `json:"algorithm"`
	Comment     string `json:"comment"`
	Fingerprint string `json:"fingerprint"`
	BitLen      int    `json:"bit_len"`
	Status      string `json:"status"`
	CreatedAt   string `json:"created_at"`
	UpdatedAt   string `json:"updated_at"`
	RevokedAt   string `json:"revoked_at"`
	OwnerID     string `json:"owner_id"`
	Blob        string `json:"blob"`
	PublicKey   string `json:"public_key"`
}

// --- key material ---

// ed25519Line generates a fresh ed25519 key and returns its authorized_keys
// line with the given comment. Keys are generated rather than hard-coded so no
// fixture in this repository is ever a key somebody might also be using.
func ed25519Line(t *testing.T, comment string) string {
	t.Helper()

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519: %v", err)
	}
	return authorizedLine(t, pub, comment)
}

// rsaLine generates an RSA key of the given size and returns its
// authorized_keys line. Sizes below domain.MinRSABits exist here only to be
// refused.
func rsaLine(t *testing.T, bits int, comment string) string {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatalf("generate rsa %d: %v", bits, err)
	}
	return authorizedLine(t, &key.PublicKey, comment)
}

func authorizedLine(t *testing.T, key any, comment string) string {
	t.Helper()

	pub, err := ssh.NewPublicKey(key)
	if err != nil {
		t.Fatalf("ssh.NewPublicKey: %v", err)
	}
	line := strings.TrimSuffix(string(ssh.MarshalAuthorizedKey(pub)), "\n")
	if comment != "" {
		line += " " + comment
	}
	return line
}

// privateKeyPEM returns a real, freshly generated OpenSSH private key in PEM
// form: the exact thing a user pastes by mistake, and the exact thing that must
// never be stored, echoed, or logged.
//
// The material is generated per call, so even a total failure of the controls
// under test cannot leak a key that matters. The test still asserts the
// controls hold.
func privateKeyPEM(t *testing.T) string {
	t.Helper()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519: %v", err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatalf("MarshalPrivateKey: %v", err)
	}
	return string(pem.EncodeToMemory(block))
}

// --- repositories ---

// memPublicKeyRepo is an in-memory PublicKeyRepository enforcing the owner
// scoping and the (owner, fingerprint) uniqueness the real adapters promise.
//
// It deliberately does NOT collapse "already revoked" into not-found, and does
// not filter revoked rows out of Get: that collapse is the service's job, and a
// fake that did it for the service would make the service's own logic
// untestable and its removal invisible.
type memPublicKeyRepo struct {
	mu   chan struct{}
	rows map[domain.PublicKeyID]*domain.PublicKey
	// order preserves insertion order so ListByOwner is deterministic, matching
	// the adapters' ORDER BY.
	order []domain.PublicKeyID
	// createErr, when set, is returned by Create instead of storing the row.
	createErr error
}

func newMemPublicKeyRepo() *memPublicKeyRepo {
	r := &memPublicKeyRepo{mu: make(chan struct{}, 1), rows: map[domain.PublicKeyID]*domain.PublicKey{}}
	r.mu <- struct{}{}
	return r
}

func (r *memPublicKeyRepo) lock()   { <-r.mu }
func (r *memPublicKeyRepo) unlock() { r.mu <- struct{}{} }

func (r *memPublicKeyRepo) count() int {
	r.lock()
	defer r.unlock()
	return len(r.rows)
}

func (r *memPublicKeyRepo) Create(_ context.Context, k *domain.PublicKey) error {
	r.lock()
	defer r.unlock()
	if r.createErr != nil {
		return r.createErr
	}
	for _, existing := range r.rows {
		if existing.OwnerID == k.OwnerID && existing.Fingerprint == k.Fingerprint {
			return domain.ErrConflict
		}
	}
	clone := *k
	r.rows[k.ID] = &clone
	r.order = append(r.order, k.ID)
	return nil
}

func (r *memPublicKeyRepo) Get(_ context.Context, ownerID domain.OwnerID, id domain.PublicKeyID) (*domain.PublicKey, error) {
	r.lock()
	defer r.unlock()
	k, ok := r.rows[id]
	if !ok || k.OwnerID != ownerID {
		return nil, domain.ErrNotFound
	}
	clone := *k
	return &clone, nil
}

func (r *memPublicKeyRepo) ListByOwner(_ context.Context, ownerID domain.OwnerID) ([]domain.PublicKey, error) {
	r.lock()
	defer r.unlock()
	// A nil slice for "none", matching the repository's nil-collection
	// convention. Returning an empty non-nil slice here would hide a service
	// that failed to preserve it.
	var out []domain.PublicKey
	for _, id := range r.order {
		if k := r.rows[id]; k != nil && k.OwnerID == ownerID {
			out = append(out, *k)
		}
	}
	return out, nil
}

func (r *memPublicKeyRepo) ListByDevice(_ context.Context, ownerID domain.OwnerID, deviceID domain.DeviceID) ([]domain.PublicKey, error) {
	r.lock()
	defer r.unlock()
	var out []domain.PublicKey
	for _, id := range r.order {
		if k := r.rows[id]; k != nil && k.OwnerID == ownerID && k.DeviceID == deviceID {
			out = append(out, *k)
		}
	}
	return out, nil
}

func (r *memPublicKeyRepo) GetByFingerprint(_ context.Context, ownerID domain.OwnerID, fingerprint string) (*domain.PublicKey, error) {
	r.lock()
	defer r.unlock()
	for _, k := range r.rows {
		if k.OwnerID == ownerID && k.Fingerprint == fingerprint {
			clone := *k
			return &clone, nil
		}
	}
	return nil, domain.ErrNotFound
}

func (r *memPublicKeyRepo) Revoke(_ context.Context, ownerID domain.OwnerID, id domain.PublicKeyID, now time.Time) error {
	r.lock()
	defer r.unlock()
	k, ok := r.rows[id]
	if !ok || k.OwnerID != ownerID {
		return domain.ErrNotFound
	}
	// Mirrors the SQLite adapter: no revoked_at filter, so a repeat succeeds at
	// the port. Collapsing it to not-found is the service's job.
	k.Status, k.UpdatedAt, k.RevokedAt = domain.KeyStatusRevoked, now, &now
	return nil
}

func (r *memPublicKeyRepo) RevokeByDevice(_ context.Context, ownerID domain.OwnerID, deviceID domain.DeviceID, now time.Time) (int64, error) {
	r.lock()
	defer r.unlock()
	var n int64
	for _, k := range r.rows {
		if k.OwnerID == ownerID && k.DeviceID == deviceID && k.Status == domain.KeyStatusActive {
			k.Status, k.UpdatedAt, k.RevokedAt = domain.KeyStatusRevoked, now, &now
			n++
		}
	}
	return n, nil
}

func (r *memPublicKeyRepo) ListActiveByKeySet(context.Context, domain.OwnerID, domain.KeySetID) ([]domain.PublicKey, error) {
	// Not part of this slice; the publish path exercises it elsewhere.
	return nil, nil
}

// errDatastoreDown stands in for an unexpected repository failure: not a
// domain sentinel, so it must reach the caller as a bare 500.
var errDatastoreDown = errors.New("datastore down")
