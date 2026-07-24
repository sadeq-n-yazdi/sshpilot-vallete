package auth_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/repository"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/secrets"
)

// fakeStore is an in-memory repository.Store for the token tests.
//
// It models the two behaviors the token service depends on for correctness and
// which a weaker double would quietly grant:
//
//   - WithTx is atomic. The credential map is snapshotted on entry and restored
//     when fn returns an error, so a test can prove that a rolled-back exchange
//     leaves nothing behind, and that a committed revocation survives a denial.
//   - MarkRotated is conditional, returning domain.ErrConflict for a credential
//     that is not active, as the port requires.
//
// The store lock is held for the whole of WithTx, which serializes writers the
// way SQLite's BEGIN IMMEDIATE does. That makes the concurrency test meaningful
// against this fake; it does not make it evidence about any real engine.
type fakeStore struct {
	mu     sync.Mutex
	creds  map[domain.RefreshCredentialID]*domain.RefreshCredential
	owners *fakeOwners
	// pairings and links are set by the enrollment tests, which need a store
	// that hands out more than credentials. They are nil for the token tests,
	// which never reach for them.
	pairings *fakePairings
	links    *fakeLinkStore

	// Fault injection. Each is returned by the correspondingly named method.
	createErr        error
	getByIDErr       error
	markRotatedErr   error
	revokeLineageErr error
	listByLineageErr error
	withTxErr        error

	// nilRow makes GetByID return (nil, nil), the port violation the service
	// must survive without dereferencing.
	nilRow bool
	// override replaces the row GetByID returns, so a test can simulate a store
	// that hands back a credential other than the one asked for.
	override *domain.RefreshCredential

	// rolledBack records whether the last WithTx ended in a rollback, so a test
	// can tell a denial (which commits) from a storage fault (which must not).
	rolledBack bool
}

var _ repository.Store = (*fakeStore)(nil)

func newFakeStore(owners *fakeOwners) *fakeStore {
	return &fakeStore{
		creds:  make(map[domain.RefreshCredentialID]*domain.RefreshCredential),
		owners: owners,
	}
}

func (f *fakeStore) Repos() repository.Repos {
	return repository.Repos{
		RefreshCredentials: &fakeCreds{store: f, lock: true},
		Owners:             f.owners,
		DevicePairings:     f.pairings,
		LinkedIdentities:   f.links,
	}
}

func (f *fakeStore) WithTx(ctx context.Context, fn func(context.Context, repository.Repos) error) error {
	if f.withTxErr != nil {
		return f.withTxErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	snapshot := make(map[domain.RefreshCredentialID]*domain.RefreshCredential, len(f.creds))
	for id, c := range f.creds {
		snapshot[id] = copyCred(c)
	}
	// The transaction repositories do not take the lock: it is already held for
	// the duration of the transaction.
	err := fn(ctx, repository.Repos{
		RefreshCredentials: &fakeCreds{store: f},
		Owners:             f.owners,
		DevicePairings:     f.pairings,
		LinkedIdentities:   f.links,
	})
	f.rolledBack = err != nil
	if err != nil {
		f.creds = snapshot
	}
	return err
}

// get returns the live row. Callers must hold the store lock.
func (f *fakeStore) get(id domain.RefreshCredentialID) *domain.RefreshCredential {
	return f.creds[id]
}

// snapshotOf returns a copy of the stored row, taking the lock. Tests use it to
// inspect state after an operation.
func (f *fakeStore) snapshotOf(id domain.RefreshCredentialID) *domain.RefreshCredential {
	f.mu.Lock()
	defer f.mu.Unlock()
	return copyCred(f.creds[id])
}

// all returns copies of every stored row.
func (f *fakeStore) all() []domain.RefreshCredential {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]domain.RefreshCredential, 0, len(f.creds))
	for _, c := range f.creds {
		out = append(out, *copyCred(c))
	}
	return out
}

func copyCred(c *domain.RefreshCredential) *domain.RefreshCredential {
	if c == nil {
		return nil
	}
	cp := *c
	cp.SecretHash = append([]byte(nil), c.SecretHash...)
	cp.Scopes = append([]domain.Scope(nil), c.Scopes...)
	if c.RotatedFromID != nil {
		id := *c.RotatedFromID
		cp.RotatedFromID = &id
	}
	if c.RevokedAt != nil {
		t := *c.RevokedAt
		cp.RevokedAt = &t
	}
	return &cp
}

// fakeCreds is the RefreshCredentialRepository view of a fakeStore. lock is set
// on the auto-commit repositories handed out by Repos and cleared on the
// transaction-bound ones, whose caller already holds the lock.
type fakeCreds struct {
	store *fakeStore
	lock  bool
}

var _ repository.RefreshCredentialRepository = (*fakeCreds)(nil)

func (r *fakeCreds) acquire() func() {
	if !r.lock {
		return func() {}
	}
	r.store.mu.Lock()
	return r.store.mu.Unlock
}

func (r *fakeCreds) Create(_ context.Context, c *domain.RefreshCredential) error {
	defer r.acquire()()
	if r.store.createErr != nil {
		return r.store.createErr
	}
	if c == nil {
		return domain.ErrInvalidInput
	}
	if _, exists := r.store.creds[c.ID]; exists {
		return domain.ErrConflict
	}
	r.store.creds[c.ID] = copyCred(c)
	return nil
}

func (r *fakeCreds) GetByID(_ context.Context, id domain.RefreshCredentialID) (*domain.RefreshCredential, error) {
	defer r.acquire()()
	if r.store.getByIDErr != nil {
		return nil, r.store.getByIDErr
	}
	if r.store.nilRow {
		return nil, nil //nolint:nilnil // deliberately models a port violation
	}
	if r.store.override != nil {
		return copyCred(r.store.override), nil
	}
	c := r.store.get(id)
	if c == nil {
		return nil, domain.ErrNotFound
	}
	return copyCred(c), nil
}

func (r *fakeCreds) Get(_ context.Context, ownerID domain.OwnerID, id domain.RefreshCredentialID) (*domain.RefreshCredential, error) {
	defer r.acquire()()
	c := r.store.get(id)
	if c == nil || c.OwnerID != ownerID {
		return nil, domain.ErrNotFound
	}
	return copyCred(c), nil
}

func (r *fakeCreds) ListByOwner(_ context.Context, ownerID domain.OwnerID) ([]domain.RefreshCredential, error) {
	defer r.acquire()()
	var out []domain.RefreshCredential
	for _, c := range r.store.creds {
		if c.OwnerID == ownerID {
			out = append(out, *copyCred(c))
		}
	}
	return out, nil
}

func (r *fakeCreds) ListByLineage(_ context.Context, ownerID domain.OwnerID, lineageID domain.LineageID) ([]domain.RefreshCredential, error) {
	defer r.acquire()()
	if r.store.listByLineageErr != nil {
		return nil, r.store.listByLineageErr
	}
	var out []domain.RefreshCredential
	for _, c := range r.store.creds {
		if c.OwnerID == ownerID && c.LineageID == lineageID {
			out = append(out, *copyCred(c))
		}
	}
	return out, nil
}

// MarkRotated implements the conditional transition the port specifies: it
// applies only to an active credential and reports domain.ErrConflict for any
// other status.
func (r *fakeCreds) MarkRotated(_ context.Context, ownerID domain.OwnerID, id domain.RefreshCredentialID, _ time.Time) error {
	defer r.acquire()()
	if r.store.markRotatedErr != nil {
		return r.store.markRotatedErr
	}
	c := r.store.get(id)
	if c == nil || c.OwnerID != ownerID {
		return domain.ErrNotFound
	}
	if c.Status != domain.CredentialStatusActive {
		return domain.ErrConflict
	}
	c.Status = domain.CredentialStatusRotated
	return nil
}

func (r *fakeCreds) Revoke(_ context.Context, ownerID domain.OwnerID, id domain.RefreshCredentialID, now time.Time) error {
	defer r.acquire()()
	c := r.store.get(id)
	if c == nil || c.OwnerID != ownerID {
		return domain.ErrNotFound
	}
	c.Status = domain.CredentialStatusRevoked
	t := now
	c.RevokedAt = &t
	return nil
}

func (r *fakeCreds) RevokeLineage(_ context.Context, ownerID domain.OwnerID, lineageID domain.LineageID, now time.Time) (int64, error) {
	defer r.acquire()()
	if r.store.revokeLineageErr != nil {
		return 0, r.store.revokeLineageErr
	}
	var n int64
	for _, c := range r.store.creds {
		if c.OwnerID != ownerID || c.LineageID != lineageID {
			continue
		}
		c.Status = domain.CredentialStatusRevoked
		t := now
		c.RevokedAt = &t
		n++
	}
	return n, nil
}

func (r *fakeCreds) DeleteExpired(context.Context, time.Time, int) (int64, error) { return 0, nil }

// The helpers below manipulate the refresh-token wire format directly. As with
// the access-token tests, the format is restated as literals rather than
// derived from the package's own constants, so a change to it is caught here
// rather than silently tracked.

const refreshPrefix = "svr_"

// splitRefresh splits a refresh token into its identifier and encoded secret.
func splitRefresh(t *testing.T, tok secrets.Redacted) (string, string) {
	t.Helper()
	body, ok := strings.CutPrefix(tok.Reveal(), refreshPrefix)
	if !ok {
		t.Fatalf("token %q lacks the refresh prefix", tok.Reveal())
	}
	id, secret, ok := strings.Cut(body, ".")
	if !ok {
		t.Fatalf("token %q has no separator", tok.Reveal())
	}
	return id, secret
}

// forgeSecret returns the same credential identifier carrying a well-formed but
// wrong secret: what an attacker who learned an identifier, and nothing else,
// is able to present.
func forgeSecret(t *testing.T, tok secrets.Redacted) secrets.Redacted {
	t.Helper()
	id, encoded := splitRefresh(t, tok)
	secret, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("decoding the secret: %v", err)
	}
	secret[0] ^= 0xff
	return secrets.NewRedacted(refreshPrefix + id + "." + base64.RawURLEncoding.EncodeToString(secret))
}

// retarget returns the same secret against a different credential identifier.
func retarget(t *testing.T, tok secrets.Redacted, id string) secrets.Redacted {
	t.Helper()
	_, encoded := splitRefresh(t, tok)
	return secrets.NewRedacted(refreshPrefix + id + "." + encoded)
}

// sha256Of returns the SHA-256 digest of b, computed independently of the
// package under test.
func sha256Of(b []byte) []byte {
	sum := sha256.Sum256(b)
	return sum[:]
}
