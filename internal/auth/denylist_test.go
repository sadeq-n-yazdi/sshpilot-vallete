package auth_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/auth"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/counter"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
)

// denylistFixture is a Denylist over a real MemoryStore with a hand-wound
// clock. The store is real rather than faked wherever the test is about
// denylist behavior, so the expiry arithmetic is exercised end to end instead of
// being asserted against a mock's recorded TTL argument.
type denylistFixture struct {
	dl    *auth.Denylist
	store *counter.MemoryStore
	now   time.Time
}

func newDenylistFixture(t *testing.T) *denylistFixture {
	t.Helper()
	f := &denylistFixture{now: time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)}
	store, err := counter.NewMemoryStore(func() time.Time { return f.now })
	if err != nil {
		t.Fatalf("NewMemoryStore: %v", err)
	}
	dl, err := auth.NewDenylist(store)
	if err != nil {
		t.Fatalf("NewDenylist: %v", err)
	}
	f.store, f.dl = store, dl
	return f
}

func (f *denylistFixture) advance(d time.Duration) { f.now = f.now.Add(d) }

// tokenFor builds an access token naming credential id. Only the fields the
// denylist reads are populated; the signature and expiry are checked elsewhere.
func tokenFor(id domain.RefreshCredentialID) *domain.AccessToken {
	return &domain.AccessToken{
		ID:                  "jti-" + string(id),
		OwnerID:             "owner-1",
		RefreshCredentialID: id,
	}
}

// failingStore is a counter.Store that cannot answer. It is the store outage the
// fail-closed rule exists for.
type failingStore struct {
	// getErr, when non-nil, is returned by every Get.
	getErr error
	// incErr, when non-nil, is returned by every Increment.
	incErr error
	// keys records the keys Increment was called with, to show that the stored
	// key is a digest rather than the identifier itself.
	keys []string
}

func (s *failingStore) Increment(_ context.Context, key string, _ int64, _ time.Duration) (counter.Count, error) {
	s.keys = append(s.keys, key)
	if s.incErr != nil {
		return counter.Count{}, s.incErr
	}
	return counter.Count{Value: 1}, nil
}

func (s *failingStore) Get(context.Context, string) (counter.Count, error) {
	if s.getErr != nil {
		return counter.Count{}, s.getErr
	}
	return counter.Count{}, nil
}

func (s *failingStore) Delete(context.Context, string) error { return nil }

func TestNewDenylistRejectsNilStore(t *testing.T) {
	dl, err := auth.NewDenylist(nil)
	if !errors.Is(err, domain.ErrInvalidInput) {
		t.Fatalf("err = %v, want domain.ErrInvalidInput", err)
	}
	if dl != nil {
		t.Fatal("a rejected construction must not return a Denylist")
	}
}

func TestCheckPermitsAnUnlistedCredential(t *testing.T) {
	f := newDenylistFixture(t)
	if err := f.dl.Check(context.Background(), tokenFor("cred-1")); err != nil {
		t.Fatalf("an unlisted credential was denied: %v", err)
	}
}

func TestCheckDeniesAListedCredential(t *testing.T) {
	f := newDenylistFixture(t)
	ctx := context.Background()

	if err := f.dl.RevokeCredential(ctx, "cred-1"); err != nil {
		t.Fatalf("RevokeCredential: %v", err)
	}

	err := f.dl.Check(ctx, tokenFor("cred-1"))
	if err == nil {
		t.Fatal("a listed credential was permitted")
	}
	// Bare, so a revoked credential is indistinguishable from a forged token.
	if err != auth.ErrAuthFailed { //nolint:errorlint // the bareness is the assertion
		t.Fatalf("err = %v, want exactly ErrAuthFailed with no wrapped cause", err)
	}

	// Revocation is per credential: a different credential is untouched, so a
	// key collision or an over-broad match would show up here.
	if err := f.dl.Check(ctx, tokenFor("cred-2")); err != nil {
		t.Fatalf("an unrelated credential was denied: %v", err)
	}
}

// TestCheckFailsClosed is the central test of this task. A store that cannot
// answer must produce a denial, never an admission: a denylist that failed open
// would turn an outage of an auxiliary store into a silent authentication
// bypass.
func TestCheckFailsClosed(t *testing.T) {
	storeDown := errors.New("dial tcp: connection refused")
	store := &failingStore{getErr: storeDown}
	dl, err := auth.NewDenylist(store)
	if err != nil {
		t.Fatalf("NewDenylist: %v", err)
	}

	// The credential was never revoked. The only reason to deny it is that the
	// store could not be consulted -- which is exactly the point.
	checkErr := dl.Check(context.Background(), tokenFor("never-revoked"))
	if checkErr == nil {
		t.Fatal("a store failure was treated as permission: the denylist fails open")
	}
	// The cause survives so an operator can tell an outage from a revocation,
	// even though both are denials.
	if !errors.Is(checkErr, storeDown) {
		t.Fatalf("err = %v, want the store failure to survive for logs", checkErr)
	}
}

// TestCheckFailsClosedOnCancelledContext covers the same rule through the real
// store, where a canceled context is the realistic form of "cannot answer": a
// request that timed out mid-flight must not be read as an empty denylist.
func TestCheckFailsClosedOnCancelledContext(t *testing.T) {
	f := newDenylistFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := f.dl.Check(ctx, tokenFor("never-revoked"))
	if err == nil {
		t.Fatal("a canceled context was treated as permission")
	}
	if !errors.Is(err, counter.ErrStoreUnavailable) {
		t.Fatalf("err = %v, want counter.ErrStoreUnavailable", err)
	}
}

func TestCheckDeniesMalformedTokens(t *testing.T) {
	f := newDenylistFixture(t)
	ctx := context.Background()

	t.Run("nil token", func(t *testing.T) {
		if err := f.dl.Check(ctx, nil); err == nil {
			t.Fatal("a nil token was permitted")
		}
	})
	// A token naming no credential cannot be checked against the denylist at
	// all, so it must not be permitted by it.
	t.Run("empty credential id", func(t *testing.T) {
		if err := f.dl.Check(ctx, tokenFor("")); err == nil {
			t.Fatal("a token with no credential id was permitted")
		}
	})
}

func TestRevokeCredentialRejectsAnEmptyID(t *testing.T) {
	f := newDenylistFixture(t)
	if err := f.dl.RevokeCredential(context.Background(), ""); !errors.Is(err, domain.ErrInvalidInput) {
		t.Fatalf("err = %v, want domain.ErrInvalidInput", err)
	}
}

func TestRevokeCredentialReportsAStoreFailure(t *testing.T) {
	storeDown := errors.New("connection refused")
	dl, err := auth.NewDenylist(&failingStore{incErr: storeDown})
	if err != nil {
		t.Fatalf("NewDenylist: %v", err)
	}
	if err := dl.RevokeCredential(context.Background(), "cred-1"); !errors.Is(err, storeDown) {
		t.Fatalf("err = %v, want the store failure reported to the caller", err)
	}
}

// TestRevokeCredentialIsIdempotent shows that revoking twice is harmless. An
// honest client retrying, or two instances reacting to one event, must not
// leave the entry in a state that reads as permitted.
func TestRevokeCredentialIsIdempotent(t *testing.T) {
	f := newDenylistFixture(t)
	ctx := context.Background()

	for range 3 {
		if err := f.dl.RevokeCredential(ctx, "cred-1"); err != nil {
			t.Fatalf("RevokeCredential: %v", err)
		}
	}
	if err := f.dl.Check(ctx, tokenFor("cred-1")); err == nil {
		t.Fatal("a repeatedly revoked credential was permitted")
	}
}

// TestEntryOutlivesTheTokenItDenies pins the expiry arithmetic against the
// access token lifetime. The entry must still deny at the last instant a token
// derived from that credential could be presented.
func TestEntryOutlivesTheTokenItDenies(t *testing.T) {
	f := newDenylistFixture(t)
	ctx := context.Background()

	if err := f.dl.RevokeCredential(ctx, "cred-1"); err != nil {
		t.Fatalf("RevokeCredential: %v", err)
	}

	// The longest-lived access token this credential could have minted expires
	// one AccessTokenLifetime from now; the entry must outlast that, with the
	// skew margin on top.
	f.advance(auth.AccessTokenLifetime + auth.DenylistSkew - time.Second)
	if err := f.dl.Check(ctx, tokenFor("cred-1")); err == nil {
		t.Fatal("the entry expired while a token it denies could still be live")
	}
}

// TestExpiredEntriesArePermittedAndReleased is the bounded-growth test. Once
// every token an entry could deny is dead of its own expiry, the entry must
// both stop matching and stop occupying space -- asserted on resident size,
// because an entry that is merely reported absent is still leaked memory.
func TestExpiredEntriesArePermittedAndReleased(t *testing.T) {
	f := newDenylistFixture(t)
	ctx := context.Background()

	if err := f.dl.RevokeCredential(ctx, "cred-1"); err != nil {
		t.Fatalf("RevokeCredential: %v", err)
	}
	if f.store.Len() != 1 {
		t.Fatalf("resident entries = %d, want 1", f.store.Len())
	}

	f.advance(auth.AccessTokenLifetime + auth.DenylistSkew)

	// Every access token from this credential is now refused by its own expiry,
	// so the entry has no work left to do.
	if err := f.dl.Check(ctx, tokenFor("cred-1")); err != nil {
		t.Fatalf("an expired entry still denied: %v", err)
	}
	if removed := f.store.Sweep(); removed != 1 {
		t.Fatalf("Sweep removed %d entries, want 1", removed)
	}
	if f.store.Len() != 0 {
		t.Fatalf("resident entries after expiry = %d, want 0: the denylist grows without bound", f.store.Len())
	}
}

// TestStoredKeysAreDigests shows the identifier itself never reaches the store.
// The store may be shared infrastructure, and a dump of it must not reveal
// which credentials were revoked.
func TestStoredKeysAreDigests(t *testing.T) {
	store := &failingStore{}
	dl, err := auth.NewDenylist(store)
	if err != nil {
		t.Fatalf("NewDenylist: %v", err)
	}
	const id = "recognizable-credential-id"
	if err := dl.RevokeCredential(context.Background(), id); err != nil {
		t.Fatalf("RevokeCredential: %v", err)
	}
	if len(store.keys) != 1 {
		t.Fatalf("Increment called %d times, want 1", len(store.keys))
	}
	if strings.Contains(store.keys[0], id) {
		t.Fatalf("the stored key %q contains the credential id verbatim", store.keys[0])
	}
	// A SHA-256 under unpadded base64url is 43 characters, so every key is the
	// same length whatever it names.
	if len(store.keys[0]) != 43 {
		t.Fatalf("key %q has length %d, want a fixed-length digest", store.keys[0], len(store.keys[0]))
	}
}

func TestRevokeLineageDeniesEveryLiveCredential(t *testing.T) {
	f := newDenylistFixture(t)
	ctx := context.Background()

	// A lineage that rotated several times, all recently enough that access
	// tokens minted from each could still be live.
	creds := []domain.RefreshCredential{
		{ID: "cred-1", IssuedAt: f.now.Add(-10 * time.Minute)},
		{ID: "cred-2", IssuedAt: f.now.Add(-5 * time.Minute)},
		{ID: "cred-3", IssuedAt: f.now},
	}
	if err := f.dl.RevokeLineage(ctx, creds, f.now); err != nil {
		t.Fatalf("RevokeLineage: %v", err)
	}

	for _, c := range creds {
		if err := f.dl.Check(ctx, tokenFor(c.ID)); err == nil {
			t.Fatalf("credential %q survived lineage revocation", c.ID)
		}
	}
}

// TestRevokeLineageSkipsCredentialsWhoseTokensAreAlreadyDead documents the
// bound on write amplification. Skipping them is not a hole: an access token
// from such a credential is already refused by the stateless expiry check, so
// an entry for it could never match anything.
func TestRevokeLineageSkipsCredentialsWhoseTokensAreAlreadyDead(t *testing.T) {
	f := newDenylistFixture(t)
	ctx := context.Background()

	ttl := auth.AccessTokenLifetime + auth.DenylistSkew
	creds := []domain.RefreshCredential{
		{ID: "ancient", IssuedAt: f.now.Add(-90 * 24 * time.Hour)},
		{ID: "just-too-old", IssuedAt: f.now.Add(-ttl)},
		{ID: "still-live", IssuedAt: f.now.Add(-ttl + time.Second)},
	}
	if err := f.dl.RevokeLineage(ctx, creds, f.now); err != nil {
		t.Fatalf("RevokeLineage: %v", err)
	}

	if f.store.Len() != 1 {
		t.Fatalf("entries written = %d, want 1 (only the credential with live tokens)", f.store.Len())
	}
	if err := f.dl.Check(ctx, tokenFor("still-live")); err == nil {
		t.Fatal("a credential with live access tokens was not listed")
	}
}

func TestRevokeLineageOfAnEmptyOrNilList(t *testing.T) {
	f := newDenylistFixture(t)
	for _, creds := range [][]domain.RefreshCredential{nil, {}} {
		if err := f.dl.RevokeLineage(context.Background(), creds, f.now); err != nil {
			t.Fatalf("RevokeLineage of an empty lineage: %v", err)
		}
	}
	if f.store.Len() != 0 {
		t.Fatalf("entries written = %d, want 0", f.store.Len())
	}
}

// TestRevokeLineageRejectsAMalformedRow shows a row with no identifier is not
// silently counted as revoked: a database that started returning empty ids must
// not look like a working denylist.
func TestRevokeLineageRejectsAMalformedRow(t *testing.T) {
	f := newDenylistFixture(t)
	creds := []domain.RefreshCredential{{ID: "", IssuedAt: f.now}}
	if err := f.dl.RevokeLineage(context.Background(), creds, f.now); !errors.Is(err, domain.ErrInvalidInput) {
		t.Fatalf("err = %v, want domain.ErrInvalidInput", err)
	}
}

func TestRevokeLineageReportsAStoreFailure(t *testing.T) {
	storeDown := errors.New("connection refused")
	dl, err := auth.NewDenylist(&failingStore{incErr: storeDown})
	if err != nil {
		t.Fatalf("NewDenylist: %v", err)
	}
	now := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	creds := []domain.RefreshCredential{{ID: "cred-1", IssuedAt: now}}
	if err := dl.RevokeLineage(context.Background(), creds, now); !errors.Is(err, storeDown) {
		t.Fatalf("err = %v, want the store failure reported to the caller", err)
	}
}
