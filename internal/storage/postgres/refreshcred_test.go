package postgres

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/repository"
)

// newCred returns a fully populated active refresh credential owned by ownerID.
func newCred(id, ownerID, lineageID string) *domain.RefreshCredential {
	return &domain.RefreshCredential{
		ID:          domain.RefreshCredentialID(id),
		OwnerID:     domain.OwnerID(ownerID),
		LineageID:   domain.LineageID(lineageID),
		SecretHash:  []byte("digest-" + id),
		Scopes:      []domain.Scope{{Kind: domain.ScopeFullOwner}},
		ClientLabel: "laptop",
		IssuedAt:    testClock,
		ExpiresAt:   testClock.Add(24 * time.Hour),
		Status:      domain.CredentialStatusActive,
	}
}

// mustCreateCred creates the owner (if needed) and the credential.
func mustCreateCred(t *testing.T, s *Store, c *domain.RefreshCredential) {
	t.Helper()
	ctx := context.Background()
	if _, err := s.Repos().Owners.Get(ctx, c.OwnerID); errors.Is(err, domain.ErrNotFound) {
		mustCreateOwner(t, s, string(c.OwnerID))
	}
	if err := s.Repos().RefreshCredentials.Create(ctx, c); err != nil {
		t.Fatalf("Create credential %q: %v", c.ID, err)
	}
}

func TestRefreshCredCreateAndGet(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	want := newCred("rc-1", "owner-a", "lin-1")
	mustCreateCred(t, s, want)

	got, err := s.Repos().RefreshCredentials.Get(ctx, "owner-a", "rc-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.ID != want.ID || got.OwnerID != want.OwnerID || got.LineageID != want.LineageID {
		t.Errorf("identity = %q/%q/%q, want rc-1/owner-a/lin-1", got.ID, got.OwnerID, got.LineageID)
	}
	// The digest must survive the BYTEA round trip byte for byte: it is what
	// the constant-time comparison in internal/auth is performed against.
	if !bytes.Equal(got.SecretHash, want.SecretHash) {
		t.Errorf("SecretHash = %x, want %x", got.SecretHash, want.SecretHash)
	}
	if got.ClientLabel != "laptop" || got.Status != domain.CredentialStatusActive {
		t.Errorf("label/status = %q/%q, want laptop/active", got.ClientLabel, got.Status)
	}
	if len(got.Scopes) != 1 || got.Scopes[0].Kind != domain.ScopeFullOwner {
		t.Errorf("Scopes = %+v, want one full-owner scope", got.Scopes)
	}
	if got.RotatedFromID != nil || got.RevokedAt != nil {
		t.Errorf("RotatedFromID/RevokedAt = %v/%v, want nil/nil", got.RotatedFromID, got.RevokedAt)
	}
}

// The expiry timestamp decides when a credential stops being accepted, so it
// must come back as the same instant, in UTC, whatever zone it was handed in.
func TestRefreshCredTimestampsRoundTripFromNonUTCZone(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	zone := time.FixedZone("UTC-7", -7*60*60)
	wantExpiry := testClock.Add(90 * time.Minute)
	c := newCred("rc-tz", "owner-a", "lin-1")
	c.IssuedAt = testClock.In(zone)
	c.ExpiresAt = wantExpiry.In(zone)
	revoked := testClock.Add(30 * time.Minute).In(zone)
	c.RevokedAt = &revoked
	mustCreateCred(t, s, c)

	got, err := s.Repos().RefreshCredentials.Get(ctx, "owner-a", "rc-tz")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !got.IssuedAt.Equal(testClock) {
		t.Errorf("IssuedAt = %v, want the same instant as %v", got.IssuedAt, testClock)
	}
	if !got.ExpiresAt.Equal(wantExpiry) {
		t.Errorf("ExpiresAt = %v, want %v", got.ExpiresAt, wantExpiry)
	}
	if got.RevokedAt == nil || !got.RevokedAt.Equal(testClock.Add(30*time.Minute)) {
		t.Errorf("RevokedAt = %v, want %v", got.RevokedAt, testClock.Add(30*time.Minute))
	}
	if got.IssuedAt.Location() != time.UTC || got.ExpiresAt.Location() != time.UTC {
		t.Errorf("locations = %v/%v, want UTC", got.IssuedAt.Location(), got.ExpiresAt.Location())
	}
}

func TestRefreshCredRotatedFromRoundTrips(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	mustCreateCred(t, s, newCred("rc-1", "owner-a", "lin-1"))
	prev := domain.RefreshCredentialID("rc-1")
	successor := newCred("rc-2", "owner-a", "lin-1")
	successor.RotatedFromID = &prev
	mustCreateCred(t, s, successor)

	got, err := s.Repos().RefreshCredentials.Get(ctx, "owner-a", "rc-2")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.RotatedFromID == nil || *got.RotatedFromID != prev {
		t.Errorf("RotatedFromID = %v, want %q", got.RotatedFromID, prev)
	}
}

func TestRefreshCredCreateNilIsInvalidInput(t *testing.T) {
	t.Parallel()
	s := newStore(t)

	if err := s.Repos().RefreshCredentials.Create(context.Background(), nil); !errors.Is(err, domain.ErrInvalidInput) {
		t.Fatalf("Create(nil) = %v, want ErrInvalidInput", err)
	}
}

// A duplicate primary key is SQLSTATE 23505, which mapError turns into the same
// domain.ErrConflict the SQLite adapter reports.
func TestRefreshCredCreateDuplicateIsConflict(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	mustCreateCred(t, s, newCred("rc-1", "owner-a", "lin-1"))

	if err := s.Repos().RefreshCredentials.Create(ctx, newCred("rc-1", "owner-a", "lin-2")); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("duplicate id = %v, want ErrConflict", err)
	}
}

// An empty scope set is stored as "[]" and decodes back to a nil slice, never
// an allocated empty one.
func TestRefreshCredCreateEmptyScopes(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	c := newCred("rc-1", "owner-a", "lin-1")
	c.Scopes = nil
	mustCreateCred(t, s, c)

	got, err := s.Repos().RefreshCredentials.Get(ctx, "owner-a", "rc-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Scopes != nil {
		t.Errorf("Scopes = %+v, want nil", got.Scopes)
	}
}

// GetByID is deliberately unscoped: it is the refresh exchange's lookup, run
// before any owner is established.
func TestRefreshCredGetByIDIsUnscoped(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	mustCreateCred(t, s, newCred("rc-1", "owner-a", "lin-1"))

	got, err := s.Repos().RefreshCredentials.GetByID(ctx, "rc-1")
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.OwnerID != "owner-a" {
		t.Errorf("OwnerID = %q, want owner-a", got.OwnerID)
	}
	if _, err := s.Repos().RefreshCredentials.GetByID(ctx, "rc-absent"); !errors.Is(err, domain.ErrNotFound) {
		t.Errorf("GetByID(absent) = %v, want ErrNotFound", err)
	}
}

// Owner B reading owner A's credential must get exactly what an id that was
// never created gets. Equality of the two errors is the property under test:
// any difference is a cross-owner existence oracle.
func TestRefreshCredGetCrossOwnerIsNotFound(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	mustCreateCred(t, s, newCred("rc-1", "owner-a", "lin-1"))
	mustCreateOwner(t, s, "owner-b")

	got, crossOwner := s.Repos().RefreshCredentials.Get(ctx, "owner-b", "rc-1")
	if got != nil {
		t.Fatalf("cross-owner Get returned %+v, want nil — owner-b read owner-a's row", got)
	}
	if !errors.Is(crossOwner, domain.ErrNotFound) {
		t.Fatalf("cross-owner Get = %v, want ErrNotFound", crossOwner)
	}
	_, invented := s.Repos().RefreshCredentials.Get(ctx, "owner-b", "rc-never-created")
	if crossOwner.Error() != invented.Error() {
		t.Errorf("cross-owner error %q differs from invented-id error %q", crossOwner, invented)
	}
}

func TestRefreshCredListByOwner(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	mustCreateCred(t, s, newCred("rc-2", "owner-a", "lin-1"))
	mustCreateCred(t, s, newCred("rc-1", "owner-a", "lin-1"))
	mustCreateCred(t, s, newCred("rc-9", "owner-b", "lin-9"))

	got, err := s.Repos().RefreshCredentials.ListByOwner(ctx, "owner-a")
	if err != nil {
		t.Fatalf("ListByOwner: %v", err)
	}
	if len(got) != 2 || got[0].ID != "rc-1" || got[1].ID != "rc-2" {
		t.Fatalf("list = %+v, want rc-1 then rc-2 and nothing of owner-b's", got)
	}
}

// An owner with no credentials, and an owner id that was never created, both
// yield a nil slice.
func TestRefreshCredListEmptyIsNil(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	mustCreateOwner(t, s, "owner-a")

	byOwner, err := s.Repos().RefreshCredentials.ListByOwner(ctx, "owner-a")
	if err != nil {
		t.Fatalf("ListByOwner: %v", err)
	}
	byLineage, err := s.Repos().RefreshCredentials.ListByLineage(ctx, "owner-a", "lin-1")
	if err != nil {
		t.Fatalf("ListByLineage: %v", err)
	}
	invented, err := s.Repos().RefreshCredentials.ListByOwner(ctx, "owner-never-created")
	if err != nil {
		t.Fatalf("ListByOwner(invented): %v", err)
	}
	if byOwner != nil || byLineage != nil || invented != nil {
		t.Errorf("lists = %v / %v / %v, want nil throughout", byOwner, byLineage, invented)
	}
}

func TestRefreshCredListByLineage(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	mustCreateCred(t, s, newCred("rc-1", "owner-a", "lin-1"))
	mustCreateCred(t, s, newCred("rc-2", "owner-a", "lin-1"))
	mustCreateCred(t, s, newCred("rc-3", "owner-a", "lin-2"))

	got, err := s.Repos().RefreshCredentials.ListByLineage(ctx, "owner-a", "lin-1")
	if err != nil {
		t.Fatalf("ListByLineage: %v", err)
	}
	if len(got) != 2 || got[0].ID != "rc-1" || got[1].ID != "rc-2" {
		t.Fatalf("list = %+v, want rc-1 then rc-2", got)
	}
}

// A lineage id is not a secret, so the owner predicate is what stops one owner
// replaying another's lineage id to enumerate their rotation chain.
func TestRefreshCredListByLineageIsOwnerScoped(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	mustCreateCred(t, s, newCred("rc-1", "owner-a", "lin-shared"))
	mustCreateOwner(t, s, "owner-b")

	got, err := s.Repos().RefreshCredentials.ListByLineage(ctx, "owner-b", "lin-shared")
	if err != nil {
		t.Fatalf("ListByLineage: %v", err)
	}
	if got != nil {
		t.Fatalf("owner-b saw %+v of owner-a's lineage, want nil", got)
	}
}

func TestRefreshCredMarkRotated(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	mustCreateCred(t, s, newCred("rc-1", "owner-a", "lin-1"))

	if err := s.Repos().RefreshCredentials.MarkRotated(ctx, "owner-a", "rc-1", testClock.Add(time.Hour)); err != nil {
		t.Fatalf("MarkRotated: %v", err)
	}
	got, err := s.Repos().RefreshCredentials.Get(ctx, "owner-a", "rc-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Status != domain.CredentialStatusRotated {
		t.Errorf("status = %q, want rotated", got.Status)
	}
}

// The second redemption of the same credential must be refused: this is the
// single-use interlock the conditional UPDATE exists for.
func TestRefreshCredMarkRotatedTwiceIsConflict(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	mustCreateCred(t, s, newCred("rc-1", "owner-a", "lin-1"))

	if err := s.Repos().RefreshCredentials.MarkRotated(ctx, "owner-a", "rc-1", testClock); err != nil {
		t.Fatalf("first MarkRotated: %v", err)
	}
	err := s.Repos().RefreshCredentials.MarkRotated(ctx, "owner-a", "rc-1", testClock)
	if !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("second MarkRotated = %v, want ErrConflict", err)
	}
}

// Rotating another owner's credential is ErrNotFound, not ErrConflict: the
// classifying SELECT is owner-scoped, so an inaccessible row cannot be
// distinguished from a missing one, and the row must be left alone.
func TestRefreshCredMarkRotatedCrossOwnerIsNotFound(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	mustCreateCred(t, s, newCred("rc-1", "owner-a", "lin-1"))
	mustCreateOwner(t, s, "owner-b")

	crossOwner := s.Repos().RefreshCredentials.MarkRotated(ctx, "owner-b", "rc-1", testClock)
	if !errors.Is(crossOwner, domain.ErrNotFound) {
		t.Fatalf("cross-owner MarkRotated = %v, want ErrNotFound", crossOwner)
	}
	invented := s.Repos().RefreshCredentials.MarkRotated(ctx, "owner-b", "rc-never-created", testClock)
	if crossOwner.Error() != invented.Error() {
		t.Errorf("cross-owner error %q differs from invented-id error %q", crossOwner, invented)
	}

	got, err := s.Repos().RefreshCredentials.Get(ctx, "owner-a", "rc-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Status != domain.CredentialStatusActive {
		t.Errorf("status = %q after a cross-owner rotate, want it untouched at active", got.Status)
	}
}

func TestRefreshCredRevoke(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	mustCreateCred(t, s, newCred("rc-1", "owner-a", "lin-1"))
	now := testClock.Add(3 * time.Hour)

	if err := s.Repos().RefreshCredentials.Revoke(ctx, "owner-a", "rc-1", now); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	got, err := s.Repos().RefreshCredentials.Get(ctx, "owner-a", "rc-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Status != domain.CredentialStatusRevoked {
		t.Errorf("status = %q, want revoked", got.Status)
	}
	if got.RevokedAt == nil || !got.RevokedAt.Equal(now) {
		t.Errorf("RevokedAt = %v, want %v", got.RevokedAt, now)
	}
}

// Revocation converges rather than objecting: the incident-response path must
// not fail on a credential that is already terminal.
func TestRefreshCredRevokeConvergesFromTerminal(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	mustCreateCred(t, s, newCred("rc-1", "owner-a", "lin-1"))

	if err := s.Repos().RefreshCredentials.MarkRotated(ctx, "owner-a", "rc-1", testClock); err != nil {
		t.Fatalf("MarkRotated: %v", err)
	}
	if err := s.Repos().RefreshCredentials.Revoke(ctx, "owner-a", "rc-1", testClock); err != nil {
		t.Fatalf("Revoke after rotate = %v, want it to converge", err)
	}
}

func TestRefreshCredRevokeCrossOwnerIsNotFound(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	mustCreateCred(t, s, newCred("rc-1", "owner-a", "lin-1"))
	mustCreateOwner(t, s, "owner-b")

	crossOwner := s.Repos().RefreshCredentials.Revoke(ctx, "owner-b", "rc-1", testClock)
	if !errors.Is(crossOwner, domain.ErrNotFound) {
		t.Fatalf("cross-owner Revoke = %v, want ErrNotFound", crossOwner)
	}
	invented := s.Repos().RefreshCredentials.Revoke(ctx, "owner-b", "rc-never-created", testClock)
	if crossOwner.Error() != invented.Error() {
		t.Errorf("cross-owner error %q differs from invented-id error %q", crossOwner, invented)
	}

	got, err := s.Repos().RefreshCredentials.Get(ctx, "owner-a", "rc-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Status != domain.CredentialStatusActive {
		t.Errorf("status = %q after a cross-owner revoke, want it untouched at active", got.Status)
	}
}

func TestRefreshCredRevokeLineage(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	mustCreateCred(t, s, newCred("rc-1", "owner-a", "lin-1"))
	mustCreateCred(t, s, newCred("rc-2", "owner-a", "lin-1"))
	mustCreateCred(t, s, newCred("rc-3", "owner-a", "lin-2"))

	n, err := s.Repos().RefreshCredentials.RevokeLineage(ctx, "owner-a", "lin-1", testClock)
	if err != nil {
		t.Fatalf("RevokeLineage: %v", err)
	}
	if n != 2 {
		t.Fatalf("revoked %d, want 2", n)
	}
	other, err := s.Repos().RefreshCredentials.Get(ctx, "owner-a", "rc-3")
	if err != nil {
		t.Fatalf("Get rc-3: %v", err)
	}
	if other.Status != domain.CredentialStatusActive {
		t.Errorf("rc-3 status = %q, want the other lineage untouched", other.Status)
	}
}

// Already-revoked rows are excluded from the count, so the number returned is
// what this call actually took out of service.
func TestRefreshCredRevokeLineageSkipsAlreadyRevoked(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	mustCreateCred(t, s, newCred("rc-1", "owner-a", "lin-1"))
	mustCreateCred(t, s, newCred("rc-2", "owner-a", "lin-1"))
	if err := s.Repos().RefreshCredentials.Revoke(ctx, "owner-a", "rc-1", testClock); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	n, err := s.Repos().RefreshCredentials.RevokeLineage(ctx, "owner-a", "lin-1", testClock)
	if err != nil {
		t.Fatalf("RevokeLineage: %v", err)
	}
	if n != 1 {
		t.Errorf("revoked %d, want 1", n)
	}
}

func TestRefreshCredRevokeLineageIsOwnerScoped(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	mustCreateCred(t, s, newCred("rc-1", "owner-a", "lin-shared"))
	mustCreateOwner(t, s, "owner-b")

	n, err := s.Repos().RefreshCredentials.RevokeLineage(ctx, "owner-b", "lin-shared", testClock)
	if err != nil {
		t.Fatalf("RevokeLineage: %v", err)
	}
	if n != 0 {
		t.Fatalf("owner-b revoked %d of owner-a's credentials, want 0", n)
	}
	got, err := s.Repos().RefreshCredentials.Get(ctx, "owner-a", "rc-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Status != domain.CredentialStatusActive {
		t.Errorf("status = %q, want active", got.Status)
	}
}

func TestRefreshCredDeleteExpired(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	old := newCred("rc-1", "owner-a", "lin-1")
	old.ExpiresAt = testClock.Add(-2 * time.Hour)
	mustCreateCred(t, s, old)

	atCutoff := newCred("rc-2", "owner-a", "lin-1")
	atCutoff.ExpiresAt = testClock
	mustCreateCred(t, s, atCutoff)

	live := newCred("rc-3", "owner-a", "lin-1")
	live.ExpiresAt = testClock.Add(2 * time.Hour)
	mustCreateCred(t, s, live)

	// The cutoff is inclusive, so rc-1 and rc-2 go and rc-3 stays. That the
	// boundary lands where it does depends on the text expiry comparison being
	// chronological, which fixed-width UTC encoding is what makes true.
	n, err := s.Repos().RefreshCredentials.DeleteExpired(ctx, testClock, 10)
	if err != nil {
		t.Fatalf("DeleteExpired: %v", err)
	}
	if n != 2 {
		t.Fatalf("DeleteExpired deleted %d, want 2", n)
	}
	if _, err := s.Repos().RefreshCredentials.Get(ctx, "owner-a", "rc-3"); err != nil {
		t.Fatalf("Get rc-3: %v, want the unexpired row to survive", err)
	}
}

// The batch bound and its oldest-first ordering: PostgreSQL has no
// DELETE ... LIMIT, so both come from the bounded subquery.
func TestRefreshCredDeleteExpiredHonoursLimit(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	for i, id := range []string{"rc-1", "rc-2", "rc-3"} {
		c := newCred(id, "owner-a", "lin-1")
		c.ExpiresAt = testClock.Add(time.Duration(-3+i) * time.Hour)
		mustCreateCred(t, s, c)
	}

	n, err := s.Repos().RefreshCredentials.DeleteExpired(ctx, testClock, 2)
	if err != nil {
		t.Fatalf("DeleteExpired: %v", err)
	}
	if n != 2 {
		t.Fatalf("DeleteExpired deleted %d, want 2", n)
	}
	// rc-3 expired last, so it is the one the bounded, oldest-first batch left.
	if _, err := s.Repos().RefreshCredentials.Get(ctx, "owner-a", "rc-3"); err != nil {
		t.Fatalf("Get rc-3: %v, want the newest expiry to survive the batch", err)
	}
}

// A caller's zero value must not become a full-table delete.
func TestRefreshCredDeleteExpiredRejectsNonPositiveLimit(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	for _, limit := range []int{0, -1} {
		n, err := s.Repos().RefreshCredentials.DeleteExpired(ctx, testClock, limit)
		if !errors.Is(err, domain.ErrInvalidInput) {
			t.Errorf("DeleteExpired(limit=%d) = %v, want ErrInvalidInput", limit, err)
		}
		if n != 0 {
			t.Errorf("DeleteExpired(limit=%d) deleted %d, want 0", limit, n)
		}
	}
}

func TestRefreshCredScopesRoundTripMultiple(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	c := newCred("rc-1", "owner-a", "lin-1")
	c.Scopes = []domain.Scope{
		{Kind: domain.ScopeReadOnly},
		{Kind: domain.ScopeSingleSet, ResourceID: "ks-1"},
	}
	mustCreateCred(t, s, c)

	got, err := s.Repos().RefreshCredentials.Get(ctx, "owner-a", "rc-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if len(got.Scopes) != 2 || got.Scopes[1].Kind != domain.ScopeSingleSet || got.Scopes[1].ResourceID != "ks-1" {
		t.Fatalf("Scopes = %+v, want read-only and single-set/ks-1", got.Scopes)
	}
}

// The decode error path, which no round trip through Create can reach.
func TestRefreshCredDecScopesRejectsMalformed(t *testing.T) {
	t.Parallel()

	if _, err := decScopes("not json"); err == nil {
		t.Fatal("decScopes(malformed) = nil error, want a decode failure")
	}
}

// The repository composes into a caller-managed transaction, and a rollback
// takes the write with it.
func TestRefreshCredTransactional(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	mustCreateOwner(t, s, "owner-a")

	wantErr := errors.New("rollback")
	err := s.WithTx(ctx, func(ctx context.Context, r repository.Repos) error {
		if cerr := r.RefreshCredentials.Create(ctx, newCred("rc-1", "owner-a", "lin-1")); cerr != nil {
			return cerr
		}
		return wantErr
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("WithTx = %v, want the rollback error", err)
	}
	if _, err := s.Repos().RefreshCredentials.GetByID(ctx, "rc-1"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("GetByID after rollback = %v, want ErrNotFound", err)
	}
}

// A corrupt expiry must surface as a decode error rather than a zero time, which
// would read as "expired in year one" and silently reject a live credential.
func TestRefreshCredRejectsCorruptTimestamp(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	mustCreateCred(t, s, newCred("rc-1", "owner-a", "lin-1"))

	if _, err := s.db.ExecContext(ctx,
		`UPDATE refresh_credentials SET expires_at = $1 WHERE id = $2`, "not-a-timestamp", "rc-1"); err != nil {
		t.Fatalf("corrupt row: %v", err)
	}
	if _, err := s.Repos().RefreshCredentials.Get(ctx, "owner-a", "rc-1"); err == nil {
		t.Error("corrupt expires_at decoded without error")
	}
}
