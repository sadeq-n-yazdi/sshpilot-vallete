package sqlite

import (
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
	prev := domain.RefreshCredentialID("rc-0")
	want.RotatedFromID = &prev
	mustCreateCred(t, s, want)

	got, err := s.Repos().RefreshCredentials.Get(ctx, "owner-a", "rc-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.ID != want.ID || got.OwnerID != want.OwnerID || got.LineageID != want.LineageID {
		t.Errorf("identity round-trip = %+v", got)
	}
	if string(got.SecretHash) != string(want.SecretHash) {
		t.Errorf("SecretHash = %q, want %q", got.SecretHash, want.SecretHash)
	}
	if len(got.Scopes) != 1 || got.Scopes[0].Kind != domain.ScopeFullOwner {
		t.Errorf("Scopes = %+v, want one full-owner scope", got.Scopes)
	}
	if got.ClientLabel != "laptop" || got.Status != domain.CredentialStatusActive {
		t.Errorf("label/status = %q/%q", got.ClientLabel, got.Status)
	}
	if got.RotatedFromID == nil || *got.RotatedFromID != prev {
		t.Errorf("RotatedFromID = %v, want %q", got.RotatedFromID, prev)
	}
	if !got.IssuedAt.Equal(want.IssuedAt) || !got.ExpiresAt.Equal(want.ExpiresAt) {
		t.Errorf("timestamps = %v/%v", got.IssuedAt, got.ExpiresAt)
	}
	if got.RevokedAt != nil {
		t.Errorf("RevokedAt = %v, want nil", got.RevokedAt)
	}
}

func TestRefreshCredCreateNilIsInvalidInput(t *testing.T) {
	t.Parallel()
	s := newStore(t)

	err := s.Repos().RefreshCredentials.Create(context.Background(), nil)
	if !errors.Is(err, domain.ErrInvalidInput) {
		t.Fatalf("Create(nil) = %v, want ErrInvalidInput", err)
	}
}

func TestRefreshCredCreateDuplicateIsConflict(t *testing.T) {
	t.Parallel()
	s := newStore(t)

	mustCreateCred(t, s, newCred("rc-1", "owner-a", "lin-1"))
	err := s.Repos().RefreshCredentials.Create(context.Background(), newCred("rc-1", "owner-a", "lin-1"))
	if !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("duplicate Create = %v, want ErrConflict", err)
	}
}

// TestRefreshCredCreateEmptyScopes covers the nil/empty scope encoding path and
// its nil-slice round trip.
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

// TestRefreshCredGetByIDIsUnscoped documents that the authentication lookup
// resolves a credential without an owner, which is what makes it the step that
// establishes one.
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

	if _, err := s.Repos().RefreshCredentials.GetByID(ctx, "nope"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("GetByID(missing) = %v, want ErrNotFound", err)
	}
}

// TestRefreshCredGetCrossOwnerIsNotFound is the isolation test: another owner's
// credential must be indistinguishable from one that does not exist.
func TestRefreshCredGetCrossOwnerIsNotFound(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	mustCreateCred(t, s, newCred("rc-1", "owner-a", "lin-1"))
	mustCreateOwner(t, s, "owner-b")

	_, wrongOwner := s.Repos().RefreshCredentials.Get(ctx, "owner-b", "rc-1")
	_, missing := s.Repos().RefreshCredentials.Get(ctx, "owner-b", "rc-absent")
	if !errors.Is(wrongOwner, domain.ErrNotFound) || !errors.Is(missing, domain.ErrNotFound) {
		t.Fatalf("cross-owner = %v, missing = %v; both must be ErrNotFound", wrongOwner, missing)
	}
}

func TestRefreshCredListByOwner(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	mustCreateCred(t, s, newCred("rc-2", "owner-a", "lin-1"))
	mustCreateCred(t, s, newCred("rc-1", "owner-a", "lin-2"))
	mustCreateCred(t, s, newCred("rc-9", "owner-b", "lin-9"))

	got, err := s.Repos().RefreshCredentials.ListByOwner(ctx, "owner-a")
	if err != nil {
		t.Fatalf("ListByOwner: %v", err)
	}
	if len(got) != 2 || got[0].ID != "rc-1" || got[1].ID != "rc-2" {
		t.Fatalf("ListByOwner = %+v, want rc-1, rc-2 in id order", got)
	}
}

// TestRefreshCredListEmptyIsNil pins the empty-list-is-nil convention for both
// listing methods.
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
	if byOwner != nil || byLineage != nil {
		t.Fatalf("empty lists = %v / %v, want nil slices", byOwner, byLineage)
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
		t.Fatalf("ListByLineage = %+v, want rc-1, rc-2", got)
	}
}

// TestRefreshCredListByLineageIsOwnerScoped proves the lineage listing cannot be
// used to read another owner's rotation chain by guessing a lineage id.
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
		t.Fatalf("ListByLineage across owners = %+v, want nil", got)
	}
}

func TestRefreshCredMarkRotated(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	mustCreateCred(t, s, newCred("rc-1", "owner-a", "lin-1"))
	rotatedAt := testClock.Add(time.Hour)

	if err := s.Repos().RefreshCredentials.MarkRotated(ctx, "owner-a", "rc-1", rotatedAt); err != nil {
		t.Fatalf("MarkRotated: %v", err)
	}
	got, err := s.Repos().RefreshCredentials.Get(ctx, "owner-a", "rc-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Status != domain.CredentialStatusRotated {
		t.Fatalf("Status = %q, want rotated", got.Status)
	}
}

// TestRefreshCredMarkRotatedTwiceIsConflict is the single-use property in its
// serial form: the second rotation of the same credential must be refused, and
// refused as ErrConflict specifically, because that is the signal the service
// reads as evidence the token was presented twice.
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

// TestRefreshCredMarkRotatedFromTerminalStates covers every non-active starting
// state, each of which must refuse the transition with ErrConflict.
func TestRefreshCredMarkRotatedFromTerminalStates(t *testing.T) {
	t.Parallel()

	for _, status := range []domain.CredentialStatus{
		domain.CredentialStatusRotated,
		domain.CredentialStatusRevoked,
		domain.CredentialStatusExpired,
	} {
		t.Run(string(status), func(t *testing.T) {
			t.Parallel()
			s := newStore(t)
			ctx := context.Background()

			c := newCred("rc-1", "owner-a", "lin-1")
			c.Status = status
			mustCreateCred(t, s, c)

			err := s.Repos().RefreshCredentials.MarkRotated(ctx, "owner-a", "rc-1", testClock)
			if !errors.Is(err, domain.ErrConflict) {
				t.Fatalf("MarkRotated from %q = %v, want ErrConflict", status, err)
			}
		})
	}
}

// TestRefreshCredMarkRotatedCrossOwnerIsNotFound is the classification test that
// separates ErrNotFound from ErrConflict. An active credential of another owner
// must report ErrNotFound, NOT ErrConflict: reporting a conflict would confirm
// that the id exists and is active, leaking a row across the owner boundary.
func TestRefreshCredMarkRotatedCrossOwnerIsNotFound(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	mustCreateCred(t, s, newCred("rc-1", "owner-a", "lin-1"))
	mustCreateOwner(t, s, "owner-b")

	wrongOwner := s.Repos().RefreshCredentials.MarkRotated(ctx, "owner-b", "rc-1", testClock)
	missing := s.Repos().RefreshCredentials.MarkRotated(ctx, "owner-b", "rc-absent", testClock)
	if !errors.Is(wrongOwner, domain.ErrNotFound) || !errors.Is(missing, domain.ErrNotFound) {
		t.Fatalf("cross-owner = %v, missing = %v; both must be ErrNotFound", wrongOwner, missing)
	}

	// The other owner's credential must also be untouched by the attempt.
	got, err := s.Repos().RefreshCredentials.Get(ctx, "owner-a", "rc-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Status != domain.CredentialStatusActive {
		t.Fatalf("Status = %q, want the row left active", got.Status)
	}
}

func TestRefreshCredRevoke(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	mustCreateCred(t, s, newCred("rc-1", "owner-a", "lin-1"))
	revokedAt := testClock.Add(time.Hour)

	if err := s.Repos().RefreshCredentials.Revoke(ctx, "owner-a", "rc-1", revokedAt); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	got, err := s.Repos().RefreshCredentials.Get(ctx, "owner-a", "rc-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Status != domain.CredentialStatusRevoked {
		t.Errorf("Status = %q, want revoked", got.Status)
	}
	if got.RevokedAt == nil || !got.RevokedAt.Equal(revokedAt) {
		t.Errorf("RevokedAt = %v, want %v", got.RevokedAt, revokedAt)
	}
}

// TestRefreshCredRevokeConvergesFromTerminal pins that revocation is
// unconditional. An operator shutting down a credential during an incident must
// not be refused because it has already rotated.
func TestRefreshCredRevokeConvergesFromTerminal(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	c := newCred("rc-1", "owner-a", "lin-1")
	c.Status = domain.CredentialStatusRotated
	mustCreateCred(t, s, c)

	if err := s.Repos().RefreshCredentials.Revoke(ctx, "owner-a", "rc-1", testClock); err != nil {
		t.Fatalf("Revoke of rotated credential = %v, want nil", err)
	}
}

func TestRefreshCredRevokeCrossOwnerIsNotFound(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	mustCreateCred(t, s, newCred("rc-1", "owner-a", "lin-1"))
	mustCreateOwner(t, s, "owner-b")

	wrongOwner := s.Repos().RefreshCredentials.Revoke(ctx, "owner-b", "rc-1", testClock)
	missing := s.Repos().RefreshCredentials.Revoke(ctx, "owner-b", "rc-absent", testClock)
	if !errors.Is(wrongOwner, domain.ErrNotFound) || !errors.Is(missing, domain.ErrNotFound) {
		t.Fatalf("cross-owner = %v, missing = %v; both must be ErrNotFound", wrongOwner, missing)
	}

	got, err := s.Repos().RefreshCredentials.Get(ctx, "owner-a", "rc-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Status != domain.CredentialStatusActive {
		t.Fatalf("Status = %q, want the other owner's row untouched", got.Status)
	}
}

// TestRefreshCredRevokeLineage is the reuse-detection response: presenting a
// spent credential burns the whole chain, including the successor an attacker
// would have just minted.
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
		t.Fatalf("RevokeLineage revoked %d, want 2", n)
	}

	for _, id := range []domain.RefreshCredentialID{"rc-1", "rc-2"} {
		got, gerr := s.Repos().RefreshCredentials.Get(ctx, "owner-a", id)
		if gerr != nil {
			t.Fatalf("Get %q: %v", id, gerr)
		}
		if got.Status != domain.CredentialStatusRevoked {
			t.Errorf("%q status = %q, want revoked", id, got.Status)
		}
	}
	// A credential in a different lineage must be untouched.
	other, err := s.Repos().RefreshCredentials.Get(ctx, "owner-a", "rc-3")
	if err != nil {
		t.Fatalf("Get rc-3: %v", err)
	}
	if other.Status != domain.CredentialStatusActive {
		t.Errorf("rc-3 status = %q, want active", other.Status)
	}
}

// TestRefreshCredRevokeLineageSkipsAlreadyRevoked pins that the returned count
// is the number actually taken out of service, not the size of the lineage.
func TestRefreshCredRevokeLineageSkipsAlreadyRevoked(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	already := newCred("rc-1", "owner-a", "lin-1")
	already.Status = domain.CredentialStatusRevoked
	mustCreateCred(t, s, already)
	mustCreateCred(t, s, newCred("rc-2", "owner-a", "lin-1"))

	n, err := s.Repos().RefreshCredentials.RevokeLineage(ctx, "owner-a", "lin-1", testClock)
	if err != nil {
		t.Fatalf("RevokeLineage: %v", err)
	}
	if n != 1 {
		t.Fatalf("RevokeLineage revoked %d, want 1", n)
	}
}

// TestRefreshCredRevokeLineageIsOwnerScoped proves one owner cannot burn
// another owner's lineage by naming its id.
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
		t.Fatalf("RevokeLineage across owners revoked %d, want 0", n)
	}

	got, err := s.Repos().RefreshCredentials.Get(ctx, "owner-a", "rc-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Status != domain.CredentialStatusActive {
		t.Fatalf("Status = %q, want the other owner's row untouched", got.Status)
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

	// The cutoff is inclusive, so rc-1 and rc-2 go and rc-3 stays.
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

// TestRefreshCredDeleteExpiredHonoursLimit pins the batch bound and its
// oldest-first ordering.
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

// TestRefreshCredDeleteExpiredRejectsNonPositiveLimit pins that a caller's zero
// value cannot become a full-table delete.
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

// TestRefreshCredScopesRoundTripMultiple covers the multi-scope encode/decode
// path including a resource-bound scope.
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

// TestRefreshCredDecScopesRejectsMalformed covers the decode error path, which
// no round trip through Create can reach.
func TestRefreshCredDecScopesRejectsMalformed(t *testing.T) {
	t.Parallel()

	if _, err := decScopes("not json"); err == nil {
		t.Fatal("decScopes(malformed) = nil error, want a decode failure")
	}
}

// TestRefreshCredTransactional pins that the repository composes into a
// caller-managed transaction and that a rollback takes the write with it.
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
