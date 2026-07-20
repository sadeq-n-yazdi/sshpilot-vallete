package postgres

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
)

// newKeySet returns a fully populated active, public, non-default key set.
func newKeySet(id, ownerID, name string) *domain.KeySet {
	return &domain.KeySet{
		ID:         domain.KeySetID(id),
		OwnerID:    domain.OwnerID(ownerID),
		Name:       name,
		Visibility: domain.VisibilityPublic,
		State:      domain.NameStateActive,
		CreatedAt:  testClock,
		UpdatedAt:  testClock,
	}
}

// mustCreateKeySet creates the owner (if needed) and the key set, failing the
// test on error.
func mustCreateKeySet(t *testing.T, s *Store, ks *domain.KeySet) *domain.KeySet {
	t.Helper()
	ctx := context.Background()
	if _, err := s.Repos().Owners.Get(ctx, ks.OwnerID); errors.Is(err, domain.ErrNotFound) {
		mustCreateOwner(t, s, string(ks.OwnerID))
	}
	if err := s.Repos().KeySets.Create(ctx, ks); err != nil {
		t.Fatalf("Create key set %q: %v", ks.ID, err)
	}
	return ks
}

// countDefaults returns how many of the owner's key sets carry is_default =
// TRUE, read directly via SQL so the assertion does not depend on the
// repository code under test.
func countDefaults(t *testing.T, s *Store, ownerID string) int {
	t.Helper()
	var n int
	const q = `SELECT COUNT(*) FROM key_sets WHERE owner_id = $1 AND is_default = TRUE`
	if err := s.db.QueryRowContext(context.Background(), q, ownerID).Scan(&n); err != nil {
		t.Fatalf("count defaults for %q: %v", ownerID, err)
	}
	return n
}

func TestKeySetCreateGetRoundTrip(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	want := newKeySet("ks-1", "owner-a", "primary")
	want.Visibility = domain.VisibilityProtected
	want.State = domain.NameStateQuarantined
	until := testClock.Add(24 * time.Hour)
	want.QuarantineUntil = &until
	want.FlaggedForReview = true
	want.QuarantineOnRelease = true
	mustCreateKeySet(t, s, want)

	got, err := s.Repos().KeySets.Get(ctx, "owner-a", "ks-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.ID != want.ID || got.OwnerID != want.OwnerID || got.Name != want.Name {
		t.Errorf("Get identity = %+v, want ks-1/owner-a/primary", got)
	}
	if got.Visibility != want.Visibility || got.State != want.State {
		t.Errorf("Get = %+v, want visibility/state %q/%q", got, want.Visibility, want.State)
	}
	// The three BOOLEAN columns must round-trip natively, without the SQLite
	// adapter's 0/1 integer encoding.
	if got.IsDefault {
		t.Errorf("IsDefault = true, want false")
	}
	if !got.FlaggedForReview || !got.QuarantineOnRelease {
		t.Errorf("boolean flags = %v/%v, want true/true", got.FlaggedForReview, got.QuarantineOnRelease)
	}
	if got.QuarantineUntil == nil || !got.QuarantineUntil.Equal(until) {
		t.Errorf("QuarantineUntil = %v, want %v", got.QuarantineUntil, until)
	}
	if !got.CreatedAt.Equal(testClock) || got.CreatedAt.Location() != time.UTC {
		t.Errorf("CreatedAt = %v, want %v in UTC", got.CreatedAt, testClock)
	}
}

func TestKeySetCreateNilQuarantineUntilRoundTrips(t *testing.T) {
	t.Parallel()
	s := newStore(t)

	mustCreateKeySet(t, s, newKeySet("ks-1", "owner-a", "primary"))
	got, err := s.Repos().KeySets.Get(context.Background(), "owner-a", "ks-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.QuarantineUntil != nil {
		t.Errorf("QuarantineUntil = %v, want nil", got.QuarantineUntil)
	}
}

func TestKeySetCreateDuplicateNameConflicts(t *testing.T) {
	t.Parallel()
	s := newStore(t)

	mustCreateKeySet(t, s, newKeySet("ks-1", "owner-a", "primary"))
	err := s.Repos().KeySets.Create(context.Background(), newKeySet("ks-2", "owner-a", "primary"))
	if !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("duplicate name Create = %v, want ErrConflict", err)
	}
}

// TestKeySetCreateDuplicateOfQuarantinedTombstoneConflicts pins that the
// uniqueness index applies in every state, so a quarantined tombstone keeps its
// name reserved.
func TestKeySetCreateDuplicateOfQuarantinedTombstoneConflicts(t *testing.T) {
	t.Parallel()
	s := newStore(t)

	tomb := newKeySet("ks-tomb", "owner-a", "reserved")
	tomb.State = domain.NameStateQuarantined
	until := testClock.Add(time.Hour)
	tomb.QuarantineUntil = &until
	mustCreateKeySet(t, s, tomb)

	err := s.Repos().KeySets.Create(context.Background(), newKeySet("ks-new", "owner-a", "reserved"))
	if !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("Create over quarantined tombstone = %v, want ErrConflict", err)
	}
}

func TestKeySetCreateSameNameDifferentOwnerAllowed(t *testing.T) {
	t.Parallel()
	s := newStore(t)

	mustCreateKeySet(t, s, newKeySet("ks-a", "owner-a", "primary"))
	mustCreateKeySet(t, s, newKeySet("ks-b", "owner-b", "primary"))
}

func TestKeySetCreateNilReturnsInvalidInput(t *testing.T) {
	t.Parallel()
	s := newStore(t)

	if err := s.Repos().KeySets.Create(context.Background(), nil); !errors.Is(err, domain.ErrInvalidInput) {
		t.Errorf("Create(nil) = %v, want ErrInvalidInput", err)
	}
}

func TestKeySetUpdateNilReturnsInvalidInput(t *testing.T) {
	t.Parallel()
	s := newStore(t)

	if err := s.Repos().KeySets.Update(context.Background(), nil); !errors.Is(err, domain.ErrInvalidInput) {
		t.Errorf("Update(nil) = %v, want ErrInvalidInput", err)
	}
}

func TestKeySetGetByName(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	mustCreateKeySet(t, s, newKeySet("ks-1", "owner-a", "primary"))
	// Another owner's set with the same name must not be resolved for owner A.
	mustCreateKeySet(t, s, newKeySet("ks-b", "owner-b", "primary"))

	got, err := s.Repos().KeySets.GetByName(ctx, "owner-a", "primary")
	if err != nil {
		t.Fatalf("GetByName: %v", err)
	}
	if got.ID != "ks-1" {
		t.Errorf("GetByName.ID = %q, want ks-1", got.ID)
	}
	if _, err := s.Repos().KeySets.GetByName(ctx, "owner-a", "absent"); !errors.Is(err, domain.ErrNotFound) {
		t.Errorf("GetByName miss = %v, want ErrNotFound", err)
	}
}

func TestKeySetGetOtherOwnerReturnsNotFound(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	mustCreateKeySet(t, s, newKeySet("ks-a", "owner-a", "primary"))
	mustCreateOwner(t, s, "owner-b")

	if got, err := s.Repos().KeySets.Get(ctx, "owner-b", "ks-a"); !errors.Is(err, domain.ErrNotFound) || got != nil {
		t.Fatalf("cross-owner Get = (%v, %v), want (nil, ErrNotFound)", got, err)
	}
}

func TestKeySetListByOwnerOrderedAndScoped(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	mustCreateKeySet(t, s, newKeySet("ks-c", "owner-a", "third"))
	mustCreateKeySet(t, s, newKeySet("ks-a", "owner-a", "first"))
	mustCreateKeySet(t, s, newKeySet("ks-b", "owner-a", "second"))
	mustCreateKeySet(t, s, newKeySet("ks-x", "owner-b", "other"))

	got, err := s.Repos().KeySets.ListByOwner(ctx, "owner-a")
	if err != nil {
		t.Fatalf("ListByOwner: %v", err)
	}
	want := []domain.KeySetID{"ks-a", "ks-b", "ks-c"}
	if len(got) != len(want) {
		t.Fatalf("ListByOwner returned %d sets, want %d", len(got), len(want))
	}
	for i, id := range want {
		if got[i].ID != id {
			t.Errorf("ListByOwner[%d].ID = %q, want %q", i, got[i].ID, id)
		}
	}
}

func TestKeySetListByOwnerEmptyReturnsNilSlice(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	mustCreateOwner(t, s, "owner-empty")

	got, err := s.Repos().KeySets.ListByOwner(context.Background(), "owner-empty")
	if err != nil {
		t.Fatalf("ListByOwner: %v", err)
	}
	if got != nil {
		t.Errorf("ListByOwner = %v, want nil slice", got)
	}
}

func TestKeySetCountByOwner(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	mustCreateKeySet(t, s, newKeySet("ks-1", "owner-a", "one"))
	mustCreateKeySet(t, s, newKeySet("ks-2", "owner-a", "two"))
	mustCreateKeySet(t, s, newKeySet("ks-x", "owner-b", "other"))

	if n, err := s.Repos().KeySets.CountByOwner(ctx, "owner-a"); err != nil || n != 2 {
		t.Fatalf("CountByOwner(owner-a) = (%d, %v), want (2, nil)", n, err)
	}
	if n, err := s.Repos().KeySets.CountByOwner(ctx, "owner-b"); err != nil || n != 1 {
		t.Fatalf("CountByOwner(owner-b) = (%d, %v), want (1, nil)", n, err)
	}
}

func TestKeySetUpdatePersistsMutableFields(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	ks := mustCreateKeySet(t, s, newKeySet("ks-1", "owner-a", "primary"))
	ks.Visibility = domain.VisibilityProtected
	ks.State = domain.NameStateQuarantined
	until := testClock.Add(48 * time.Hour)
	ks.QuarantineUntil = &until
	ks.FlaggedForReview = true
	ks.QuarantineOnRelease = true
	ks.UpdatedAt = testClock.Add(time.Hour)

	if err := s.Repos().KeySets.Update(ctx, ks); err != nil {
		t.Fatalf("Update: %v", err)
	}
	got, err := s.Repos().KeySets.Get(ctx, "owner-a", "ks-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Visibility != domain.VisibilityProtected || got.State != domain.NameStateQuarantined {
		t.Errorf("Update did not persist visibility/state: %+v", got)
	}
	if !got.FlaggedForReview || !got.QuarantineOnRelease {
		t.Errorf("Update did not persist boolean flags: %+v", got)
	}
	if got.QuarantineUntil == nil || !got.QuarantineUntil.Equal(until) {
		t.Errorf("QuarantineUntil = %v, want %v", got.QuarantineUntil, until)
	}
	if !got.UpdatedAt.Equal(ks.UpdatedAt) {
		t.Errorf("UpdatedAt = %v, want %v", got.UpdatedAt, ks.UpdatedAt)
	}
}

// TestKeySetUpdateIgnoresNameAndIsDefault pins that Update writes neither name
// (immutable per row) nor is_default (owned exclusively by SetDefault).
func TestKeySetUpdateIgnoresNameAndIsDefault(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	ks := mustCreateKeySet(t, s, newKeySet("ks-1", "owner-a", "original"))
	ks.Name = "renamed"
	ks.IsDefault = true
	if err := s.Repos().KeySets.Update(ctx, ks); err != nil {
		t.Fatalf("Update: %v", err)
	}

	got, err := s.Repos().KeySets.Get(ctx, "owner-a", "ks-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Name != "original" {
		t.Errorf("Name = %q, want unchanged original", got.Name)
	}
	if got.IsDefault {
		t.Error("Update set is_default; only SetDefault may move the default")
	}
}

func TestKeySetUpdateOtherOwnerReturnsNotFound(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	mustCreateKeySet(t, s, newKeySet("ks-a", "owner-a", "primary"))
	mustCreateOwner(t, s, "owner-b")

	hijack := newKeySet("ks-a", "owner-b", "primary")
	hijack.State = domain.NameStateRetired
	if err := s.Repos().KeySets.Update(ctx, hijack); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("cross-owner Update = %v, want ErrNotFound", err)
	}

	got, err := s.Repos().KeySets.Get(ctx, "owner-a", "ks-a")
	if err != nil {
		t.Fatalf("owner A Get: %v", err)
	}
	if got.State != domain.NameStateActive {
		t.Errorf("owner A set mutated by cross-owner Update: state %q", got.State)
	}
}

// TestKeySetSetDefaultMovesDefaultAtomically pins the clear-then-set order: the
// partial unique index permits at most one default per owner, so moving it must
// never leave two rows flagged.
func TestKeySetSetDefaultMovesDefaultAtomically(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	mustCreateKeySet(t, s, newKeySet("ks-1", "owner-a", "one"))
	mustCreateKeySet(t, s, newKeySet("ks-2", "owner-a", "two"))

	if err := s.Repos().KeySets.SetDefault(ctx, "owner-a", "ks-1"); err != nil {
		t.Fatalf("SetDefault ks-1: %v", err)
	}
	if n := countDefaults(t, s, "owner-a"); n != 1 {
		t.Fatalf("defaults after first SetDefault = %d, want 1", n)
	}

	// Moving the default must clear the old one in the same transaction.
	if err := s.Repos().KeySets.SetDefault(ctx, "owner-a", "ks-2"); err != nil {
		t.Fatalf("SetDefault ks-2: %v", err)
	}
	if n := countDefaults(t, s, "owner-a"); n != 1 {
		t.Fatalf("defaults after moving = %d, want exactly 1", n)
	}
	got, err := s.Repos().KeySets.GetDefault(ctx, "owner-a")
	if err != nil {
		t.Fatalf("GetDefault: %v", err)
	}
	if got.ID != "ks-2" {
		t.Errorf("GetDefault.ID = %q, want ks-2", got.ID)
	}
}

// TestKeySetSetDefaultOtherOwnerReturnsNotFoundAndPreservesDefault pins that a
// cross-owner SetDefault rolls its clear back: owner A's default must survive
// owner B's attempt.
func TestKeySetSetDefaultOtherOwnerReturnsNotFoundAndPreservesDefault(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	mustCreateKeySet(t, s, newKeySet("ks-a", "owner-a", "primary"))
	if err := s.Repos().KeySets.SetDefault(ctx, "owner-a", "ks-a"); err != nil {
		t.Fatalf("SetDefault: %v", err)
	}
	mustCreateOwner(t, s, "owner-b")

	if err := s.Repos().KeySets.SetDefault(ctx, "owner-b", "ks-a"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("cross-owner SetDefault = %v, want ErrNotFound", err)
	}
	// The clear ran inside the transaction; the rollback must have undone it.
	got, err := s.Repos().KeySets.GetDefault(ctx, "owner-a")
	if err != nil {
		t.Fatalf("owner A GetDefault after cross-owner attempt: %v", err)
	}
	if got.ID != "ks-a" {
		t.Errorf("owner A default = %q, want preserved ks-a", got.ID)
	}
}

// TestKeySetSetDefaultIsPerOwner pins that the partial unique index is scoped
// per owner: two owners may each hold their own default simultaneously.
func TestKeySetSetDefaultIsPerOwner(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	mustCreateKeySet(t, s, newKeySet("ks-a", "owner-a", "primary"))
	mustCreateKeySet(t, s, newKeySet("ks-b", "owner-b", "primary"))

	if err := s.Repos().KeySets.SetDefault(ctx, "owner-a", "ks-a"); err != nil {
		t.Fatalf("SetDefault owner-a: %v", err)
	}
	if err := s.Repos().KeySets.SetDefault(ctx, "owner-b", "ks-b"); err != nil {
		t.Fatalf("SetDefault owner-b: %v", err)
	}
	if n := countDefaults(t, s, "owner-a"); n != 1 {
		t.Errorf("owner-a defaults = %d, want 1", n)
	}
	if n := countDefaults(t, s, "owner-b"); n != 1 {
		t.Errorf("owner-b defaults = %d, want 1", n)
	}
}

func TestKeySetGetDefaultMissReturnsNotFound(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	mustCreateKeySet(t, s, newKeySet("ks-1", "owner-a", "primary"))

	if _, err := s.Repos().KeySets.GetDefault(context.Background(), "owner-a"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("GetDefault with no default = %v, want ErrNotFound", err)
	}
}

// TestKeySetDeleteDefaultRefused pins the ErrDefaultKeySet signal: the owner
// must designate another default before deleting this one.
func TestKeySetDeleteDefaultRefused(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	mustCreateKeySet(t, s, newKeySet("ks-1", "owner-a", "primary"))
	if err := s.Repos().KeySets.SetDefault(ctx, "owner-a", "ks-1"); err != nil {
		t.Fatalf("SetDefault: %v", err)
	}

	if err := s.Repos().KeySets.Delete(ctx, "owner-a", "ks-1"); !errors.Is(err, domain.ErrDefaultKeySet) {
		t.Fatalf("Delete default = %v, want ErrDefaultKeySet", err)
	}
	if _, err := s.Repos().KeySets.Get(ctx, "owner-a", "ks-1"); err != nil {
		t.Errorf("refused Delete removed the set anyway: %v", err)
	}
}

// TestKeySetDeleteOtherOwnerReturnsNotFound pins that the default-refusal can
// never be provoked for another owner's set: the owner-scoped read misses first
// and reports ErrNotFound, never ErrDefaultKeySet, which would confirm the row
// exists and is the default.
func TestKeySetDeleteOtherOwnerReturnsNotFound(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	mustCreateKeySet(t, s, newKeySet("ks-a", "owner-a", "primary"))
	if err := s.Repos().KeySets.SetDefault(ctx, "owner-a", "ks-a"); err != nil {
		t.Fatalf("SetDefault: %v", err)
	}
	mustCreateOwner(t, s, "owner-b")

	err := s.Repos().KeySets.Delete(ctx, "owner-b", "ks-a")
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("cross-owner Delete = %v, want ErrNotFound", err)
	}
	if errors.Is(err, domain.ErrDefaultKeySet) {
		t.Errorf("cross-owner Delete leaked existence via ErrDefaultKeySet: %v", err)
	}
	if _, gerr := s.Repos().KeySets.Get(ctx, "owner-a", "ks-a"); gerr != nil {
		t.Errorf("owner A set removed by cross-owner Delete: %v", gerr)
	}
}

// TestKeySetDeleteRemovesMembershipButKeepsKeys pins that Delete clears the
// join rows and leaves the referenced public keys intact.
func TestKeySetListExpiredQuarantine(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	// Two expired tombstones (oldest first) plus one not yet due and one active
	// set that must never be swept.
	mkQuarantined := func(id string, until time.Time) {
		ks := newKeySet(id, "owner-a", "name-"+id)
		ks.State = domain.NameStateQuarantined
		u := until
		ks.QuarantineUntil = &u
		mustCreateKeySet(t, s, ks)
	}
	mkQuarantined("ks-late", testClock.Add(-time.Hour))
	mkQuarantined("ks-early", testClock.Add(-24*time.Hour))
	mkQuarantined("ks-future", testClock.Add(24*time.Hour))
	mustCreateKeySet(t, s, newKeySet("ks-active", "owner-a", "active"))

	got, err := s.Repos().KeySets.ListExpiredQuarantine(ctx, testClock, 10)
	if err != nil {
		t.Fatalf("ListExpiredQuarantine: %v", err)
	}
	if len(got) != 2 || got[0].ID != "ks-early" || got[1].ID != "ks-late" {
		t.Fatalf("ListExpiredQuarantine = %+v, want ks-early then ks-late", got)
	}

	// The limit is honored.
	limited, err := s.Repos().KeySets.ListExpiredQuarantine(ctx, testClock, 1)
	if err != nil {
		t.Fatalf("ListExpiredQuarantine limited: %v", err)
	}
	if len(limited) != 1 || limited[0].ID != "ks-early" {
		t.Errorf("limited sweep = %+v, want only ks-early", limited)
	}
}

func TestKeySetListExpiredQuarantineEmptyReturnsNilSlice(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	mustCreateKeySet(t, s, newKeySet("ks-active", "owner-a", "active"))

	got, err := s.Repos().KeySets.ListExpiredQuarantine(context.Background(), testClock, 10)
	if err != nil {
		t.Fatalf("ListExpiredQuarantine: %v", err)
	}
	if got != nil {
		t.Errorf("ListExpiredQuarantine = %v, want nil slice", got)
	}
}

// TestKeySetQueryErrorsMapped drives the driver-error branches of the read and
// write paths with an already-canceled context.
func TestKeySetQueryErrorsMapped(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	mustCreateKeySet(t, s, newKeySet("ks-1", "owner-a", "primary"))
	mustCreatePublicKey(t, s, newPublicKey("k-1", "owner-a", "d-1"))

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := s.Repos().KeySets.Create(ctx, newKeySet("ks-2", "owner-a", "second")); err == nil {
		t.Error("Create on canceled ctx: nil error")
	}
	if _, err := s.Repos().KeySets.Get(ctx, "owner-a", "ks-1"); err == nil {
		t.Error("Get on canceled ctx: nil error")
	}
	if _, err := s.Repos().KeySets.GetByName(ctx, "owner-a", "primary"); err == nil {
		t.Error("GetByName on canceled ctx: nil error")
	}
	if _, err := s.Repos().KeySets.GetDefault(ctx, "owner-a"); err == nil {
		t.Error("GetDefault on canceled ctx: nil error")
	}
	if _, err := s.Repos().KeySets.ListByOwner(ctx, "owner-a"); err == nil {
		t.Error("ListByOwner on canceled ctx: nil error")
	}
	if _, err := s.Repos().KeySets.CountByOwner(ctx, "owner-a"); err == nil {
		t.Error("CountByOwner on canceled ctx: nil error")
	}
	if err := s.Repos().KeySets.Update(ctx, newKeySet("ks-1", "owner-a", "primary")); err == nil {
		t.Error("Update on canceled ctx: nil error")
	}
	if _, err := s.Repos().KeySets.ListMembers(ctx, "owner-a", "ks-1"); err == nil {
		t.Error("ListMembers on canceled ctx: nil error")
	}
	if _, err := s.Repos().KeySets.ListSetsForKey(ctx, "owner-a", "k-1"); err == nil {
		t.Error("ListSetsForKey on canceled ctx: nil error")
	}
	if _, err := s.Repos().KeySets.ListExpiredQuarantine(ctx, testClock, 10); err == nil {
		t.Error("ListExpiredQuarantine on canceled ctx: nil error")
	}
	if err := s.Repos().KeySets.AddMember(ctx, "owner-a", "ks-1", "k-1", testClock); err == nil {
		t.Error("AddMember on canceled ctx: nil error")
	}
	if err := s.Repos().KeySets.RemoveMember(ctx, "owner-a", "ks-1", "k-1"); err == nil {
		t.Error("RemoveMember on canceled ctx: nil error")
	}
	// The two transaction-scoped methods must fail at BEGIN rather than panic.
	if err := s.Repos().KeySets.SetDefault(ctx, "owner-a", "ks-1"); err == nil {
		t.Error("SetDefault on canceled ctx: nil error")
	}
	if err := s.Repos().KeySets.Delete(ctx, "owner-a", "ks-1"); err == nil {
		t.Error("Delete on canceled ctx: nil error")
	}
}

// TestKeySetConflictLeaksNoSQL asserts that a mapped conflict error carries a
// domain sentinel and no SQL text, table name, or Postgres constraint name.
func TestKeySetConflictLeaksNoSQL(t *testing.T) {
	t.Parallel()
	s := newStore(t)

	mustCreateKeySet(t, s, newKeySet("ks-1", "owner-a", "primary"))
	err := s.Repos().KeySets.Create(context.Background(), newKeySet("ks-2", "owner-a", "primary"))
	if !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("duplicate error = %v, want ErrConflict", err)
	}
	msg := strings.ToUpper(err.Error())
	for _, leak := range []string{"INSERT", "SELECT", "KEY_SETS", "UNIQUE", "PRIMARY KEY", "23505"} {
		if strings.Contains(msg, leak) {
			t.Errorf("error message %q leaks SQL fragment %q", err.Error(), leak)
		}
	}
}

// TestKeySetMembershipRunsInsideCallerTransaction pins that the repositories
// handed out by WithTx compose: a membership written inside a rolled-back
// transaction must not survive.
