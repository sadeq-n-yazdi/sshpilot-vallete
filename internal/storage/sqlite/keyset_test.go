package sqlite

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
)

// newKeySet returns a fully populated active, public, non-default key set owned
// by ownerID with a nil QuarantineUntil.
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

// countDefaults returns how many of the owner's key sets carry is_default = 1,
// read directly via SQL so the assertion does not depend on the repository code
// under test.
func countDefaults(t *testing.T, s *Store, ownerID string) int {
	t.Helper()
	const q = `SELECT COUNT(*) FROM key_sets WHERE owner_id = ? AND is_default = 1`
	var n int
	if err := s.db.QueryRowContext(context.Background(), q, ownerID).Scan(&n); err != nil {
		t.Fatalf("count defaults for %q: %v", ownerID, err)
	}
	return n
}

func TestKeySetCreateGetRoundTrip(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	until := testClock.Add(48 * time.Hour)
	want := &domain.KeySet{
		ID:                  "ks-round",
		OwnerID:             "o-round",
		Name:                "laptops",
		Visibility:          domain.VisibilityProtected,
		State:               domain.NameStateQuarantined,
		QuarantineUntil:     &until,
		FlaggedForReview:    true,
		QuarantineOnRelease: true,
		CreatedAt:           testClock,
		UpdatedAt:           testClock.Add(time.Minute),
	}
	mustCreateKeySet(t, s, want)

	assertSame := func(t *testing.T, label string, got *domain.KeySet) {
		t.Helper()
		if got.ID != want.ID || got.OwnerID != want.OwnerID || got.Name != want.Name {
			t.Fatalf("%s identity = %+v, want %+v", label, got, want)
		}
		if got.Visibility != want.Visibility || got.State != want.State {
			t.Fatalf("%s visibility/state = %q/%q, want %q/%q",
				label, got.Visibility, got.State, want.Visibility, want.State)
		}
		if got.IsDefault {
			t.Fatalf("%s IsDefault = true, want false", label)
		}
		if !got.FlaggedForReview || !got.QuarantineOnRelease {
			t.Fatalf("%s bools = %v/%v, want true/true",
				label, got.FlaggedForReview, got.QuarantineOnRelease)
		}
		if got.QuarantineUntil == nil || !got.QuarantineUntil.Equal(until) {
			t.Fatalf("%s QuarantineUntil = %v, want %v", label, got.QuarantineUntil, until)
		}
		if !got.CreatedAt.Equal(want.CreatedAt) || !got.UpdatedAt.Equal(want.UpdatedAt) {
			t.Fatalf("%s timestamps = %v/%v, want %v/%v",
				label, got.CreatedAt, got.UpdatedAt, want.CreatedAt, want.UpdatedAt)
		}
	}

	got, err := s.Repos().KeySets.Get(ctx, "o-round", "ks-round")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	assertSame(t, "Get", got)

	byName, err := s.Repos().KeySets.GetByName(ctx, "o-round", "laptops")
	if err != nil {
		t.Fatalf("GetByName: %v", err)
	}
	assertSame(t, "GetByName", byName)
}

func TestKeySetCreateNilQuarantineUntilRoundTrips(t *testing.T) {
	t.Parallel()
	s := newStore(t)

	mustCreateKeySet(t, s, newKeySet("ks-nil", "o-nil", "servers"))

	got, err := s.Repos().KeySets.Get(context.Background(), "o-nil", "ks-nil")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.QuarantineUntil != nil {
		t.Fatalf("QuarantineUntil = %v, want nil", got.QuarantineUntil)
	}
	if got.Visibility != domain.VisibilityPublic || got.State != domain.NameStateActive {
		t.Fatalf("visibility/state = %q/%q, want public/active", got.Visibility, got.State)
	}
	if got.FlaggedForReview || got.QuarantineOnRelease {
		t.Fatalf("bools = %v/%v, want false/false", got.FlaggedForReview, got.QuarantineOnRelease)
	}
}

func TestKeySetCreateDuplicateNameConflicts(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	mustCreateKeySet(t, s, newKeySet("ks-dup-1", "o-dup", "laptops"))

	err := s.Repos().KeySets.Create(ctx, newKeySet("ks-dup-2", "o-dup", "laptops"))
	if !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("duplicate (owner, name) error = %v, want ErrConflict", err)
	}
}

func TestKeySetCreateDuplicateOfQuarantinedTombstoneConflicts(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	// A freed name is kept as a quarantined tombstone; the name must stay
	// reserved, so re-creating it is a conflict just like an active clash.
	until := testClock.Add(72 * time.Hour)
	tombstone := newKeySet("ks-tomb", "o-tomb", "retired-name")
	tombstone.State = domain.NameStateQuarantined
	tombstone.QuarantineUntil = &until
	mustCreateKeySet(t, s, tombstone)

	err := s.Repos().KeySets.Create(ctx, newKeySet("ks-tomb-2", "o-tomb", "retired-name"))
	if !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("duplicate of tombstone error = %v, want ErrConflict", err)
	}
}

func TestKeySetCreateSameNameDifferentOwnerAllowed(t *testing.T) {
	t.Parallel()
	s := newStore(t)

	mustCreateKeySet(t, s, newKeySet("ks-a", "o-a", "shared-name"))
	mustCreateKeySet(t, s, newKeySet("ks-b", "o-b", "shared-name"))
}

func TestKeySetCreateNilReturnsInvalidInput(t *testing.T) {
	t.Parallel()
	s := newStore(t)

	err := s.Repos().KeySets.Create(context.Background(), nil)
	if !errors.Is(err, domain.ErrInvalidInput) {
		t.Fatalf("Create(nil) error = %v, want ErrInvalidInput", err)
	}
}

func TestKeySetUpdateNilReturnsInvalidInput(t *testing.T) {
	t.Parallel()
	s := newStore(t)

	err := s.Repos().KeySets.Update(context.Background(), nil)
	if !errors.Is(err, domain.ErrInvalidInput) {
		t.Fatalf("Update(nil) error = %v, want ErrInvalidInput", err)
	}
}

func TestKeySetGetOtherOwnerReturnsNotFound(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	mustCreateKeySet(t, s, newKeySet("ks-scoped", "o-owner", "mine"))
	mustCreateOwner(t, s, "o-intruder")

	if _, err := s.Repos().KeySets.Get(ctx, "o-intruder", "ks-scoped"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("Get across owners = %v, want ErrNotFound", err)
	}
	if _, err := s.Repos().KeySets.GetByName(ctx, "o-intruder", "mine"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("GetByName across owners = %v, want ErrNotFound", err)
	}
	if _, err := s.Repos().KeySets.Get(ctx, "o-owner", "ks-missing"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("Get missing = %v, want ErrNotFound", err)
	}
}

func TestKeySetListByOwnerOrderedAndScoped(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	mustCreateKeySet(t, s, newKeySet("ks-3", "o-list", "three"))
	mustCreateKeySet(t, s, newKeySet("ks-1", "o-list", "one"))
	mustCreateKeySet(t, s, newKeySet("ks-2", "o-list", "two"))
	mustCreateKeySet(t, s, newKeySet("ks-other", "o-list-other", "other"))

	sets, err := s.Repos().KeySets.ListByOwner(ctx, "o-list")
	if err != nil {
		t.Fatalf("ListByOwner: %v", err)
	}
	var ids []string
	for _, ks := range sets {
		ids = append(ids, string(ks.ID))
	}
	if got := strings.Join(ids, ","); got != "ks-1,ks-2,ks-3" {
		t.Fatalf("ListByOwner ids = %q, want ks-1,ks-2,ks-3", got)
	}
}

func TestKeySetListByOwnerEmptyReturnsNilSlice(t *testing.T) {
	t.Parallel()
	s := newStore(t)

	mustCreateOwner(t, s, "o-empty")
	sets, err := s.Repos().KeySets.ListByOwner(context.Background(), "o-empty")
	if err != nil {
		t.Fatalf("ListByOwner: %v", err)
	}
	if sets != nil {
		t.Fatalf("ListByOwner on empty owner = %#v, want nil slice", sets)
	}
}

func TestKeySetCountByOwner(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	mustCreateOwner(t, s, "o-count-empty")
	if n, err := s.Repos().KeySets.CountByOwner(ctx, "o-count-empty"); err != nil || n != 0 {
		t.Fatalf("CountByOwner empty = (%d, %v), want (0, nil)", n, err)
	}

	mustCreateKeySet(t, s, newKeySet("ks-c1", "o-count", "one"))
	mustCreateKeySet(t, s, newKeySet("ks-c2", "o-count", "two"))
	mustCreateKeySet(t, s, newKeySet("ks-c3", "o-count-other", "three"))

	if n, err := s.Repos().KeySets.CountByOwner(ctx, "o-count"); err != nil || n != 2 {
		t.Fatalf("CountByOwner = (%d, %v), want (2, nil)", n, err)
	}
}

func TestKeySetUpdatePersistsMutableFields(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	mustCreateKeySet(t, s, newKeySet("ks-upd", "o-upd", "original"))

	until := testClock.Add(24 * time.Hour)
	if err := s.Repos().KeySets.Update(ctx, &domain.KeySet{
		ID:                  "ks-upd",
		OwnerID:             "o-upd",
		Visibility:          domain.VisibilityProtected,
		State:               domain.NameStateQuarantined,
		QuarantineUntil:     &until,
		FlaggedForReview:    true,
		QuarantineOnRelease: true,
		UpdatedAt:           testClock.Add(time.Hour),
	}); err != nil {
		t.Fatalf("Update: %v", err)
	}

	got, err := s.Repos().KeySets.Get(ctx, "o-upd", "ks-upd")
	if err != nil {
		t.Fatalf("Get after Update: %v", err)
	}
	if got.Visibility != domain.VisibilityProtected {
		t.Fatalf("Visibility = %q, want protected", got.Visibility)
	}
	if got.State != domain.NameStateQuarantined {
		t.Fatalf("State = %q, want quarantined", got.State)
	}
	if got.QuarantineUntil == nil || !got.QuarantineUntil.Equal(until) {
		t.Fatalf("QuarantineUntil = %v, want %v", got.QuarantineUntil, until)
	}
	if !got.FlaggedForReview || !got.QuarantineOnRelease {
		t.Fatalf("bools = %v/%v, want true/true", got.FlaggedForReview, got.QuarantineOnRelease)
	}
}

func TestKeySetUpdateIgnoresNameAndIsDefault(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	mustCreateKeySet(t, s, newKeySet("ks-imm", "o-imm", "original"))

	// Name is immutable and IsDefault belongs to SetDefault: both are supplied
	// here with different values and must not reach the row.
	if err := s.Repos().KeySets.Update(ctx, &domain.KeySet{
		ID:         "ks-imm",
		OwnerID:    "o-imm",
		Name:       "renamed",
		IsDefault:  true,
		Visibility: domain.VisibilityProtected,
		State:      domain.NameStateActive,
		UpdatedAt:  testClock.Add(time.Hour),
	}); err != nil {
		t.Fatalf("Update: %v", err)
	}

	got, err := s.Repos().KeySets.Get(ctx, "o-imm", "ks-imm")
	if err != nil {
		t.Fatalf("Get after Update: %v", err)
	}
	if got.Name != "original" {
		t.Fatalf("Name = %q, want unchanged \"original\"", got.Name)
	}
	if got.IsDefault {
		t.Fatalf("IsDefault = true, want unchanged false")
	}
	if got.Visibility != domain.VisibilityProtected {
		t.Fatalf("Visibility = %q, want the mutable field to have been applied", got.Visibility)
	}
	if n := countDefaults(t, s, "o-imm"); n != 0 {
		t.Fatalf("default rows = %d, want 0", n)
	}
}

func TestKeySetUpdateOtherOwnerReturnsNotFound(t *testing.T) {
	t.Parallel()
	s := newStore(t)

	mustCreateKeySet(t, s, newKeySet("ks-upd-scope", "o-upd-a", "mine"))
	mustCreateOwner(t, s, "o-upd-b")

	err := s.Repos().KeySets.Update(context.Background(), &domain.KeySet{
		ID:         "ks-upd-scope",
		OwnerID:    "o-upd-b",
		Visibility: domain.VisibilityProtected,
		State:      domain.NameStateActive,
		UpdatedAt:  testClock,
	})
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("Update across owners = %v, want ErrNotFound", err)
	}
}

func TestKeySetSetDefaultMovesDefaultAtomically(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	mustCreateKeySet(t, s, newKeySet("ks-d1", "o-def", "first"))
	mustCreateKeySet(t, s, newKeySet("ks-d2", "o-def", "second"))

	if err := s.Repos().KeySets.SetDefault(ctx, "o-def", "ks-d1"); err != nil {
		t.Fatalf("SetDefault first: %v", err)
	}
	if n := countDefaults(t, s, "o-def"); n != 1 {
		t.Fatalf("default rows after first SetDefault = %d, want 1", n)
	}

	// Moving the default must clear the old one before setting the new one, or
	// the partial unique index on (owner_id) WHERE is_default = 1 would reject
	// the write.
	if err := s.Repos().KeySets.SetDefault(ctx, "o-def", "ks-d2"); err != nil {
		t.Fatalf("SetDefault second: %v", err)
	}
	if n := countDefaults(t, s, "o-def"); n != 1 {
		t.Fatalf("default rows after move = %d, want exactly 1", n)
	}

	got, err := s.Repos().KeySets.GetDefault(ctx, "o-def")
	if err != nil {
		t.Fatalf("GetDefault: %v", err)
	}
	if got.ID != "ks-d2" {
		t.Fatalf("default = %q, want ks-d2", got.ID)
	}

	old, err := s.Repos().KeySets.Get(ctx, "o-def", "ks-d1")
	if err != nil {
		t.Fatalf("Get old default: %v", err)
	}
	if old.IsDefault {
		t.Fatal("old default was not cleared")
	}
}

func TestKeySetSetDefaultOtherOwnerReturnsNotFoundAndPreservesDefault(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	mustCreateKeySet(t, s, newKeySet("ks-victim", "o-victim", "victim"))
	mustCreateKeySet(t, s, newKeySet("ks-keep", "o-intruder2", "keep"))
	if err := s.Repos().KeySets.SetDefault(ctx, "o-intruder2", "ks-keep"); err != nil {
		t.Fatalf("SetDefault own: %v", err)
	}

	err := s.Repos().KeySets.SetDefault(ctx, "o-intruder2", "ks-victim")
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("SetDefault across owners = %v, want ErrNotFound", err)
	}

	// The failed attempt must roll back the clear step, leaving the intruder's
	// own default untouched and the victim's set unaffected.
	got, err := s.Repos().KeySets.GetDefault(ctx, "o-intruder2")
	if err != nil {
		t.Fatalf("GetDefault after failed SetDefault: %v", err)
	}
	if got.ID != "ks-keep" {
		t.Fatalf("default = %q, want ks-keep preserved by rollback", got.ID)
	}
	victim, err := s.Repos().KeySets.Get(ctx, "o-victim", "ks-victim")
	if err != nil {
		t.Fatalf("Get victim: %v", err)
	}
	if victim.IsDefault {
		t.Fatal("cross-owner SetDefault modified another owner's set")
	}
}

func TestKeySetSetDefaultIsPerOwner(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	mustCreateKeySet(t, s, newKeySet("ks-p1", "o-p1", "one"))
	mustCreateKeySet(t, s, newKeySet("ks-p2", "o-p2", "two"))

	if err := s.Repos().KeySets.SetDefault(ctx, "o-p1", "ks-p1"); err != nil {
		t.Fatalf("SetDefault o-p1: %v", err)
	}
	if err := s.Repos().KeySets.SetDefault(ctx, "o-p2", "ks-p2"); err != nil {
		t.Fatalf("SetDefault o-p2: %v", err)
	}

	for _, tc := range []struct{ owner, want string }{{"o-p1", "ks-p1"}, {"o-p2", "ks-p2"}} {
		got, err := s.Repos().KeySets.GetDefault(ctx, domain.OwnerID(tc.owner))
		if err != nil {
			t.Fatalf("GetDefault %s: %v", tc.owner, err)
		}
		if string(got.ID) != tc.want {
			t.Fatalf("%s default = %q, want %q", tc.owner, got.ID, tc.want)
		}
	}
}

func TestKeySetGetDefaultMissReturnsNotFound(t *testing.T) {
	t.Parallel()
	s := newStore(t)

	mustCreateKeySet(t, s, newKeySet("ks-nodef", "o-nodef", "plain"))

	_, err := s.Repos().KeySets.GetDefault(context.Background(), "o-nodef")
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("GetDefault with no default = %v, want ErrNotFound", err)
	}
}

func TestKeySetDeleteDefaultRefused(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	mustCreateKeySet(t, s, newKeySet("ks-del-def", "o-del-def", "primary"))
	if err := s.Repos().KeySets.SetDefault(ctx, "o-del-def", "ks-del-def"); err != nil {
		t.Fatalf("SetDefault: %v", err)
	}

	err := s.Repos().KeySets.Delete(ctx, "o-del-def", "ks-del-def")
	if !errors.Is(err, domain.ErrDefaultKeySet) {
		t.Fatalf("Delete of default = %v, want ErrDefaultKeySet", err)
	}
	if errors.Is(err, domain.ErrConflict) {
		t.Fatal("Delete of default must not also report ErrConflict")
	}

	got, err := s.Repos().KeySets.Get(ctx, "o-del-def", "ks-del-def")
	if err != nil {
		t.Fatalf("default set did not survive refused Delete: %v", err)
	}
	if !got.IsDefault {
		t.Fatal("default flag was cleared by the refused Delete")
	}
}

func TestKeySetDeleteOtherOwnerReturnsNotFound(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	mustCreateKeySet(t, s, newKeySet("ks-del-scope", "o-del-a", "mine"))
	mustCreateOwner(t, s, "o-del-b")

	if err := s.Repos().KeySets.Delete(ctx, "o-del-b", "ks-del-scope"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("Delete across owners = %v, want ErrNotFound", err)
	}
	if _, err := s.Repos().KeySets.Get(ctx, "o-del-a", "ks-del-scope"); err != nil {
		t.Fatalf("set was removed by a cross-owner Delete: %v", err)
	}

	if err := s.Repos().KeySets.Delete(ctx, "o-del-a", "ks-absent"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("Delete of missing set = %v, want ErrNotFound", err)
	}
}

func TestKeySetListExpiredQuarantine(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	quarantined := func(id, owner, name string, until time.Time) *domain.KeySet {
		ks := newKeySet(id, owner, name)
		ks.State = domain.NameStateQuarantined
		u := until
		ks.QuarantineUntil = &u
		return ks
	}
	now := testClock.Add(24 * time.Hour)

	// Two expired sets under different owners: the sweep is unscoped and must
	// span them both.
	mustCreateKeySet(t, s, quarantined("ks-exp-1", "o-sweep-a", "expired-a", testClock))
	mustCreateKeySet(t, s, quarantined("ks-exp-2", "o-sweep-b", "expired-b", testClock.Add(time.Hour)))
	// Not yet expired, and an active set with no quarantine at all.
	mustCreateKeySet(t, s, quarantined("ks-future", "o-sweep-a", "future", now.Add(72*time.Hour)))
	mustCreateKeySet(t, s, newKeySet("ks-active", "o-sweep-a", "active"))

	got, err := s.Repos().KeySets.ListExpiredQuarantine(ctx, now, 0)
	if err != nil {
		t.Fatalf("ListExpiredQuarantine: %v", err)
	}
	var ids []string
	for _, ks := range got {
		ids = append(ids, string(ks.ID))
	}
	if joined := strings.Join(ids, ","); joined != "ks-exp-1,ks-exp-2" {
		t.Fatalf("expired ids = %q, want ks-exp-1,ks-exp-2 across owners", joined)
	}

	limited, err := s.Repos().KeySets.ListExpiredQuarantine(ctx, now, 1)
	if err != nil {
		t.Fatalf("ListExpiredQuarantine limited: %v", err)
	}
	if len(limited) != 1 || limited[0].ID != "ks-exp-1" {
		t.Fatalf("limited result = %+v, want just ks-exp-1", limited)
	}
}

func TestKeySetListExpiredQuarantineEmptyReturnsNilSlice(t *testing.T) {
	t.Parallel()
	s := newStore(t)

	mustCreateKeySet(t, s, newKeySet("ks-none", "o-none", "active"))

	got, err := s.Repos().KeySets.ListExpiredQuarantine(context.Background(), testClock, 10)
	if err != nil {
		t.Fatalf("ListExpiredQuarantine: %v", err)
	}
	if got != nil {
		t.Fatalf("result = %#v, want nil slice", got)
	}
}

func TestKeySetConflictLeaksNoSQL(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	mustCreateKeySet(t, s, newKeySet("ks-leak-1", "o-leak", "taken"))
	err := s.Repos().KeySets.Create(ctx, newKeySet("ks-leak-2", "o-leak", "taken"))
	if !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("error = %v, want ErrConflict", err)
	}

	msg := strings.ToLower(err.Error())
	for _, leak := range []string{"key_sets", "insert", "unique", "index", "select", "sqlite"} {
		if strings.Contains(msg, leak) {
			t.Fatalf("error message %q leaks %q", err.Error(), leak)
		}
	}
}

// countMembers returns how many key_set_members rows reference setID, read
// directly via SQL so a test can prove no row was written even when the
// repository would refuse to read it back.
func countMembers(t *testing.T, s *Store, setID string) int {
	t.Helper()
	const q = `SELECT COUNT(*) FROM key_set_members WHERE key_set_id = ?`
	var n int
	if err := s.db.QueryRowContext(context.Background(), q, setID).Scan(&n); err != nil {
		t.Fatalf("count members of %q: %v", setID, err)
	}
	return n
}

// seedOwnerWithKey creates an owner, a device, and one public key for it,
// returning the key.
func seedOwnerWithKey(t *testing.T, s *Store, ownerID, keyID string) *domain.PublicKey {
	t.Helper()
	k := newPublicKey(keyID, ownerID, "dev-"+ownerID)
	mustCreatePublicKey(t, s, k)
	return k
}

func TestKeySetAddMemberRejectsAnotherOwnersKey(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	// The schema cannot stop this write: key_set_members has no owner_id and
	// its foreign keys only require that both referenced rows exist, which they
	// do. The repository is the sole enforcement point.
	seedOwnerWithKey(t, s, "o-victim-a", "pk-a")
	victimKey := seedOwnerWithKey(t, s, "o-victim-b", "pk-b")
	mustCreateKeySet(t, s, newKeySet("ks-attacker", "o-victim-a", "attacker-set"))

	err := s.Repos().KeySets.AddMember(ctx, "o-victim-a", "ks-attacker", victimKey.ID, testClock)
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("AddMember with another owner's key = %v, want ErrNotFound", err)
	}
	if n := countMembers(t, s, "ks-attacker"); n != 0 {
		t.Fatalf("membership rows = %d, want 0: a cross-owner key was linked", n)
	}
}

func TestKeySetAddMemberRejectsAnotherOwnersSet(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	seedOwnerWithKey(t, s, "o-set-a", "pk-set-a")
	intruderKey := seedOwnerWithKey(t, s, "o-set-b", "pk-set-b")
	mustCreateKeySet(t, s, newKeySet("ks-owned-by-a", "o-set-a", "a-set"))

	err := s.Repos().KeySets.AddMember(ctx, "o-set-b", "ks-owned-by-a", intruderKey.ID, testClock)
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("AddMember into another owner's set = %v, want ErrNotFound", err)
	}
	if n := countMembers(t, s, "ks-owned-by-a"); n != 0 {
		t.Fatalf("membership rows = %d, want 0: a cross-owner set was written to", n)
	}
}

func TestKeySetAddMemberMissingSetAndKeyReturnNotFound(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	key := seedOwnerWithKey(t, s, "o-miss", "pk-miss")
	mustCreateKeySet(t, s, newKeySet("ks-miss", "o-miss", "set"))

	if err := s.Repos().KeySets.AddMember(ctx, "o-miss", "ks-absent", key.ID, testClock); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("AddMember with absent set = %v, want ErrNotFound", err)
	}
	if err := s.Repos().KeySets.AddMember(ctx, "o-miss", "ks-miss", "pk-absent", testClock); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("AddMember with absent key = %v, want ErrNotFound", err)
	}
}

func TestKeySetAddMemberHappyPathAndDuplicateConflicts(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	key := seedOwnerWithKey(t, s, "o-add", "pk-add")
	mustCreateKeySet(t, s, newKeySet("ks-add", "o-add", "set"))

	added := testClock.Add(2 * time.Hour)
	if err := s.Repos().KeySets.AddMember(ctx, "o-add", "ks-add", key.ID, added); err != nil {
		t.Fatalf("AddMember: %v", err)
	}

	members, err := s.Repos().KeySets.ListMembers(ctx, "o-add", "ks-add")
	if err != nil {
		t.Fatalf("ListMembers: %v", err)
	}
	if len(members) != 1 {
		t.Fatalf("members = %d, want 1", len(members))
	}
	if members[0].KeySetID != "ks-add" || members[0].PublicKeyID != key.ID {
		t.Fatalf("membership = %+v, want ks-add/%s", members[0], key.ID)
	}
	if !members[0].AddedAt.Equal(added) {
		t.Fatalf("AddedAt = %v, want %v", members[0].AddedAt, added)
	}

	if err := s.Repos().KeySets.AddMember(ctx, "o-add", "ks-add", key.ID, added); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("duplicate AddMember = %v, want ErrConflict", err)
	}
}

func TestKeySetRemoveMember(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	key := seedOwnerWithKey(t, s, "o-rm", "pk-rm")
	seedOwnerWithKey(t, s, "o-rm-other", "pk-rm-other")
	mustCreateKeySet(t, s, newKeySet("ks-rm", "o-rm", "set"))
	if err := s.Repos().KeySets.AddMember(ctx, "o-rm", "ks-rm", key.ID, testClock); err != nil {
		t.Fatalf("AddMember: %v", err)
	}

	// Another owner may neither remove from a set they do not own nor have the
	// membership row disappear from under the real owner.
	if err := s.Repos().KeySets.RemoveMember(ctx, "o-rm-other", "ks-rm", key.ID); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("RemoveMember across owners = %v, want ErrNotFound", err)
	}
	if n := countMembers(t, s, "ks-rm"); n != 1 {
		t.Fatalf("membership rows after cross-owner remove = %d, want 1", n)
	}

	if err := s.Repos().KeySets.RemoveMember(ctx, "o-rm", "ks-rm", key.ID); err != nil {
		t.Fatalf("RemoveMember: %v", err)
	}
	if n := countMembers(t, s, "ks-rm"); n != 0 {
		t.Fatalf("membership rows after remove = %d, want 0", n)
	}

	// The key row itself is never touched by a membership removal.
	if _, err := s.Repos().PublicKeys.Get(ctx, "o-rm", key.ID); err != nil {
		t.Fatalf("public key removed along with its membership: %v", err)
	}
	if err := s.Repos().KeySets.RemoveMember(ctx, "o-rm", "ks-rm", key.ID); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("RemoveMember of absent membership = %v, want ErrNotFound", err)
	}
}

func TestKeySetListMembersOrderedAndOwnerScoped(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	seedOwnerWithKey(t, s, "o-lm", "pk-3")
	mustCreatePublicKey(t, s, newPublicKey("pk-1", "o-lm", "dev-o-lm"))
	mustCreatePublicKey(t, s, newPublicKey("pk-2", "o-lm", "dev-o-lm"))
	mustCreateKeySet(t, s, newKeySet("ks-lm", "o-lm", "set"))
	mustCreateOwner(t, s, "o-lm-other")

	for _, id := range []domain.PublicKeyID{"pk-3", "pk-1", "pk-2"} {
		if err := s.Repos().KeySets.AddMember(ctx, "o-lm", "ks-lm", id, testClock); err != nil {
			t.Fatalf("AddMember %s: %v", id, err)
		}
	}

	members, err := s.Repos().KeySets.ListMembers(ctx, "o-lm", "ks-lm")
	if err != nil {
		t.Fatalf("ListMembers: %v", err)
	}
	var ids []string
	for _, m := range members {
		ids = append(ids, string(m.PublicKeyID))
	}
	if joined := strings.Join(ids, ","); joined != "pk-1,pk-2,pk-3" {
		t.Fatalf("member ids = %q, want pk-1,pk-2,pk-3", joined)
	}

	other, err := s.Repos().KeySets.ListMembers(ctx, "o-lm-other", "ks-lm")
	if err != nil {
		t.Fatalf("ListMembers other owner: %v", err)
	}
	if other != nil {
		t.Fatalf("another owner saw %d membership rows, want none", len(other))
	}
}

func TestKeySetListSetsForKeyOrderedAndOwnerScoped(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	key := seedOwnerWithKey(t, s, "o-lsk", "pk-lsk")
	mustCreateKeySet(t, s, newKeySet("ks-y", "o-lsk", "why"))
	mustCreateKeySet(t, s, newKeySet("ks-x", "o-lsk", "ex"))
	mustCreateKeySet(t, s, newKeySet("ks-none-2", "o-lsk", "unrelated"))
	mustCreateOwner(t, s, "o-lsk-other")

	for _, setID := range []domain.KeySetID{"ks-y", "ks-x"} {
		if err := s.Repos().KeySets.AddMember(ctx, "o-lsk", setID, key.ID, testClock); err != nil {
			t.Fatalf("AddMember %s: %v", setID, err)
		}
	}

	sets, err := s.Repos().KeySets.ListSetsForKey(ctx, "o-lsk", key.ID)
	if err != nil {
		t.Fatalf("ListSetsForKey: %v", err)
	}
	var ids []string
	for _, ks := range sets {
		ids = append(ids, string(ks.ID))
	}
	if joined := strings.Join(ids, ","); joined != "ks-x,ks-y" {
		t.Fatalf("set ids = %q, want ks-x,ks-y", joined)
	}

	other, err := s.Repos().KeySets.ListSetsForKey(ctx, "o-lsk-other", key.ID)
	if err != nil {
		t.Fatalf("ListSetsForKey other owner: %v", err)
	}
	if other != nil {
		t.Fatalf("another owner saw %d sets for the key, want none", len(other))
	}
}

func TestKeySetListSetsForKeyIgnoresCrossOwnerMembership(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	// Simulate a membership row that AddMember would refuse, written directly
	// via SQL exactly as the schema (which cannot prevent it) would allow. It
	// links owner A's set to owner B's key and must not surface for either.
	seedOwnerWithKey(t, s, "o-cross-a", "pk-cross-a")
	mustCreatePublicKey(t, s, newPublicKey("pk-cross-b", "o-cross-b", "dev-o-cross-b"))
	mustCreateKeySet(t, s, newKeySet("ks-cross", "o-cross-a", "cross"))
	seedMembership(t, s, "ks-cross", "pk-cross-b")

	sets, err := s.Repos().KeySets.ListSetsForKey(ctx, "o-cross-a", "pk-cross-b")
	if err != nil {
		t.Fatalf("ListSetsForKey: %v", err)
	}
	if sets != nil {
		t.Fatalf("cross-owner membership surfaced %d sets, want none", len(sets))
	}
}

func TestKeySetDeleteRemovesMembershipButKeepsKeys(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	key := seedOwnerWithKey(t, s, "o-delmem", "pk-delmem")
	mustCreateKeySet(t, s, newKeySet("ks-delmem", "o-delmem", "set"))
	if err := s.Repos().KeySets.AddMember(ctx, "o-delmem", "ks-delmem", key.ID, testClock); err != nil {
		t.Fatalf("AddMember: %v", err)
	}

	if err := s.Repos().KeySets.Delete(ctx, "o-delmem", "ks-delmem"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := s.Repos().KeySets.Get(ctx, "o-delmem", "ks-delmem"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("set survived Delete: %v", err)
	}
	if n := countMembers(t, s, "ks-delmem"); n != 0 {
		t.Fatalf("membership rows after Delete = %d, want 0", n)
	}
	if _, err := s.Repos().PublicKeys.Get(ctx, "o-delmem", key.ID); err != nil {
		t.Fatalf("public key deleted along with its set: %v", err)
	}
}
