package postgres

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/migrate"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/schema"
)

// newHandle returns a fully populated active handle owned by ownerID.
//
// The fixture sets no fold: there is no field for one. The adapter derives it
// from Name on write, which is what makes the look-alike tests below evidence
// about the adapter rather than about what the fixture happened to pass in.
func newHandle(id, ownerID, name string) *domain.Handle {
	return &domain.Handle{
		ID:        domain.HandleID(id),
		OwnerID:   domain.OwnerID(ownerID),
		Name:      name,
		State:     domain.NameStateActive,
		CreatedAt: testClock,
		UpdatedAt: testClock,
	}
}

// mustRegisterHandle creates the owner (if needed) and registers the handle.
func mustRegisterHandle(t *testing.T, s *Store, h *domain.Handle) {
	t.Helper()
	ctx := context.Background()
	if _, err := s.Repos().Owners.Get(ctx, h.OwnerID); errors.Is(err, domain.ErrNotFound) {
		mustCreateOwner(t, s, string(h.OwnerID))
	}
	if err := s.Repos().Handles.Register(ctx, h); err != nil {
		t.Fatalf("Register handle %q: %v", h.ID, err)
	}
}

func TestHandleRegisterAndGet(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	h := newHandle("h-1", "owner-a", "alice")
	mustRegisterHandle(t, s, h)

	got, err := s.Repos().Handles.Get(ctx, "owner-a", "h-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Name != "alice" || got.OwnerID != "owner-a" || got.State != domain.NameStateActive {
		t.Errorf("Get = %+v, want name alice owner owner-a active", got)
	}
}

// TestHandleBooleanRoundTrip pins the native BOOLEAN encoding: both flags must
// survive a write/read cycle in both states.
func TestHandleBooleanRoundTrip(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	set := newHandle("h-set", "owner-a", "flagged")
	set.FlaggedForReview = true
	set.QuarantineOnRelease = true
	mustRegisterHandle(t, s, set)
	// A second owner, because ux_handles_owner_active allows one active claim
	// each and this test is about boolean encoding, not that invariant.
	cleared := newHandle("h-clear", "owner-b", "unflagged")
	mustRegisterHandle(t, s, cleared)

	got, err := s.Repos().Handles.Get(ctx, "owner-a", "h-set")
	if err != nil {
		t.Fatalf("Get set: %v", err)
	}
	if !got.FlaggedForReview || !got.QuarantineOnRelease {
		t.Errorf("true flags did not round-trip: %+v", got)
	}
	got, err = s.Repos().Handles.Get(ctx, "owner-b", "h-clear")
	if err != nil {
		t.Fatalf("Get clear: %v", err)
	}
	if got.FlaggedForReview || got.QuarantineOnRelease {
		t.Errorf("false flags did not round-trip: %+v", got)
	}
}

func TestHandleRegisterDuplicateNameConflict(t *testing.T) {
	t.Parallel()
	s := newStore(t)

	mustRegisterHandle(t, s, newHandle("h-a", "owner-a", "shared"))
	mustCreateOwner(t, s, "owner-b")
	// A different owner claiming the same normalized name clashes globally.
	err := s.Repos().Handles.Register(context.Background(), newHandle("h-b", "owner-b", "shared"))
	if !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("duplicate name Register error = %v, want ErrConflict", err)
	}
}

func TestHandleRegisterNilInvalidInput(t *testing.T) {
	t.Parallel()
	s := newStore(t)

	if err := s.Repos().Handles.Register(context.Background(), nil); !errors.Is(err, domain.ErrInvalidInput) {
		t.Fatalf("Register(nil) error = %v, want ErrInvalidInput", err)
	}
}

// TestHandleUpdateNilInvalidInput pins the nil guard on Update. Register was
// already guarded; Update was not, so a nil entity panicked inside the
// transaction instead of returning ErrInvalidInput like its sibling.
func TestHandleUpdateNilInvalidInput(t *testing.T) {
	t.Parallel()
	s := newStore(t)

	if err := s.Repos().Handles.Update(context.Background(), nil); !errors.Is(err, domain.ErrInvalidInput) {
		t.Fatalf("Update(nil) error = %v, want ErrInvalidInput", err)
	}
}

func TestHandleGetByNameResolves(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	mustRegisterHandle(t, s, newHandle("h-r", "owner-a", "resolveme"))

	got, err := s.Repos().Handles.GetByName(ctx, "resolveme")
	if err != nil {
		t.Fatalf("GetByName: %v", err)
	}
	if got.ID != "h-r" {
		t.Errorf("GetByName id = %q, want h-r", got.ID)
	}

	if _, err := s.Repos().Handles.GetByName(ctx, "unclaimed"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("GetByName unclaimed error = %v, want ErrNotFound", err)
	}
}

func TestHandleGetActiveByOwner(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	mustCreateOwner(t, s, "owner-a")
	active := newHandle("h-active", "owner-a", "current")
	retired := newHandle("h-old", "owner-a", "former")
	retired.State = domain.NameStateRetired
	if err := s.Repos().Handles.Register(ctx, active); err != nil {
		t.Fatalf("register active: %v", err)
	}
	if err := s.Repos().Handles.Register(ctx, retired); err != nil {
		t.Fatalf("register retired: %v", err)
	}

	got, err := s.Repos().Handles.GetActiveByOwner(ctx, "owner-a")
	if err != nil {
		t.Fatalf("GetActiveByOwner: %v", err)
	}
	if got.ID != "h-active" {
		t.Errorf("GetActiveByOwner id = %q, want h-active", got.ID)
	}

	mustCreateOwner(t, s, "owner-none")
	if _, err := s.Repos().Handles.GetActiveByOwner(ctx, "owner-none"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("GetActiveByOwner none error = %v, want ErrNotFound", err)
	}
}

func TestHandleListByOwner(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	// One active claim plus the tombstone of a name renamed away from: that is
	// the shape an owner's rows actually take, and the only shape
	// ux_handles_owner_active permits.
	mustRegisterHandle(t, s, newHandle("h-1", "owner-a", "n1"))
	freed := newHandle("h-2", "owner-a", "n2")
	freed.State = domain.NameStateQuarantined
	until := testClock.Add(30 * 24 * time.Hour)
	freed.QuarantineUntil = &until
	mustRegisterHandle(t, s, freed)
	mustRegisterHandle(t, s, newHandle("h-3", "owner-b", "n3"))

	got, err := s.Repos().Handles.ListByOwner(ctx, "owner-a")
	if err != nil {
		t.Fatalf("ListByOwner: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("ListByOwner returned %d rows, want 2 (owner-a only)", len(got))
	}
	for i := range got {
		if got[i].OwnerID != "owner-a" {
			t.Errorf("ListByOwner leaked row for owner %q", got[i].OwnerID)
		}
	}
}

// TestHandleListByOwnerEmptyReturnsNilSlice pins the empty-list convention.
func TestHandleListByOwnerEmptyReturnsNilSlice(t *testing.T) {
	t.Parallel()
	s := newStore(t)

	mustCreateOwner(t, s, "owner-empty")
	got, err := s.Repos().Handles.ListByOwner(context.Background(), "owner-empty")
	if err != nil {
		t.Fatalf("ListByOwner: %v", err)
	}
	if got != nil {
		t.Errorf("ListByOwner with no rows = %#v, want nil slice", got)
	}
}

func TestHandleUpdateMutableFields(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	h := newHandle("h-u", "owner-a", "mutable")
	mustRegisterHandle(t, s, h)

	until := testClock.Add(72 * time.Hour)
	h.State = domain.NameStateQuarantined
	h.QuarantineUntil = &until
	h.FlaggedForReview = true
	h.QuarantineOnRelease = true
	h.UpdatedAt = testClock.Add(time.Hour)
	if err := s.Repos().Handles.Update(ctx, h); err != nil {
		t.Fatalf("Update: %v", err)
	}

	got, err := s.Repos().Handles.Get(ctx, "owner-a", "h-u")
	if err != nil {
		t.Fatalf("Get after Update: %v", err)
	}
	if got.State != domain.NameStateQuarantined || !got.FlaggedForReview || !got.QuarantineOnRelease {
		t.Errorf("mutable fields not persisted: %+v", got)
	}
	if got.QuarantineUntil == nil || !got.QuarantineUntil.Equal(until) {
		t.Errorf("QuarantineUntil = %v, want %v", got.QuarantineUntil, until)
	}
	if !got.UpdatedAt.Equal(h.UpdatedAt) {
		t.Errorf("UpdatedAt = %v, want %v", got.UpdatedAt, h.UpdatedAt)
	}
}

// TestHandleUpdateClearsQuarantineUntil checks the NULL path: setting the
// pointer back to nil must store SQL NULL and read back as nil, not as a zero
// time.
func TestHandleUpdateClearsQuarantineUntil(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	until := testClock.Add(time.Hour)
	h := newHandle("h-null", "owner-a", "nullable")
	h.State = domain.NameStateQuarantined
	h.QuarantineUntil = &until
	mustRegisterHandle(t, s, h)

	h.State = domain.NameStateActive
	h.QuarantineUntil = nil
	if err := s.Repos().Handles.Update(ctx, h); err != nil {
		t.Fatalf("Update: %v", err)
	}
	got, err := s.Repos().Handles.Get(ctx, "owner-a", "h-null")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.QuarantineUntil != nil {
		t.Errorf("QuarantineUntil = %v, want nil after clearing", got.QuarantineUntil)
	}
}

func TestHandleUpdateNameImmutable(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	h := newHandle("h-i", "owner-a", "original")
	mustRegisterHandle(t, s, h)

	renamed := newHandle("h-i", "owner-a", "renamed")
	if err := s.Repos().Handles.Update(ctx, renamed); !errors.Is(err, domain.ErrImmutable) {
		t.Fatalf("Update with name change error = %v, want ErrImmutable", err)
	}
	// The original name must be untouched.
	got, err := s.Repos().Handles.Get(ctx, "owner-a", "h-i")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Name != "original" {
		t.Errorf("name mutated to %q despite ErrImmutable", got.Name)
	}
}

func TestHandleUpdateMissingNotFound(t *testing.T) {
	t.Parallel()
	s := newStore(t)

	mustCreateOwner(t, s, "owner-a")
	err := s.Repos().Handles.Update(context.Background(), newHandle("ghost", "owner-a", "x"))
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("Update missing error = %v, want ErrNotFound", err)
	}
}

func TestHandleListExpiredQuarantine(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	mustCreateOwner(t, s, "owner-a")
	past := testClock.Add(-time.Hour)
	future := testClock.Add(time.Hour)

	expired := newHandle("h-exp", "owner-a", "expired")
	expired.State = domain.NameStateQuarantined
	expired.QuarantineUntil = &past
	pending := newHandle("h-pend", "owner-a", "pending")
	pending.State = domain.NameStateQuarantined
	pending.QuarantineUntil = &future
	active := newHandle("h-act", "owner-a", "active")

	for _, h := range []*domain.Handle{expired, pending, active} {
		if err := s.Repos().Handles.Register(ctx, h); err != nil {
			t.Fatalf("register %q: %v", h.ID, err)
		}
	}

	got, err := s.Repos().Handles.ListExpiredQuarantine(ctx, testClock, 10)
	if err != nil {
		t.Fatalf("ListExpiredQuarantine: %v", err)
	}
	if len(got) != 1 || got[0].ID != "h-exp" {
		t.Fatalf("ListExpiredQuarantine = %+v, want only h-exp", got)
	}
}

func TestHandleListExpiredQuarantineRejectsNonPositiveLimit(t *testing.T) {
	t.Parallel()
	s := newStore(t)

	for _, limit := range []int{0, -1} {
		_, err := s.Repos().Handles.ListExpiredQuarantine(context.Background(), testClock, limit)
		if !errors.Is(err, domain.ErrInvalidInput) {
			t.Errorf("ListExpiredQuarantine(limit %d) = %v, want ErrInvalidInput", limit, err)
		}
	}
}

// TestHandleQueryErrorsMapped drives the driver-error branches of the read
// paths with an already-canceled context: every method must surface a wrapped
// error (never a nil error with partial data) through mapError.
func TestHandleQueryErrorsMapped(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	mustRegisterHandle(t, s, newHandle("h-1", "owner-a", "n1"))

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := s.Repos().Handles.Get(ctx, "owner-a", "h-1"); err == nil {
		t.Error("Get on canceled ctx: nil error")
	}
	if _, err := s.Repos().Handles.GetByName(ctx, "n1"); err == nil {
		t.Error("GetByName on canceled ctx: nil error")
	}
	if _, err := s.Repos().Handles.GetActiveByOwner(ctx, "owner-a"); err == nil {
		t.Error("GetActiveByOwner on canceled ctx: nil error")
	}
	if _, err := s.Repos().Handles.ListByOwner(ctx, "owner-a"); err == nil {
		t.Error("ListByOwner on canceled ctx: nil error")
	}
	if _, err := s.Repos().Handles.ListExpiredQuarantine(ctx, testClock, 10); err == nil {
		t.Error("ListExpiredQuarantine on canceled ctx: nil error")
	}
	if err := s.Repos().Handles.Update(ctx, newHandle("h-1", "owner-a", "n1")); err == nil {
		t.Error("Update on canceled ctx: nil error")
	}
}

// TestHandleCrossTenantIsolation is the core security invariant: owner B must
// never observe owner A's handle through any owner-scoped method, and every
// such access must be reported as domain.ErrNotFound — never the row, and never
// a different error that would confirm the row's existence.
func TestHandleCrossTenantIsolation(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	// Owner A owns the handle; owner B exists but owns nothing.
	mustRegisterHandle(t, s, newHandle("h-secret", "owner-a", "secret"))
	mustCreateOwner(t, s, "owner-b")

	// Scoped Get by B for A's handle id -> ErrNotFound, no row.
	if got, err := s.Repos().Handles.Get(ctx, "owner-b", "h-secret"); !errors.Is(err, domain.ErrNotFound) || got != nil {
		t.Fatalf("cross-tenant Get = (%v, %v), want (nil, ErrNotFound)", got, err)
	}

	// GetActiveByOwner for B -> ErrNotFound (A's active handle is invisible).
	if got, err := s.Repos().Handles.GetActiveByOwner(ctx, "owner-b"); !errors.Is(err, domain.ErrNotFound) || got != nil {
		t.Fatalf("cross-tenant GetActiveByOwner = (%v, %v), want (nil, ErrNotFound)", got, err)
	}

	// ListByOwner for B -> empty, never A's row.
	if got, err := s.Repos().Handles.ListByOwner(ctx, "owner-b"); err != nil || len(got) != 0 {
		t.Fatalf("cross-tenant ListByOwner = (%v, %v), want (empty, nil)", got, err)
	}

	// Update by B on A's handle -> ErrNotFound, NOT ErrImmutable and NOT
	// ErrConflict. B even supplies the correct current name to try to smuggle
	// past the immutability check; the owner-scoped read must gate it out first.
	wrongOwnerUpdate := newHandle("h-secret", "owner-b", "secret")
	wrongOwnerUpdate.State = domain.NameStateRetired
	err := s.Repos().Handles.Update(ctx, wrongOwnerUpdate)
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("cross-tenant Update error = %v, want ErrNotFound", err)
	}
	if errors.Is(err, domain.ErrImmutable) || errors.Is(err, domain.ErrConflict) {
		t.Fatalf("cross-tenant Update leaked existence via %v", err)
	}

	// Sanity: A's handle is unchanged and still active.
	got, err := s.Repos().Handles.Get(ctx, "owner-a", "h-secret")
	if err != nil {
		t.Fatalf("owner A Get after cross-tenant attempts: %v", err)
	}
	if got.State != domain.NameStateActive {
		t.Errorf("owner A handle mutated by cross-tenant Update: state %q", got.State)
	}
}

// TestHandleMissingAndWrongOwnerIndistinguishable is the existence-leak guard
// stated directly: a lookup for a handle that does not exist at all and a
// lookup for one that exists under another owner must return the identical
// error value, so a caller cannot tell the two apart.
func TestHandleMissingAndWrongOwnerIndistinguishable(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	mustRegisterHandle(t, s, newHandle("h-real", "owner-a", "real"))
	mustCreateOwner(t, s, "owner-b")

	_, wrongOwner := s.Repos().Handles.Get(ctx, "owner-b", "h-real")
	_, missing := s.Repos().Handles.Get(ctx, "owner-b", "h-does-not-exist")
	if wrongOwner == nil || missing == nil {
		t.Fatal("expected errors from both lookups")
	}
	if wrongOwner.Error() != missing.Error() {
		t.Errorf("wrong-owner error %q differs from missing-row error %q; existence leaks",
			wrongOwner, missing)
	}

	updWrongOwner := s.Repos().Handles.Update(ctx, newHandle("h-real", "owner-b", "real"))
	updMissing := s.Repos().Handles.Update(ctx, newHandle("h-nope", "owner-b", "nope"))
	if updWrongOwner == nil || updMissing == nil {
		t.Fatal("expected errors from both updates")
	}
	if updWrongOwner.Error() != updMissing.Error() {
		t.Errorf("wrong-owner Update error %q differs from missing-row error %q; existence leaks",
			updWrongOwner, updMissing)
	}
}

// TestHandleRegisterLookAlikeConflict is the mechanism behind ADR-0026's
// normalized-form uniqueness, proven on PostgreSQL. "ad-min" and "adm1n" are
// distinct, individually valid slugs, so the unique index on the raw name
// cannot see the collision; only the fold can.
func TestHandleRegisterLookAlikeConflict(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct{ taken, lookAlike string }{
		{"paypal", "p4ypal"}, // leetspeak, 4 folds to a
		{"admin", "adm1n"},   // leetspeak, 1 folds to i
		{"admin", "ad-min"},  // separator
		{"stripe", "str1pe"}, // leetspeak, interior
	} {
		t.Run(tc.taken+"/"+tc.lookAlike, func(t *testing.T) {
			t.Parallel()
			s := newStore(t)

			mustRegisterHandle(t, s, newHandle("h-taken", "owner-a", tc.taken))
			mustCreateOwner(t, s, "owner-b")

			err := s.Repos().Handles.Register(
				context.Background(), newHandle("h-look", "owner-b", tc.lookAlike))
			if !errors.Is(err, domain.ErrConflict) {
				t.Fatalf("Register look-alike %q against %q = %v, want ErrConflict",
					tc.lookAlike, tc.taken, err)
			}
		})
	}
}

// TestHandleResolutionIgnoresFold is the guardrail on storing the fold at all.
// If the fold ever became a resolution key, a request for a look-alike would
// answer with the imitated owner's keys.
func TestHandleResolutionIgnoresFold(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	mustRegisterHandle(t, s, newHandle("h-1", "owner-a", "paypal"))

	if _, err := s.Repos().Handles.GetByName(ctx, "p4ypal"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("GetByName(p4ypal) = %v, want ErrNotFound: resolution must not "+
			"go through the fold", err)
	}
	if _, err := s.Repos().Handles.GetByName(ctx, "paypal"); err != nil {
		t.Fatalf("GetByName(paypal) = %v, want the row", err)
	}
}

// TestHandleRegisterSecondActiveConflict proves an owner cannot hold two active
// name-claims, which would make GetActiveByOwner's singularity a lie.
func TestHandleRegisterSecondActiveConflict(t *testing.T) {
	t.Parallel()
	s := newStore(t)

	mustRegisterHandle(t, s, newHandle("h-1", "owner-a", "first"))

	err := s.Repos().Handles.Register(
		context.Background(), newHandle("h-2", "owner-a", "second"))
	if !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("second active claim for one owner = %v, want ErrConflict", err)
	}
}

// TestHandleReleaseFreesTheName covers the end of the quarantine on PostgreSQL:
// the row is deleted once the hold elapses, and only then is the name claimable.
func TestHandleReleaseFreesTheName(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	mustCreateOwner(t, s, "owner-a")
	past := testClock.Add(-time.Hour)
	freed := newHandle("h-freed", "owner-a", "released")
	freed.State = domain.NameStateQuarantined
	freed.QuarantineUntil = &past
	if err := s.Repos().Handles.Register(ctx, freed); err != nil {
		t.Fatalf("register quarantined: %v", err)
	}

	mustCreateOwner(t, s, "owner-b")
	if err := s.Repos().Handles.Register(ctx, newHandle("h-b", "owner-b", "released")); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("claim during quarantine = %v, want ErrConflict", err)
	}

	if err := s.Repos().Handles.Release(ctx, "h-freed", testClock); err != nil {
		t.Fatalf("Release: %v", err)
	}
	if err := s.Repos().Handles.Register(ctx, newHandle("h-b", "owner-b", "released")); err != nil {
		t.Fatalf("claim after release: %v", err)
	}
}

// TestHandleReleaseRefusesEarlyAndReclaimed is the sweep-window race: between a
// sweep listing a claim and releasing it, the owner may reclaim it or an
// operator may retire it. Neither may be deleted, nor may a running hold.
func TestHandleReleaseRefusesEarlyAndReclaimed(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	future := testClock.Add(time.Hour)
	past := testClock.Add(-time.Hour)

	for _, tc := range []struct {
		name  string
		state domain.NameState
		until *time.Time
	}{
		{"hold still running", domain.NameStateQuarantined, &future},
		{"reclaimed by its owner", domain.NameStateActive, &past},
		{"retired by an operator", domain.NameStateRetired, &past},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s := newStore(t)
			mustCreateOwner(t, s, "owner-a")

			h := newHandle("h-x", "owner-a", "held")
			h.State = tc.state
			h.QuarantineUntil = tc.until
			if err := s.Repos().Handles.Register(ctx, h); err != nil {
				t.Fatalf("register: %v", err)
			}

			if err := s.Repos().Handles.Release(ctx, "h-x", testClock); !errors.Is(err, domain.ErrNotFound) {
				t.Fatalf("Release = %v, want ErrNotFound", err)
			}
			if _, err := s.Repos().Handles.GetByName(ctx, "held"); err != nil {
				t.Fatalf("claim was deleted despite Release refusing: %v", err)
			}
		})
	}
}

// TestHandleLifecycleMigrationReverses exercises Up, Down, and Up again on
// PostgreSQL. The schema package's Down coverage runs on SQLite only, and the
// two engines fail differently here: migration 0012 adds two indexes over
// name_fold plus a partial index over state, and a Down that dropped the
// columns before the indexes depending on them would be rejected. Reverting to
// empty and reapplying proves the ordering holds and that nothing 0012 creates
// survives to collide with the second Up.
func TestHandleLifecycleMigrationReverses(t *testing.T) {
	t.Parallel()

	dsn := requireDSN(t)
	schemaName := randomSchemaName(t)

	admin, err := Open(Options{DSN: dsn, MaxOpenConns: 2})
	if err != nil {
		t.Fatalf("Open admin handle: %v", err)
	}
	t.Cleanup(func() { _ = admin.Close() })

	ctx := context.Background()
	if _, err := admin.ExecContext(ctx, fmt.Sprintf("CREATE SCHEMA %s", schemaName)); err != nil {
		t.Skipf("cannot create test schema (is %s reachable?): %v", dsnEnv, err)
	}
	t.Cleanup(func() {
		if _, err := admin.ExecContext(context.Background(),
			fmt.Sprintf("DROP SCHEMA IF EXISTS %s CASCADE", schemaName)); err != nil {
			t.Errorf("drop test schema %s: %v", schemaName, err)
		}
	})

	db := openTestDB(t, dsn, schemaName)
	reg, err := schema.Registry()
	if err != nil {
		t.Fatalf("schema.Registry: %v", err)
	}
	runner, err := migrate.NewRunner(NewMigrateDB(db), migrate.EnginePostgres, reg)
	if err != nil {
		t.Fatalf("migrate.NewRunner: %v", err)
	}

	if _, err := runner.Up(ctx); err != nil {
		t.Fatalf("first Up: %v", err)
	}
	if _, err := runner.Down(ctx, ""); err != nil {
		t.Fatalf("Down to empty: %v", err)
	}
	if _, err := runner.Up(ctx); err != nil {
		t.Fatalf("second Up: %v", err)
	}

	// The reapplied schema must still refuse a look-alike, which is the point
	// of the migration: a Down that left the index behind, or a second Up that
	// silently skipped recreating it, would both pass a bare Up/Down check.
	s := NewStore(db)
	mustCreateOwner(t, s, "owner-a")
	mustCreateOwner(t, s, "owner-b")
	if err := s.Repos().Handles.Register(ctx, newHandle("h-1", "owner-a", "stripe")); err != nil {
		t.Fatalf("register stripe: %v", err)
	}
	err = s.Repos().Handles.Register(ctx, newHandle("h-2", "owner-b", "str1pe"))
	if !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("register look-alike after Down/Up = %v, want domain.ErrConflict", err)
	}
}
