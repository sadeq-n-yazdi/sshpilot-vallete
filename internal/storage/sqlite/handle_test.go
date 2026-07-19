package sqlite

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
)

// newHandle returns a fully populated active handle owned by ownerID.
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

	mustRegisterHandle(t, s, newHandle("h-1", "owner-a", "n1"))
	mustRegisterHandle(t, s, newHandle("h-2", "owner-a", "n2"))
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
