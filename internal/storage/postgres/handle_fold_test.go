package postgres

import (
	"context"
	"errors"
	"testing"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/blocklist"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
)

// foldOf reads the write-only name_fold and fold_version columns straight from
// the row, because domain.Handle deliberately carries neither: an assertion
// about the stored fold has to go to the column, not to a struct field the
// adapter could have populated from thin air.
func foldOf(t *testing.T, s *Store, id string) (string, int) {
	t.Helper()
	var fold string
	var ver int
	err := s.db.QueryRowContext(context.Background(),
		`SELECT name_fold, fold_version FROM handles WHERE id = $1`, id).Scan(&fold, &ver)
	if err != nil {
		t.Fatalf("read fold for %q: %v", id, err)
	}
	return fold, ver
}

// TestHandleRegisterFailsClosedOnStaleFold proves the create guard: a single row
// whose fold_version is behind the current table revision refuses every new
// registration, so no claim is written while the look-alike index cannot be
// trusted (ADR-0030).
func TestHandleRegisterFailsClosedOnStaleFold(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()

	first := newHandle("h-1", "owner-a", "alice")
	mustRegisterHandle(t, s, first)

	// Knock its fold back to a stale revision, mimicking migration 0012's
	// fold_version = 0 backfill.
	if err := s.Repos().Handles.SetFold(ctx, "h-1", "alice", 0, testClock); err != nil {
		t.Fatalf("SetFold to stale: %v", err)
	}

	mustCreateOwner(t, s, "owner-b")
	second := newHandle("h-2", "owner-b", "bob")
	if err := s.Repos().Handles.Register(ctx, second); !errors.Is(err, domain.ErrFoldStale) {
		t.Fatalf("Register with a stale row present = %v, want ErrFoldStale", err)
	}

	if _, err := s.Repos().Handles.GetByName(ctx, "bob"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("GetByName(bob) after refused register = %v, want ErrNotFound", err)
	}
}

// TestHandleRegisterSucceedsWhenFoldsCurrent is the other half of the guard: with
// every row at the current revision, registration is unaffected.
func TestHandleRegisterSucceedsWhenFoldsCurrent(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()

	mustRegisterHandle(t, s, newHandle("h-1", "owner-a", "alice"))
	mustCreateOwner(t, s, "owner-b")
	if err := s.Repos().Handles.Register(ctx, newHandle("h-2", "owner-b", "bob")); err != nil {
		t.Fatalf("Register with all folds current: %v", err)
	}
	if _, ver := foldOf(t, s, "h-2"); ver != blocklist.TableVersion {
		t.Fatalf("h-2 fold_version = %d, want %d", ver, blocklist.TableVersion)
	}
}

// TestHandleListStaleFolds returns exactly the rows behind the current revision,
// oldest first, and excludes current rows.
func TestHandleListStaleFolds(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()

	mustRegisterHandle(t, s, newHandle("h-1", "owner-a", "alice"))
	mustCreateOwner(t, s, "owner-b")
	if err := s.Repos().Handles.Register(ctx, newHandle("h-2", "owner-b", "bob")); err != nil {
		t.Fatalf("Register h-2: %v", err)
	}

	if err := s.Repos().Handles.SetFold(ctx, "h-1", "alice", 0, testClock); err != nil {
		t.Fatalf("SetFold h-1 stale: %v", err)
	}

	stale, err := s.Repos().Handles.ListStaleFolds(ctx, blocklist.TableVersion)
	if err != nil {
		t.Fatalf("ListStaleFolds: %v", err)
	}
	if len(stale) != 1 || stale[0].ID != "h-1" {
		t.Fatalf("ListStaleFolds = %+v, want only h-1", stale)
	}
}

// TestHandleSetFoldWritesFoldAndVersion checks the recompute writer overwrites
// both columns.
func TestHandleSetFoldWritesFoldAndVersion(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()

	mustRegisterHandle(t, s, newHandle("h-1", "owner-a", "alice"))
	if err := s.Repos().Handles.SetFold(ctx, "h-1", "alyce", 3, testClock); err != nil {
		t.Fatalf("SetFold: %v", err)
	}
	fold, ver := foldOf(t, s, "h-1")
	if fold != "alyce" || ver != 3 {
		t.Fatalf("after SetFold got fold=%q ver=%d, want alyce/3", fold, ver)
	}
}

// TestHandleSetFoldConflict proves the writer surfaces a fold clash as
// ErrConflict rather than corrupting the index.
func TestHandleSetFoldConflict(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()

	mustRegisterHandle(t, s, newHandle("h-1", "owner-a", "alice"))
	mustCreateOwner(t, s, "owner-b")
	if err := s.Repos().Handles.Register(ctx, newHandle("h-2", "owner-b", "bob")); err != nil {
		t.Fatalf("Register h-2: %v", err)
	}
	if err := s.Repos().Handles.SetFold(ctx, "h-2", "alice", blocklist.TableVersion, testClock); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("SetFold onto an occupied fold = %v, want ErrConflict", err)
	}
}

// TestHandleSetFoldNotFound reports a missing row rather than silently doing
// nothing.
func TestHandleSetFoldNotFound(t *testing.T) {
	s := newStore(t)
	if err := s.Repos().Handles.SetFold(context.Background(), "h-ghost", "x", blocklist.TableVersion, testClock); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("SetFold on a missing row = %v, want ErrNotFound", err)
	}
}

// TestHandleQuarantineLookalike holds a row indefinitely and flags it, leaving no
// release deadline for the sweep to act on.
func TestHandleQuarantineLookalike(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()

	mustRegisterHandle(t, s, newHandle("h-1", "owner-a", "alice"))
	if err := s.Repos().Handles.QuarantineLookalike(ctx, "h-1", testClock); err != nil {
		t.Fatalf("QuarantineLookalike: %v", err)
	}
	got, err := s.Repos().Handles.Get(ctx, "owner-a", "h-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.State != domain.NameStateQuarantined {
		t.Errorf("state = %q, want quarantined", got.State)
	}
	if !got.FlaggedForReview {
		t.Error("FlaggedForReview = false, want true")
	}
	if got.QuarantineUntil != nil {
		t.Errorf("QuarantineUntil = %v, want nil (held indefinitely)", got.QuarantineUntil)
	}
}

// TestHandleQuarantineLookalikeNotFound reports a missing row.
func TestHandleQuarantineLookalikeNotFound(t *testing.T) {
	s := newStore(t)
	if err := s.Repos().Handles.QuarantineLookalike(context.Background(), "h-ghost", testClock); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("QuarantineLookalike on a missing row = %v, want ErrNotFound", err)
	}
}
