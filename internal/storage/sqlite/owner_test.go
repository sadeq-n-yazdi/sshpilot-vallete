package sqlite

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/repository"
)

func TestOwnerCreateAndGet(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	repos := s.Repos()

	want := newOwner("o-1")
	if err := repos.Owners.Create(ctx, want); err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := repos.Owners.Get(ctx, "o-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.ID != want.ID || got.Status != want.Status {
		t.Errorf("Get = %+v, want id/status %q/%q", got, want.ID, want.Status)
	}
	if !got.CreatedAt.Equal(want.CreatedAt) || !got.UpdatedAt.Equal(want.UpdatedAt) {
		t.Errorf("timestamps round-trip mismatch: got %v/%v", got.CreatedAt, got.UpdatedAt)
	}
	if got.DeletedAt != nil {
		t.Errorf("DeletedAt = %v, want nil", got.DeletedAt)
	}
}

func TestOwnerCreateDuplicateConflict(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	repos := s.Repos()

	if err := repos.Owners.Create(ctx, newOwner("dup")); err != nil {
		t.Fatalf("first Create: %v", err)
	}
	err := repos.Owners.Create(ctx, newOwner("dup"))
	if !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("duplicate Create error = %v, want ErrConflict", err)
	}
}

func TestOwnerGetMissingNotFound(t *testing.T) {
	t.Parallel()
	s := newStore(t)

	_, err := s.Repos().Owners.Get(context.Background(), "ghost")
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("Get missing error = %v, want ErrNotFound", err)
	}
}

func TestOwnerUpdateStatus(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	repos := s.Repos()

	mustCreateOwner(t, s, "o-status")
	later := testClock.Add(time.Hour)
	if err := repos.Owners.UpdateStatus(ctx, "o-status", domain.OwnerStatusSuspended, later); err != nil {
		t.Fatalf("UpdateStatus: %v", err)
	}

	got, err := repos.Owners.Get(ctx, "o-status")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Status != domain.OwnerStatusSuspended {
		t.Errorf("Status = %q, want suspended", got.Status)
	}
	if !got.UpdatedAt.Equal(later) {
		t.Errorf("UpdatedAt = %v, want %v", got.UpdatedAt, later)
	}
}

func TestOwnerUpdateStatusMissingNotFound(t *testing.T) {
	t.Parallel()
	s := newStore(t)

	err := s.Repos().Owners.UpdateStatus(context.Background(), "ghost", domain.OwnerStatusSuspended, testClock)
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("UpdateStatus missing error = %v, want ErrNotFound", err)
	}
}

func TestOwnerSoftDelete(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	repos := s.Repos()

	mustCreateOwner(t, s, "o-del")
	later := testClock.Add(2 * time.Hour)
	if err := repos.Owners.SoftDelete(ctx, "o-del", later); err != nil {
		t.Fatalf("SoftDelete: %v", err)
	}

	got, err := repos.Owners.Get(ctx, "o-del")
	if err != nil {
		t.Fatalf("Get after SoftDelete: %v", err)
	}
	if got.DeletedAt == nil || !got.DeletedAt.Equal(later) {
		t.Errorf("DeletedAt = %v, want %v", got.DeletedAt, later)
	}
	if !got.UpdatedAt.Equal(later) {
		t.Errorf("UpdatedAt = %v, want %v", got.UpdatedAt, later)
	}
	// SoftDelete deliberately does not touch status; that is UpdateStatus's job.
	if got.Status != domain.OwnerStatusActive {
		t.Errorf("Status = %q, want unchanged active", got.Status)
	}
}

func TestOwnerSoftDeleteMissingNotFound(t *testing.T) {
	t.Parallel()
	s := newStore(t)

	err := s.Repos().Owners.SoftDelete(context.Background(), "ghost", testClock)
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("SoftDelete missing error = %v, want ErrNotFound", err)
	}
}

func TestOwnerListPaginates(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	repos := s.Repos()

	// Insert ids owner-0000..owner-0009; id order is deterministic.
	const n = 10
	for i := 0; i < n; i++ {
		mustCreateOwner(t, s, fmt.Sprintf("owner-%04d", i))
	}

	var seen []string
	cursor := ""
	pages := 0
	for {
		got, next, err := repos.Owners.List(ctx, repository.Page{Limit: 3, Cursor: cursor})
		if err != nil {
			t.Fatalf("List page %d: %v", pages, err)
		}
		for i := range got {
			seen = append(seen, string(got[i].ID))
		}
		pages++
		if next == "" {
			break
		}
		cursor = next
		if pages > n+2 {
			t.Fatal("pagination did not terminate")
		}
	}

	if len(seen) != n {
		t.Fatalf("saw %d owners across pages, want %d", len(seen), n)
	}
	for i := 1; i < len(seen); i++ {
		if seen[i-1] >= seen[i] {
			t.Fatalf("owners not strictly ascending/unique: %q then %q", seen[i-1], seen[i])
		}
	}
}

func TestOwnerListDefaultLimit(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	mustCreateOwner(t, s, "only")
	got, next, err := s.Repos().Owners.List(ctx, repository.Page{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 1 || next != "" {
		t.Fatalf("List = %d owners, next %q; want 1 owner and empty cursor", len(got), next)
	}
}

// TestOwnerQueryErrorsMapped drives the driver-error branches of the owner
// read/write paths with an already-canceled context.
func TestOwnerQueryErrorsMapped(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	mustCreateOwner(t, s, "o-1")

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := s.Repos().Owners.Get(ctx, "o-1"); err == nil {
		t.Error("Get on canceled ctx: nil error")
	}
	if _, _, err := s.Repos().Owners.List(ctx, repository.Page{Limit: 5}); err == nil {
		t.Error("List on canceled ctx: nil error")
	}
	if err := s.Repos().Owners.UpdateStatus(ctx, "o-1", domain.OwnerStatusSuspended, testClock); err == nil {
		t.Error("UpdateStatus on canceled ctx: nil error")
	}
	if err := s.Repos().Owners.SoftDelete(ctx, "o-1", testClock); err == nil {
		t.Error("SoftDelete on canceled ctx: nil error")
	}
}

// TestOwnerErrorLeaksNoSQL asserts that a mapped conflict error carries a domain
// sentinel and no SQL text or table names.
func TestOwnerErrorLeaksNoSQL(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	repos := s.Repos()

	if err := repos.Owners.Create(ctx, newOwner("leak")); err != nil {
		t.Fatalf("first Create: %v", err)
	}
	err := repos.Owners.Create(ctx, newOwner("leak"))
	if !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("duplicate error = %v, want ErrConflict", err)
	}
	msg := strings.ToUpper(err.Error())
	for _, leak := range []string{"INSERT", "SELECT", "OWNERS", "UNIQUE", "PRIMARY KEY"} {
		if strings.Contains(msg, leak) {
			t.Errorf("error message %q leaks SQL fragment %q", err.Error(), leak)
		}
	}
}
