package postgres

import (
	"context"
	"errors"
	"fmt"
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
	// The stored value must come back in UTC, not in the server's or the
	// client's local zone.
	if got.CreatedAt.Location() != time.UTC {
		t.Errorf("CreatedAt location = %v, want UTC", got.CreatedAt.Location())
	}
	if got.DeletedAt != nil {
		t.Errorf("DeletedAt = %v, want nil", got.DeletedAt)
	}
}

// TestOwnerCreateNonUTCRoundTripsToUTC pins the encoding invariant: a timestamp
// supplied in a non-UTC zone is normalized on write and read back as the same
// instant in UTC, so the fixed-width text ordering used by the sweeps holds.
func TestOwnerCreateNonUTCRoundTripsToUTC(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	zone := time.FixedZone("UTC+7", 7*60*60)
	o := newOwner("o-zone")
	o.CreatedAt = testClock.In(zone)
	o.UpdatedAt = testClock.In(zone)
	deleted := testClock.Add(time.Hour).In(zone)
	o.DeletedAt = &deleted

	if err := s.Repos().Owners.Create(ctx, o); err != nil {
		t.Fatalf("Create: %v", err)
	}
	got, err := s.Repos().Owners.Get(ctx, "o-zone")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !got.CreatedAt.Equal(testClock) || got.CreatedAt.Location() != time.UTC {
		t.Errorf("CreatedAt = %v, want %v in UTC", got.CreatedAt, testClock)
	}
	if got.DeletedAt == nil || !got.DeletedAt.Equal(deleted) {
		t.Errorf("DeletedAt = %v, want %v", got.DeletedAt, deleted)
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

func TestOwnerCreateNilInvalidInput(t *testing.T) {
	t.Parallel()
	s := newStore(t)

	if err := s.Repos().Owners.Create(context.Background(), nil); !errors.Is(err, domain.ErrInvalidInput) {
		t.Fatalf("Create(nil) error = %v, want ErrInvalidInput", err)
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

// TestOwnerSoftDelete checks that SoftDelete stamps only deleted_at and
// updated_at: status is owned by UpdateStatus and must be left untouched.
func TestOwnerSoftDelete(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	mustCreateOwner(t, s, "o-del")
	at := testClock.Add(2 * time.Hour)
	if err := s.Repos().Owners.SoftDelete(ctx, "o-del", at); err != nil {
		t.Fatalf("SoftDelete: %v", err)
	}

	got, err := s.Repos().Owners.Get(ctx, "o-del")
	if err != nil {
		t.Fatalf("Get after SoftDelete: %v", err)
	}
	if got.DeletedAt == nil || !got.DeletedAt.Equal(at) {
		t.Errorf("DeletedAt = %v, want %v", got.DeletedAt, at)
	}
	if !got.UpdatedAt.Equal(at) {
		t.Errorf("UpdatedAt = %v, want %v", got.UpdatedAt, at)
	}
	if got.Status != domain.OwnerStatusActive {
		t.Errorf("SoftDelete changed status to %q, want it untouched", got.Status)
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

// TestOwnerListPaginates walks the keyset cursor to the end and checks that
// every owner is visited exactly once and that the final page returns an empty
// cursor.
func TestOwnerListPaginates(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	const total = 5
	for i := range total {
		mustCreateOwner(t, s, fmt.Sprintf("o-%02d", i))
	}

	seen := map[domain.OwnerID]bool{}
	cursor := ""
	for pages := 0; ; pages++ {
		if pages > total {
			t.Fatal("pagination did not terminate")
		}
		got, next, err := s.Repos().Owners.List(ctx, repository.Page{Limit: 2, Cursor: cursor})
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		for _, o := range got {
			if seen[o.ID] {
				t.Errorf("owner %q returned twice", o.ID)
			}
			seen[o.ID] = true
		}
		if next == "" {
			break
		}
		cursor = next
	}
	if len(seen) != total {
		t.Errorf("List visited %d owners, want %d", len(seen), total)
	}
}

// TestOwnerListEmptyReturnsNilSlice pins the empty-list convention: no rows
// yields a nil slice, not an allocated empty one.
func TestOwnerListEmptyReturnsNilSlice(t *testing.T) {
	t.Parallel()
	s := newStore(t)

	got, next, err := s.Repos().Owners.List(context.Background(), repository.Page{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if got != nil {
		t.Errorf("List on empty table = %#v, want nil slice", got)
	}
	if next != "" {
		t.Errorf("next cursor = %q, want empty", next)
	}
}

// TestOwnerListDefaultLimit checks that a non-positive Limit falls back to
// defaultPageLimit rather than returning nothing.
func TestOwnerListDefaultLimit(t *testing.T) {
	t.Parallel()
	s := newStore(t)

	for i := range 3 {
		mustCreateOwner(t, s, fmt.Sprintf("o-%02d", i))
	}
	got, next, err := s.Repos().Owners.List(context.Background(), repository.Page{Limit: 0})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 3 {
		t.Errorf("List with zero limit returned %d rows, want 3", len(got))
	}
	if next != "" {
		t.Errorf("next cursor = %q, want empty (all rows fit one page)", next)
	}
}

// TestOwnerQueryErrorsMapped drives the driver-error branches with an
// already-canceled context: every method must surface an error rather than a
// nil error with partial data.
func TestOwnerQueryErrorsMapped(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	mustCreateOwner(t, s, "o-1")

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	repos := s.Repos()
	if err := repos.Owners.Create(ctx, newOwner("o-2")); err == nil {
		t.Error("Create on canceled ctx: nil error")
	}
	if _, err := repos.Owners.Get(ctx, "o-1"); err == nil {
		t.Error("Get on canceled ctx: nil error")
	}
	if err := repos.Owners.UpdateStatus(ctx, "o-1", domain.OwnerStatusSuspended, testClock); err == nil {
		t.Error("UpdateStatus on canceled ctx: nil error")
	}
	if err := repos.Owners.SoftDelete(ctx, "o-1", testClock); err == nil {
		t.Error("SoftDelete on canceled ctx: nil error")
	}
	if _, _, err := repos.Owners.List(ctx, repository.Page{Limit: 2}); err == nil {
		t.Error("List on canceled ctx: nil error")
	}
}
