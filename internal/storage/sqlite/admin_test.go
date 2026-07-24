package sqlite

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/repository"
)

func newAdminRepo(t *testing.T) (*adminRepo, *Store) {
	t.Helper()
	s := newStore(t)
	return &adminRepo{e: s.db}, s
}

// testAdmin builds a valid administrator with fixed, distinguishable
// timestamps, so a test that asserts round-tripping cannot pass by comparing
// two zero values.
func testAdmin(id string) *domain.Administrator {
	created := time.Date(2026, 7, 19, 10, 0, 0, 0, time.UTC)
	return &domain.Administrator{
		ID:        domain.AdministratorID(id),
		Label:     "ops " + id,
		Status:    domain.AdminStatusActive,
		CreatedAt: created,
		UpdatedAt: created,
	}
}

func TestAdminCreateAndGetRoundTrips(t *testing.T) {
	t.Parallel()
	repo, _ := newAdminRepo(t)
	ctx := context.Background()

	want := testAdmin("adm-1")
	if err := repo.Create(ctx, want); err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := repo.Get(ctx, want.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.ID != want.ID || got.Label != want.Label || got.Status != want.Status {
		t.Errorf("Get = %+v, want %+v", got, want)
	}
	if !got.CreatedAt.Equal(want.CreatedAt) || !got.UpdatedAt.Equal(want.UpdatedAt) {
		t.Errorf("timestamps = %v/%v, want %v/%v",
			got.CreatedAt, got.UpdatedAt, want.CreatedAt, want.UpdatedAt)
	}
}

func TestAdminGetMissingIsNotFound(t *testing.T) {
	t.Parallel()
	repo, _ := newAdminRepo(t)

	_, err := repo.Get(context.Background(), "nope")
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("Get missing error = %v, want ErrNotFound", err)
	}
}

func TestAdminCreateRejectsInvalidInput(t *testing.T) {
	t.Parallel()
	repo, _ := newAdminRepo(t)
	ctx := context.Background()

	badStatus := testAdmin("adm-bad")
	badStatus.Status = domain.AdminStatus("superuser")

	cases := []struct {
		name string
		a    *domain.Administrator
	}{
		{"nil", nil},
		{"empty id", &domain.Administrator{Status: domain.AdminStatusActive}},
		// An unknown status must never reach the table: it would later be read
		// back as an authorization input nobody defined.
		{"unknown status", badStatus},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if err := repo.Create(ctx, tc.a); !errors.Is(err, domain.ErrInvalidInput) {
				t.Fatalf("Create(%s) error = %v, want ErrInvalidInput", tc.name, err)
			}
		})
	}
}

func TestAdminCreateDuplicateIDConflicts(t *testing.T) {
	t.Parallel()
	repo, _ := newAdminRepo(t)
	ctx := context.Background()

	a := testAdmin("adm-dup")
	if err := repo.Create(ctx, a); err != nil {
		t.Fatalf("first Create: %v", err)
	}
	// A second administrator must not be able to take an existing ID: the ID is
	// what an audit record names, so two principals sharing one would make the
	// record ambiguous about who acted.
	if err := repo.Create(ctx, a); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("duplicate Create error = %v, want ErrConflict", err)
	}
}

func TestAdminListIsOrderedByID(t *testing.T) {
	t.Parallel()
	repo, _ := newAdminRepo(t)
	ctx := context.Background()

	for _, id := range []string{"adm-c", "adm-a", "adm-b"} {
		if err := repo.Create(ctx, testAdmin(id)); err != nil {
			t.Fatalf("Create %s: %v", id, err)
		}
	}

	got, err := repo.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	want := []string{"adm-a", "adm-b", "adm-c"}
	if len(got) != len(want) {
		t.Fatalf("List returned %d rows, want %d", len(got), len(want))
	}
	for i, id := range want {
		if string(got[i].ID) != id {
			t.Errorf("List[%d].ID = %q, want %q", i, got[i].ID, id)
		}
	}
}

func TestAdminListEmpty(t *testing.T) {
	t.Parallel()
	repo, _ := newAdminRepo(t)

	got, err := repo.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("List on empty table returned %d rows", len(got))
	}
}

func TestAdminSetLabel(t *testing.T) {
	t.Parallel()
	repo, _ := newAdminRepo(t)
	ctx := context.Background()

	a := testAdmin("adm-label")
	if err := repo.Create(ctx, a); err != nil {
		t.Fatalf("Create: %v", err)
	}

	later := a.CreatedAt.Add(time.Hour)
	if err := repo.SetLabel(ctx, a.ID, "on call", later); err != nil {
		t.Fatalf("SetLabel: %v", err)
	}

	got, err := repo.Get(ctx, a.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Label != "on call" {
		t.Errorf("Label = %q, want %q", got.Label, "on call")
	}
	if !got.UpdatedAt.Equal(later) {
		t.Errorf("UpdatedAt = %v, want %v", got.UpdatedAt, later)
	}
	// CreatedAt must not move: it is the fact of when the role was granted.
	if !got.CreatedAt.Equal(a.CreatedAt) {
		t.Errorf("CreatedAt moved to %v, want %v", got.CreatedAt, a.CreatedAt)
	}
}

func TestAdminUpdateStatus(t *testing.T) {
	t.Parallel()
	repo, _ := newAdminRepo(t)
	ctx := context.Background()

	a := testAdmin("adm-status")
	if err := repo.Create(ctx, a); err != nil {
		t.Fatalf("Create: %v", err)
	}

	later := a.CreatedAt.Add(time.Hour)
	if err := repo.UpdateStatus(ctx, a.ID, domain.AdminStatusDisabled, later); err != nil {
		t.Fatalf("UpdateStatus: %v", err)
	}

	got, err := repo.Get(ctx, a.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Status != domain.AdminStatusDisabled {
		t.Errorf("Status = %q, want %q", got.Status, domain.AdminStatusDisabled)
	}
	if !got.UpdatedAt.Equal(later) {
		t.Errorf("UpdatedAt = %v, want %v", got.UpdatedAt, later)
	}
}

func TestAdminUpdateStatusRejectsUnknownStatus(t *testing.T) {
	t.Parallel()
	repo, _ := newAdminRepo(t)
	ctx := context.Background()

	a := testAdmin("adm-badstatus")
	if err := repo.Create(ctx, a); err != nil {
		t.Fatalf("Create: %v", err)
	}

	err := repo.UpdateStatus(ctx, a.ID, domain.AdminStatus("root"), time.Now())
	if !errors.Is(err, domain.ErrInvalidInput) {
		t.Fatalf("UpdateStatus(unknown) error = %v, want ErrInvalidInput", err)
	}

	// The refusal must leave the stored status untouched, not half-applied.
	got, gerr := repo.Get(ctx, a.ID)
	if gerr != nil {
		t.Fatalf("Get: %v", gerr)
	}
	if got.Status != domain.AdminStatusActive {
		t.Errorf("Status = %q after refused update, want unchanged %q",
			got.Status, domain.AdminStatusActive)
	}
}

func TestAdminUpdatesOnMissingRowAreNotFound(t *testing.T) {
	t.Parallel()
	repo, _ := newAdminRepo(t)
	ctx := context.Background()
	now := time.Now()

	// A no-op UPDATE must not read as success: an edit against an administrator
	// that does not exist is a failure the caller has to see.
	if err := repo.SetLabel(ctx, "ghost", "x", now); !errors.Is(err, domain.ErrNotFound) {
		t.Errorf("SetLabel on missing error = %v, want ErrNotFound", err)
	}
	if err := repo.UpdateStatus(ctx, "ghost", domain.AdminStatusDisabled, now); !errors.Is(err, domain.ErrNotFound) {
		t.Errorf("UpdateStatus on missing error = %v, want ErrNotFound", err)
	}
}

func TestAdminEmptyIDIsRejectedOnEveryMethod(t *testing.T) {
	t.Parallel()
	repo, _ := newAdminRepo(t)
	ctx := context.Background()
	now := time.Now()

	if _, err := repo.Get(ctx, ""); !errors.Is(err, domain.ErrInvalidInput) {
		t.Errorf("Get(\"\") error = %v, want ErrInvalidInput", err)
	}
	if err := repo.SetLabel(ctx, "", "x", now); !errors.Is(err, domain.ErrInvalidInput) {
		t.Errorf("SetLabel(\"\") error = %v, want ErrInvalidInput", err)
	}
	if err := repo.UpdateStatus(ctx, "", domain.AdminStatusActive, now); !errors.Is(err, domain.ErrInvalidInput) {
		t.Errorf("UpdateStatus(\"\") error = %v, want ErrInvalidInput", err)
	}
}

// TestAdminReadRefusesUnknownStatusInTable is the defense-in-depth case: a row
// whose status the domain does not recognize must fail the read rather than be
// returned. The row is written by raw SQL because both the adapter and the
// CHECK constraint refuse it — which is the point, this simulates the table
// being modified out from under the application.
func TestAdminReadRefusesUnknownStatusInTable(t *testing.T) {
	t.Parallel()
	repo, s := newAdminRepo(t)
	ctx := context.Background()

	// PRAGMA ignore_check_constraints lets the test plant the row the CHECK
	// would otherwise refuse, so the adapter's own validation is what is
	// under test here.
	if _, err := s.db.ExecContext(ctx, `PRAGMA ignore_check_constraints = ON`); err != nil {
		t.Fatalf("disable check constraints: %v", err)
	}
	const q = `INSERT INTO administrators (id, label, status, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?)`
	ts := encTime(time.Now())
	if _, err := s.db.ExecContext(ctx, q, "adm-corrupt", "x", "superuser", ts, ts); err != nil {
		t.Skipf("could not plant an out-of-range status row: %v", err)
	}

	if _, err := repo.Get(ctx, "adm-corrupt"); !errors.Is(err, domain.ErrInvalidInput) {
		t.Errorf("Get(corrupt row) error = %v, want ErrInvalidInput", err)
	}
	if _, err := repo.List(ctx); !errors.Is(err, domain.ErrInvalidInput) {
		t.Errorf("List(corrupt row) error = %v, want ErrInvalidInput", err)
	}
}

// TestAdminMalformedTimestampIsRejected covers the other decode failure: a
// timestamp that is not in the adapter's fixed layout must be an error rather
// than a zero time silently standing in for a real one.
func TestAdminMalformedTimestampIsRejected(t *testing.T) {
	t.Parallel()
	repo, s := newAdminRepo(t)
	ctx := context.Background()

	const q = `INSERT INTO administrators (id, label, status, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?)`
	if _, err := s.db.ExecContext(ctx, q, "adm-time", "x", "active", "not-a-time", "not-a-time"); err != nil {
		t.Fatalf("plant row: %v", err)
	}

	if _, err := repo.Get(ctx, "adm-time"); err == nil {
		t.Error("Get on a malformed timestamp returned no error")
	}
}

// TestAdminRoundTripsThroughStoreRepos pins the wiring: an administrator must
// be reachable through the Store's repository set, not only through a directly
// constructed adapter. Without this, the adapter could be correct and still not
// be connected to anything.
func TestAdminRoundTripsThroughStoreRepos(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	repos := s.Repos()
	if repos.Admins == nil {
		t.Fatal("Store.Repos().Admins is nil: the adapter is not wired")
	}
	a := testAdmin("adm-wired")
	if err := repos.Admins.Create(ctx, a); err != nil {
		t.Fatalf("Create through Repos: %v", err)
	}
	got, err := repos.Admins.Get(ctx, a.ID)
	if err != nil {
		t.Fatalf("Get through Repos: %v", err)
	}
	if got.ID != a.ID {
		t.Errorf("ID = %q, want %q", got.ID, a.ID)
	}
}

// TestAdminWithTxRollsBack pins that the administrator adapter participates in
// the store's unit of work. The authorization edits in Fb3 depend on this: the
// entry change and its audit record are committed together or not at all, which
// is only true if this repository honors the transaction.
func TestAdminWithTxRollsBack(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	sentinel := errors.New("roll back")
	err := s.WithTx(ctx, func(ctx context.Context, r repository.Repos) error {
		if cerr := r.Admins.Create(ctx, testAdmin("adm-tx")); cerr != nil {
			return cerr
		}
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("WithTx error = %v, want the sentinel", err)
	}

	if _, gerr := s.Repos().Admins.Get(ctx, "adm-tx"); !errors.Is(gerr, domain.ErrNotFound) {
		t.Fatalf("administrator survived a rolled-back transaction: %v", gerr)
	}
}
