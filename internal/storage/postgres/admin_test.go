package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/repository"
)

// newAdmin returns a fully populated administrator. Administrators are
// system-axis principals: there is deliberately no owner to attach one to, and
// the table carries no owner_id, so no owner fixture is created here.
func newAdmin(id, label string, status domain.AdminStatus) *domain.Administrator {
	return &domain.Administrator{
		ID:        domain.AdministratorID(id),
		Label:     label,
		Status:    status,
		CreatedAt: testClock,
		UpdatedAt: testClock,
	}
}

// mustCreateAdmin creates the administrator, failing the test on error.
func mustCreateAdmin(t *testing.T, s *Store, a *domain.Administrator) *domain.Administrator {
	t.Helper()
	if err := s.Repos().Admins.Create(context.Background(), a); err != nil {
		t.Fatalf("Create administrator %q: %v", a.ID, err)
	}
	return a
}

// setAdminStatusRaw writes status straight to the column, bypassing the
// repository's validation so a read-back can be tested against a value the
// domain does not recognize.
func setAdminStatusRaw(t *testing.T, s *Store, id, status string) {
	t.Helper()
	const q = `UPDATE administrators SET status = $1 WHERE id = $2`
	if _, err := s.db.ExecContext(context.Background(), q, status, id); err != nil {
		t.Fatalf("force status %q on %q: %v", status, id, err)
	}
}

func TestAdminCreateAndGet(t *testing.T) {
	t.Parallel()
	s := newStore(t)

	want := mustCreateAdmin(t, s, newAdmin("adm-1", "Alice", domain.AdminStatusActive))

	got, err := s.Repos().Admins.Get(context.Background(), "adm-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.ID != want.ID || got.Label != "Alice" || got.Status != domain.AdminStatusActive {
		t.Errorf("administrator = %q/%q/%q, want adm-1/Alice/active", got.ID, got.Label, got.Status)
	}
	if !got.CreatedAt.Equal(testClock) || !got.UpdatedAt.Equal(testClock) {
		t.Errorf("timestamps = %v/%v, want both %v", got.CreatedAt, got.UpdatedAt, testClock)
	}
}

func TestAdminGetMissingReturnsNotFound(t *testing.T) {
	t.Parallel()
	s := newStore(t)

	if _, err := s.Repos().Admins.Get(context.Background(), "adm-nope"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("Get missing = %v, want ErrNotFound", err)
	}
}

func TestAdminCreateRejectsBadInput(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	tests := []struct {
		name string
		a    *domain.Administrator
	}{
		{name: "nil administrator", a: nil},
		{name: "empty id", a: newAdmin("", "Alice", domain.AdminStatusActive)},
		{name: "unknown status", a: newAdmin("adm-x", "Alice", domain.AdminStatus("superuser"))},
		{name: "empty status", a: newAdmin("adm-y", "Alice", domain.AdminStatus(""))},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := s.Repos().Admins.Create(ctx, tt.a); !errors.Is(err, domain.ErrInvalidInput) {
				t.Errorf("Create = %v, want ErrInvalidInput", err)
			}
		})
	}
}

func TestAdminCreateDuplicateIDConflicts(t *testing.T) {
	t.Parallel()
	s := newStore(t)

	mustCreateAdmin(t, s, newAdmin("adm-dup", "First", domain.AdminStatusActive))
	err := s.Repos().Admins.Create(context.Background(),
		newAdmin("adm-dup", "Second", domain.AdminStatusActive))
	if !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("duplicate Create = %v, want ErrConflict", err)
	}
}

func TestAdminListIsOrderedByID(t *testing.T) {
	t.Parallel()
	s := newStore(t)

	mustCreateAdmin(t, s, newAdmin("adm-c", "Carol", domain.AdminStatusActive))
	mustCreateAdmin(t, s, newAdmin("adm-a", "Alice", domain.AdminStatusActive))
	mustCreateAdmin(t, s, newAdmin("adm-b", "Bob", domain.AdminStatusDisabled))

	got, err := s.Repos().Admins.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("List returned %d administrators, want 3", len(got))
	}
	for i, want := range []domain.AdministratorID{"adm-a", "adm-b", "adm-c"} {
		if got[i].ID != want {
			t.Errorf("List[%d] = %q, want %q", i, got[i].ID, want)
		}
	}
	// The disabled principal must still be listed: an incident review needs to
	// see that it exists, which is why disabling is a status and not a delete.
	if got[1].Status != domain.AdminStatusDisabled {
		t.Errorf("adm-b status = %q, want disabled", got[1].Status)
	}
}

func TestAdminListEmptyReturnsNil(t *testing.T) {
	t.Parallel()
	s := newStore(t)

	got, err := s.Repos().Admins.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if got != nil {
		t.Errorf("List with no administrators = %v, want nil slice", got)
	}
}

func TestAdminSetLabelUpdatesLabelAndTimestamp(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	mustCreateAdmin(t, s, newAdmin("adm-1", "Alice", domain.AdminStatusActive))
	now := testClock.Add(time.Hour)

	if err := s.Repos().Admins.SetLabel(ctx, "adm-1", "Alice Smith", now); err != nil {
		t.Fatalf("SetLabel: %v", err)
	}

	got, err := s.Repos().Admins.Get(ctx, "adm-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Label != "Alice Smith" {
		t.Errorf("Label = %q, want Alice Smith", got.Label)
	}
	if !got.UpdatedAt.Equal(now) {
		t.Errorf("UpdatedAt = %v, want %v", got.UpdatedAt, now)
	}
	// CreatedAt records when the principal was granted the role and must not be
	// rewritten by an unrelated edit.
	if !got.CreatedAt.Equal(testClock) {
		t.Errorf("CreatedAt = %v, want %v (unchanged)", got.CreatedAt, testClock)
	}
	// The label is cosmetic; changing it must not alter the authorization input.
	if got.Status != domain.AdminStatusActive {
		t.Errorf("Status = %q, want active (unchanged)", got.Status)
	}
}

func TestAdminUpdateStatusDisables(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	mustCreateAdmin(t, s, newAdmin("adm-1", "Alice", domain.AdminStatusActive))
	now := testClock.Add(2 * time.Hour)

	if err := s.Repos().Admins.UpdateStatus(ctx, "adm-1", domain.AdminStatusDisabled, now); err != nil {
		t.Fatalf("UpdateStatus: %v", err)
	}

	got, err := s.Repos().Admins.Get(ctx, "adm-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Status != domain.AdminStatusDisabled {
		t.Errorf("Status = %q, want disabled", got.Status)
	}
	if !got.UpdatedAt.Equal(now) {
		t.Errorf("UpdatedAt = %v, want %v", got.UpdatedAt, now)
	}
	if got.Label != "Alice" {
		t.Errorf("Label = %q, want Alice (unchanged)", got.Label)
	}
}

// An unknown status must be refused before it reaches the table, so the caller
// gets ErrInvalidInput rather than an opaque CHECK-constraint driver error —
// and so a status nobody defined can never become readable as authorization.
func TestAdminUpdateStatusRejectsUnknownStatus(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	mustCreateAdmin(t, s, newAdmin("adm-1", "Alice", domain.AdminStatusActive))

	err := s.Repos().Admins.UpdateStatus(ctx, "adm-1", domain.AdminStatus("superuser"), testClock)
	if !errors.Is(err, domain.ErrInvalidInput) {
		t.Fatalf("UpdateStatus with unknown status = %v, want ErrInvalidInput", err)
	}

	got, gerr := s.Repos().Admins.Get(ctx, "adm-1")
	if gerr != nil {
		t.Fatalf("Get: %v", gerr)
	}
	if got.Status != domain.AdminStatusActive {
		t.Errorf("Status = %q, want active (unchanged by the refused update)", got.Status)
	}
}

// An update against an administrator that does not exist must be reported
// rather than silently succeeding, or an operator believes they disabled a
// principal that was never there.
func TestAdminUpdatesOnMissingRowReturnNotFound(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	if err := s.Repos().Admins.SetLabel(ctx, "adm-ghost", "Ghost", testClock); !errors.Is(err, domain.ErrNotFound) {
		t.Errorf("SetLabel on missing = %v, want ErrNotFound", err)
	}
	err := s.Repos().Admins.UpdateStatus(ctx, "adm-ghost", domain.AdminStatusDisabled, testClock)
	if !errors.Is(err, domain.ErrNotFound) {
		t.Errorf("UpdateStatus on missing = %v, want ErrNotFound", err)
	}
}

func TestAdminMethodsRejectEmptyID(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	if _, err := s.Repos().Admins.Get(ctx, ""); !errors.Is(err, domain.ErrInvalidInput) {
		t.Errorf("Get(\"\") = %v, want ErrInvalidInput", err)
	}
	if err := s.Repos().Admins.SetLabel(ctx, "", "x", testClock); !errors.Is(err, domain.ErrInvalidInput) {
		t.Errorf("SetLabel(\"\") = %v, want ErrInvalidInput", err)
	}
	err := s.Repos().Admins.UpdateStatus(ctx, "", domain.AdminStatusActive, testClock)
	if !errors.Is(err, domain.ErrInvalidInput) {
		t.Errorf("UpdateStatus(\"\") = %v, want ErrInvalidInput", err)
	}
}

// A row whose status the domain does not recognize means the table was edited
// out from under the application. Returning it would make the caller authorize
// on data it cannot interpret, so both reads must fail closed instead.
func TestAdminReadsRefuseUnknownStatus(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	mustCreateAdmin(t, s, newAdmin("adm-1", "Alice", domain.AdminStatusActive))
	// The CHECK constraint refuses a value outside the enum, so the tampered
	// value has to be one the constraint allows but the domain does not know.
	// Dropping the constraint models the same situation: the stored status is
	// not a domain.AdminStatus.
	if _, err := s.db.ExecContext(ctx,
		`ALTER TABLE administrators DROP CONSTRAINT administrators_status_check`); err != nil {
		t.Fatalf("drop status CHECK: %v", err)
	}
	setAdminStatusRaw(t, s, "adm-1", "superuser")

	if _, err := s.Repos().Admins.Get(ctx, "adm-1"); !errors.Is(err, domain.ErrInvalidInput) {
		t.Errorf("Get of tampered row = %v, want ErrInvalidInput", err)
	}
	if _, err := s.Repos().Admins.List(ctx); !errors.Is(err, domain.ErrInvalidInput) {
		t.Errorf("List with a tampered row = %v, want ErrInvalidInput", err)
	}
}

// The CHECK constraint is the backstop behind the adapter's own validation: a
// status the domain would not recognize must be refused by the database too.
func TestAdminStatusCheckConstraintRefusesUnknownValue(t *testing.T) {
	t.Parallel()
	s := newStore(t)

	const q = `INSERT INTO administrators (id, label, status, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5)`
	_, err := s.db.ExecContext(context.Background(), q,
		"adm-raw", "Raw", "superuser", encTime(testClock), encTime(testClock))
	if err == nil {
		t.Fatal("INSERT with an unknown status succeeded; the CHECK constraint is missing")
	}
}

// Administrators are system-axis, so a write inside a caller's transaction must
// still compose: the same execer plumbing carries the repository into WithTx.
func TestAdminHonorsTransactionRollback(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	boom := errors.New("boom")

	err := s.WithTx(ctx, func(ctx context.Context, r repository.Repos) error {
		if cerr := r.Admins.Create(ctx, newAdmin("adm-tx", "Tx", domain.AdminStatusActive)); cerr != nil {
			return cerr
		}
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatalf("WithTx = %v, want boom", err)
	}
	if _, gerr := s.Repos().Admins.Get(ctx, "adm-tx"); !errors.Is(gerr, domain.ErrNotFound) {
		t.Fatalf("Get after rollback = %v, want ErrNotFound", gerr)
	}
}
