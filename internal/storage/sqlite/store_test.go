package sqlite

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/migrate"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/repository"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/schema"
)

// testClock is a fixed reference time used to build deterministic entities.
var testClock = time.Date(2026, 7, 19, 10, 0, 0, 0, time.UTC)

// newStore opens a fresh in-memory database, applies the full domain schema
// through the migrate runner, and returns the Store wrapping it.
func newStore(t *testing.T) *Store {
	t.Helper()

	db := openMemory(t)
	reg, err := schema.Registry()
	if err != nil {
		t.Fatalf("schema.Registry: %v", err)
	}
	runner, err := migrate.NewRunner(NewMigrateDB(db), migrate.EngineSQLite, reg)
	if err != nil {
		t.Fatalf("migrate.NewRunner: %v", err)
	}
	if _, err := runner.Up(context.Background()); err != nil {
		t.Fatalf("migrate Up: %v", err)
	}
	return NewStore(db)
}

// newOwner returns a fully populated active owner with the given id.
func newOwner(id string) *domain.Owner {
	return &domain.Owner{
		ID:        domain.OwnerID(id),
		Status:    domain.OwnerStatusActive,
		CreatedAt: testClock,
		UpdatedAt: testClock,
	}
}

// mustCreateOwner creates an owner through the auto-commit repos, failing the
// test on error.
func mustCreateOwner(t *testing.T, s *Store, id string) *domain.Owner {
	t.Helper()
	o := newOwner(id)
	if err := s.Repos().Owners.Create(context.Background(), o); err != nil {
		t.Fatalf("create owner %q: %v", id, err)
	}
	return o
}

func TestWithTxCommitPersists(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	err := s.WithTx(ctx, func(ctx context.Context, r repository.Repos) error {
		return r.Owners.Create(ctx, newOwner("o-commit"))
	})
	if err != nil {
		t.Fatalf("WithTx: %v", err)
	}

	if _, err := s.Repos().Owners.Get(ctx, "o-commit"); err != nil {
		t.Fatalf("owner not persisted after commit: %v", err)
	}
}

func TestWithTxErrorRollsBack(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	sentinel := errors.New("boom")
	err := s.WithTx(ctx, func(ctx context.Context, r repository.Repos) error {
		if cerr := r.Owners.Create(ctx, newOwner("o-rollback")); cerr != nil {
			t.Fatalf("create inside tx: %v", cerr)
		}
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("WithTx error = %v, want sentinel", err)
	}

	if _, err := s.Repos().Owners.Get(ctx, "o-rollback"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("owner persisted despite rollback: got err %v, want ErrNotFound", err)
	}
}

func TestWithTxPanicRollsBackAndRepanics(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	func() {
		defer func() {
			if p := recover(); p == nil {
				t.Fatal("panic did not propagate out of WithTx")
			}
		}()
		_ = s.WithTx(ctx, func(ctx context.Context, r repository.Repos) error {
			if cerr := r.Owners.Create(ctx, newOwner("o-panic")); cerr != nil {
				t.Fatalf("create inside tx: %v", cerr)
			}
			panic("kaboom")
		})
	}()

	if _, err := s.Repos().Owners.Get(ctx, "o-panic"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("owner persisted despite panic rollback: got err %v, want ErrNotFound", err)
	}
}

func TestWithTxNestedReturnsError(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	outerErr := s.WithTx(ctx, func(ctx context.Context, _ repository.Repos) error {
		return s.WithTx(ctx, func(context.Context, repository.Repos) error {
			t.Fatal("nested WithTx body must not run")
			return nil
		})
	})
	if !errors.Is(outerErr, ErrNestedTx) {
		t.Fatalf("nested WithTx error = %v, want ErrNestedTx", outerErr)
	}
}

func TestWithTxCancellationPropagates(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := s.WithTx(ctx, func(context.Context, repository.Repos) error {
		t.Fatal("body must not run on an already-canceled context")
		return nil
	})
	if err == nil {
		t.Fatal("WithTx on canceled context returned nil, want error")
	}
}
