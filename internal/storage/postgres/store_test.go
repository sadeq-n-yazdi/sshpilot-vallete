package postgres

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/migrate"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/repository"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/schema"
)

// dsnEnv names the environment variable holding the DSN of a PostgreSQL
// instance the tests may create and drop schemas in. It matches the variable
// the CI workflow already exports for its postgres matrix leg. When it is
// unset every test in this package skips, so `go test ./...` stays green on a
// machine without a database.
const dsnEnv = "VALLET_TEST_POSTGRES_DSN"

// testClock is a fixed reference time used to build deterministic entities.
var testClock = time.Date(2026, 7, 19, 10, 0, 0, 0, time.UTC)

// requireDSN returns the test DSN, skipping the test when it is not configured.
func requireDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv(dsnEnv)
	if dsn == "" {
		t.Skipf("%s is not set; skipping PostgreSQL integration test", dsnEnv)
	}
	return dsn
}

// randomSchemaName returns a fresh, collision-resistant PostgreSQL schema
// identifier. It is built only from a fixed prefix and hex digits, so it is
// safe to interpolate into the DDL below, which cannot take a bind parameter
// for an identifier.
func randomSchemaName(t *testing.T) string {
	t.Helper()
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatalf("generate schema name: %v", err)
	}
	return "vallet_test_" + hex.EncodeToString(b[:])
}

// openTestDB opens a handle whose connections all resolve unqualified table
// names inside schemaName. search_path is carried in the DSN as a connection
// runtime parameter rather than issued as a SET after connecting: the pool may
// open a new connection at any time, and a SET would apply to only one of them,
// leaving later queries pointed at the wrong schema.
func openTestDB(t *testing.T, dsn, schemaName string) *sql.DB {
	t.Helper()

	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatalf("parse %s: %v", dsnEnv, err)
	}
	q := u.Query()
	q.Set("search_path", schemaName)
	u.RawQuery = q.Encode()

	db, err := Open(Options{DSN: u.String()})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// newStore creates a private PostgreSQL schema, applies the full domain schema
// into it through the migrate runner, and returns the Store wrapping a handle
// scoped to it. Each test gets its own namespace, so tests remain independent
// and can run in parallel against one shared server; the schema is dropped on
// cleanup.
func newStore(t *testing.T) *Store {
	t.Helper()

	dsn := requireDSN(t)
	schemaName := randomSchemaName(t)

	// The admin handle runs the CREATE/DROP SCHEMA statements; it deliberately
	// does not carry search_path, since the schema does not exist yet.
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

// TestReposPopulatesImplementedRepositories pins the slice boundary: this
// adapter implements the owner, handle, device and public key repositories, and the
// remaining fields are expected to stay nil until later slices fill them.
func TestReposPopulatesImplementedRepositories(t *testing.T) {
	t.Parallel()
	r := reposFor((*sql.DB)(nil))
	if r.Owners == nil || r.Handles == nil || r.Devices == nil || r.PublicKeys == nil {
		t.Fatalf("Repos left an implemented repository nil: %+v", r)
	}
	if r.KeySets != nil {
		t.Errorf("Repos populated a repository this slice does not implement: %+v", r)
	}
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
		t.Fatalf("Get after commit: %v", err)
	}
}

func TestWithTxRollbackDiscards(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	boom := errors.New("boom")

	err := s.WithTx(ctx, func(ctx context.Context, r repository.Repos) error {
		if cerr := r.Owners.Create(ctx, newOwner("o-rollback")); cerr != nil {
			return cerr
		}
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatalf("WithTx error = %v, want boom", err)
	}
	if _, err := s.Repos().Owners.Get(ctx, "o-rollback"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("Get after rollback = %v, want ErrNotFound", err)
	}
}

// TestWithTxRollsBackOnPanic checks that a panic inside the transaction rolls
// back and then continues unwinding rather than being swallowed.
func TestWithTxRollsBackOnPanic(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	func() {
		defer func() {
			if p := recover(); p == nil {
				t.Error("panic did not propagate out of WithTx")
			}
		}()
		_ = s.WithTx(ctx, func(ctx context.Context, r repository.Repos) error {
			if cerr := r.Owners.Create(ctx, newOwner("o-panic")); cerr != nil {
				t.Errorf("Create inside tx: %v", cerr)
			}
			panic("boom")
		})
	}()

	if _, err := s.Repos().Owners.Get(ctx, "o-panic"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("Get after panic rollback = %v, want ErrNotFound", err)
	}
}

func TestWithTxNestedRefused(t *testing.T) {
	t.Parallel()
	s := newStore(t)

	err := s.WithTx(context.Background(), func(ctx context.Context, _ repository.Repos) error {
		return s.WithTx(ctx, func(context.Context, repository.Repos) error {
			t.Error("nested WithTx body unexpectedly ran")
			return nil
		})
	})
	if !errors.Is(err, ErrNestedTx) {
		t.Fatalf("nested WithTx error = %v, want ErrNestedTx", err)
	}
}
