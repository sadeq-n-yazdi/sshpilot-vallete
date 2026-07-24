package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
)

func TestMapErrorNil(t *testing.T) {
	t.Parallel()
	if err := mapError(nil); err != nil {
		t.Errorf("mapError(nil) = %v, want nil", err)
	}
}

func TestMapErrorNoRows(t *testing.T) {
	t.Parallel()
	if err := mapError(sql.ErrNoRows); !errors.Is(err, domain.ErrNotFound) {
		t.Errorf("mapError(sql.ErrNoRows) = %v, want domain.ErrNotFound", err)
	}
}

func TestMapErrorUniqueViolation(t *testing.T) {
	t.Parallel()
	db := openMemory(t)
	ctx := context.Background()

	if _, err := db.ExecContext(ctx,
		"CREATE TABLE u (v TEXT NOT NULL, CONSTRAINT uq UNIQUE (v))"); err != nil {
		t.Fatalf("create table: %v", err)
	}
	if _, err := db.ExecContext(ctx, "INSERT INTO u (v) VALUES ('a')"); err != nil {
		t.Fatalf("first insert: %v", err)
	}
	_, dupErr := db.ExecContext(ctx, "INSERT INTO u (v) VALUES ('a')")
	if dupErr == nil {
		t.Fatal("duplicate insert unexpectedly succeeded")
	}

	if !isUniqueViolation(dupErr) {
		t.Errorf("isUniqueViolation(%v) = false, want true", dupErr)
	}
	if got := mapError(dupErr); !errors.Is(got, domain.ErrConflict) {
		t.Errorf("mapError(unique) = %v, want domain.ErrConflict", got)
	}
}

func TestMapErrorPrimaryKeyViolation(t *testing.T) {
	t.Parallel()
	db := openMemory(t)
	ctx := context.Background()

	if _, err := db.ExecContext(ctx,
		"CREATE TABLE pk (id INTEGER PRIMARY KEY)"); err != nil {
		t.Fatalf("create table: %v", err)
	}
	if _, err := db.ExecContext(ctx, "INSERT INTO pk (id) VALUES (1)"); err != nil {
		t.Fatalf("first insert: %v", err)
	}
	_, dupErr := db.ExecContext(ctx, "INSERT INTO pk (id) VALUES (1)")
	if dupErr == nil {
		t.Fatal("duplicate primary key insert unexpectedly succeeded")
	}
	if got := mapError(dupErr); !errors.Is(got, domain.ErrConflict) {
		t.Errorf("mapError(primary key) = %v, want domain.ErrConflict", got)
	}
}

func TestMapErrorOtherIsWrapped(t *testing.T) {
	t.Parallel()
	sentinel := errors.New("underlying failure")
	got := mapError(sentinel)

	if errors.Is(got, domain.ErrNotFound) || errors.Is(got, domain.ErrConflict) {
		t.Errorf("mapError misclassified a generic error: %v", got)
	}
	if !errors.Is(got, sentinel) {
		t.Errorf("mapError did not wrap the underlying error with %%w: %v", got)
	}
	if got.Error() == sentinel.Error() {
		t.Errorf("mapError did not add the static prefix: %q", got.Error())
	}
}

// TestMapErrorNotNullNotConflict guards the primary-code (19) fallback in
// isUniqueViolation: a NOT NULL violation is a real *sqlite.Error constraint
// failure that is NOT a uniqueness conflict, so it must be wrapped rather than
// mapped to domain.ErrConflict. If this fails, the driver surfaces only the
// primary constraint code and the fallback is too broad.
func TestMapErrorNotNullNotConflict(t *testing.T) {
	t.Parallel()
	db := openMemory(t)
	ctx := context.Background()

	if _, err := db.ExecContext(ctx,
		"CREATE TABLE nn (id INTEGER PRIMARY KEY, v TEXT NOT NULL)"); err != nil {
		t.Fatalf("create table: %v", err)
	}
	_, nnErr := db.ExecContext(ctx, "INSERT INTO nn (id, v) VALUES (1, NULL)")
	if nnErr == nil {
		t.Fatal("NOT NULL violation insert unexpectedly succeeded")
	}

	if isUniqueViolation(nnErr) {
		t.Errorf("isUniqueViolation(NOT NULL error) = true, want false")
	}
	if got := mapError(nnErr); errors.Is(got, domain.ErrConflict) {
		t.Errorf("mapError(NOT NULL) = ErrConflict, want wrapped: %v", got)
	}
}

func TestIsUniqueViolationNonDriverError(t *testing.T) {
	t.Parallel()
	if isUniqueViolation(errors.New("plain")) {
		t.Error("isUniqueViolation(plain error) = true, want false")
	}
	if isUniqueViolation(nil) {
		t.Error("isUniqueViolation(nil) = true, want false")
	}
}
