package postgres

import (
	"context"
	"database/sql"
	"errors"
	"strings"
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

func TestIsUniqueViolationNonDriverError(t *testing.T) {
	t.Parallel()
	if isUniqueViolation(errors.New("plain")) {
		t.Error("isUniqueViolation(plain error) = true, want false")
	}
	if isUniqueViolation(nil) {
		t.Error("isUniqueViolation(nil) = true, want false")
	}
	if isForeignKeyViolation(errors.New("plain")) {
		t.Error("isForeignKeyViolation(plain error) = true, want false")
	}
}

// TestMapErrorUniqueViolation drives a real 23505 out of the server rather
// than constructing a PgError by hand, so the SQLSTATE the driver actually
// reports is the one the mapping is pinned to.
func TestMapErrorUniqueViolation(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	mustRegisterHandle(t, s, newHandle("h-a", "owner-a", "taken"))
	mustCreateOwner(t, s, "owner-b")
	dupErr := s.Repos().Handles.Register(ctx, newHandle("h-b", "owner-b", "taken"))

	if !errors.Is(dupErr, domain.ErrConflict) {
		t.Fatalf("unique violation mapped to %v, want domain.ErrConflict", dupErr)
	}
}

// TestMapErrorPrimaryKeyViolation checks that a primary-key clash also lands on
// ErrConflict. Postgres reports it under the same 23505 the unique index uses,
// unlike SQLite which has a distinct extended code for it.
func TestMapErrorPrimaryKeyViolation(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	mustCreateOwner(t, s, "pk-owner")
	err := s.Repos().Owners.Create(ctx, newOwner("pk-owner"))
	if !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("primary key violation mapped to %v, want domain.ErrConflict", err)
	}
}

// TestMapErrorForeignKeyNotConflict pins the deliberate parity choice: a
// foreign-key violation (23503) — here, a handle referencing an owner that does
// not exist — must NOT be reported as a conflict. It falls through to the
// generic wrap, exactly as the SQLite adapter does, because the port contracts
// promise ErrConflict only for a uniqueness clash.
func TestMapErrorForeignKeyNotConflict(t *testing.T) {
	t.Parallel()
	s := newStore(t)

	err := s.Repos().Handles.Register(context.Background(), newHandle("h-orphan", "no-such-owner", "orphan"))
	if err == nil {
		t.Fatal("registering a handle for a missing owner unexpectedly succeeded")
	}
	if !isForeignKeyViolation(err) {
		t.Fatalf("expected a foreign-key violation, got %v", err)
	}
	if errors.Is(err, domain.ErrConflict) {
		t.Errorf("foreign-key violation mapped to ErrConflict, want a generic wrap: %v", err)
	}
	if errors.Is(err, domain.ErrNotFound) {
		t.Errorf("foreign-key violation mapped to ErrNotFound, want a generic wrap: %v", err)
	}
	if !strings.HasPrefix(err.Error(), errPrefix+":") {
		t.Errorf("wrapped error %q does not carry the static %q prefix", err, errPrefix)
	}
}

// TestMapErrorCheckViolationNotConflict guards the breadth of the mapping: a
// CHECK failure (23514) is a real constraint violation that is not a uniqueness
// conflict, so it must be wrapped rather than mapped to ErrConflict. If this
// fails, the SQLSTATE match has been widened too far.
func TestMapErrorCheckViolationNotConflict(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	// owners.status carries a CHECK restricting it to the OwnerStatus set.
	bad := newOwner("o-check")
	bad.Status = domain.OwnerStatus("not-a-status")
	err := s.Repos().Owners.Create(ctx, bad)
	if err == nil {
		t.Fatal("CHECK violation insert unexpectedly succeeded")
	}
	if isUniqueViolation(err) {
		t.Error("isUniqueViolation(CHECK error) = true, want false")
	}
	if errors.Is(err, domain.ErrConflict) {
		t.Errorf("mapError(CHECK) = ErrConflict, want wrapped: %v", err)
	}
}

// TestWrappedErrorDoesNotLeakBoundValues is the disclosure guard on the generic
// wrap: the driver message may name constraints and relations, but a value the
// caller bound must never appear in the error text a layer above the adapter
// sees.
func TestWrappedErrorDoesNotLeakBoundValues(t *testing.T) {
	t.Parallel()
	s := newStore(t)

	const secret = "sup3rs3cret-handle-name"
	err := s.Repos().Handles.Register(context.Background(), newHandle("h-leak", "no-such-owner", secret))
	if err == nil {
		t.Fatal("expected the insert to fail")
	}
	if strings.Contains(err.Error(), secret) {
		t.Errorf("error text leaked a bound value: %q", err)
	}
}
