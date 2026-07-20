package postgres

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
)

// TestOpenRejectsEmptyDSN checks the eager guard: an empty DSN is a
// configuration error and must not produce a handle that fails later at an
// unrelated call site.
func TestOpenRejectsEmptyDSN(t *testing.T) {
	t.Parallel()
	if _, err := Open(Options{}); err == nil {
		t.Fatal("Open with empty DSN returned no error")
	}
}

// TestOpenDoesNotLeakDSN checks that a malformed DSN — which may embed a
// password — is reported without echoing the connection string back.
func TestOpenDoesNotLeakDSN(t *testing.T) {
	t.Parallel()
	const dsn = "postgres://user:hunter2@:::/nope?bad=%zz"
	_, err := Open(Options{DSN: dsn})
	if err == nil {
		t.Skip("driver accepted the malformed DSN; nothing to assert")
	}
	if strings.Contains(err.Error(), "hunter2") {
		t.Errorf("Open error leaked the DSN password: %q", err)
	}
}

// TestWithLocalTxRejectsUnsupportedExecer covers the nil/typed-nil guard: a
// nil execer must produce an error rather than a panic.
func TestWithLocalTxRejectsUnsupportedExecer(t *testing.T) {
	t.Parallel()

	err := withLocalTx(context.Background(), (*sql.DB)(nil), func(execer) error {
		t.Error("fn unexpectedly ran on a nil execer")
		return nil
	})
	if err == nil {
		t.Fatal("withLocalTx with a typed-nil *sql.DB returned no error")
	}

	err = withLocalTx(context.Background(), (*sql.Tx)(nil), func(execer) error {
		t.Error("fn unexpectedly ran on a nil execer")
		return nil
	})
	if err == nil {
		t.Fatal("withLocalTx with a typed-nil *sql.Tx returned no error")
	}
}

// TestWithLocalTxCommitsAndRollsBack exercises both outcomes of the private
// transaction path taken when the execer is a *sql.DB.
func TestWithLocalTxCommitsAndRollsBack(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	if err := withLocalTx(ctx, s.db, func(ex execer) error {
		return (&ownerRepo{e: ex}).Create(ctx, newOwner("o-local-commit"))
	}); err != nil {
		t.Fatalf("withLocalTx commit: %v", err)
	}
	if _, err := s.Repos().Owners.Get(ctx, "o-local-commit"); err != nil {
		t.Fatalf("Get after local commit: %v", err)
	}

	boom := errors.New("boom")
	err := withLocalTx(ctx, s.db, func(ex execer) error {
		if cerr := (&ownerRepo{e: ex}).Create(ctx, newOwner("o-local-rollback")); cerr != nil {
			return cerr
		}
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatalf("withLocalTx error = %v, want boom", err)
	}
	if _, err := s.Repos().Owners.Get(ctx, "o-local-rollback"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("Get after local rollback = %v, want ErrNotFound", err)
	}
}

// TestWithLocalTxRunsInlineInsideCallerTx checks the composition rule: when the
// execer is already a *sql.Tx, withLocalTx must run inline and leave commit or
// rollback to the caller that owns the transaction. Here the caller rolls back,
// so the inner write must vanish with it.
func TestWithLocalTxRunsInlineInsideCallerTx(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("BeginTx: %v", err)
	}
	if err := withLocalTx(ctx, tx, func(ex execer) error {
		return (&ownerRepo{e: ex}).Create(ctx, newOwner("o-inline"))
	}); err != nil {
		t.Fatalf("withLocalTx inline: %v", err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatalf("Rollback: %v", err)
	}

	if _, err := s.Repos().Owners.Get(ctx, "o-inline"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("inner write survived the caller's rollback: %v", err)
	}
}
