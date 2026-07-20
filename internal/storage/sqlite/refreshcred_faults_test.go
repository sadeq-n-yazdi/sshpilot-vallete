package sqlite

import (
	"context"
	"errors"
	"testing"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
)

// TestRefreshCredSurfacesDriverErrors drives every method against a closed
// database so each statement fails at the driver. The point is that a storage
// fault is reported, never swallowed into a nil error or an empty result: a
// silently-empty ListByOwner would read as "this owner holds no credentials",
// and a silently-successful MarkRotated would report a token spent when it was
// not.
func TestRefreshCredSurfacesDriverErrors(t *testing.T) {
	t.Parallel()
	repo := &refreshCredRepo{e: closedStore(t).db}
	ctx := context.Background()

	t.Run("Create", func(t *testing.T) {
		if err := repo.Create(ctx, newCred("rc-1", "owner-a", "lin-1")); err == nil {
			t.Error("Create on a closed db = nil error, want error")
		}
	})
	t.Run("GetByID", func(t *testing.T) {
		if _, err := repo.GetByID(ctx, "rc-1"); err == nil {
			t.Error("GetByID on a closed db = nil error, want error")
		}
	})
	t.Run("Get", func(t *testing.T) {
		if _, err := repo.Get(ctx, "owner-a", "rc-1"); err == nil {
			t.Error("Get on a closed db = nil error, want error")
		}
	})
	t.Run("ListByOwner", func(t *testing.T) {
		if _, err := repo.ListByOwner(ctx, "owner-a"); err == nil {
			t.Error("ListByOwner on a closed db = nil error, want error")
		}
	})
	t.Run("ListByLineage", func(t *testing.T) {
		if _, err := repo.ListByLineage(ctx, "owner-a", "lin-1"); err == nil {
			t.Error("ListByLineage on a closed db = nil error, want error")
		}
	})
	t.Run("MarkRotated", func(t *testing.T) {
		if err := repo.MarkRotated(ctx, "owner-a", "rc-1", testClock); err == nil {
			t.Error("MarkRotated on a closed db = nil error, want error")
		}
	})
	t.Run("Revoke", func(t *testing.T) {
		if err := repo.Revoke(ctx, "owner-a", "rc-1", testClock); err == nil {
			t.Error("Revoke on a closed db = nil error, want error")
		}
	})
	t.Run("RevokeLineage", func(t *testing.T) {
		if _, err := repo.RevokeLineage(ctx, "owner-a", "lin-1", testClock); err == nil {
			t.Error("RevokeLineage on a closed db = nil error, want error")
		}
	})
	t.Run("DeleteExpired", func(t *testing.T) {
		if _, err := repo.DeleteExpired(ctx, testClock, 10); err == nil {
			t.Error("DeleteExpired on a closed db = nil error, want error")
		}
	})
}

// TestRefreshCredSurfacesRowsAffectedErrors covers the RowsAffected failure
// branches, which the real driver never takes. Each must surface the fault
// rather than report zero — a MarkRotated that mistook a count failure for
// "zero rows" would tell the caller a live credential had already been spent.
func TestRefreshCredSurfacesRowsAffectedErrors(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	mustCreateCred(t, s, newCred("rc-1", "owner-a", "lin-1"))

	boom := errors.New("rows affected failed")
	repo := &refreshCredRepo{e: countErrExecer{execer: s.db, err: boom}}

	if err := repo.MarkRotated(ctx, "owner-a", "rc-1", testClock); !errors.Is(err, boom) {
		t.Errorf("MarkRotated = %v, want the RowsAffected failure", err)
	}
	if err := repo.Revoke(ctx, "owner-a", "rc-1", testClock); !errors.Is(err, boom) {
		t.Errorf("Revoke = %v, want the RowsAffected failure", err)
	}
	if _, err := repo.RevokeLineage(ctx, "owner-a", "lin-1", testClock); !errors.Is(err, boom) {
		t.Errorf("RevokeLineage = %v, want the RowsAffected failure", err)
	}
	if _, err := repo.DeleteExpired(ctx, testClock, 10); !errors.Is(err, boom) {
		t.Errorf("DeleteExpired = %v, want the RowsAffected failure", err)
	}
}

// insertRawCred writes a credential row with raw column values, bypassing the
// repository so a row that Create could never produce can be planted.
func insertRawCred(t *testing.T, s *Store, id, scopes, issuedAt, expiresAt string, revokedAt any) {
	t.Helper()
	const q = `INSERT INTO refresh_credentials (id, owner_id, lineage_id, secret_hash, scopes,
client_label, rotated_from_id, issued_at, expires_at, status, revoked_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	if _, err := s.db.ExecContext(context.Background(), q,
		id, "owner-a", "lin-1", []byte("d"), scopes, "l", nil,
		issuedAt, expiresAt, string(domain.CredentialStatusActive), revokedAt,
	); err != nil {
		t.Fatalf("insert raw credential %q: %v", id, err)
	}
}

// TestRefreshCredRejectsCorruptRows pins that a row which cannot be decoded is
// an error, not a partially-populated credential. A credential silently
// returned with a zero ExpiresAt would read as long expired, and one returned
// with dropped scopes would read as carrying no authority — both fail closed,
// but both would also be lies about what is stored, so the read is refused.
func TestRefreshCredRejectsCorruptRows(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	mustCreateOwner(t, s, "owner-a")

	good := encTime(testClock)
	// Each row corrupts exactly one decoded column so every decode branch in
	// scanRefreshCred is reached.
	insertRawCred(t, s, "rc-bad-scopes", "not json", good, good, nil)
	insertRawCred(t, s, "rc-bad-issued", "[]", "not-a-timestamp", good, nil)
	insertRawCred(t, s, "rc-bad-expires", "[]", good, "not-a-timestamp", nil)
	insertRawCred(t, s, "rc-bad-revoked", "[]", good, good, "not-a-timestamp")

	for _, id := range []domain.RefreshCredentialID{
		"rc-bad-scopes", "rc-bad-issued", "rc-bad-expires", "rc-bad-revoked",
	} {
		if _, err := s.Repos().RefreshCredentials.Get(ctx, "owner-a", id); err == nil {
			t.Errorf("Get(%q) on a corrupt row = nil error, want a decode failure", id)
		}
	}

	// The same failure must propagate through the row-iterating path.
	if _, err := s.Repos().RefreshCredentials.ListByOwner(ctx, "owner-a"); err == nil {
		t.Error("ListByOwner over corrupt rows = nil error, want a decode failure")
	}
}
