package sqlite

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
)

// A pairing minted with an owner already set must store that owner rather than
// NULL: the manual-mint path is approved at creation and has no approval step
// to bind it later.
func TestPairingCreateWithOwnerStoresIt(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	mustCreateOwner(t, s, "o-1")

	p := newPairing("p-manual")
	p.OwnerID = "o-1"
	p.Status = domain.PairingStatusApproved
	approvedAt := testClock
	p.ApprovedAt = &approvedAt
	mustCreatePairing(t, s, p)

	got, err := s.Repos().DevicePairings.Get(ctx, "o-1", "p-manual")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.OwnerID != "o-1" {
		t.Errorf("owner = %q, want o-1", got.OwnerID)
	}
	if got.ApprovedAt == nil || !got.ApprovedAt.Equal(approvedAt) {
		t.Errorf("approved_at = %v, want %v", got.ApprovedAt, approvedAt)
	}
}

// Every method must surface a driver failure rather than reporting a benign
// zero value. A sweep that silently claims it deleted nothing, or a transition
// that silently reports success, would hide a storage fault on the enrollment
// path.
func TestPairingSurfacesDriverErrors(t *testing.T) {
	t.Parallel()
	repo := &pairingRepo{e: closedStore(t).db}
	ctx := context.Background()

	if err := repo.Create(ctx, newPairing("p-1")); err == nil {
		t.Error("Create on closed db = nil, want error")
	}
	if _, err := repo.GetByID(ctx, "p-1"); err == nil {
		t.Error("GetByID on closed db = nil, want error")
	}
	if _, err := repo.GetByUserCodeHash(ctx, []byte("user-p-1")); err == nil {
		t.Error("GetByUserCodeHash on closed db = nil, want error")
	}
	if _, err := repo.Get(ctx, "o-1", "p-1"); err == nil {
		t.Error("Get on closed db = nil, want error")
	}
	if _, err := repo.ListByOwner(ctx, "o-1"); err == nil {
		t.Error("ListByOwner on closed db = nil, want error")
	}
	if err := repo.Approve(ctx, "p-1", "o-1", testClock); err == nil {
		t.Error("Approve on closed db = nil, want error")
	}
	if err := repo.MarkRedeemed(ctx, "o-1", "p-1", "lin-1", testClock); err == nil {
		t.Error("MarkRedeemed on closed db = nil, want error")
	}
	if err := repo.Revoke(ctx, "o-1", "p-1", testClock); err == nil {
		t.Error("Revoke on closed db = nil, want error")
	}
	if err := repo.Touch(ctx, "p-1", testClock); err == nil {
		t.Error("Touch on closed db = nil, want error")
	}
	if _, err := repo.DeleteExpired(ctx, testClock, 10); err == nil {
		t.Error("DeleteExpired on closed db = nil, want error")
	}
}

// A RowsAffected failure must surface. For the conditional transitions this
// matters twice over: the row count is how the adapter decides between success
// and ErrConflict, so a swallowed failure would turn a storage fault into a
// wrong lifecycle answer.
func TestPairingSurfacesRowsAffectedErrors(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	mustCreateOwner(t, s, "o-1")
	mustApprove(t, s, "p-1", "o-1")

	boom := errors.New("rows affected failed")
	repo := &pairingRepo{e: countErrExecer{execer: s.db, err: boom}}

	if err := repo.Approve(ctx, "p-1", "o-1", testClock); !errors.Is(err, boom) {
		t.Errorf("Approve = %v, want %v", err, boom)
	}
	if err := repo.MarkRedeemed(ctx, "o-1", "p-1", "lin-1", testClock); !errors.Is(err, boom) {
		t.Errorf("MarkRedeemed = %v, want %v", err, boom)
	}
	if err := repo.Revoke(ctx, "o-1", "p-1", testClock); !errors.Is(err, boom) {
		t.Errorf("Revoke = %v, want %v", err, boom)
	}
	if err := repo.Touch(ctx, "p-1", testClock); !errors.Is(err, boom) {
		t.Errorf("Touch = %v, want %v", err, boom)
	}
	if _, err := repo.DeleteExpired(ctx, testClock, 10); !errors.Is(err, boom) {
		t.Errorf("DeleteExpired = %v, want %v", err, boom)
	}
}

// insertRawPairing writes a row bypassing the adapter so malformed stored
// values can be exercised.
func insertRawPairing(t *testing.T, s *Store, id, ownerID, scopes, nextPollAt, createdAt, expiresAt string) {
	t.Helper()
	const q = `INSERT INTO device_pairings
(id, owner_id, device_code_hash, user_code_hash, client_label, scopes, status,
 lineage_id, next_poll_at, created_at, expires_at, approved_at, redeemed_at, revoked_at)
VALUES (?, ?, ?, NULL, '', ?, 'pending', '', ?, ?, ?, NULL, NULL, NULL)`
	if _, err := s.db.ExecContext(context.Background(), q, id, ownerID, []byte("device-"+id),
		scopes, nextPollAt, createdAt, expiresAt); err != nil {
		t.Fatalf("raw insert %q: %v", id, err)
	}
}

// A row whose stored values are malformed must fail loudly rather than decode
// into zero values that downstream code would treat as real data — a zero
// ExpiresAt in particular would read as long expired, or as never expiring,
// depending on the comparison.
func TestPairingRejectsCorruptRows(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	mustCreateOwner(t, s, "o-1")

	good := encTime(testClock)
	cases := []struct {
		name                              string
		id                                string
		scopes, nextPoll, created, expiry string
	}{
		{"bad scopes", "p-scopes", "{not json", good, good, good},
		{"bad next_poll_at", "p-poll", "[]", "nope", good, good},
		{"bad created_at", "p-created", "[]", good, "nope", good},
		{"bad expires_at", "p-expires", "[]", good, good, "nope"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			insertRawPairing(t, s, tc.id, "o-1", tc.scopes, tc.nextPoll, tc.created, tc.expiry)
			if _, err := s.Repos().DevicePairings.GetByID(ctx, domain.PairingID(tc.id)); err == nil {
				t.Errorf("%s: GetByID = nil, want error", tc.name)
			}
		})
	}

	// The same failure must propagate through the iterating list path, not just
	// the single-row read.
	if _, err := s.Repos().DevicePairings.ListByOwner(ctx, "o-1"); err == nil {
		t.Error("ListByOwner over corrupt rows = nil, want error")
	}
}

// A corrupt lifecycle timestamp must also fail, and must do so on the nullable
// columns rather than silently decoding as absent.
func TestPairingRejectsCorruptNullableTimestamps(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	const q = `INSERT INTO device_pairings
(id, owner_id, device_code_hash, user_code_hash, client_label, scopes, status,
 lineage_id, next_poll_at, created_at, expires_at, approved_at, redeemed_at, revoked_at)
VALUES (?, NULL, ?, NULL, '', '[]', 'pending', '', ?, ?, ?, ?, ?, ?)`
	good := encTime(testClock)

	cases := []struct{ name, id, approved, redeemed, revoked string }{
		{"bad approved_at", "p-a", "nope", good, good},
		{"bad redeemed_at", "p-r", good, "nope", good},
		{"bad revoked_at", "p-v", good, good, "nope"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := s.db.ExecContext(ctx, q, tc.id, []byte("device"), good, good,
				encTime(testClock.Add(time.Minute)), tc.approved, tc.redeemed, tc.revoked); err != nil {
				t.Fatalf("raw insert: %v", err)
			}
			if _, err := s.Repos().DevicePairings.GetByID(ctx, domain.PairingID(tc.id)); err == nil {
				t.Errorf("%s: GetByID = nil, want error", tc.name)
			}
		})
	}
}
