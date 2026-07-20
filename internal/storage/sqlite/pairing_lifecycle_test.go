package sqlite

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/repository"
)

func TestPairingApproveBindsOwner(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	mustCreateOwner(t, s, "o-1")
	mustCreatePairing(t, s, newPairing("p-1"))

	approvedAt := testClock.Add(time.Minute)
	if err := s.Repos().DevicePairings.Approve(ctx, "p-1", "o-1", approvedAt); err != nil {
		t.Fatalf("Approve: %v", err)
	}

	got, err := s.Repos().DevicePairings.Get(ctx, "o-1", "p-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Status != domain.PairingStatusApproved {
		t.Errorf("status = %q, want approved", got.Status)
	}
	if got.OwnerID != "o-1" {
		t.Errorf("owner = %q, want o-1", got.OwnerID)
	}
	if got.ApprovedAt == nil || !got.ApprovedAt.Equal(approvedAt) {
		t.Errorf("approved_at = %v, want %v", got.ApprovedAt, approvedAt)
	}
}

// The condition on Approve is the owner binding. A second approval must be
// refused and must NOT rewrite owner_id, or an attacker who guessed a user code
// could re-point a pairing another owner had already approved and the enrolling
// device would hand its credentials to the wrong account.
func TestPairingSecondApprovalCannotRebindOwner(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	mustCreateOwner(t, s, "o-1")
	mustCreateOwner(t, s, "o-attacker")
	mustApprove(t, s, "p-1", "o-1")

	err := s.Repos().DevicePairings.Approve(ctx, "p-1", "o-attacker", testClock.Add(time.Minute))
	if !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("second approval = %v, want ErrConflict", err)
	}

	got, err := s.Repos().DevicePairings.GetByID(ctx, "p-1")
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.OwnerID != "o-1" {
		t.Errorf("owner rebound to %q, want o-1", got.OwnerID)
	}
}

func TestPairingApproveMissingIsNotFound(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	mustCreateOwner(t, s, "o-1")

	err := s.Repos().DevicePairings.Approve(context.Background(), "absent", "o-1", testClock)
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("approve missing = %v, want ErrNotFound", err)
	}
}

func TestPairingMarkRedeemed(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	mustCreateOwner(t, s, "o-1")
	mustApprove(t, s, "p-1", "o-1")

	redeemedAt := testClock.Add(2 * time.Minute)
	if err := s.Repos().DevicePairings.MarkRedeemed(ctx, "o-1", "p-1", "lin-1", redeemedAt); err != nil {
		t.Fatalf("MarkRedeemed: %v", err)
	}

	got, err := s.Repos().DevicePairings.Get(ctx, "o-1", "p-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Status != domain.PairingStatusRedeemed {
		t.Errorf("status = %q, want redeemed", got.Status)
	}
	if got.LineageID != "lin-1" {
		t.Errorf("lineage = %q, want lin-1", got.LineageID)
	}
	if got.RedeemedAt == nil || !got.RedeemedAt.Equal(redeemedAt) {
		t.Errorf("redeemed_at = %v, want %v", got.RedeemedAt, redeemedAt)
	}
}

// A device code is single-use: the second redemption must be refused and must
// not overwrite the lineage the first one installed.
func TestPairingSecondRedemptionConflicts(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	mustCreateOwner(t, s, "o-1")
	mustApprove(t, s, "p-1", "o-1")
	if err := s.Repos().DevicePairings.MarkRedeemed(ctx, "o-1", "p-1", "lin-1", testClock); err != nil {
		t.Fatalf("first redeem: %v", err)
	}

	err := s.Repos().DevicePairings.MarkRedeemed(ctx, "o-1", "p-1", "lin-2", testClock)
	if !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("second redeem = %v, want ErrConflict", err)
	}

	got, err := s.Repos().DevicePairings.Get(ctx, "o-1", "p-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.LineageID != "lin-1" {
		t.Errorf("lineage = %q, want lin-1 (second redemption must not overwrite)", got.LineageID)
	}
}

// A pending pairing has not been approved, so it cannot be redeemed.
func TestPairingRedeemRequiresApproval(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	mustCreateOwner(t, s, "o-1")
	mustCreatePairing(t, s, newPairing("p-1"))

	// A pending pairing has no owner, so this is ErrNotFound for that owner
	// rather than a conflict — the owner cannot reach a row it does not own.
	err := s.Repos().DevicePairings.MarkRedeemed(ctx, "o-1", "p-1", "lin-1", testClock)
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("redeem pending = %v, want ErrNotFound", err)
	}
}

// Redeeming another owner's approved pairing must report ErrNotFound — the same
// answer as a missing row, never ErrConflict, which would confirm the id exists.
func TestPairingMarkRedeemedIsOwnerScoped(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	mustCreateOwner(t, s, "o-1")
	mustCreateOwner(t, s, "o-2")
	mustApprove(t, s, "p-1", "o-1")

	err := s.Repos().DevicePairings.MarkRedeemed(ctx, "o-2", "p-1", "lin-x", testClock)
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("cross-owner redeem = %v, want ErrNotFound", err)
	}
	if errors.Is(err, domain.ErrConflict) {
		t.Error("cross-owner redeem leaked ErrConflict, confirming the id exists")
	}

	got, err := s.Repos().DevicePairings.Get(ctx, "o-1", "p-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Status != domain.PairingStatusApproved {
		t.Errorf("status = %q, want approved (untouched)", got.Status)
	}
}

func TestPairingRevoke(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	mustCreateOwner(t, s, "o-1")
	mustApprove(t, s, "p-1", "o-1")

	revokedAt := testClock.Add(3 * time.Minute)
	if err := s.Repos().DevicePairings.Revoke(ctx, "o-1", "p-1", revokedAt); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	got, err := s.Repos().DevicePairings.Get(ctx, "o-1", "p-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Status != domain.PairingStatusRevoked {
		t.Errorf("status = %q, want revoked", got.Status)
	}
	if got.RevokedAt == nil || !got.RevokedAt.Equal(revokedAt) {
		t.Errorf("revoked_at = %v, want %v", got.RevokedAt, revokedAt)
	}
}

// Revoke is conditional, unlike the refresh-credential revoke. Re-revoking a
// terminal pairing must conflict rather than silently overwrite the terminal
// state, which would erase the record of how the pairing actually ended.
func TestPairingRevokeTerminalConflicts(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	mustCreateOwner(t, s, "o-1")

	mustApprove(t, s, "p-redeemed", "o-1")
	if err := s.Repos().DevicePairings.MarkRedeemed(ctx, "o-1", "p-redeemed", "lin-1", testClock); err != nil {
		t.Fatalf("redeem: %v", err)
	}
	mustApprove(t, s, "p-revoked", "o-1")
	if err := s.Repos().DevicePairings.Revoke(ctx, "o-1", "p-revoked", testClock); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	for _, id := range []domain.PairingID{"p-redeemed", "p-revoked"} {
		if err := s.Repos().DevicePairings.Revoke(ctx, "o-1", id, testClock); !errors.Is(err, domain.ErrConflict) {
			t.Errorf("revoke terminal %q = %v, want ErrConflict", id, err)
		}
	}

	// The redeemed pairing must still read as redeemed, not revoked.
	got, err := s.Repos().DevicePairings.Get(ctx, "o-1", "p-redeemed")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Status != domain.PairingStatusRedeemed {
		t.Errorf("status = %q, want redeemed", got.Status)
	}
}

func TestPairingRevokeIsOwnerScoped(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	mustCreateOwner(t, s, "o-1")
	mustCreateOwner(t, s, "o-2")
	mustApprove(t, s, "p-1", "o-1")

	if err := s.Repos().DevicePairings.Revoke(ctx, "o-2", "p-1", testClock); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("cross-owner revoke = %v, want ErrNotFound", err)
	}
	got, err := s.Repos().DevicePairings.Get(ctx, "o-1", "p-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Status != domain.PairingStatusApproved {
		t.Errorf("status = %q, want approved (untouched)", got.Status)
	}
}

// Touch is unconditional by design: it must throttle a client polling a pairing
// in any state, including a terminal one.
func TestPairingTouch(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	mustCreatePairing(t, s, newPairing("p-1"))

	next := testClock.Add(5 * time.Second)
	if err := s.Repos().DevicePairings.Touch(ctx, "p-1", next); err != nil {
		t.Fatalf("Touch: %v", err)
	}
	got, err := s.Repos().DevicePairings.GetByID(ctx, "p-1")
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if !got.NextPollAt.Equal(next) {
		t.Errorf("next_poll_at = %v, want %v", got.NextPollAt, next)
	}

	if err := s.Repos().DevicePairings.Touch(ctx, "absent", next); !errors.Is(err, domain.ErrNotFound) {
		t.Errorf("touch missing = %v, want ErrNotFound", err)
	}
}

func TestPairingTouchWorksOnTerminalPairing(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	mustCreateOwner(t, s, "o-1")
	mustApprove(t, s, "p-1", "o-1")
	if err := s.Repos().DevicePairings.Revoke(ctx, "o-1", "p-1", testClock); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	if err := s.Repos().DevicePairings.Touch(ctx, "p-1", testClock.Add(time.Second)); err != nil {
		t.Errorf("touch revoked pairing = %v, want nil", err)
	}
}

func TestPairingDeleteExpired(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	for i, exp := range []time.Duration{-3 * time.Minute, -2 * time.Minute, -time.Minute, time.Minute} {
		p := newPairing(string(rune('a'+i)) + "-p")
		p.ExpiresAt = testClock.Add(exp)
		mustCreatePairing(t, s, p)
	}

	// The cutoff is inclusive ("at or before"), so the pairing expiring exactly
	// at the cutoff is swept.
	n, err := s.Repos().DevicePairings.DeleteExpired(ctx, testClock.Add(-2*time.Minute), 10)
	if err != nil {
		t.Fatalf("DeleteExpired: %v", err)
	}
	if n != 2 {
		t.Errorf("deleted = %d, want 2", n)
	}

	// The unexpired pairing must survive.
	if _, err := s.Repos().DevicePairings.GetByID(ctx, "d-p"); err != nil {
		t.Errorf("unexpired pairing swept: %v", err)
	}
}

func TestPairingDeleteExpiredRespectsLimit(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	for i := range 5 {
		p := newPairing(string(rune('a'+i)) + "-p")
		p.ExpiresAt = testClock.Add(-time.Hour)
		mustCreatePairing(t, s, p)
	}

	n, err := s.Repos().DevicePairings.DeleteExpired(ctx, testClock, 2)
	if err != nil {
		t.Fatalf("DeleteExpired: %v", err)
	}
	if n != 2 {
		t.Errorf("deleted = %d, want 2 (limit)", n)
	}
}

// A non-positive limit must not be read as "unbounded", which would turn a
// caller's zero value into a full-table delete.
func TestPairingDeleteExpiredRejectsNonPositiveLimit(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	p := newPairing("p-1")
	p.ExpiresAt = testClock.Add(-time.Hour)
	mustCreatePairing(t, s, p)

	for _, limit := range []int{0, -1} {
		if _, err := s.Repos().DevicePairings.DeleteExpired(ctx, testClock, limit); !errors.Is(err, domain.ErrInvalidInput) {
			t.Errorf("limit %d = %v, want ErrInvalidInput", limit, err)
		}
	}
	if _, err := s.Repos().DevicePairings.GetByID(ctx, "p-1"); err != nil {
		t.Errorf("rejected sweep still deleted rows: %v", err)
	}
}

// Empty scopes round-trip as a nil slice, per the package's list convention.
func TestPairingEmptyScopesRoundTripAsNil(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	p := newPairing("p-1")
	p.Scopes = nil
	mustCreatePairing(t, s, p)

	got, err := s.Repos().DevicePairings.GetByID(ctx, "p-1")
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.Scopes != nil {
		t.Errorf("scopes = %v, want nil", got.Scopes)
	}
}

func TestPairingTransactional(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	sentinel := errors.New("rollback")
	err := s.WithTx(ctx, func(ctx context.Context, r repository.Repos) error {
		if cerr := r.DevicePairings.Create(ctx, newPairing("p-1")); cerr != nil {
			return cerr
		}
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("WithTx = %v, want sentinel", err)
	}
	if _, err := s.Repos().DevicePairings.GetByID(ctx, "p-1"); !errors.Is(err, domain.ErrNotFound) {
		t.Errorf("pairing survived rollback: %v", err)
	}
}

// rawPairingUserCodeIsNull reports whether the stored user_code_hash is SQL
// NULL, which the tests use to pin the write-side representation directly
// rather than inferring it from a lookup that the read-side guard also affects.
func rawPairingUserCodeIsNull(t *testing.T, s *Store, id string) bool {
	t.Helper()
	var isNull bool
	const q = `SELECT user_code_hash IS NULL FROM device_pairings WHERE id = ?`
	if err := s.db.QueryRowContext(context.Background(), q, id).Scan(&isNull); err != nil {
		t.Fatalf("raw read %q: %v", id, err)
	}
	return isNull
}

// An absent user code must be stored as SQL NULL even when the caller passes a
// non-nil empty slice. Storing an empty blob instead would make every such row
// match a lookup for the empty digest, so the two spellings of "no code" must
// converge on one representation at the point of writing.
func TestPairingEmptyUserCodeHashIsStoredAsNull(t *testing.T) {
	t.Parallel()
	s := newStore(t)

	nilHash := newPairing("p-nil")
	nilHash.UserCodeHash = nil
	mustCreatePairing(t, s, nilHash)

	emptyHash := newPairing("p-empty")
	emptyHash.UserCodeHash = []byte{}
	mustCreatePairing(t, s, emptyHash)

	for _, id := range []string{"p-nil", "p-empty"} {
		if !rawPairingUserCodeIsNull(t, s, id) {
			t.Errorf("%s: user_code_hash stored as a value, want SQL NULL", id)
		}
	}
}

// The read-side guard must hold regardless of how an absent code is spelled in
// storage. This inserts a row whose user_code_hash is an empty BLOB rather than
// NULL — the representation a future change might introduce — and asserts a
// caller presenting no code still matches nothing. Without the guard, SQL would
// happily match empty against empty and hand back a pairing to a caller who
// supplied no user code at all.
func TestPairingEmptyLookupNeverMatchesEmptyBlobRow(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	const q = `INSERT INTO device_pairings
(id, owner_id, device_code_hash, user_code_hash, client_label, scopes, status,
 lineage_id, next_poll_at, created_at, expires_at, approved_at, redeemed_at, revoked_at)
VALUES (?, NULL, ?, ?, '', '[]', 'pending', '', ?, ?, ?, NULL, NULL, NULL)`
	if _, err := s.db.ExecContext(ctx, q, "p-emptyblob", []byte("device"), []byte{},
		encTime(testClock), encTime(testClock), encTime(testClock.Add(time.Minute))); err != nil {
		t.Fatalf("raw insert: %v", err)
	}

	// The fixture really does hold an empty blob, not NULL, so the guard is
	// what must refuse the lookup rather than SQL's NULL semantics.
	if rawPairingUserCodeIsNull(t, s, "p-emptyblob") {
		t.Fatal("fixture stored NULL, want an empty blob")
	}

	for _, hash := range [][]byte{nil, {}} {
		if _, err := s.Repos().DevicePairings.GetByUserCodeHash(ctx, hash); !errors.Is(err, domain.ErrNotFound) {
			t.Errorf("lookup with %v hash matched an empty-blob row: %v", hash, err)
		}
	}
}

// The status CHECK constraint is defense in depth: the adapter never writes an
// out-of-range status, so this asserts the database itself refuses one. That is
// the claim the migration makes — the value set holds regardless of what any
// adapter does — and it is only true if the constraint is actually present.
func TestPairingStatusCheckConstraintRejectsUnknownStatus(t *testing.T) {
	t.Parallel()
	s := newStore(t)

	const q = `INSERT INTO device_pairings
(id, owner_id, device_code_hash, user_code_hash, client_label, scopes, status,
 lineage_id, next_poll_at, created_at, expires_at, approved_at, redeemed_at, revoked_at)
VALUES (?, NULL, ?, NULL, '', '[]', ?, '', ?, ?, ?, NULL, NULL, NULL)`
	_, err := s.db.ExecContext(context.Background(), q, "p-bogus", []byte("device"), "not-a-status",
		encTime(testClock), encTime(testClock), encTime(testClock.Add(time.Minute)))
	if err == nil {
		t.Fatal("database accepted an out-of-range status, want a CHECK violation")
	}
}
