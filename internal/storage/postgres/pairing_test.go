package postgres

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/repository"
)

// newPairing returns a fully populated pending pairing with distinct digests
// derived from id, so a lookup that matches the wrong row is visible.
func newPairing(id string) *domain.DevicePairing {
	return &domain.DevicePairing{
		ID:             domain.PairingID(id),
		DeviceCodeHash: []byte("device-" + id),
		UserCodeHash:   []byte("user-" + id),
		ClientLabel:    "laptop",
		Scopes:         []domain.Scope{{Kind: domain.ScopeReadOnly}},
		Status:         domain.PairingStatusPending,
		NextPollAt:     testClock,
		CreatedAt:      testClock,
		ExpiresAt:      testClock.Add(10 * time.Minute),
	}
}

// mustCreatePairing creates a pairing through the auto-commit repos.
func mustCreatePairing(t *testing.T, s *Store, p *domain.DevicePairing) *domain.DevicePairing {
	t.Helper()
	if err := s.Repos().DevicePairings.Create(context.Background(), p); err != nil {
		t.Fatalf("create pairing %q: %v", p.ID, err)
	}
	return p
}

// mustApprove creates a pending pairing and approves it for ownerID.
func mustApprove(t *testing.T, s *Store, id, ownerID string) *domain.DevicePairing {
	t.Helper()
	p := mustCreatePairing(t, s, newPairing(id))
	if err := s.Repos().DevicePairings.Approve(context.Background(), p.ID, domain.OwnerID(ownerID), testClock); err != nil {
		t.Fatalf("approve %q: %v", id, err)
	}
	return p
}

// rawPairingUserCodeIsNull reports whether the stored user_code_hash is SQL
// NULL, bypassing the adapter so the storage representation itself is asserted.
func rawPairingUserCodeIsNull(t *testing.T, s *Store, id string) bool {
	t.Helper()
	var isNull bool
	if err := s.db.QueryRowContext(context.Background(),
		`SELECT user_code_hash IS NULL FROM device_pairings WHERE id = $1`, id).Scan(&isNull); err != nil {
		t.Fatalf("probe user_code_hash of %q: %v", id, err)
	}
	return isNull
}

func TestPairingCreateAndGetByIDRoundTrips(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	want := mustCreatePairing(t, s, newPairing("p-1"))

	got, err := s.Repos().DevicePairings.GetByID(ctx, "p-1")
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.Status != domain.PairingStatusPending {
		t.Errorf("status = %q, want pending", got.Status)
	}
	// A pending pairing has no owner yet; it must not decode as some other value.
	if got.OwnerID != "" {
		t.Errorf("OwnerID = %q, want empty", got.OwnerID)
	}
	// The digests must survive the BYTEA round trip byte for byte: they are what
	// the constant-time comparison in internal/auth is performed against.
	if !bytes.Equal(got.DeviceCodeHash, want.DeviceCodeHash) {
		t.Errorf("DeviceCodeHash = %x, want %x", got.DeviceCodeHash, want.DeviceCodeHash)
	}
	if !bytes.Equal(got.UserCodeHash, want.UserCodeHash) {
		t.Errorf("UserCodeHash = %x, want %x", got.UserCodeHash, want.UserCodeHash)
	}
	if got.ClientLabel != "laptop" || got.LineageID != "" {
		t.Errorf("label/lineage = %q/%q, want laptop and empty", got.ClientLabel, got.LineageID)
	}
	if len(got.Scopes) != 1 || got.Scopes[0].Kind != domain.ScopeReadOnly {
		t.Errorf("Scopes = %+v, want one read-only scope", got.Scopes)
	}
	if got.ApprovedAt != nil || got.RedeemedAt != nil || got.RevokedAt != nil {
		t.Errorf("terminal timestamps = %v/%v/%v, want all nil", got.ApprovedAt, got.RedeemedAt, got.RevokedAt)
	}
}

// expires_at decides when a device code stops being redeemable, so it must come
// back as the same instant in UTC whatever zone it was handed in.
func TestPairingTimestampsRoundTripFromNonUTCZone(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	zone := time.FixedZone("UTC+3", 3*60*60)
	wantExpiry := testClock.Add(10 * time.Minute)
	p := newPairing("p-tz")
	p.CreatedAt = testClock.In(zone)
	p.NextPollAt = testClock.In(zone)
	p.ExpiresAt = wantExpiry.In(zone)
	mustCreatePairing(t, s, p)

	got, err := s.Repos().DevicePairings.GetByID(ctx, "p-tz")
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if !got.ExpiresAt.Equal(wantExpiry) || !got.CreatedAt.Equal(testClock) || !got.NextPollAt.Equal(testClock) {
		t.Errorf("timestamps = %v/%v/%v, want %v/%v/%v",
			got.CreatedAt, got.NextPollAt, got.ExpiresAt, testClock, testClock, wantExpiry)
	}
	if got.ExpiresAt.Location() != time.UTC {
		t.Errorf("ExpiresAt location = %v, want UTC", got.ExpiresAt.Location())
	}
}

func TestPairingCreateRejectsNil(t *testing.T) {
	t.Parallel()
	s := newStore(t)

	if err := s.Repos().DevicePairings.Create(context.Background(), nil); !errors.Is(err, domain.ErrInvalidInput) {
		t.Fatalf("Create(nil) = %v, want ErrInvalidInput", err)
	}
}

// A duplicate primary key is SQLSTATE 23505, which mapError turns into the same
// domain.ErrConflict the SQLite adapter reports.
func TestPairingCreateDuplicateIDConflicts(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	mustCreatePairing(t, s, newPairing("p-1"))

	if err := s.Repos().DevicePairings.Create(context.Background(), newPairing("p-1")); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("duplicate id = %v, want ErrConflict", err)
	}
}

func TestPairingGetByIDMissing(t *testing.T) {
	t.Parallel()
	s := newStore(t)

	if _, err := s.Repos().DevicePairings.GetByID(context.Background(), "p-absent"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("GetByID(absent) = %v, want ErrNotFound", err)
	}
}

func TestPairingGetByUserCodeHash(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	mustCreatePairing(t, s, newPairing("p-1"))
	mustCreatePairing(t, s, newPairing("p-2"))

	got, err := s.Repos().DevicePairings.GetByUserCodeHash(ctx, []byte("user-p-2"))
	if err != nil {
		t.Fatalf("GetByUserCodeHash: %v", err)
	}
	if got.ID != "p-2" {
		t.Errorf("id = %q, want p-2", got.ID)
	}
	if _, err := s.Repos().DevicePairings.GetByUserCodeHash(ctx, []byte("user-absent")); !errors.Is(err, domain.ErrNotFound) {
		t.Errorf("unknown hash = %v, want ErrNotFound", err)
	}
}

// A manually minted pairing has a NULL user_code_hash. A caller presenting no
// code at all must not reach it: that would be an unauthenticated route into a
// pairing that was never meant to be reachable by user code.
func TestPairingEmptyUserCodeHashNeverMatchesNullRow(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	manual := newPairing("p-manual")
	manual.UserCodeHash = nil
	mustCreatePairing(t, s, manual)

	stored, err := s.Repos().DevicePairings.GetByID(ctx, "p-manual")
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if stored.UserCodeHash != nil {
		t.Fatalf("fixture user code hash = %q, want nil", stored.UserCodeHash)
	}

	for _, hash := range [][]byte{nil, {}} {
		if _, err := s.Repos().DevicePairings.GetByUserCodeHash(ctx, hash); !errors.Is(err, domain.ErrNotFound) {
			t.Errorf("lookup with %v hash = %v, want ErrNotFound", hash, err)
		}
	}
}

// Both spellings of "no user code" must converge on SQL NULL at write time:
// storing an empty BYTEA would make every such row match a lookup for the empty
// digest.
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
// storage. This inserts a row whose user_code_hash is an empty BYTEA rather
// than NULL — the representation a future change might introduce — and asserts
// a caller presenting no code still matches nothing. Without the guard, SQL
// would happily match empty against empty.
func TestPairingEmptyLookupNeverMatchesEmptyBlobRow(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	const q = `INSERT INTO device_pairings
(id, owner_id, device_code_hash, user_code_hash, client_label, scopes, status,
 lineage_id, next_poll_at, created_at, expires_at, approved_at, redeemed_at, revoked_at)
VALUES ($1, NULL, $2, $3, '', '[]', 'pending', '', $4, $5, $6, NULL, NULL, NULL)`
	if _, err := s.db.ExecContext(ctx, q, "p-emptyblob", []byte("device"), []byte{},
		encTime(testClock), encTime(testClock), encTime(testClock.Add(time.Minute))); err != nil {
		t.Fatalf("raw insert: %v", err)
	}
	if rawPairingUserCodeIsNull(t, s, "p-emptyblob") {
		t.Fatal("fixture stored NULL, want an empty value")
	}

	for _, hash := range [][]byte{nil, {}} {
		if _, err := s.Repos().DevicePairings.GetByUserCodeHash(ctx, hash); !errors.Is(err, domain.ErrNotFound) {
			t.Errorf("lookup with %v hash matched an empty row: %v", hash, err)
		}
	}
}

// Owner B reading owner A's pairing must get exactly what an id that never
// existed gets; the two errors being equal is the isolation property.
func TestPairingGetIsOwnerScoped(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	mustApprove(t, s, "p-1", "o-1")

	if _, err := s.Repos().DevicePairings.Get(ctx, "o-1", "p-1"); err != nil {
		t.Fatalf("owner Get: %v", err)
	}
	got, crossOwner := s.Repos().DevicePairings.Get(ctx, "o-2", "p-1")
	if got != nil {
		t.Fatalf("cross-owner Get returned %+v, want nil — o-2 read o-1's row", got)
	}
	if !errors.Is(crossOwner, domain.ErrNotFound) {
		t.Fatalf("cross-owner Get = %v, want ErrNotFound", crossOwner)
	}
	_, invented := s.Repos().DevicePairings.Get(ctx, "o-2", "p-never-created")
	if crossOwner.Error() != invented.Error() {
		t.Errorf("cross-owner error %q differs from invented-id error %q", crossOwner, invented)
	}
}

func TestPairingListByOwnerIsScopedAndOrdered(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	mustApprove(t, s, "p-b", "o-1")
	mustApprove(t, s, "p-a", "o-1")
	mustApprove(t, s, "p-z", "o-2")

	got, err := s.Repos().DevicePairings.ListByOwner(ctx, "o-1")
	if err != nil {
		t.Fatalf("ListByOwner: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2 (other owner's pairing must not appear)", len(got))
	}
	if got[0].ID != "p-a" || got[1].ID != "p-b" {
		t.Errorf("order = %q,%q, want p-a,p-b", got[0].ID, got[1].ID)
	}
	for _, p := range got {
		if p.OwnerID != "o-1" {
			t.Errorf("pairing %q belongs to %q, want o-1", p.ID, p.OwnerID)
		}
	}
}

// A pending pairing has no owner, so it must not surface in any owner's list,
// and an owner with nothing gets a nil slice rather than an empty one.
func TestPairingListByOwnerExcludesPendingAndIsNilWhenEmpty(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	mustCreatePairing(t, s, newPairing("p-pending"))

	got, err := s.Repos().DevicePairings.ListByOwner(ctx, "o-1")
	if err != nil {
		t.Fatalf("ListByOwner: %v", err)
	}
	invented, err := s.Repos().DevicePairings.ListByOwner(ctx, "o-never-created")
	if err != nil {
		t.Fatalf("ListByOwner(invented): %v", err)
	}
	if got != nil || invented != nil {
		t.Errorf("lists = %v / %v, want nil / nil", got, invented)
	}
}

func TestPairingApproveBindsOwner(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	mustCreatePairing(t, s, newPairing("p-1"))
	now := testClock.Add(time.Minute)

	if err := s.Repos().DevicePairings.Approve(ctx, "p-1", "o-1", now); err != nil {
		t.Fatalf("Approve: %v", err)
	}
	got, err := s.Repos().DevicePairings.Get(ctx, "o-1", "p-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Status != domain.PairingStatusApproved || got.OwnerID != "o-1" {
		t.Errorf("status/owner = %q/%q, want approved/o-1", got.Status, got.OwnerID)
	}
	if got.ApprovedAt == nil || !got.ApprovedAt.Equal(now) {
		t.Errorf("ApprovedAt = %v, want %v", got.ApprovedAt, now)
	}
}

// The status predicate is what stops a second approval rebinding the owner of a
// pairing somebody else already approved.
func TestPairingSecondApprovalCannotRebindOwner(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	mustApprove(t, s, "p-1", "o-1")

	err := s.Repos().DevicePairings.Approve(ctx, "p-1", "o-2", testClock)
	if !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("second approval = %v, want ErrConflict", err)
	}
	got, err := s.Repos().DevicePairings.GetByID(ctx, "p-1")
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.OwnerID != "o-1" {
		t.Errorf("owner = %q after a second approval, want o-1", got.OwnerID)
	}
}

func TestPairingApproveMissingIsNotFound(t *testing.T) {
	t.Parallel()
	s := newStore(t)

	err := s.Repos().DevicePairings.Approve(context.Background(), "p-absent", "o-1", testClock)
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("approve missing = %v, want ErrNotFound", err)
	}
}

func TestPairingMarkRedeemed(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	mustApprove(t, s, "p-1", "o-1")
	now := testClock.Add(2 * time.Minute)

	if err := s.Repos().DevicePairings.MarkRedeemed(ctx, "o-1", "p-1", "lin-1", now); err != nil {
		t.Fatalf("MarkRedeemed: %v", err)
	}
	got, err := s.Repos().DevicePairings.Get(ctx, "o-1", "p-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Status != domain.PairingStatusRedeemed || got.LineageID != "lin-1" {
		t.Errorf("status/lineage = %q/%q, want redeemed/lin-1", got.Status, got.LineageID)
	}
	if got.RedeemedAt == nil || !got.RedeemedAt.Equal(now) {
		t.Errorf("RedeemedAt = %v, want %v", got.RedeemedAt, now)
	}
}

// A device code is single-use: the second redemption must change nothing.
func TestPairingSecondRedemptionConflicts(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	mustApprove(t, s, "p-1", "o-1")

	if err := s.Repos().DevicePairings.MarkRedeemed(ctx, "o-1", "p-1", "lin-1", testClock); err != nil {
		t.Fatalf("first MarkRedeemed: %v", err)
	}
	err := s.Repos().DevicePairings.MarkRedeemed(ctx, "o-1", "p-1", "lin-2", testClock)
	if !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("second MarkRedeemed = %v, want ErrConflict", err)
	}
	got, err := s.Repos().DevicePairings.Get(ctx, "o-1", "p-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.LineageID != "lin-1" {
		t.Errorf("lineage = %q, want the first redemption's lin-1", got.LineageID)
	}
}

// Redemption requires an approval first: a pending pairing cannot be redeemed.
func TestPairingRedeemRequiresApproval(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	mustCreatePairing(t, s, newPairing("p-1"))

	// Pending rows have no owner, so this is ErrNotFound rather than a
	// conflict: the owner-scoped classifying SELECT cannot see the row either.
	err := s.Repos().DevicePairings.MarkRedeemed(ctx, "o-1", "p-1", "lin-1", testClock)
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("redeem pending = %v, want ErrNotFound", err)
	}
}

// Another owner redeeming must get the error a missing id gets, and must leave
// the pairing approved and unspent.
func TestPairingMarkRedeemedIsOwnerScoped(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	mustApprove(t, s, "p-1", "o-1")

	crossOwner := s.Repos().DevicePairings.MarkRedeemed(ctx, "o-2", "p-1", "lin-attacker", testClock)
	if !errors.Is(crossOwner, domain.ErrNotFound) {
		t.Fatalf("cross-owner MarkRedeemed = %v, want ErrNotFound", crossOwner)
	}
	invented := s.Repos().DevicePairings.MarkRedeemed(ctx, "o-2", "p-never-created", "lin-x", testClock)
	if crossOwner.Error() != invented.Error() {
		t.Errorf("cross-owner error %q differs from invented-id error %q", crossOwner, invented)
	}

	got, err := s.Repos().DevicePairings.GetByID(ctx, "p-1")
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.Status != domain.PairingStatusApproved || got.LineageID != "" {
		t.Errorf("status/lineage = %q/%q after a cross-owner redemption, want approved and empty",
			got.Status, got.LineageID)
	}
}

func TestPairingRevoke(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	mustApprove(t, s, "p-1", "o-1")
	now := testClock.Add(5 * time.Minute)

	if err := s.Repos().DevicePairings.Revoke(ctx, "o-1", "p-1", now); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	got, err := s.Repos().DevicePairings.Get(ctx, "o-1", "p-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Status != domain.PairingStatusRevoked {
		t.Errorf("status = %q, want revoked", got.Status)
	}
	if got.RevokedAt == nil || !got.RevokedAt.Equal(now) {
		t.Errorf("RevokedAt = %v, want %v", got.RevokedAt, now)
	}
}

// Re-revoking a terminal pairing is a conflict, not a silent overwrite: the
// record of how the pairing ended must survive.
func TestPairingRevokeTerminalConflicts(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	mustApprove(t, s, "p-1", "o-1")
	if err := s.Repos().DevicePairings.MarkRedeemed(ctx, "o-1", "p-1", "lin-1", testClock); err != nil {
		t.Fatalf("MarkRedeemed: %v", err)
	}

	err := s.Repos().DevicePairings.Revoke(ctx, "o-1", "p-1", testClock)
	if !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("revoke redeemed = %v, want ErrConflict", err)
	}
	got, err := s.Repos().DevicePairings.Get(ctx, "o-1", "p-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Status != domain.PairingStatusRedeemed {
		t.Errorf("status = %q, want the terminal redeemed state preserved", got.Status)
	}
}

func TestPairingRevokeIsOwnerScoped(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	mustApprove(t, s, "p-1", "o-1")

	crossOwner := s.Repos().DevicePairings.Revoke(ctx, "o-2", "p-1", testClock)
	if !errors.Is(crossOwner, domain.ErrNotFound) {
		t.Fatalf("cross-owner Revoke = %v, want ErrNotFound", crossOwner)
	}
	invented := s.Repos().DevicePairings.Revoke(ctx, "o-2", "p-never-created", testClock)
	if crossOwner.Error() != invented.Error() {
		t.Errorf("cross-owner error %q differs from invented-id error %q", crossOwner, invented)
	}

	got, err := s.Repos().DevicePairings.GetByID(ctx, "p-1")
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.Status != domain.PairingStatusApproved {
		t.Errorf("status = %q after a cross-owner revoke, want it untouched at approved", got.Status)
	}
}

func TestPairingTouch(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	mustCreatePairing(t, s, newPairing("p-1"))
	next := testClock.Add(30 * time.Second)

	if err := s.Repos().DevicePairings.Touch(ctx, "p-1", next); err != nil {
		t.Fatalf("Touch: %v", err)
	}
	got, err := s.Repos().DevicePairings.GetByID(ctx, "p-1")
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if !got.NextPollAt.Equal(next) {
		t.Errorf("NextPollAt = %v, want %v", got.NextPollAt, next)
	}
	if err := s.Repos().DevicePairings.Touch(ctx, "p-absent", next); !errors.Is(err, domain.ErrNotFound) {
		t.Errorf("Touch(absent) = %v, want ErrNotFound", err)
	}
}

// Throttling has no status predicate: a client polling a terminal pairing must
// still be slowed down rather than refused.
func TestPairingTouchWorksOnTerminalPairing(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	mustApprove(t, s, "p-1", "o-1")
	if err := s.Repos().DevicePairings.Revoke(ctx, "o-1", "p-1", testClock); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	if err := s.Repos().DevicePairings.Touch(ctx, "p-1", testClock.Add(time.Minute)); err != nil {
		t.Errorf("Touch on a revoked pairing = %v, want it to succeed", err)
	}
}

func TestPairingDeleteExpired(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	old := newPairing("p-1")
	old.ExpiresAt = testClock.Add(-2 * time.Hour)
	mustCreatePairing(t, s, old)

	atCutoff := newPairing("p-2")
	atCutoff.ExpiresAt = testClock
	mustCreatePairing(t, s, atCutoff)

	live := newPairing("p-3")
	live.ExpiresAt = testClock.Add(time.Hour)
	mustCreatePairing(t, s, live)

	n, err := s.Repos().DevicePairings.DeleteExpired(ctx, testClock, 10)
	if err != nil {
		t.Fatalf("DeleteExpired: %v", err)
	}
	if n != 2 {
		t.Fatalf("deleted %d, want 2 (the cutoff is inclusive)", n)
	}
	if _, err := s.Repos().DevicePairings.GetByID(ctx, "p-3"); err != nil {
		t.Fatalf("GetByID p-3: %v, want the unexpired row to survive", err)
	}
}

// PostgreSQL has no DELETE ... LIMIT, so both the batch bound and its
// oldest-first ordering come from the bounded subquery.
func TestPairingDeleteExpiredRespectsLimit(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	for i, id := range []string{"p-1", "p-2", "p-3"} {
		p := newPairing(id)
		p.ExpiresAt = testClock.Add(time.Duration(-3+i) * time.Hour)
		mustCreatePairing(t, s, p)
	}

	n, err := s.Repos().DevicePairings.DeleteExpired(ctx, testClock, 2)
	if err != nil {
		t.Fatalf("DeleteExpired: %v", err)
	}
	if n != 2 {
		t.Fatalf("deleted %d, want 2", n)
	}
	if _, err := s.Repos().DevicePairings.GetByID(ctx, "p-3"); err != nil {
		t.Fatalf("GetByID p-3: %v, want the newest expiry to survive the batch", err)
	}
}

// A caller's zero value must not become a full-table delete.
func TestPairingDeleteExpiredRejectsNonPositiveLimit(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	for _, limit := range []int{0, -1} {
		n, err := s.Repos().DevicePairings.DeleteExpired(ctx, testClock, limit)
		if !errors.Is(err, domain.ErrInvalidInput) {
			t.Errorf("DeleteExpired(limit=%d) = %v, want ErrInvalidInput", limit, err)
		}
		if n != 0 {
			t.Errorf("DeleteExpired(limit=%d) deleted %d, want 0", limit, n)
		}
	}
}

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
		t.Errorf("Scopes = %+v, want nil", got.Scopes)
	}
}

// The decode error path, which no round trip through Create can reach.
func TestPairingDecScopesRejectsMalformed(t *testing.T) {
	t.Parallel()

	if _, err := decPairingScopes("not json"); err == nil {
		t.Fatal("decPairingScopes(malformed) = nil error, want a decode failure")
	}
}

// The status CHECK constraint is defense in depth: the adapter never writes an
// out-of-range status, so this asserts the database itself refuses one. A CHECK
// violation is SQLSTATE 23514, which mapError deliberately leaves as a generic
// wrapped error rather than promoting it to a conflict.
func TestPairingStatusCheckConstraintRejectsUnknownStatus(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	mustCreatePairing(t, s, newPairing("p-1"))

	_, err := s.db.ExecContext(ctx,
		`UPDATE device_pairings SET status = $1 WHERE id = $2`, "not-a-status", "p-1")
	if err == nil {
		t.Fatal("the database accepted an out-of-range status")
	}
	if errors.Is(mapError(err), domain.ErrConflict) {
		t.Error("a CHECK violation mapped to ErrConflict, want a generic wrapped error")
	}
}

// The repository composes into a caller-managed transaction, and a rollback
// takes the write with it.
func TestPairingTransactional(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	wantErr := errors.New("rollback")

	err := s.WithTx(ctx, func(ctx context.Context, r repository.Repos) error {
		if cerr := r.DevicePairings.Create(ctx, newPairing("p-tx")); cerr != nil {
			return cerr
		}
		return wantErr
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("WithTx = %v, want the rollback error", err)
	}
	if _, err := s.Repos().DevicePairings.GetByID(ctx, "p-tx"); !errors.Is(err, domain.ErrNotFound) {
		t.Errorf("pairing survived rollback: %v", err)
	}
}

// A corrupt expiry must surface as a decode error rather than a zero time,
// which would read as "expired in year one".
func TestPairingRejectsCorruptTimestamp(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	mustCreatePairing(t, s, newPairing("p-1"))

	if _, err := s.db.ExecContext(ctx,
		`UPDATE device_pairings SET expires_at = $1 WHERE id = $2`, "not-a-timestamp", "p-1"); err != nil {
		t.Fatalf("corrupt row: %v", err)
	}
	if _, err := s.Repos().DevicePairings.GetByID(ctx, "p-1"); err == nil {
		t.Error("corrupt expires_at decoded without error")
	}
}

func TestEncPairingOwnerAndHash(t *testing.T) {
	t.Parallel()

	if got := encPairingOwner(""); got != nil {
		t.Errorf("encPairingOwner(\"\") = %v, want nil so unowned is SQL NULL", got)
	}
	if got := encPairingOwner("o-1"); got != "o-1" {
		t.Errorf("encPairingOwner(o-1) = %v, want o-1", got)
	}
	if got := encPairingHash(nil); got != nil {
		t.Errorf("encPairingHash(nil) = %v, want nil", got)
	}
	if got := encPairingHash([]byte{}); got != nil {
		t.Errorf("encPairingHash(empty) = %v, want nil so it stores as SQL NULL", got)
	}
}

// A NULL owner_id decodes to the empty OwnerID rather than failing the scan.
func TestScanPairingNullOwnerDecodesEmpty(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	mustCreatePairing(t, s, newPairing("p-1"))

	var isNull bool
	if err := s.db.QueryRowContext(ctx,
		`SELECT owner_id IS NULL FROM device_pairings WHERE id = $1`, "p-1").Scan(&isNull); err != nil {
		t.Fatalf("probe owner_id: %v", err)
	}
	if !isNull {
		t.Fatal("a pending pairing stored a non-NULL owner_id")
	}

	got, err := s.Repos().DevicePairings.GetByID(ctx, "p-1")
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.OwnerID != "" {
		t.Errorf("OwnerID = %q, want empty", got.OwnerID)
	}
}
