package sqlite

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
)

// newPublicKey returns a fully populated active public key owned by ownerID on
// deviceID with a nil RevokedAt and a distinct blob/fingerprint derived from id.
func newPublicKey(id, ownerID, deviceID string) *domain.PublicKey {
	return &domain.PublicKey{
		ID:          domain.PublicKeyID(id),
		OwnerID:     domain.OwnerID(ownerID),
		DeviceID:    domain.DeviceID(deviceID),
		Algorithm:   domain.AlgEd25519,
		Blob:        []byte("blob-" + id),
		Comment:     "comment-" + id,
		Fingerprint: "SHA256:" + id,
		BitLen:      256,
		Status:      domain.KeyStatusActive,
		CreatedAt:   testClock,
		UpdatedAt:   testClock,
	}
}

// mustCreatePublicKey creates the owner and device (if needed) and the public
// key, failing the test on error.
func mustCreatePublicKey(t *testing.T, s *Store, k *domain.PublicKey) {
	t.Helper()
	ctx := context.Background()
	if _, err := s.Repos().Owners.Get(ctx, k.OwnerID); errors.Is(err, domain.ErrNotFound) {
		mustCreateOwner(t, s, string(k.OwnerID))
	}
	if _, err := s.Repos().Devices.Get(ctx, k.OwnerID, k.DeviceID); errors.Is(err, domain.ErrNotFound) {
		mustCreateDevice(t, s, newDevice(string(k.DeviceID), string(k.OwnerID), "dev-"+string(k.DeviceID)))
	}
	if err := s.Repos().PublicKeys.Create(ctx, k); err != nil {
		t.Fatalf("Create public key %q: %v", k.ID, err)
	}
}

// seedKeySet inserts a minimal active key set for ownerID directly via SQL so
// tests do not depend on the not-yet-implemented KeySetRepository.
func seedKeySet(t *testing.T, s *Store, setID, ownerID string) {
	t.Helper()
	const q = `INSERT INTO key_sets (id, owner_id, name, visibility, is_default, state, created_at, updated_at)
VALUES (?, ?, ?, 'public', 0, 'active', ?, ?)`
	if _, err := s.db.ExecContext(context.Background(), q,
		setID, ownerID, "set-"+setID, encTime(testClock), encTime(testClock),
	); err != nil {
		t.Fatalf("seed key set %q: %v", setID, err)
	}
}

// seedMembership inserts a key_set_members row directly via SQL.
func seedMembership(t *testing.T, s *Store, setID, keyID string) {
	t.Helper()
	const q = `INSERT INTO key_set_members (key_set_id, public_key_id, added_at) VALUES (?, ?, ?)`
	if _, err := s.db.ExecContext(context.Background(), q, setID, keyID, encTime(testClock)); err != nil {
		t.Fatalf("seed membership set=%q key=%q: %v", setID, keyID, err)
	}
}

func TestPublicKeyCreateAndGet(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	want := newPublicKey("k-1", "owner-a", "d-1")
	mustCreatePublicKey(t, s, want)

	got, err := s.Repos().PublicKeys.Get(ctx, "owner-a", "k-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.ID != want.ID || got.OwnerID != want.OwnerID || got.DeviceID != want.DeviceID {
		t.Errorf("Get id/owner/device = %q/%q/%q, want k-1/owner-a/d-1", got.ID, got.OwnerID, got.DeviceID)
	}
	if got.Algorithm != want.Algorithm || got.Status != want.Status {
		t.Errorf("Get algorithm/status = %q/%q, want %q/%q", got.Algorithm, got.Status, want.Algorithm, want.Status)
	}
	if string(got.Blob) != string(want.Blob) {
		t.Errorf("Blob = %q, want %q", got.Blob, want.Blob)
	}
	if got.Comment != want.Comment || got.Fingerprint != want.Fingerprint || got.BitLen != want.BitLen {
		t.Errorf("Get comment/fingerprint/bitlen = %q/%q/%d, want %q/%q/%d",
			got.Comment, got.Fingerprint, got.BitLen, want.Comment, want.Fingerprint, want.BitLen)
	}
	if !got.CreatedAt.Equal(want.CreatedAt) || !got.UpdatedAt.Equal(want.UpdatedAt) {
		t.Errorf("timestamps round-trip mismatch: got %v/%v", got.CreatedAt, got.UpdatedAt)
	}
	if got.RevokedAt != nil {
		t.Errorf("RevokedAt = %v, want nil", got.RevokedAt)
	}
	if got.Signature != nil {
		t.Errorf("Signature = %v, want nil (not persisted in phase 1)", got.Signature)
	}
}

func TestPublicKeyCreateWithRevokedAtRoundTrips(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	revoked := testClock.Add(3 * time.Hour)
	k := newPublicKey("k-rev", "owner-a", "d-1")
	k.Status = domain.KeyStatusRevoked
	k.RevokedAt = &revoked
	mustCreatePublicKey(t, s, k)

	got, err := s.Repos().PublicKeys.Get(ctx, "owner-a", "k-rev")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Status != domain.KeyStatusRevoked {
		t.Errorf("Status = %q, want revoked", got.Status)
	}
	if got.RevokedAt == nil || !got.RevokedAt.Equal(revoked) {
		t.Errorf("RevokedAt = %v, want %v", got.RevokedAt, revoked)
	}
}

func TestPublicKeyGetMissingNotFound(t *testing.T) {
	t.Parallel()
	s := newStore(t)

	mustCreateOwner(t, s, "owner-a")
	_, err := s.Repos().PublicKeys.Get(context.Background(), "owner-a", "ghost")
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("Get missing error = %v, want ErrNotFound", err)
	}
}

func TestPublicKeyCreateDuplicateFingerprintConflict(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	mustCreatePublicKey(t, s, newPublicKey("k-1", "owner-a", "d-1"))
	// Same (owner_id, fingerprint), different id -> UNIQUE violation -> conflict.
	dup := newPublicKey("k-2", "owner-a", "d-1")
	dup.Fingerprint = "SHA256:k-1"
	err := s.Repos().PublicKeys.Create(ctx, dup)
	if !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("duplicate fingerprint Create error = %v, want ErrConflict", err)
	}
}

func TestPublicKeyDuplicateFingerprintDifferentOwnerAllowed(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	mustCreatePublicKey(t, s, newPublicKey("k-a", "owner-a", "d-a"))
	// Same fingerprint under a DIFFERENT owner is not a conflict.
	other := newPublicKey("k-b", "owner-b", "d-b")
	other.Fingerprint = "SHA256:k-a"
	mustCreatePublicKey(t, s, other)

	if _, err := s.Repos().PublicKeys.GetByFingerprint(ctx, "owner-b", "SHA256:k-a"); err != nil {
		t.Fatalf("GetByFingerprint owner-b: %v", err)
	}
}

func TestPublicKeyCreateRejectsNil(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	if err := s.Repos().PublicKeys.Create(context.Background(), nil); !errors.Is(err, domain.ErrInvalidInput) {
		t.Errorf("Create(nil) = %v, want ErrInvalidInput", err)
	}
}

func TestPublicKeyListByOwner(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	// Insert out of id order to prove ORDER BY id ASC is applied.
	mustCreatePublicKey(t, s, newPublicKey("k-3", "owner-a", "d-1"))
	mustCreatePublicKey(t, s, newPublicKey("k-1", "owner-a", "d-1"))
	mustCreatePublicKey(t, s, newPublicKey("k-2", "owner-a", "d-2"))
	mustCreatePublicKey(t, s, newPublicKey("k-x", "owner-b", "d-x"))

	got, err := s.Repos().PublicKeys.ListByOwner(ctx, "owner-a")
	if err != nil {
		t.Fatalf("ListByOwner: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("ListByOwner returned %d rows, want 3 (owner-a only)", len(got))
	}
	wantOrder := []domain.PublicKeyID{"k-1", "k-2", "k-3"}
	for i := range got {
		if got[i].OwnerID != "owner-a" {
			t.Errorf("ListByOwner leaked row for owner %q", got[i].OwnerID)
		}
		if got[i].ID != wantOrder[i] {
			t.Errorf("ListByOwner[%d] id = %q, want %q (ascending)", i, got[i].ID, wantOrder[i])
		}
	}
}

func TestPublicKeyListByOwnerEmpty(t *testing.T) {
	t.Parallel()
	s := newStore(t)

	mustCreateOwner(t, s, "owner-empty")
	got, err := s.Repos().PublicKeys.ListByOwner(context.Background(), "owner-empty")
	if err != nil {
		t.Fatalf("ListByOwner: %v", err)
	}
	if got != nil {
		t.Fatalf("ListByOwner = %v, want nil slice when empty", got)
	}
}

func TestPublicKeyListByDevice(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	mustCreatePublicKey(t, s, newPublicKey("k-2", "owner-a", "d-1"))
	mustCreatePublicKey(t, s, newPublicKey("k-1", "owner-a", "d-1"))
	mustCreatePublicKey(t, s, newPublicKey("k-other", "owner-a", "d-2"))

	got, err := s.Repos().PublicKeys.ListByDevice(ctx, "owner-a", "d-1")
	if err != nil {
		t.Fatalf("ListByDevice: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("ListByDevice returned %d rows, want 2 (d-1 only)", len(got))
	}
	wantOrder := []domain.PublicKeyID{"k-1", "k-2"}
	for i := range got {
		if got[i].DeviceID != "d-1" {
			t.Errorf("ListByDevice[%d] leaked device %q, want d-1", i, got[i].DeviceID)
		}
		if got[i].ID != wantOrder[i] {
			t.Errorf("ListByDevice[%d] id = %q, want %q (ascending)", i, got[i].ID, wantOrder[i])
		}
	}
}

func TestPublicKeyListByDeviceEmpty(t *testing.T) {
	t.Parallel()
	s := newStore(t)

	mustCreatePublicKey(t, s, newPublicKey("k-1", "owner-a", "d-1"))
	got, err := s.Repos().PublicKeys.ListByDevice(context.Background(), "owner-a", "d-nope")
	if err != nil {
		t.Fatalf("ListByDevice: %v", err)
	}
	if got != nil {
		t.Fatalf("ListByDevice = %v, want nil slice when none", got)
	}
}

func TestPublicKeyGetByFingerprint(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	mustCreatePublicKey(t, s, newPublicKey("k-1", "owner-a", "d-1"))

	got, err := s.Repos().PublicKeys.GetByFingerprint(ctx, "owner-a", "SHA256:k-1")
	if err != nil {
		t.Fatalf("GetByFingerprint hit: %v", err)
	}
	if got.ID != "k-1" {
		t.Errorf("GetByFingerprint id = %q, want k-1", got.ID)
	}

	if _, err := s.Repos().PublicKeys.GetByFingerprint(ctx, "owner-a", "SHA256:absent"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("GetByFingerprint miss error = %v, want ErrNotFound", err)
	}
}

func TestPublicKeyRevoke(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	mustCreatePublicKey(t, s, newPublicKey("k-rv", "owner-a", "d-1"))
	later := testClock.Add(2 * time.Hour)
	if err := s.Repos().PublicKeys.Revoke(ctx, "owner-a", "k-rv", later); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	got, err := s.Repos().PublicKeys.Get(ctx, "owner-a", "k-rv")
	if err != nil {
		t.Fatalf("Get after Revoke: %v", err)
	}
	if got.Status != domain.KeyStatusRevoked {
		t.Errorf("Status = %q, want revoked", got.Status)
	}
	if got.RevokedAt == nil || !got.RevokedAt.Equal(later) {
		t.Errorf("RevokedAt = %v, want %v", got.RevokedAt, later)
	}
	if !got.UpdatedAt.Equal(later) {
		t.Errorf("UpdatedAt = %v, want %v", got.UpdatedAt, later)
	}
}

func TestPublicKeyRevokeMissingNotFound(t *testing.T) {
	t.Parallel()
	s := newStore(t)

	mustCreateOwner(t, s, "owner-a")
	err := s.Repos().PublicKeys.Revoke(context.Background(), "owner-a", "ghost", testClock)
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("Revoke missing error = %v, want ErrNotFound", err)
	}
}

func TestPublicKeyRevokeByDevice(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	mustCreatePublicKey(t, s, newPublicKey("k-1", "owner-a", "d-1"))
	mustCreatePublicKey(t, s, newPublicKey("k-2", "owner-a", "d-1"))
	mustCreatePublicKey(t, s, newPublicKey("k-other", "owner-a", "d-2"))
	// An already-revoked key on d-1 must not be re-counted.
	already := newPublicKey("k-done", "owner-a", "d-1")
	already.Status = domain.KeyStatusRevoked
	prev := testClock.Add(time.Minute)
	already.RevokedAt = &prev
	mustCreatePublicKey(t, s, already)

	later := testClock.Add(2 * time.Hour)
	n, err := s.Repos().PublicKeys.RevokeByDevice(ctx, "owner-a", "d-1", later)
	if err != nil {
		t.Fatalf("RevokeByDevice: %v", err)
	}
	if n != 2 {
		t.Fatalf("RevokeByDevice count = %d, want 2 (only active d-1 keys)", n)
	}

	// The two active d-1 keys are now revoked with the new timestamp.
	for _, id := range []domain.PublicKeyID{"k-1", "k-2"} {
		got, err := s.Repos().PublicKeys.Get(ctx, "owner-a", id)
		if err != nil {
			t.Fatalf("Get %q: %v", id, err)
		}
		if got.Status != domain.KeyStatusRevoked || got.RevokedAt == nil || !got.RevokedAt.Equal(later) {
			t.Errorf("%q status/revoked = %q/%v, want revoked/%v", id, got.Status, got.RevokedAt, later)
		}
	}
	// The other device's key is untouched.
	if got, _ := s.Repos().PublicKeys.Get(ctx, "owner-a", "k-other"); got.Status != domain.KeyStatusActive {
		t.Errorf("k-other status = %q, want active (different device)", got.Status)
	}
	// The already-revoked key keeps its original revoked_at, not the new one.
	if got, _ := s.Repos().PublicKeys.Get(ctx, "owner-a", "k-done"); got.RevokedAt == nil || !got.RevokedAt.Equal(prev) {
		t.Errorf("k-done RevokedAt = %v, want unchanged %v", got.RevokedAt, prev)
	}
}

func TestPublicKeyRevokeByDeviceZeroWhenNone(t *testing.T) {
	t.Parallel()
	s := newStore(t)

	mustCreatePublicKey(t, s, newPublicKey("k-1", "owner-a", "d-1"))
	n, err := s.Repos().PublicKeys.RevokeByDevice(context.Background(), "owner-a", "d-empty", testClock)
	if err != nil {
		t.Fatalf("RevokeByDevice on device with no keys: %v", err)
	}
	if n != 0 {
		t.Fatalf("RevokeByDevice count = %d, want 0", n)
	}
}

// TestPublicKeyCrossTenantIsolation is the core security invariant: owner B must
// never observe or mutate owner A's key through any owner-scoped method.
func TestPublicKeyCrossTenantIsolation(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	mustCreatePublicKey(t, s, newPublicKey("k-secret", "owner-a", "d-a"))
	mustCreateOwner(t, s, "owner-b")

	// Get by B for A's key id -> ErrNotFound, no row.
	if got, err := s.Repos().PublicKeys.Get(ctx, "owner-b", "k-secret"); !errors.Is(err, domain.ErrNotFound) || got != nil {
		t.Fatalf("cross-tenant Get = (%v, %v), want (nil, ErrNotFound)", got, err)
	}
	// GetByFingerprint by B for A's fingerprint -> ErrNotFound.
	if _, err := s.Repos().PublicKeys.GetByFingerprint(ctx, "owner-b", "SHA256:k-secret"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("cross-tenant GetByFingerprint error = %v, want ErrNotFound", err)
	}
	// ListByOwner for B excludes A's key.
	if got, err := s.Repos().PublicKeys.ListByOwner(ctx, "owner-b"); err != nil || len(got) != 0 {
		t.Fatalf("cross-tenant ListByOwner = (%v, %v), want (empty, nil)", got, err)
	}
	// ListByDevice by B for A's device -> empty.
	if got, err := s.Repos().PublicKeys.ListByDevice(ctx, "owner-b", "d-a"); err != nil || len(got) != 0 {
		t.Fatalf("cross-tenant ListByDevice = (%v, %v), want (empty, nil)", got, err)
	}
	// Revoke by B on A's key -> ErrNotFound, NOT ErrConflict.
	rerr := s.Repos().PublicKeys.Revoke(ctx, "owner-b", "k-secret", testClock.Add(time.Hour))
	if !errors.Is(rerr, domain.ErrNotFound) || errors.Is(rerr, domain.ErrConflict) {
		t.Fatalf("cross-tenant Revoke error = %v, want ErrNotFound", rerr)
	}
	// RevokeByDevice by B on A's device touches nothing.
	if n, err := s.Repos().PublicKeys.RevokeByDevice(ctx, "owner-b", "d-a", testClock.Add(time.Hour)); err != nil || n != 0 {
		t.Fatalf("cross-tenant RevokeByDevice = (%d, %v), want (0, nil)", n, err)
	}

	// Sanity: A's key is completely unmutated by B's attempts.
	got, err := s.Repos().PublicKeys.Get(ctx, "owner-a", "k-secret")
	if err != nil {
		t.Fatalf("owner A Get after cross-tenant attempts: %v", err)
	}
	if got.Status != domain.KeyStatusActive || got.RevokedAt != nil {
		t.Errorf("owner A key mutated by cross-tenant attempts: status=%q revoked=%v", got.Status, got.RevokedAt)
	}
}

// TestPublicKeyCreateForeignDeviceRejected asserts the composite device foreign
// key (device_id, owner_id) -> devices(id, owner_id) is the DB-level tenant
// backstop: owner B cannot create a key referencing owner A's device_id.
func TestPublicKeyCreateForeignDeviceRejected(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	// Owner A owns device d-a; owner B exists but has no such device.
	mustCreatePublicKey(t, s, newPublicKey("k-a", "owner-a", "d-a"))
	mustCreateOwner(t, s, "owner-b")

	// B references A's device_id: the composite FK has no matching (d-a, owner-b).
	foreign := newPublicKey("k-b", "owner-b", "d-a")
	if err := s.Repos().PublicKeys.Create(ctx, foreign); err == nil {
		t.Fatal("Create referencing another owner's device_id: nil error, want FK rejection")
	}
}

// TestPublicKeyListActiveByKeySet is the publish-path invariant: the query
// returns only ACTIVE keys that are members of the given set, owner-scoped, in
// deterministic order — excluding revoked members, non-members, and another
// owner's set/keys.
func TestPublicKeyListActiveByKeySet(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	// Owner A: two active members (out of id order), one revoked member, one
	// active non-member.
	mustCreatePublicKey(t, s, newPublicKey("k-3", "owner-a", "d-1"))
	mustCreatePublicKey(t, s, newPublicKey("k-1", "owner-a", "d-1"))
	revoked := newPublicKey("k-rev", "owner-a", "d-1")
	revoked.Status = domain.KeyStatusRevoked
	rt := testClock.Add(time.Hour)
	revoked.RevokedAt = &rt
	mustCreatePublicKey(t, s, revoked)
	mustCreatePublicKey(t, s, newPublicKey("k-nonmember", "owner-a", "d-1"))

	seedKeySet(t, s, "set-a", "owner-a")
	seedMembership(t, s, "set-a", "k-3")
	seedMembership(t, s, "set-a", "k-1")
	seedMembership(t, s, "set-a", "k-rev") // member but revoked -> excluded

	// Owner B: an active key in its own set with the SAME set id would collide
	// on PK, so use a distinct set id; must never appear in A's result.
	mustCreatePublicKey(t, s, newPublicKey("k-b", "owner-b", "d-b"))
	seedKeySet(t, s, "set-b", "owner-b")
	seedMembership(t, s, "set-b", "k-b")

	got, err := s.Repos().PublicKeys.ListActiveByKeySet(ctx, "owner-a", "set-a")
	if err != nil {
		t.Fatalf("ListActiveByKeySet: %v", err)
	}
	wantOrder := []domain.PublicKeyID{"k-1", "k-3"}
	if len(got) != len(wantOrder) {
		t.Fatalf("ListActiveByKeySet returned %d keys, want %d (active members only)", len(got), len(wantOrder))
	}
	for i := range got {
		if got[i].ID != wantOrder[i] {
			t.Errorf("ListActiveByKeySet[%d] id = %q, want %q (ascending, active members)", i, got[i].ID, wantOrder[i])
		}
		if got[i].OwnerID != "owner-a" || got[i].Status != domain.KeyStatusActive {
			t.Errorf("ListActiveByKeySet[%d] leaked owner/status %q/%q", i, got[i].OwnerID, got[i].Status)
		}
	}

	// Owner A querying owner B's set id returns nothing (owner-scope on pk).
	if other, err := s.Repos().PublicKeys.ListActiveByKeySet(ctx, "owner-a", "set-b"); err != nil || len(other) != 0 {
		t.Fatalf("cross-owner set = (%v, %v), want (empty, nil)", other, err)
	}
	// Empty for an unknown set.
	if none, err := s.Repos().PublicKeys.ListActiveByKeySet(ctx, "owner-a", "set-ghost"); err != nil || none != nil {
		t.Fatalf("unknown set = (%v, %v), want (nil, nil)", none, err)
	}
}

// TestPublicKeyQueryErrorsMapped drives the driver-error branches of every read
// and write path with an already-canceled context: each method must surface a
// non-nil error through mapError.
func TestPublicKeyQueryErrorsMapped(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	mustCreatePublicKey(t, s, newPublicKey("k-1", "owner-a", "d-1"))

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := s.Repos().PublicKeys.Create(ctx, newPublicKey("k-2", "owner-a", "d-1")); err == nil {
		t.Error("Create on canceled ctx: nil error")
	}
	if _, err := s.Repos().PublicKeys.Get(ctx, "owner-a", "k-1"); err == nil {
		t.Error("Get on canceled ctx: nil error")
	}
	if _, err := s.Repos().PublicKeys.ListByOwner(ctx, "owner-a"); err == nil {
		t.Error("ListByOwner on canceled ctx: nil error")
	}
	if _, err := s.Repos().PublicKeys.ListByDevice(ctx, "owner-a", "d-1"); err == nil {
		t.Error("ListByDevice on canceled ctx: nil error")
	}
	if _, err := s.Repos().PublicKeys.GetByFingerprint(ctx, "owner-a", "SHA256:k-1"); err == nil {
		t.Error("GetByFingerprint on canceled ctx: nil error")
	}
	if err := s.Repos().PublicKeys.Revoke(ctx, "owner-a", "k-1", testClock); err == nil {
		t.Error("Revoke on canceled ctx: nil error")
	}
	if _, err := s.Repos().PublicKeys.RevokeByDevice(ctx, "owner-a", "d-1", testClock); err == nil {
		t.Error("RevokeByDevice on canceled ctx: nil error")
	}
	if _, err := s.Repos().PublicKeys.ListActiveByKeySet(ctx, "owner-a", "set-a"); err == nil {
		t.Error("ListActiveByKeySet on canceled ctx: nil error")
	}
}

// TestPublicKeyDecodeErrorsSurface drives the timestamp-decode failure branches
// in scanPublicKey and collectPublicKeys by planting rows with a malformed
// timestamp directly, bypassing encTime. Both the single-row read (Get) and the
// iteration read (ListByOwner) must surface the decode error.
func TestPublicKeyDecodeErrorsSurface(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	mustCreateOwner(t, s, "owner-a")
	mustCreateDevice(t, s, newDevice("d-1", "owner-a", "dev"))
	const ins = `INSERT INTO public_keys (id, owner_id, device_id, algorithm, blob, comment, fingerprint, bit_len, status, created_at, updated_at, revoked_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	good := encTime(testClock)
	rows := []struct {
		id                            string
		createdAt, updatedAt, revoked any
	}{
		{"k-bad-created", "not-a-timestamp", good, nil},
		{"k-bad-updated", good, "not-a-timestamp", nil},
		{"k-bad-revoked", good, good, "not-a-timestamp"},
	}
	for _, r := range rows {
		if _, err := s.db.ExecContext(ctx, ins,
			r.id, "owner-a", "d-1", string(domain.AlgEd25519), []byte("b"), "c",
			"fp-"+r.id, 256, string(domain.KeyStatusActive), r.createdAt, r.updatedAt, r.revoked,
		); err != nil {
			t.Fatalf("plant malformed row %q: %v", r.id, err)
		}
		if _, err := s.Repos().PublicKeys.Get(ctx, "owner-a", domain.PublicKeyID(r.id)); err == nil {
			t.Errorf("Get on malformed row %q: nil error", r.id)
		}
	}
	if _, err := s.Repos().PublicKeys.ListByOwner(ctx, "owner-a"); err == nil {
		t.Error("ListByOwner over malformed rows: nil error")
	}
}

// TestPublicKeyErrorLeaksNoSQL asserts that a mapped conflict carries the domain
// sentinel and no SQL text or table names.
func TestPublicKeyErrorLeaksNoSQL(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	mustCreatePublicKey(t, s, newPublicKey("k-1", "owner-a", "d-1"))
	dup := newPublicKey("k-2", "owner-a", "d-1")
	dup.Fingerprint = "SHA256:k-1"
	err := s.Repos().PublicKeys.Create(ctx, dup)
	if !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("duplicate error = %v, want ErrConflict", err)
	}
	msg := strings.ToUpper(err.Error())
	for _, leak := range []string{"INSERT", "SELECT", "UPDATE", "PUBLIC_KEYS", "UNIQUE", "PRIMARY KEY", "FINGERPRINT"} {
		if strings.Contains(msg, leak) {
			t.Errorf("error message %q leaks SQL fragment %q", err.Error(), leak)
		}
	}
}
