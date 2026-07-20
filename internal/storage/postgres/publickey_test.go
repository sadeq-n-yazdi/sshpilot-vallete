package postgres

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
)

// newPublicKey returns a fully populated active public key owned by ownerID and
// attached to deviceID, with a nil RevokedAt.
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
		t.Errorf("Get identity = %+v, want k-1/owner-a/d-1", got)
	}
	if got.Algorithm != want.Algorithm || got.Comment != want.Comment ||
		got.Fingerprint != want.Fingerprint || got.BitLen != want.BitLen ||
		got.Status != want.Status {
		t.Errorf("Get = %+v, want %+v", got, want)
	}
	// The BYTEA column must round-trip the blob byte-for-byte.
	if !bytes.Equal(got.Blob, want.Blob) {
		t.Errorf("Blob = %q, want %q", got.Blob, want.Blob)
	}
	if !got.CreatedAt.Equal(want.CreatedAt) || got.CreatedAt.Location() != time.UTC {
		t.Errorf("CreatedAt = %v, want %v in UTC", got.CreatedAt, want.CreatedAt)
	}
	if got.RevokedAt != nil {
		t.Errorf("RevokedAt = %v, want nil", got.RevokedAt)
	}
	// Signature has no column in phase 1 and must come back unset.
	if got.Signature != nil {
		t.Errorf("Signature = %v, want nil", got.Signature)
	}
}

func TestPublicKeyCreateWithRevokedAtRoundTrips(t *testing.T) {
	t.Parallel()
	s := newStore(t)

	k := newPublicKey("k-rev", "owner-a", "d-1")
	k.Status = domain.KeyStatusRevoked
	revoked := testClock.Add(2 * time.Hour)
	k.RevokedAt = &revoked
	mustCreatePublicKey(t, s, k)

	got, err := s.Repos().PublicKeys.Get(context.Background(), "owner-a", "k-rev")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.RevokedAt == nil || !got.RevokedAt.Equal(revoked) {
		t.Errorf("RevokedAt = %v, want %v", got.RevokedAt, revoked)
	}
}

func TestPublicKeyGetMissingNotFound(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	mustCreateOwner(t, s, "owner-a")

	if _, err := s.Repos().PublicKeys.Get(context.Background(), "owner-a", "nope"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("Get missing = %v, want ErrNotFound", err)
	}
}

// TestPublicKeyCreateDuplicateFingerprintConflict pins the per-owner uniqueness
// index: the same fingerprint cannot be registered twice by one owner.
func TestPublicKeyCreateDuplicateFingerprintConflict(t *testing.T) {
	t.Parallel()
	s := newStore(t)

	mustCreatePublicKey(t, s, newPublicKey("k-1", "owner-a", "d-1"))
	dup := newPublicKey("k-2", "owner-a", "d-1")
	dup.Fingerprint = "SHA256:k-1"
	if err := s.Repos().PublicKeys.Create(context.Background(), dup); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("duplicate fingerprint Create = %v, want ErrConflict", err)
	}
}

// TestPublicKeyDuplicateFingerprintDifferentOwnerAllowed pins the other side of
// that index: it is scoped per owner, so two owners may hold the same key.
func TestPublicKeyDuplicateFingerprintDifferentOwnerAllowed(t *testing.T) {
	t.Parallel()
	s := newStore(t)

	mustCreatePublicKey(t, s, newPublicKey("k-1", "owner-a", "d-1"))
	other := newPublicKey("k-2", "owner-b", "d-2")
	other.Fingerprint = "SHA256:k-1"
	mustCreatePublicKey(t, s, other)

	if _, err := s.Repos().PublicKeys.Get(context.Background(), "owner-b", "k-2"); err != nil {
		t.Fatalf("Get owner-b key: %v", err)
	}
}

func TestPublicKeyCreateNilInvalidInput(t *testing.T) {
	t.Parallel()
	s := newStore(t)

	if err := s.Repos().PublicKeys.Create(context.Background(), nil); !errors.Is(err, domain.ErrInvalidInput) {
		t.Errorf("Create(nil) = %v, want ErrInvalidInput", err)
	}
}

// TestPublicKeyCreateForeignDeviceRejected pins the composite (device_id,
// owner_id) foreign key: a key may not attach to another owner's device. The
// failure is a 23503 foreign-key violation, which mapError deliberately routes
// to a generic wrap rather than a sentinel, matching the SQLite adapter.
func TestPublicKeyCreateForeignDeviceRejected(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	mustCreateDevice(t, s, newDevice("d-a", "owner-a", "owned-by-a"))
	mustCreateOwner(t, s, "owner-b")

	// Owner B tries to hang a key off owner A's device.
	k := newPublicKey("k-foreign", "owner-b", "d-a")
	err := s.Repos().PublicKeys.Create(ctx, k)
	if err == nil {
		t.Fatal("Create with another owner's device succeeded; the composite FK did not hold")
	}
	if errors.Is(err, domain.ErrConflict) {
		t.Errorf("foreign-key violation mapped to ErrConflict (%v); it must fall through to a generic wrap", err)
	}
}

func TestPublicKeyListByOwner(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	mustCreatePublicKey(t, s, newPublicKey("k-c", "owner-a", "d-1"))
	mustCreatePublicKey(t, s, newPublicKey("k-a", "owner-a", "d-1"))
	mustCreatePublicKey(t, s, newPublicKey("k-b", "owner-a", "d-1"))
	mustCreatePublicKey(t, s, newPublicKey("k-other", "owner-b", "d-2"))

	got, err := s.Repos().PublicKeys.ListByOwner(ctx, "owner-a")
	if err != nil {
		t.Fatalf("ListByOwner: %v", err)
	}
	want := []domain.PublicKeyID{"k-a", "k-b", "k-c"}
	if len(got) != len(want) {
		t.Fatalf("ListByOwner returned %d keys, want %d", len(got), len(want))
	}
	for i, id := range want {
		if got[i].ID != id {
			t.Errorf("ListByOwner[%d].ID = %q, want %q", i, got[i].ID, id)
		}
	}
}

func TestPublicKeyListByOwnerEmptyReturnsNilSlice(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	mustCreateOwner(t, s, "owner-empty")

	got, err := s.Repos().PublicKeys.ListByOwner(context.Background(), "owner-empty")
	if err != nil {
		t.Fatalf("ListByOwner: %v", err)
	}
	if got != nil {
		t.Errorf("ListByOwner = %v, want nil slice", got)
	}
}

func TestPublicKeyListByDevice(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	mustCreatePublicKey(t, s, newPublicKey("k-1", "owner-a", "d-1"))
	mustCreatePublicKey(t, s, newPublicKey("k-2", "owner-a", "d-2"))
	mustCreatePublicKey(t, s, newPublicKey("k-3", "owner-a", "d-1"))

	got, err := s.Repos().PublicKeys.ListByDevice(ctx, "owner-a", "d-1")
	if err != nil {
		t.Fatalf("ListByDevice: %v", err)
	}
	if len(got) != 2 || got[0].ID != "k-1" || got[1].ID != "k-3" {
		t.Fatalf("ListByDevice = %+v, want k-1 and k-3", got)
	}
}

func TestPublicKeyListByDeviceEmptyReturnsNilSlice(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	mustCreateDevice(t, s, newDevice("d-bare", "owner-a", "bare"))

	got, err := s.Repos().PublicKeys.ListByDevice(context.Background(), "owner-a", "d-bare")
	if err != nil {
		t.Fatalf("ListByDevice: %v", err)
	}
	if got != nil {
		t.Errorf("ListByDevice = %v, want nil slice", got)
	}
}

func TestPublicKeyGetByFingerprint(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	mustCreatePublicKey(t, s, newPublicKey("k-1", "owner-a", "d-1"))

	got, err := s.Repos().PublicKeys.GetByFingerprint(ctx, "owner-a", "SHA256:k-1")
	if err != nil {
		t.Fatalf("GetByFingerprint: %v", err)
	}
	if got.ID != "k-1" {
		t.Errorf("GetByFingerprint.ID = %q, want k-1", got.ID)
	}

	if _, err := s.Repos().PublicKeys.GetByFingerprint(ctx, "owner-a", "SHA256:absent"); !errors.Is(err, domain.ErrNotFound) {
		t.Errorf("GetByFingerprint miss = %v, want ErrNotFound", err)
	}
}

func TestPublicKeyRevoke(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	mustCreatePublicKey(t, s, newPublicKey("k-1", "owner-a", "d-1"))
	at := testClock.Add(3 * time.Hour)
	if err := s.Repos().PublicKeys.Revoke(ctx, "owner-a", "k-1", at); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	got, err := s.Repos().PublicKeys.Get(ctx, "owner-a", "k-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Status != domain.KeyStatusRevoked {
		t.Errorf("Status = %q, want revoked", got.Status)
	}
	if got.RevokedAt == nil || !got.RevokedAt.Equal(at) || !got.UpdatedAt.Equal(at) {
		t.Errorf("RevokedAt/UpdatedAt = %v/%v, want %v", got.RevokedAt, got.UpdatedAt, at)
	}
}

func TestPublicKeyRevokeMissingNotFound(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	mustCreateOwner(t, s, "owner-a")

	if err := s.Repos().PublicKeys.Revoke(context.Background(), "owner-a", "nope", testClock); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("Revoke missing = %v, want ErrNotFound", err)
	}
}

// TestPublicKeyRevokeByDevice checks the bulk path: only the owner's ACTIVE
// keys on that device are revoked, and the count reflects exactly those.
func TestPublicKeyRevokeByDevice(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	mustCreatePublicKey(t, s, newPublicKey("k-1", "owner-a", "d-1"))
	mustCreatePublicKey(t, s, newPublicKey("k-2", "owner-a", "d-1"))
	// A key on another device of the same owner must not be touched.
	mustCreatePublicKey(t, s, newPublicKey("k-3", "owner-a", "d-2"))
	// An already-revoked key on the target device is not counted again.
	already := newPublicKey("k-4", "owner-a", "d-1")
	already.Status = domain.KeyStatusRevoked
	mustCreatePublicKey(t, s, already)
	// Another owner's key must not be touched. Device ids are globally unique,
	// so owner B necessarily has its own device rather than a same-named one.
	mustCreatePublicKey(t, s, newPublicKey("k-other", "owner-b", "d-b"))

	at := testClock.Add(time.Hour)
	n, err := s.Repos().PublicKeys.RevokeByDevice(ctx, "owner-a", "d-1", at)
	if err != nil {
		t.Fatalf("RevokeByDevice: %v", err)
	}
	if n != 2 {
		t.Errorf("RevokeByDevice revoked %d keys, want 2", n)
	}

	for _, id := range []domain.PublicKeyID{"k-1", "k-2"} {
		got, gerr := s.Repos().PublicKeys.Get(ctx, "owner-a", id)
		if gerr != nil {
			t.Fatalf("Get %q: %v", id, gerr)
		}
		if got.Status != domain.KeyStatusRevoked || got.RevokedAt == nil || !got.RevokedAt.Equal(at) {
			t.Errorf("key %q = %+v, want revoked at %v", id, got, at)
		}
	}
	untouched, err := s.Repos().PublicKeys.Get(ctx, "owner-a", "k-3")
	if err != nil {
		t.Fatalf("Get k-3: %v", err)
	}
	if untouched.Status != domain.KeyStatusActive {
		t.Errorf("key on another device was revoked: %+v", untouched)
	}
	foreign, err := s.Repos().PublicKeys.Get(ctx, "owner-b", "k-other")
	if err != nil {
		t.Fatalf("Get k-other: %v", err)
	}
	if foreign.Status != domain.KeyStatusActive {
		t.Errorf("another owner's key was revoked: %+v", foreign)
	}
}

// TestPublicKeyRevokeByDeviceZeroWhenNone pins that touching no rows is not an
// error.
func TestPublicKeyRevokeByDeviceZeroWhenNone(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	mustCreateDevice(t, s, newDevice("d-bare", "owner-a", "bare"))

	n, err := s.Repos().PublicKeys.RevokeByDevice(context.Background(), "owner-a", "d-bare", testClock)
	if err != nil {
		t.Fatalf("RevokeByDevice: %v", err)
	}
	if n != 0 {
		t.Errorf("RevokeByDevice = %d, want 0", n)
	}
}

// TestPublicKeyCrossTenantIsolation is the core security invariant: owner B must
// never observe or mutate owner A's key through any owner-scoped method.
func TestPublicKeyCrossTenantIsolation(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	mustCreatePublicKey(t, s, newPublicKey("k-secret", "owner-a", "d-1"))
	mustCreateOwner(t, s, "owner-b")

	if got, err := s.Repos().PublicKeys.Get(ctx, "owner-b", "k-secret"); !errors.Is(err, domain.ErrNotFound) || got != nil {
		t.Fatalf("cross-tenant Get = (%v, %v), want (nil, ErrNotFound)", got, err)
	}
	if got, err := s.Repos().PublicKeys.GetByFingerprint(ctx, "owner-b", "SHA256:k-secret"); !errors.Is(err, domain.ErrNotFound) || got != nil {
		t.Fatalf("cross-tenant GetByFingerprint = (%v, %v), want (nil, ErrNotFound)", got, err)
	}
	if got, err := s.Repos().PublicKeys.ListByOwner(ctx, "owner-b"); err != nil || len(got) != 0 {
		t.Fatalf("cross-tenant ListByOwner = (%v, %v), want (empty, nil)", got, err)
	}
	if got, err := s.Repos().PublicKeys.ListByDevice(ctx, "owner-b", "d-1"); err != nil || len(got) != 0 {
		t.Fatalf("cross-tenant ListByDevice = (%v, %v), want (empty, nil)", got, err)
	}

	rerr := s.Repos().PublicKeys.Revoke(ctx, "owner-b", "k-secret", testClock.Add(time.Hour))
	if !errors.Is(rerr, domain.ErrNotFound) || errors.Is(rerr, domain.ErrConflict) {
		t.Fatalf("cross-tenant Revoke error = %v, want ErrNotFound", rerr)
	}
	n, berr := s.Repos().PublicKeys.RevokeByDevice(ctx, "owner-b", "d-1", testClock.Add(time.Hour))
	if berr != nil || n != 0 {
		t.Fatalf("cross-tenant RevokeByDevice = (%d, %v), want (0, nil)", n, berr)
	}

	// Sanity: A's key is untouched and still active.
	got, err := s.Repos().PublicKeys.Get(ctx, "owner-a", "k-secret")
	if err != nil {
		t.Fatalf("owner A Get after cross-tenant attempts: %v", err)
	}
	if got.Status != domain.KeyStatusActive || got.RevokedAt != nil {
		t.Errorf("owner A key mutated by cross-tenant revoke: %+v", got)
	}
}

// TestPublicKeyMissingAndWrongOwnerIndistinguishable is the existence-leak
// guard: a missing key and another owner's key must produce identical errors.
func TestPublicKeyMissingAndWrongOwnerIndistinguishable(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	mustCreatePublicKey(t, s, newPublicKey("k-real", "owner-a", "d-1"))
	mustCreateOwner(t, s, "owner-b")

	_, wrongOwner := s.Repos().PublicKeys.Get(ctx, "owner-b", "k-real")
	_, missing := s.Repos().PublicKeys.Get(ctx, "owner-b", "k-does-not-exist")
	if wrongOwner == nil || missing == nil {
		t.Fatal("expected errors from both lookups")
	}
	if wrongOwner.Error() != missing.Error() {
		t.Errorf("wrong-owner error %q differs from missing-row error %q; existence leaks",
			wrongOwner, missing)
	}

	revWrongOwner := s.Repos().PublicKeys.Revoke(ctx, "owner-b", "k-real", testClock)
	revMissing := s.Repos().PublicKeys.Revoke(ctx, "owner-b", "k-nope", testClock)
	if revWrongOwner == nil || revMissing == nil {
		t.Fatal("expected errors from both revokes")
	}
	if revWrongOwner.Error() != revMissing.Error() {
		t.Errorf("wrong-owner Revoke error %q differs from missing-row error %q; existence leaks",
			revWrongOwner, revMissing)
	}
}

// TestPublicKeyQueryErrorsMapped drives the driver-error branches of the read
// and write paths with an already-canceled context.
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
	if _, err := s.Repos().PublicKeys.GetByFingerprint(ctx, "owner-a", "SHA256:k-1"); err == nil {
		t.Error("GetByFingerprint on canceled ctx: nil error")
	}
	if _, err := s.Repos().PublicKeys.ListByOwner(ctx, "owner-a"); err == nil {
		t.Error("ListByOwner on canceled ctx: nil error")
	}
	if _, err := s.Repos().PublicKeys.ListByDevice(ctx, "owner-a", "d-1"); err == nil {
		t.Error("ListByDevice on canceled ctx: nil error")
	}
	if _, err := s.Repos().PublicKeys.ListActiveByKeySet(ctx, "owner-a", "ks-1"); err == nil {
		t.Error("ListActiveByKeySet on canceled ctx: nil error")
	}
	if err := s.Repos().PublicKeys.Revoke(ctx, "owner-a", "k-1", testClock); err == nil {
		t.Error("Revoke on canceled ctx: nil error")
	}
	if _, err := s.Repos().PublicKeys.RevokeByDevice(ctx, "owner-a", "d-1", testClock); err == nil {
		t.Error("RevokeByDevice on canceled ctx: nil error")
	}
}

// TestPublicKeyErrorLeaksNoSQL asserts that a mapped conflict error carries a
// domain sentinel and no SQL text, table name, or Postgres constraint name.
func TestPublicKeyErrorLeaksNoSQL(t *testing.T) {
	t.Parallel()
	s := newStore(t)

	mustCreatePublicKey(t, s, newPublicKey("leak", "owner-a", "d-1"))
	err := s.Repos().PublicKeys.Create(context.Background(), newPublicKey("leak", "owner-a", "d-1"))
	if !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("duplicate error = %v, want ErrConflict", err)
	}
	msg := strings.ToUpper(err.Error())
	for _, leak := range []string{"INSERT", "SELECT", "PUBLIC_KEYS", "FINGERPRINT", "UNIQUE", "PRIMARY KEY", "23505"} {
		if strings.Contains(msg, leak) {
			t.Errorf("error message %q leaks SQL fragment %q", err.Error(), leak)
		}
	}
}
