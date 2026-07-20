package postgres

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
)

// newDevice returns a fully populated active device owned by ownerID with a nil
// RevokedAt.
func newDevice(id, ownerID, name string) *domain.Device {
	return &domain.Device{
		ID:        domain.DeviceID(id),
		OwnerID:   domain.OwnerID(ownerID),
		Name:      name,
		Status:    domain.DeviceStatusActive,
		CreatedAt: testClock,
		UpdatedAt: testClock,
	}
}

// mustCreateDevice creates the owner (if needed) and the device, failing the
// test on error.
func mustCreateDevice(t *testing.T, s *Store, d *domain.Device) {
	t.Helper()
	ctx := context.Background()
	if _, err := s.Repos().Owners.Get(ctx, d.OwnerID); errors.Is(err, domain.ErrNotFound) {
		mustCreateOwner(t, s, string(d.OwnerID))
	}
	if err := s.Repos().Devices.Create(ctx, d); err != nil {
		t.Fatalf("Create device %q: %v", d.ID, err)
	}
}

func TestDeviceCreateAndGet(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	want := newDevice("d-1", "owner-a", "laptop")
	mustCreateDevice(t, s, want)

	got, err := s.Repos().Devices.Get(ctx, "owner-a", "d-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.ID != want.ID || got.OwnerID != want.OwnerID || got.Name != want.Name || got.Status != want.Status {
		t.Errorf("Get = %+v, want id/owner/name/status d-1/owner-a/laptop/active", got)
	}
	if !got.CreatedAt.Equal(want.CreatedAt) || !got.UpdatedAt.Equal(want.UpdatedAt) {
		t.Errorf("timestamps round-trip mismatch: got %v/%v", got.CreatedAt, got.UpdatedAt)
	}
	if got.CreatedAt.Location() != time.UTC {
		t.Errorf("CreatedAt location = %v, want UTC", got.CreatedAt.Location())
	}
	if got.RevokedAt != nil {
		t.Errorf("RevokedAt = %v, want nil", got.RevokedAt)
	}
}

func TestDeviceCreateWithRevokedAtRoundTrips(t *testing.T) {
	t.Parallel()
	s := newStore(t)

	d := newDevice("d-rev", "owner-a", "old")
	d.Status = domain.DeviceStatusRevoked
	revoked := testClock.Add(2 * time.Hour)
	d.RevokedAt = &revoked
	mustCreateDevice(t, s, d)

	got, err := s.Repos().Devices.Get(context.Background(), "owner-a", "d-rev")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.RevokedAt == nil || !got.RevokedAt.Equal(revoked) {
		t.Errorf("RevokedAt = %v, want %v", got.RevokedAt, revoked)
	}
	if got.Status != domain.DeviceStatusRevoked {
		t.Errorf("Status = %q, want revoked", got.Status)
	}
}

func TestDeviceGetMissingNotFound(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	mustCreateOwner(t, s, "owner-a")

	if _, err := s.Repos().Devices.Get(context.Background(), "owner-a", "nope"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("Get missing = %v, want ErrNotFound", err)
	}
}

func TestDeviceCreateDuplicateConflict(t *testing.T) {
	t.Parallel()
	s := newStore(t)

	mustCreateDevice(t, s, newDevice("d-dup", "owner-a", "first"))
	err := s.Repos().Devices.Create(context.Background(), newDevice("d-dup", "owner-a", "second"))
	if !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("duplicate Create = %v, want ErrConflict", err)
	}
}

// TestDeviceCreateNilInvalidInput pins the nil guard: a nil entity is a caller
// programming error reported as ErrInvalidInput, never a panic.
func TestDeviceCreateNilInvalidInput(t *testing.T) {
	t.Parallel()
	s := newStore(t)

	if err := s.Repos().Devices.Create(context.Background(), nil); !errors.Is(err, domain.ErrInvalidInput) {
		t.Errorf("Create(nil) = %v, want ErrInvalidInput", err)
	}
}

func TestDeviceListByOwner(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	// Inserted out of order so the id ordering of the result is meaningful.
	mustCreateDevice(t, s, newDevice("d-c", "owner-a", "third"))
	mustCreateDevice(t, s, newDevice("d-a", "owner-a", "first"))
	mustCreateDevice(t, s, newDevice("d-b", "owner-a", "second"))

	got, err := s.Repos().Devices.ListByOwner(ctx, "owner-a")
	if err != nil {
		t.Fatalf("ListByOwner: %v", err)
	}
	want := []domain.DeviceID{"d-a", "d-b", "d-c"}
	if len(got) != len(want) {
		t.Fatalf("ListByOwner returned %d devices, want %d", len(got), len(want))
	}
	for i, id := range want {
		if got[i].ID != id {
			t.Errorf("ListByOwner[%d].ID = %q, want %q", i, got[i].ID, id)
		}
	}
}

// TestDeviceListByOwnerEmptyReturnsNilSlice pins the empty-list convention: an
// owner with no devices yields a nil slice, not an allocated empty one.
func TestDeviceListByOwnerEmptyReturnsNilSlice(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	mustCreateOwner(t, s, "owner-empty")

	got, err := s.Repos().Devices.ListByOwner(context.Background(), "owner-empty")
	if err != nil {
		t.Fatalf("ListByOwner: %v", err)
	}
	if got != nil {
		t.Errorf("ListByOwner = %v, want nil slice", got)
	}
}

func TestDeviceRename(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	mustCreateDevice(t, s, newDevice("d-1", "owner-a", "before"))
	later := testClock.Add(time.Hour)
	if err := s.Repos().Devices.Rename(ctx, "owner-a", "d-1", "after", later); err != nil {
		t.Fatalf("Rename: %v", err)
	}

	got, err := s.Repos().Devices.Get(ctx, "owner-a", "d-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Name != "after" {
		t.Errorf("Name = %q, want after", got.Name)
	}
	if !got.UpdatedAt.Equal(later) {
		t.Errorf("UpdatedAt = %v, want %v", got.UpdatedAt, later)
	}
	if !got.CreatedAt.Equal(testClock) {
		t.Errorf("CreatedAt = %v, want unchanged %v", got.CreatedAt, testClock)
	}
}

func TestDeviceRenameMissingNotFound(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	mustCreateOwner(t, s, "owner-a")

	err := s.Repos().Devices.Rename(context.Background(), "owner-a", "nope", "x", testClock)
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("Rename missing = %v, want ErrNotFound", err)
	}
}

func TestDeviceRevoke(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	mustCreateDevice(t, s, newDevice("d-1", "owner-a", "laptop"))
	at := testClock.Add(3 * time.Hour)
	if err := s.Repos().Devices.Revoke(ctx, "owner-a", "d-1", at); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	got, err := s.Repos().Devices.Get(ctx, "owner-a", "d-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Status != domain.DeviceStatusRevoked {
		t.Errorf("Status = %q, want revoked", got.Status)
	}
	if got.RevokedAt == nil || !got.RevokedAt.Equal(at) {
		t.Errorf("RevokedAt = %v, want %v", got.RevokedAt, at)
	}
	if !got.UpdatedAt.Equal(at) {
		t.Errorf("UpdatedAt = %v, want %v", got.UpdatedAt, at)
	}
}

func TestDeviceRevokeMissingNotFound(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	mustCreateOwner(t, s, "owner-a")

	err := s.Repos().Devices.Revoke(context.Background(), "owner-a", "nope", testClock)
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("Revoke missing = %v, want ErrNotFound", err)
	}
}

// TestDeviceCrossTenantIsolation is the core security invariant: owner B must
// never observe or mutate owner A's device through any owner-scoped method, and
// every such access must be reported as domain.ErrNotFound — never the row, and
// never a different error that would confirm the row's existence.
func TestDeviceCrossTenantIsolation(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	// Owner A owns the device; owner B exists but owns nothing.
	mustCreateDevice(t, s, newDevice("d-secret", "owner-a", "secret"))
	mustCreateOwner(t, s, "owner-b")

	// Scoped Get by B for A's device id -> ErrNotFound, no row.
	if got, err := s.Repos().Devices.Get(ctx, "owner-b", "d-secret"); !errors.Is(err, domain.ErrNotFound) || got != nil {
		t.Fatalf("cross-tenant Get = (%v, %v), want (nil, ErrNotFound)", got, err)
	}

	// ListByOwner for B -> empty, never A's row.
	if got, err := s.Repos().Devices.ListByOwner(ctx, "owner-b"); err != nil || len(got) != 0 {
		t.Fatalf("cross-tenant ListByOwner = (%v, %v), want (empty, nil)", got, err)
	}

	// Rename by B on A's device -> ErrNotFound, NOT ErrConflict.
	rerr := s.Repos().Devices.Rename(ctx, "owner-b", "d-secret", "hijacked", testClock.Add(time.Hour))
	if !errors.Is(rerr, domain.ErrNotFound) || errors.Is(rerr, domain.ErrConflict) {
		t.Fatalf("cross-tenant Rename error = %v, want ErrNotFound", rerr)
	}

	// Revoke by B on A's device -> ErrNotFound, NOT ErrConflict.
	verr := s.Repos().Devices.Revoke(ctx, "owner-b", "d-secret", testClock.Add(time.Hour))
	if !errors.Is(verr, domain.ErrNotFound) || errors.Is(verr, domain.ErrConflict) {
		t.Fatalf("cross-tenant Revoke error = %v, want ErrNotFound", verr)
	}

	// Sanity: A's row is completely unmutated by B's attempts.
	got, err := s.Repos().Devices.Get(ctx, "owner-a", "d-secret")
	if err != nil {
		t.Fatalf("owner A Get after cross-tenant attempts: %v", err)
	}
	if got.Name != "secret" {
		t.Errorf("owner A device name mutated to %q by cross-tenant Rename", got.Name)
	}
	if got.Status != domain.DeviceStatusActive {
		t.Errorf("owner A device status mutated to %q by cross-tenant Revoke", got.Status)
	}
	if got.RevokedAt != nil {
		t.Errorf("owner A device RevokedAt mutated to %v by cross-tenant Revoke", got.RevokedAt)
	}
}

// TestDeviceMissingAndWrongOwnerIndistinguishable is the existence-leak guard
// stated directly: a lookup for a device that does not exist at all and one for
// a device that exists under another owner must return the identical error
// value, so a caller cannot tell the two apart.
func TestDeviceMissingAndWrongOwnerIndistinguishable(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	mustCreateDevice(t, s, newDevice("d-real", "owner-a", "real"))
	mustCreateOwner(t, s, "owner-b")

	_, wrongOwner := s.Repos().Devices.Get(ctx, "owner-b", "d-real")
	_, missing := s.Repos().Devices.Get(ctx, "owner-b", "d-does-not-exist")
	if wrongOwner == nil || missing == nil {
		t.Fatal("expected errors from both lookups")
	}
	if wrongOwner.Error() != missing.Error() {
		t.Errorf("wrong-owner error %q differs from missing-row error %q; existence leaks",
			wrongOwner, missing)
	}

	renWrongOwner := s.Repos().Devices.Rename(ctx, "owner-b", "d-real", "x", testClock)
	renMissing := s.Repos().Devices.Rename(ctx, "owner-b", "d-nope", "x", testClock)
	if renWrongOwner == nil || renMissing == nil {
		t.Fatal("expected errors from both renames")
	}
	if renWrongOwner.Error() != renMissing.Error() {
		t.Errorf("wrong-owner Rename error %q differs from missing-row error %q; existence leaks",
			renWrongOwner, renMissing)
	}
}

// TestDeviceQueryErrorsMapped drives the driver-error branches of the read and
// write paths with an already-canceled context: every method must surface a
// wrapped error (never a nil error with partial data) through mapError.
func TestDeviceQueryErrorsMapped(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	mustCreateDevice(t, s, newDevice("d-1", "owner-a", "n1"))

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := s.Repos().Devices.Create(ctx, newDevice("d-2", "owner-a", "n2")); err == nil {
		t.Error("Create on canceled ctx: nil error")
	}
	if _, err := s.Repos().Devices.Get(ctx, "owner-a", "d-1"); err == nil {
		t.Error("Get on canceled ctx: nil error")
	}
	if _, err := s.Repos().Devices.ListByOwner(ctx, "owner-a"); err == nil {
		t.Error("ListByOwner on canceled ctx: nil error")
	}
	if err := s.Repos().Devices.Rename(ctx, "owner-a", "d-1", "x", testClock); err == nil {
		t.Error("Rename on canceled ctx: nil error")
	}
	if err := s.Repos().Devices.Revoke(ctx, "owner-a", "d-1", testClock); err == nil {
		t.Error("Revoke on canceled ctx: nil error")
	}
}

// TestDeviceErrorLeaksNoSQL asserts that a mapped conflict error carries a
// domain sentinel and no SQL text, table name, or Postgres constraint name.
func TestDeviceErrorLeaksNoSQL(t *testing.T) {
	t.Parallel()
	s := newStore(t)

	mustCreateDevice(t, s, newDevice("leak", "owner-a", "first"))
	err := s.Repos().Devices.Create(context.Background(), newDevice("leak", "owner-a", "second"))
	if !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("duplicate error = %v, want ErrConflict", err)
	}
	msg := strings.ToUpper(err.Error())
	for _, leak := range []string{"INSERT", "SELECT", "UPDATE", "DEVICES", "UNIQUE", "PRIMARY KEY", "23505"} {
		if strings.Contains(msg, leak) {
			t.Errorf("error message %q leaks SQL fragment %q", err.Error(), leak)
		}
	}
}
