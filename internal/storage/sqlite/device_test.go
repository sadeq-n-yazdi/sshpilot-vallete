package sqlite

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
	if got.RevokedAt != nil {
		t.Errorf("RevokedAt = %v, want nil", got.RevokedAt)
	}
}

func TestDeviceCreateWithRevokedAtRoundTrips(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	revoked := testClock.Add(3 * time.Hour)
	d := newDevice("d-rev", "owner-a", "retired")
	d.Status = domain.DeviceStatusRevoked
	d.RevokedAt = &revoked
	mustCreateDevice(t, s, d)

	got, err := s.Repos().Devices.Get(ctx, "owner-a", "d-rev")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Status != domain.DeviceStatusRevoked {
		t.Errorf("Status = %q, want revoked", got.Status)
	}
	if got.RevokedAt == nil || !got.RevokedAt.Equal(revoked) {
		t.Errorf("RevokedAt = %v, want %v", got.RevokedAt, revoked)
	}
}

func TestDeviceGetMissingNotFound(t *testing.T) {
	t.Parallel()
	s := newStore(t)

	mustCreateOwner(t, s, "owner-a")
	_, err := s.Repos().Devices.Get(context.Background(), "owner-a", "ghost")
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("Get missing error = %v, want ErrNotFound", err)
	}
}

func TestDeviceCreateDuplicateConflict(t *testing.T) {
	t.Parallel()
	s := newStore(t)

	mustCreateDevice(t, s, newDevice("dup", "owner-a", "first"))
	// Same primary key id -> PRIMARY KEY violation -> ErrConflict.
	err := s.Repos().Devices.Create(context.Background(), newDevice("dup", "owner-a", "second"))
	if !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("duplicate Create error = %v, want ErrConflict", err)
	}
}

func TestDeviceListByOwner(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	// Insert out of id order to prove ORDER BY id ASC is applied.
	mustCreateDevice(t, s, newDevice("d-3", "owner-a", "n3"))
	mustCreateDevice(t, s, newDevice("d-1", "owner-a", "n1"))
	mustCreateDevice(t, s, newDevice("d-2", "owner-a", "n2"))
	mustCreateDevice(t, s, newDevice("d-x", "owner-b", "other"))

	got, err := s.Repos().Devices.ListByOwner(ctx, "owner-a")
	if err != nil {
		t.Fatalf("ListByOwner: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("ListByOwner returned %d rows, want 3 (owner-a only)", len(got))
	}
	wantOrder := []domain.DeviceID{"d-1", "d-2", "d-3"}
	for i := range got {
		if got[i].OwnerID != "owner-a" {
			t.Errorf("ListByOwner leaked row for owner %q", got[i].OwnerID)
		}
		if got[i].ID != wantOrder[i] {
			t.Errorf("ListByOwner[%d] id = %q, want %q (ascending)", i, got[i].ID, wantOrder[i])
		}
	}
}

func TestDeviceListByOwnerEmpty(t *testing.T) {
	t.Parallel()
	s := newStore(t)

	mustCreateOwner(t, s, "owner-empty")
	got, err := s.Repos().Devices.ListByOwner(context.Background(), "owner-empty")
	if err != nil {
		t.Fatalf("ListByOwner: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("ListByOwner = %d rows, want empty", len(got))
	}
}

func TestDeviceRename(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	mustCreateDevice(t, s, newDevice("d-ren", "owner-a", "old-name"))
	later := testClock.Add(time.Hour)
	if err := s.Repos().Devices.Rename(ctx, "owner-a", "d-ren", "new-name", later); err != nil {
		t.Fatalf("Rename: %v", err)
	}

	got, err := s.Repos().Devices.Get(ctx, "owner-a", "d-ren")
	if err != nil {
		t.Fatalf("Get after Rename: %v", err)
	}
	if got.Name != "new-name" {
		t.Errorf("Name = %q, want new-name", got.Name)
	}
	if !got.UpdatedAt.Equal(later) {
		t.Errorf("UpdatedAt = %v, want %v", got.UpdatedAt, later)
	}
}

func TestDeviceRenameMissingNotFound(t *testing.T) {
	t.Parallel()
	s := newStore(t)

	mustCreateOwner(t, s, "owner-a")
	err := s.Repos().Devices.Rename(context.Background(), "owner-a", "ghost", "x", testClock)
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("Rename missing error = %v, want ErrNotFound", err)
	}
}

func TestDeviceRevoke(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	mustCreateDevice(t, s, newDevice("d-rv", "owner-a", "doomed"))
	later := testClock.Add(2 * time.Hour)
	if err := s.Repos().Devices.Revoke(ctx, "owner-a", "d-rv", later); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	got, err := s.Repos().Devices.Get(ctx, "owner-a", "d-rv")
	if err != nil {
		t.Fatalf("Get after Revoke: %v", err)
	}
	if got.Status != domain.DeviceStatusRevoked {
		t.Errorf("Status = %q, want revoked", got.Status)
	}
	if got.RevokedAt == nil || !got.RevokedAt.Equal(later) {
		t.Errorf("RevokedAt = %v, want %v", got.RevokedAt, later)
	}
	if !got.UpdatedAt.Equal(later) {
		t.Errorf("UpdatedAt = %v, want %v", got.UpdatedAt, later)
	}
}

func TestDeviceRevokeMissingNotFound(t *testing.T) {
	t.Parallel()
	s := newStore(t)

	mustCreateOwner(t, s, "owner-a")
	err := s.Repos().Devices.Revoke(context.Background(), "owner-a", "ghost", testClock)
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("Revoke missing error = %v, want ErrNotFound", err)
	}
}

// TestDeviceCrossTenantIsolation is the core security invariant: owner B must
// never observe or mutate owner A's device through any owner-scoped method.
// Every such access must report domain.ErrNotFound (never ErrConflict, never
// the row) and must leave A's row completely unmutated.
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

// TestDeviceDecodeErrorsSurface drives the timestamp-decode failure branches in
// scanDevice and collectDevices by planting a row with a malformed created_at
// directly, bypassing encTime. Both the single-row read (Get) and the iteration
// read (ListByOwner) must surface the decode error rather than silently succeed.
func TestDeviceDecodeErrorsSurface(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	mustCreateOwner(t, s, "owner-a")
	const ins = `INSERT INTO devices (id, owner_id, name, status, created_at, updated_at, revoked_at)
VALUES (?, ?, ?, ?, ?, ?, ?)`
	good := encTime(testClock)
	// Each row corrupts exactly one timestamp column so every decode branch in
	// scanDevice (created_at, then updated_at, then revoked_at) is exercised.
	rows := []struct {
		id                            string
		createdAt, updatedAt, revoked any
	}{
		{"d-bad-created", "not-a-timestamp", good, nil},
		{"d-bad-updated", good, "not-a-timestamp", nil},
		{"d-bad-revoked", good, good, "not-a-timestamp"},
	}
	for _, r := range rows {
		if _, err := s.db.ExecContext(ctx, ins,
			r.id, "owner-a", "corrupt", string(domain.DeviceStatusActive),
			r.createdAt, r.updatedAt, r.revoked,
		); err != nil {
			t.Fatalf("plant malformed row %q: %v", r.id, err)
		}
		if _, err := s.Repos().Devices.Get(ctx, "owner-a", domain.DeviceID(r.id)); err == nil {
			t.Errorf("Get on malformed row %q: nil error", r.id)
		}
	}

	// The iteration path (collectDevices) must also surface a decode error.
	if _, err := s.Repos().Devices.ListByOwner(ctx, "owner-a"); err == nil {
		t.Error("ListByOwner over malformed rows: nil error")
	}
}

// TestDeviceErrorLeaksNoSQL asserts that a mapped conflict error carries a
// domain sentinel and no SQL text or table names.
func TestDeviceErrorLeaksNoSQL(t *testing.T) {
	t.Parallel()
	s := newStore(t)

	mustCreateDevice(t, s, newDevice("leak", "owner-a", "first"))
	err := s.Repos().Devices.Create(context.Background(), newDevice("leak", "owner-a", "second"))
	if !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("duplicate error = %v, want ErrConflict", err)
	}
	msg := strings.ToUpper(err.Error())
	for _, leak := range []string{"INSERT", "SELECT", "UPDATE", "DEVICES", "UNIQUE", "PRIMARY KEY"} {
		if strings.Contains(msg, leak) {
			t.Errorf("error message %q leaks SQL fragment %q", err.Error(), leak)
		}
	}
}

// TestRepoCreateRejectsNil verifies that the Create/Register entry points guard
// against a nil entity: a nil pointer is a caller programming error and must be
// reported as domain.ErrInvalidInput, never dereferenced into a panic.
func TestRepoCreateRejectsNil(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	repos := s.Repos()

	if err := repos.Devices.Create(ctx, nil); !errors.Is(err, domain.ErrInvalidInput) {
		t.Errorf("Devices.Create(nil) = %v, want ErrInvalidInput", err)
	}
	if err := repos.Owners.Create(ctx, nil); !errors.Is(err, domain.ErrInvalidInput) {
		t.Errorf("Owners.Create(nil) = %v, want ErrInvalidInput", err)
	}
	if err := repos.Handles.Register(ctx, nil); !errors.Is(err, domain.ErrInvalidInput) {
		t.Errorf("Handles.Register(nil) = %v, want ErrInvalidInput", err)
	}
}
