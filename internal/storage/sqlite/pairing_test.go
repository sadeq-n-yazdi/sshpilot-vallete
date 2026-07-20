package sqlite

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
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
		t.Errorf("owner = %q, want empty for a pending pairing", got.OwnerID)
	}
	if string(got.DeviceCodeHash) != string(want.DeviceCodeHash) {
		t.Errorf("device code hash = %q, want %q", got.DeviceCodeHash, want.DeviceCodeHash)
	}
	if string(got.UserCodeHash) != string(want.UserCodeHash) {
		t.Errorf("user code hash = %q, want %q", got.UserCodeHash, want.UserCodeHash)
	}
	if len(got.Scopes) != 1 || got.Scopes[0].Kind != domain.ScopeReadOnly {
		t.Errorf("scopes = %v, want [read-only]", got.Scopes)
	}
	if got.ClientLabel != "laptop" {
		t.Errorf("client label = %q, want laptop", got.ClientLabel)
	}
	if !got.ExpiresAt.Equal(want.ExpiresAt) || !got.NextPollAt.Equal(testClock) {
		t.Errorf("timestamps = %v/%v", got.ExpiresAt, got.NextPollAt)
	}
	if got.ApprovedAt != nil || got.RedeemedAt != nil || got.RevokedAt != nil {
		t.Error("pending pairing has a lifecycle timestamp set")
	}
}

func TestPairingCreateRejectsNil(t *testing.T) {
	t.Parallel()
	s := newStore(t)

	if err := s.Repos().DevicePairings.Create(context.Background(), nil); !errors.Is(err, domain.ErrInvalidInput) {
		t.Fatalf("Create(nil) = %v, want ErrInvalidInput", err)
	}
}

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

	if _, err := s.Repos().DevicePairings.GetByID(context.Background(), "absent"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("missing = %v, want ErrNotFound", err)
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

	// The NULL row really is there and really has no user code hash.
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

func TestPairingGetIsOwnerScoped(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	mustCreateOwner(t, s, "o-1")
	mustCreateOwner(t, s, "o-2")
	mustApprove(t, s, "p-1", "o-1")

	if _, err := s.Repos().DevicePairings.Get(ctx, "o-1", "p-1"); err != nil {
		t.Fatalf("owner Get: %v", err)
	}
	// The other owner gets the same answer as for an id that does not exist.
	if _, err := s.Repos().DevicePairings.Get(ctx, "o-2", "p-1"); !errors.Is(err, domain.ErrNotFound) {
		t.Errorf("cross-owner Get = %v, want ErrNotFound", err)
	}
	if _, err := s.Repos().DevicePairings.Get(ctx, "o-2", "absent"); !errors.Is(err, domain.ErrNotFound) {
		t.Errorf("missing Get = %v, want ErrNotFound", err)
	}
}

func TestPairingListByOwnerIsScopedAndOrdered(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	mustCreateOwner(t, s, "o-1")
	mustCreateOwner(t, s, "o-2")
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
}

// A pending pairing has no owner, so it must not surface in any owner's list.
func TestPairingListByOwnerExcludesPending(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	mustCreateOwner(t, s, "o-1")
	mustCreatePairing(t, s, newPairing("p-pending"))

	got, err := s.Repos().DevicePairings.ListByOwner(ctx, "o-1")
	if err != nil {
		t.Fatalf("ListByOwner: %v", err)
	}
	if got != nil {
		t.Errorf("list = %v, want nil", got)
	}
}
