package auth_test

import (
	"context"
	"sync"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/repository"
)

// fakePairings is an in-memory DevicePairingRepository.
//
// It implements the one behavior the enrollment path depends on for
// correctness and which a weaker double would quietly grant: Approve and
// MarkRedeemed are CONDITIONAL, returning domain.ErrConflict when the row is
// not in the state the transition requires. Both take the store lock for the
// whole read-check-write, which is what a single conditional UPDATE gives on a
// real engine. Without that, the concurrency tests would pass against a fake
// that cannot fail.
type fakePairings struct {
	mu   sync.Mutex
	rows map[domain.PairingID]*domain.DevicePairing

	// Fault injection. Each is returned by the correspondingly named method.
	createErr      error
	getByIDErr     error
	getByUserErr   error
	approveErr     error
	markErr        error
	revokeErr      error
	touchErr       error
	listByOwnerErr error

	// nilRow makes GetByID return (nil, nil), the port violation the provider
	// must survive without dereferencing.
	nilRow bool
	// override replaces the row GetByID returns, so a test can simulate a store
	// that hands back a pairing other than the one asked for.
	override *domain.DevicePairing
	// nilOwnedRow makes the owner-scoped Get return (nil, nil), the port
	// violation an owner-scoped caller must survive without dereferencing.
	nilOwnedRow bool
}

var _ repository.DevicePairingRepository = (*fakePairings)(nil)

func newFakePairings() *fakePairings {
	return &fakePairings{rows: make(map[domain.PairingID]*domain.DevicePairing)}
}

func copyPairing(p *domain.DevicePairing) *domain.DevicePairing {
	if p == nil {
		return nil
	}
	cp := *p
	cp.DeviceCodeHash = append([]byte(nil), p.DeviceCodeHash...)
	cp.UserCodeHash = append([]byte(nil), p.UserCodeHash...)
	cp.Scopes = append([]domain.Scope(nil), p.Scopes...)
	for _, src := range []struct{ from, to **time.Time }{
		{&p.ApprovedAt, &cp.ApprovedAt},
		{&p.RedeemedAt, &cp.RedeemedAt},
		{&p.RevokedAt, &cp.RevokedAt},
	} {
		if *src.from != nil {
			t := **src.from
			*src.to = &t
		}
	}
	return &cp
}

func (f *fakePairings) Create(_ context.Context, p *domain.DevicePairing) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.createErr != nil {
		return f.createErr
	}
	if p == nil {
		return domain.ErrInvalidInput
	}
	if _, exists := f.rows[p.ID]; exists {
		return domain.ErrConflict
	}
	f.rows[p.ID] = copyPairing(p)
	return nil
}

func (f *fakePairings) GetByID(_ context.Context, id domain.PairingID) (*domain.DevicePairing, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.getByIDErr != nil {
		return nil, f.getByIDErr
	}
	if f.nilRow {
		return nil, nil //nolint:nilnil // deliberately models a port violation
	}
	if f.override != nil {
		return copyPairing(f.override), nil
	}
	p := f.rows[id]
	if p == nil {
		return nil, domain.ErrNotFound
	}
	return copyPairing(p), nil
}

func (f *fakePairings) GetByUserCodeHash(_ context.Context, hash []byte) (*domain.DevicePairing, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.getByUserErr != nil {
		return nil, f.getByUserErr
	}
	for _, p := range f.rows {
		if len(p.UserCodeHash) > 0 && string(p.UserCodeHash) == string(hash) {
			return copyPairing(p), nil
		}
	}
	return nil, domain.ErrNotFound
}

func (f *fakePairings) Get(_ context.Context, ownerID domain.OwnerID, id domain.PairingID) (*domain.DevicePairing, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.nilOwnedRow {
		return nil, nil //nolint:nilnil // deliberately models a port violation
	}
	p := f.rows[id]
	// A row belonging to another owner is reported exactly as a missing one.
	if p == nil || p.OwnerID != ownerID {
		return nil, domain.ErrNotFound
	}
	return copyPairing(p), nil
}

func (f *fakePairings) ListByOwner(_ context.Context, ownerID domain.OwnerID) ([]domain.DevicePairing, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.listByOwnerErr != nil {
		return nil, f.listByOwnerErr
	}
	var out []domain.DevicePairing
	for _, p := range f.rows {
		if p.OwnerID == ownerID {
			out = append(out, *copyPairing(p))
		}
	}
	return out, nil
}

// Approve implements the conditional transition the port specifies: it applies
// only to a pending pairing and reports domain.ErrConflict for any other state.
func (f *fakePairings) Approve(_ context.Context, id domain.PairingID, ownerID domain.OwnerID, now time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.approveErr != nil {
		return f.approveErr
	}
	p := f.rows[id]
	if p == nil {
		return domain.ErrNotFound
	}
	if p.Status != domain.PairingStatusPending {
		return domain.ErrConflict
	}
	p.Status = domain.PairingStatusApproved
	p.OwnerID = ownerID
	t := now
	p.ApprovedAt = &t
	return nil
}

// MarkRedeemed implements the conditional transition that makes a device code
// single-use: it applies only to an approved pairing owned by ownerID.
func (f *fakePairings) MarkRedeemed(_ context.Context, ownerID domain.OwnerID, id domain.PairingID, lineageID domain.LineageID, now time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.markErr != nil {
		return f.markErr
	}
	p := f.rows[id]
	if p == nil || p.OwnerID != ownerID {
		return domain.ErrNotFound
	}
	if p.Status != domain.PairingStatusApproved {
		return domain.ErrConflict
	}
	p.Status = domain.PairingStatusRedeemed
	p.LineageID = lineageID
	t := now
	p.RedeemedAt = &t
	return nil
}

func (f *fakePairings) Revoke(_ context.Context, ownerID domain.OwnerID, id domain.PairingID, now time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.revokeErr != nil {
		return f.revokeErr
	}
	p := f.rows[id]
	if p == nil || p.OwnerID != ownerID {
		return domain.ErrNotFound
	}
	if p.Status == domain.PairingStatusRevoked {
		return domain.ErrConflict
	}
	p.Status = domain.PairingStatusRevoked
	t := now
	p.RevokedAt = &t
	return nil
}

func (f *fakePairings) Touch(_ context.Context, id domain.PairingID, nextPollAt time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.touchErr != nil {
		return f.touchErr
	}
	p := f.rows[id]
	if p == nil {
		return domain.ErrNotFound
	}
	p.NextPollAt = nextPollAt
	return nil
}

func (f *fakePairings) DeleteExpired(context.Context, time.Time, int) (int64, error) { return 0, nil }

// snapshotOf returns a copy of a stored row so a test can inspect state after
// an operation.
func (f *fakePairings) snapshotOf(id domain.PairingID) *domain.DevicePairing {
	f.mu.Lock()
	defer f.mu.Unlock()
	return copyPairing(f.rows[id])
}

// fakeLinkStore is a writable LinkedIdentityRepository.
//
// fakeLinks, which the authenticator tests use, is deliberately read-only: it
// exists to exercise resolution against a fixed set of rows. The enrollment
// service creates links, and the tests need to read back, repoint and remove
// them, so it gets a store of its own rather than making the other fake mutable
// for everyone.
type fakeLinkStore struct {
	mu   sync.Mutex
	rows map[linkKey]*domain.LinkedIdentity
	err  error
}

var _ repository.LinkedIdentityRepository = (*fakeLinkStore)(nil)

func newFakeLinkStore() *fakeLinkStore {
	return &fakeLinkStore{rows: make(map[linkKey]*domain.LinkedIdentity)}
}

func (f *fakeLinkStore) Create(_ context.Context, li *domain.LinkedIdentity) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	if li == nil {
		return domain.ErrInvalidInput
	}
	k := linkKey{provider: li.Provider, subject: li.Subject}
	if _, exists := f.rows[k]; exists {
		return domain.ErrConflict
	}
	cp := *li
	f.rows[k] = &cp
	return nil
}

func (f *fakeLinkStore) GetByProviderSubject(_ context.Context, provider, subject string) (*domain.LinkedIdentity, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	li, ok := f.rows[linkKey{provider: provider, subject: subject}]
	if !ok {
		return nil, domain.ErrNotFound
	}
	cp := *li
	return &cp, nil
}

func (f *fakeLinkStore) ListByOwner(_ context.Context, ownerID domain.OwnerID) ([]domain.LinkedIdentity, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []domain.LinkedIdentity
	for _, li := range f.rows {
		if li.OwnerID == ownerID {
			out = append(out, *li)
		}
	}
	return out, nil
}

func (f *fakeLinkStore) Delete(context.Context, domain.OwnerID, domain.LinkedIdentityID) error {
	return nil
}

func (f *fakeLinkStore) DeleteByOwner(context.Context, domain.OwnerID) (int64, error) { return 0, nil }

// get returns the stored link, or nil.
func (f *fakeLinkStore) get(provider, subject string) *domain.LinkedIdentity {
	li, err := f.GetByProviderSubject(context.Background(), provider, subject)
	if err != nil {
		return nil
	}
	return li
}

// remove drops a link, modeling a credential removed after the pairing was
// created.
func (f *fakeLinkStore) remove(provider, subject string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.rows, linkKey{provider: provider, subject: subject})
}

// setOwner repoints a link at another owner, modeling a tampered row or a
// lookup that returned a neighbor.
func (f *fakeLinkStore) setOwner(provider, subject string, ownerID domain.OwnerID) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if li, ok := f.rows[linkKey{provider: provider, subject: subject}]; ok {
		li.OwnerID = ownerID
	}
}
