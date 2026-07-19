package repository

import (
	"context"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
)

// KeySetRepository persists KeySet rows and their membership rows. A freed set
// name is kept as a tombstone KeySet row with
// State == domain.NameStateQuarantined, so the name stays reserved. Every
// method is owner-scoped; the implementation MUST filter by ownerID. There is
// no Rename method: renaming a set is a service-layer WithTx composition.
type KeySetRepository interface {
	// Create persists a fully populated KeySet. It returns domain.ErrConflict
	// if the (OwnerID, Name) pair already exists in any state, including
	// quarantined tombstones.
	Create(ctx context.Context, s *domain.KeySet) error

	// Get returns the owner's key set with the given ID, or domain.ErrNotFound
	// if it does not exist or belongs to another owner.
	Get(ctx context.Context, ownerID domain.OwnerID, id domain.KeySetID) (*domain.KeySet, error)

	// GetByName returns the owner's key set with the given normalized name, or
	// domain.ErrNotFound if the owner has none.
	GetByName(ctx context.Context, ownerID domain.OwnerID, normalized string) (*domain.KeySet, error)

	// ListByOwner returns all of the owner's key sets.
	ListByOwner(ctx context.Context, ownerID domain.OwnerID) ([]domain.KeySet, error)

	// CountByOwner returns the number of the owner's key sets. The service uses
	// it inside a WithTx to enforce the per-owner cap of 100.
	CountByOwner(ctx context.Context, ownerID domain.OwnerID) (int, error)

	// Update persists changes to the mutable fields of a key set, scoped by
	// s.OwnerID and s.ID. It returns domain.ErrNotFound if the set does not
	// exist or belongs to another owner.
	Update(ctx context.Context, s *domain.KeySet) error

	// SetDefault makes the given set the owner's default, atomically clearing
	// the previous default and setting this one. It returns domain.ErrNotFound
	// if the set does not exist or belongs to another owner.
	SetDefault(ctx context.Context, ownerID domain.OwnerID, id domain.KeySetID) error

	// GetDefault returns the owner's default key set, or domain.ErrNotFound if
	// the owner has none.
	GetDefault(ctx context.Context, ownerID domain.OwnerID) (*domain.KeySet, error)

	// Delete removes the key set and its membership rows (never the PublicKey
	// rows). The implementation MUST refuse to delete a set whose IsDefault is
	// true, returning domain.ErrDefaultKeySet so callers can distinguish this
	// recoverable "designate another default first" condition from a generic
	// state clash. It returns domain.ErrNotFound if the set does not exist or
	// belongs to another owner.
	Delete(ctx context.Context, ownerID domain.OwnerID, id domain.KeySetID) error

	// AddMember adds the key to the set, stamping AddedAt with now. It returns
	// domain.ErrConflict if the key is already a member, and domain.ErrNotFound
	// unless BOTH the set and the key belong to ownerID.
	AddMember(ctx context.Context, ownerID domain.OwnerID, setID domain.KeySetID, keyID domain.PublicKeyID, now time.Time) error

	// RemoveMember removes the key from the set. It returns domain.ErrNotFound
	// if the membership is absent (or either row belongs to another owner).
	RemoveMember(ctx context.Context, ownerID domain.OwnerID, setID domain.KeySetID, keyID domain.PublicKeyID) error

	// ListMembers returns the membership rows of the owner's set.
	ListMembers(ctx context.Context, ownerID domain.OwnerID, setID domain.KeySetID) ([]domain.KeySetMembership, error)

	// ListSetsForKey returns the owner's key sets that contain the given key.
	ListSetsForKey(ctx context.Context, ownerID domain.OwnerID, keyID domain.PublicKeyID) ([]domain.KeySet, error)

	// ListExpiredQuarantine returns up to limit quarantined key-set tombstones
	// whose QuarantineUntil is at or before now, for the release sweep.
	//
	// UNSCOPED: this is a system-maintenance sweep across all owners; the
	// quarantine-release job is not acting on behalf of any single owner.
	ListExpiredQuarantine(ctx context.Context, now time.Time, limit int) ([]domain.KeySet, error)
}
