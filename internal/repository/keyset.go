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
	// it inside a WithTx, immediately after LockOwnerForCreate, to enforce the
	// per-owner cap (config.Retention.MaxSetsPerOwner, default 100).
	CountByOwner(ctx context.Context, ownerID domain.OwnerID) (int, error)

	// LockOwnerForCreate serializes concurrent key-set creates for one owner so
	// that a CountByOwner/Create pair cannot interleave with another
	// transaction's.
	//
	// SECURITY: the per-owner cap is a check-then-insert, which is only an
	// invariant if no other transaction can insert between the two statements.
	// Engines differ in whether that is already true. SQLite opens every
	// transaction as BEGIN IMMEDIATE (_txlock=immediate), so writers are
	// already serialized database-wide and this method has nothing left to do.
	// PostgreSQL runs transactions at READ COMMITTED, where two concurrent
	// creates can both count cap-1 and both insert, leaving the owner over the
	// cap; there this method takes a row lock that holds until the transaction
	// ends, so the second create's count observes the first's committed insert.
	//
	// It MUST be called inside a Store.WithTx and before the count, and it MUST
	// be the transaction's first lock on the owner's data: taking it after a
	// key_sets write would invert the lock order that keeps concurrent creates
	// and renames deadlock-free.
	//
	// An owner with no row is not an error. Nothing exists to lock, and the
	// key_sets.owner_id foreign key refuses the insert that would follow, so
	// the cap cannot be exceeded through that path.
	LockOwnerForCreate(ctx context.Context, ownerID domain.OwnerID) error

	// Update persists changes to the mutable fields of a key set, scoped by
	// s.OwnerID and s.ID. Only Visibility, State, QuarantineUntil,
	// FlaggedForReview, and QuarantineOnRelease are mutable here. Name is
	// immutable (renaming is a service-layer WithTx composition, not a field
	// update) and IsDefault must be changed only via SetDefault; the
	// implementation MUST ignore or reject changes to those fields rather than
	// silently persist them. It returns domain.ErrNotFound if the set does not
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
