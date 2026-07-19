package repository

import (
	"context"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
)

// AccessKeyRepository persists AccessKey bearer credentials. Every method is
// owner-scoped; the implementation MUST filter by ownerID.
type AccessKeyRepository interface {
	// Create persists a fully populated AccessKey, including its SecretHash.
	Create(ctx context.Context, k *domain.AccessKey) error

	// Get returns the owner's access key with the given ID, or
	// domain.ErrNotFound if it does not exist or belongs to another owner. This
	// also serves Bearer verification: the caller resolves the handle to an
	// owner first, then loads the key under that owner and compares SecretHash.
	Get(ctx context.Context, ownerID domain.OwnerID, id domain.AccessKeyID) (*domain.AccessKey, error)

	// ListByKeySet returns the owner's access keys that resolve the given key
	// set.
	ListByKeySet(ctx context.Context, ownerID domain.OwnerID, setID domain.KeySetID) ([]domain.AccessKey, error)

	// ListByOwner returns all of the owner's access keys.
	ListByOwner(ctx context.Context, ownerID domain.OwnerID) ([]domain.AccessKey, error)

	// MarkRotated moves the key into the grace state, recording the replacement
	// key in ReplacedByID and the grace deadline in GraceUntil. It returns
	// domain.ErrNotFound if the key does not exist or belongs to another owner.
	MarkRotated(ctx context.Context, ownerID domain.OwnerID, id domain.AccessKeyID, replacedBy domain.AccessKeyID, graceUntil time.Time) error

	// Revoke marks the key revoked, setting RevokedAt to now. It returns
	// domain.ErrNotFound if the key does not exist or belongs to another owner.
	Revoke(ctx context.Context, ownerID domain.OwnerID, id domain.AccessKeyID, now time.Time) error

	// ListExpiredGrace returns up to limit access keys in the grace state whose
	// GraceUntil is at or before now, for the grace-expiry sweep.
	//
	// UNSCOPED: this is a system-maintenance sweep across all owners; the
	// grace-expiry job is not acting on behalf of any single owner.
	ListExpiredGrace(ctx context.Context, now time.Time, limit int) ([]domain.AccessKey, error)
}
