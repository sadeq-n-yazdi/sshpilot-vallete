package repository

import (
	"context"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
)

// RefreshCredentialRepository persists RefreshCredential rows. The token
// denylist is intentionally not modeled here; it is separate infrastructure
// (ADR-0018). Methods are owner-scoped except GetByID, which authenticates.
type RefreshCredentialRepository interface {
	// Create persists a fully populated RefreshCredential, including its
	// SecretHash.
	Create(ctx context.Context, c *domain.RefreshCredential) error

	// GetByID returns the refresh credential with the given ID, or
	// domain.ErrNotFound if none exists.
	//
	// UNSCOPED: the refresh exchange IS the authentication step, so the owner
	// is not yet established when this runs. The caller MUST verify SecretHash
	// and status before trusting the returned OwnerID.
	GetByID(ctx context.Context, id domain.RefreshCredentialID) (*domain.RefreshCredential, error)

	// Get returns the owner's refresh credential with the given ID, or
	// domain.ErrNotFound if it does not exist or belongs to another owner.
	Get(ctx context.Context, ownerID domain.OwnerID, id domain.RefreshCredentialID) (*domain.RefreshCredential, error)

	// ListByOwner returns all of the owner's refresh credentials.
	ListByOwner(ctx context.Context, ownerID domain.OwnerID) ([]domain.RefreshCredential, error)

	// ListByLineage returns the owner's refresh credentials in the given
	// rotation lineage.
	ListByLineage(ctx context.Context, ownerID domain.OwnerID, lineageID domain.LineageID) ([]domain.RefreshCredential, error)

	// MarkRotated moves the credential into the rotated state and stamps its
	// timestamps with now. It returns domain.ErrNotFound if the credential does
	// not exist or belongs to another owner.
	MarkRotated(ctx context.Context, ownerID domain.OwnerID, id domain.RefreshCredentialID, now time.Time) error

	// Revoke marks the credential revoked, setting RevokedAt to now. It returns
	// domain.ErrNotFound if the credential does not exist or belongs to another
	// owner.
	Revoke(ctx context.Context, ownerID domain.OwnerID, id domain.RefreshCredentialID, now time.Time) error

	// RevokeLineage revokes every credential in the owner's lineage, setting
	// RevokedAt to now, and returns the number revoked. This is the
	// reuse-detection response.
	RevokeLineage(ctx context.Context, ownerID domain.OwnerID, lineageID domain.LineageID, now time.Time) (int64, error)

	// DeleteExpired removes up to limit credentials whose ExpiresAt is at or
	// before cutoff, and returns the number deleted.
	//
	// UNSCOPED: this is a system-maintenance sweep across all owners; the
	// expiry-cleanup job is not acting on behalf of any single owner.
	DeleteExpired(ctx context.Context, cutoff time.Time, limit int) (int64, error)
}

// LinkedIdentityRepository persists LinkedIdentity rows, which bind an external
// provider subject to an owner and hold the owner's personal data for
// independent crypto-erasure.
type LinkedIdentityRepository interface {
	// Create persists a fully populated LinkedIdentity. It returns
	// domain.ErrConflict if the (Provider, Subject) pair is already linked.
	Create(ctx context.Context, li *domain.LinkedIdentity) error

	// GetByProviderSubject returns the linked identity for the given provider
	// and subject, or domain.ErrNotFound if none exists.
	//
	// UNSCOPED: this is the login bootstrap that resolves an external subject
	// to an owner; the owner is not yet known when this runs.
	GetByProviderSubject(ctx context.Context, provider, subject string) (*domain.LinkedIdentity, error)

	// ListByOwner returns all of the owner's linked identities.
	ListByOwner(ctx context.Context, ownerID domain.OwnerID) ([]domain.LinkedIdentity, error)

	// Delete removes the owner's linked identity with the given ID. It returns
	// domain.ErrNotFound if it does not exist or belongs to another owner.
	Delete(ctx context.Context, ownerID domain.OwnerID, id domain.LinkedIdentityID) error

	// DeleteByOwner removes all of the owner's linked identities and returns the
	// number deleted. This supports account deletion and crypto-erasure.
	DeleteByOwner(ctx context.Context, ownerID domain.OwnerID) (int64, error)
}
