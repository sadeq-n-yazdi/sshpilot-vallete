package repository

import (
	"context"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
)

// PublicKeyRepository persists PublicKey rows. Every method is owner-scoped:
// the implementation MUST filter by ownerID.
type PublicKeyRepository interface {
	// Create persists a fully populated PublicKey. It returns
	// domain.ErrConflict if the (OwnerID, Fingerprint) pair already exists.
	Create(ctx context.Context, k *domain.PublicKey) error

	// Get returns the owner's public key with the given ID, or
	// domain.ErrNotFound if it does not exist or belongs to another owner.
	Get(ctx context.Context, ownerID domain.OwnerID, id domain.PublicKeyID) (*domain.PublicKey, error)

	// ListByOwner returns all of the owner's public keys.
	ListByOwner(ctx context.Context, ownerID domain.OwnerID) ([]domain.PublicKey, error)

	// ListByDevice returns the owner's public keys that belong to the given
	// device.
	ListByDevice(ctx context.Context, ownerID domain.OwnerID, deviceID domain.DeviceID) ([]domain.PublicKey, error)

	// GetByFingerprint returns the owner's public key with the given
	// fingerprint, or domain.ErrNotFound if none exists for that owner.
	GetByFingerprint(ctx context.Context, ownerID domain.OwnerID, fingerprint string) (*domain.PublicKey, error)

	// Revoke marks the key revoked, setting RevokedAt and UpdatedAt to now. It
	// returns domain.ErrNotFound if the key does not exist or belongs to
	// another owner.
	Revoke(ctx context.Context, ownerID domain.OwnerID, id domain.PublicKeyID, now time.Time) error

	// RevokeByDevice revokes all of the owner's active keys on the given
	// device, stamping RevokedAt and UpdatedAt with now, and returns the number
	// of keys revoked.
	RevokeByDevice(ctx context.Context, ownerID domain.OwnerID, deviceID domain.DeviceID, now time.Time) (int64, error)

	// ListActiveByKeySet returns the owner's active public keys that are
	// members of the given key set (active keys intersected with membership).
	// This is the publisher-facing resolution query.
	ListActiveByKeySet(ctx context.Context, ownerID domain.OwnerID, setID domain.KeySetID) ([]domain.PublicKey, error)
}
