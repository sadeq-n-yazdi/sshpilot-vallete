package repository

import (
	"context"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
)

// DeviceRepository persists Device rows. Every method is owner-scoped: the
// implementation MUST filter by ownerID so one owner can never observe or
// mutate another owner's devices.
type DeviceRepository interface {
	// Create persists a fully populated Device. The owner is carried in
	// d.OwnerID.
	Create(ctx context.Context, d *domain.Device) error

	// Get returns the owner's device with the given ID, or domain.ErrNotFound
	// if it does not exist or belongs to another owner.
	Get(ctx context.Context, ownerID domain.OwnerID, id domain.DeviceID) (*domain.Device, error)

	// ListByOwner returns all of the owner's devices.
	ListByOwner(ctx context.Context, ownerID domain.OwnerID) ([]domain.Device, error)

	// Rename sets the device's display name and stamps UpdatedAt with now. The
	// service supplies the already-validated name. It returns
	// domain.ErrNotFound if the device does not exist or belongs to another
	// owner.
	Rename(ctx context.Context, ownerID domain.OwnerID, id domain.DeviceID, name string, now time.Time) error

	// Revoke marks the device revoked, setting RevokedAt and UpdatedAt to now.
	// It returns domain.ErrNotFound if the device does not exist or belongs to
	// another owner.
	Revoke(ctx context.Context, ownerID domain.OwnerID, id domain.DeviceID, now time.Time) error
}
