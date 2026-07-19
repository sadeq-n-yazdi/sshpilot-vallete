package repository

import (
	"context"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
)

// OwnerRepository persists Owner root entities. Owners are the top of the
// ownership axis and are therefore identified directly by their OwnerID rather
// than scoped under another owner.
type OwnerRepository interface {
	// Create persists a fully populated Owner. The service supplies the ID and
	// timestamps. It returns domain.ErrConflict if an owner with the same ID
	// already exists.
	Create(ctx context.Context, o *domain.Owner) error

	// Get returns the owner with the given ID, or domain.ErrNotFound if none
	// exists.
	Get(ctx context.Context, id domain.OwnerID) (*domain.Owner, error)

	// UpdateStatus sets the owner's lifecycle status and stamps UpdatedAt with
	// now. It returns domain.ErrNotFound if the owner does not exist.
	UpdateStatus(ctx context.Context, id domain.OwnerID, status domain.OwnerStatus, now time.Time) error

	// SoftDelete marks the owner deleted, setting DeletedAt and UpdatedAt to
	// now without removing the row. It returns domain.ErrNotFound if the owner
	// does not exist.
	SoftDelete(ctx context.Context, id domain.OwnerID, now time.Time) error

	// List returns a page of owners together with the next-page cursor. A
	// returned cursor of "" means there are no further pages. This method is an
	// administrative sweep across all owners and so is not owner-scoped.
	List(ctx context.Context, page Page) ([]domain.Owner, string, error)
}
