package repository

import (
	"context"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
)

// AdministratorRepository persists Administrator rows. Administrators sit on the
// system axis rather than the owner axis, so every method here is deliberately
// unscoped: there is no owner to filter by.
type AdministratorRepository interface {
	// Create persists a fully populated Administrator.
	//
	// UNSCOPED: administrators are system-axis principals, not owner-owned data.
	Create(ctx context.Context, a *domain.Administrator) error

	// Get returns the administrator with the given ID, or domain.ErrNotFound if
	// none exists.
	//
	// UNSCOPED: administrators are system-axis principals, not owner-owned data.
	Get(ctx context.Context, id domain.AdministratorID) (*domain.Administrator, error)

	// List returns all administrators.
	//
	// UNSCOPED: administrators are system-axis principals, not owner-owned data.
	List(ctx context.Context) ([]domain.Administrator, error)

	// SetLabel sets the administrator's display label and stamps UpdatedAt with
	// now. It returns domain.ErrNotFound if none exists.
	//
	// UNSCOPED: administrators are system-axis principals, not owner-owned data.
	SetLabel(ctx context.Context, id domain.AdministratorID, label string, now time.Time) error

	// UpdateStatus sets the administrator's lifecycle status and stamps
	// UpdatedAt with now. It returns domain.ErrNotFound if none exists.
	//
	// UNSCOPED: administrators are system-axis principals, not owner-owned data.
	UpdateStatus(ctx context.Context, id domain.AdministratorID, status domain.AdminStatus, now time.Time) error
}
