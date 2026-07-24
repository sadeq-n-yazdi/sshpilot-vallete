package domain

import "time"

// AdministratorID is the opaque, non-guessable identifier for an Administrator.
type AdministratorID string

// AdminStatus is the lifecycle status of an Administrator.
type AdminStatus string

// Administrator status values.
const (
	AdminStatusActive   AdminStatus = "active"
	AdminStatusDisabled AdminStatus = "disabled"
)

// IsValid reports whether s is a known AdminStatus.
func (s AdminStatus) IsValid() bool {
	switch s {
	case AdminStatusActive, AdminStatusDisabled:
		return true
	default:
		return false
	}
}

// Administrator is a privileged operator of the service.
type Administrator struct {
	ID        AdministratorID
	Label     string
	Status    AdminStatus
	CreatedAt time.Time
	UpdatedAt time.Time
}
