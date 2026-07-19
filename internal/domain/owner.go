package domain

import "time"

// OwnerID is the opaque, non-guessable identifier for an Owner.
type OwnerID string

// OwnerStatus is the lifecycle status of an Owner.
type OwnerStatus string

// Owner status values.
const (
	OwnerStatusActive    OwnerStatus = "active"
	OwnerStatusSuspended OwnerStatus = "suspended"
	OwnerStatusDeleted   OwnerStatus = "deleted"
)

// IsValid reports whether s is a known OwnerStatus.
func (s OwnerStatus) IsValid() bool {
	switch s {
	case OwnerStatusActive, OwnerStatusSuspended, OwnerStatusDeleted:
		return true
	default:
		return false
	}
}

// Owner is the root account entity. It carries no name or email; personal data
// lives on LinkedIdentity so it can be crypto-erased independently.
type Owner struct {
	ID        OwnerID
	Status    OwnerStatus
	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt *time.Time
}
