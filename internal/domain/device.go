package domain

import "time"

// DeviceID is the opaque, non-guessable identifier for a Device.
type DeviceID string

// DeviceStatus is the lifecycle status of a Device.
type DeviceStatus string

// Device status values.
const (
	DeviceStatusActive  DeviceStatus = "active"
	DeviceStatusRevoked DeviceStatus = "revoked"
)

// IsValid reports whether s is a known DeviceStatus.
func (s DeviceStatus) IsValid() bool {
	switch s {
	case DeviceStatusActive, DeviceStatusRevoked:
		return true
	default:
		return false
	}
}

// Device is a machine registered by an owner that holds public keys.
type Device struct {
	ID        DeviceID
	OwnerID   OwnerID
	Name      string
	Status    DeviceStatus
	CreatedAt time.Time
	UpdatedAt time.Time
	RevokedAt *time.Time
}
