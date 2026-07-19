package domain

import "time"

// AccessKeyID is the opaque, non-guessable identifier for an AccessKey.
type AccessKeyID string

// AccessKeyStatus is the lifecycle status of an AccessKey.
type AccessKeyStatus string

// Access key status values.
const (
	AccessKeyStatusActive  AccessKeyStatus = "active"
	AccessKeyStatusGrace   AccessKeyStatus = "grace"
	AccessKeyStatusRevoked AccessKeyStatus = "revoked"
)

// IsValid reports whether s is a known AccessKeyStatus.
func (s AccessKeyStatus) IsValid() bool {
	switch s {
	case AccessKeyStatusActive, AccessKeyStatusGrace, AccessKeyStatusRevoked:
		return true
	default:
		return false
	}
}

// AccessKey is a bearer credential that resolves a specific key set. SecretHash
// is never serialized to JSON.
type AccessKey struct {
	ID           AccessKeyID
	OwnerID      OwnerID
	KeySetID     KeySetID
	Name         string
	SecretHash   []byte `json:"-"`
	Status       AccessKeyStatus
	CreatedAt    time.Time
	RevokedAt    *time.Time
	GraceUntil   *time.Time
	ReplacedByID *AccessKeyID
}
