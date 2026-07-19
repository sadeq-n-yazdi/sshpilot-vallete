package domain

import "time"

// KeySetID is the opaque, non-guessable identifier for a KeySet.
type KeySetID string

// Visibility controls who may resolve a key set.
type Visibility string

// Visibility values.
const (
	VisibilityPublic    Visibility = "public"
	VisibilityProtected Visibility = "protected"
)

// IsValid reports whether v is a known Visibility.
func (v Visibility) IsValid() bool {
	switch v {
	case VisibilityPublic, VisibilityProtected:
		return true
	default:
		return false
	}
}

// KeySet is a named, resolvable collection of an owner's public keys. Its State
// uses the shared NameState type.
type KeySet struct {
	ID                  KeySetID
	OwnerID             OwnerID
	Name                string
	Visibility          Visibility
	IsDefault           bool
	State               NameState
	QuarantineUntil     *time.Time
	FlaggedForReview    bool
	QuarantineOnRelease bool
	CreatedAt           time.Time
	UpdatedAt           time.Time
}

// KeySetMembership associates a public key with a key set.
type KeySetMembership struct {
	KeySetID    KeySetID
	PublicKeyID PublicKeyID
	AddedAt     time.Time
}
