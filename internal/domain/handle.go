package domain

import "time"

// HandleID is the opaque, non-guessable identifier for a Handle.
type HandleID string

// NameState is the lifecycle state of a claimable name. It is shared by Handle
// and KeySet.
type NameState string

// Name state values.
const (
	NameStateActive      NameState = "active"
	NameStateQuarantined NameState = "quarantined"
	NameStateRetired     NameState = "retired"
)

// IsValid reports whether s is a known NameState.
func (s NameState) IsValid() bool {
	switch s {
	case NameStateActive, NameStateQuarantined, NameStateRetired:
		return true
	default:
		return false
	}
}

// Handle is an owner's globally unique public name.
type Handle struct {
	ID                  HandleID
	OwnerID             OwnerID
	Name                string
	State               NameState
	QuarantineUntil     *time.Time
	FlaggedForReview    bool
	QuarantineOnRelease bool
	CreatedAt           time.Time
	UpdatedAt           time.Time
}
