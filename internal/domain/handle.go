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
//
// NameFold and FoldVersion are write-only: they are supplied on Register so the
// database can refuse a look-alike of a live handle, and are deliberately not
// populated when a Handle is read back. Nothing resolves a handle through the
// fold — a request for a look-alike must miss, not land on the name it
// resembles — so a reader that never sees the value cannot accidentally start
// matching on it.
type Handle struct {
	ID                  HandleID
	OwnerID             OwnerID
	Name                string
	NameFold            string
	FoldVersion         int
	State               NameState
	QuarantineUntil     *time.Time
	FlaggedForReview    bool
	QuarantineOnRelease bool
	CreatedAt           time.Time
	UpdatedAt           time.Time
}
