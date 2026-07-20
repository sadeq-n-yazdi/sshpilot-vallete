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
// There is deliberately no fold field here. The database carries a name_fold
// column so it can refuse a look-alike of a live claim, but that value is
// derived from Name by the adapter on write. Exposing it as a field would make
// it independently settable, and a caller that set a fold disagreeing with the
// name would slip a look-alike past the index that exists to catch it. The
// value is also never read back: nothing resolves a handle through the fold, so
// a request for a look-alike must miss rather than land on the name it
// resembles.
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
