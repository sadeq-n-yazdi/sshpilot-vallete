package domain

import "time"

// RefreshCredentialID is the opaque, non-guessable identifier for a
// RefreshCredential.
type RefreshCredentialID string

// LineageID groups a chain of rotated refresh credentials.
type LineageID string

// CredentialStatus is the lifecycle status of a RefreshCredential.
type CredentialStatus string

// Credential status values.
const (
	CredentialStatusActive  CredentialStatus = "active"
	CredentialStatusRotated CredentialStatus = "rotated"
	CredentialStatusRevoked CredentialStatus = "revoked"
	CredentialStatusExpired CredentialStatus = "expired"
)

// IsValid reports whether s is a known CredentialStatus.
func (s CredentialStatus) IsValid() bool {
	switch s {
	case CredentialStatusActive, CredentialStatusRotated, CredentialStatusRevoked, CredentialStatusExpired:
		return true
	default:
		return false
	}
}

// RefreshCredential is a long-lived, rotatable credential used to mint access
// tokens. SecretHash is never serialized to JSON.
type RefreshCredential struct {
	ID            RefreshCredentialID
	OwnerID       OwnerID
	LineageID     LineageID
	SecretHash    []byte `json:"-"`
	Scopes        []Scope
	ClientLabel   string
	RotatedFromID *RefreshCredentialID
	IssuedAt      time.Time
	ExpiresAt     time.Time
	Status        CredentialStatus
	RevokedAt     *time.Time
}

// AccessToken is a short-lived, non-persisted bearer token derived from a
// refresh credential.
type AccessToken struct {
	ID                  string
	OwnerID             OwnerID
	RefreshCredentialID RefreshCredentialID
	Scopes              []Scope
	IssuedAt            time.Time
	ExpiresAt           time.Time
}

// LinkedIdentityID is the opaque, non-guessable identifier for a
// LinkedIdentity.
type LinkedIdentityID string

// LinkedIdentity binds an external identity provider subject to an owner. It
// holds the owner's personal data so it can be crypto-erased independently.
type LinkedIdentity struct {
	ID        LinkedIdentityID
	OwnerID   OwnerID
	Provider  string
	Subject   string
	Email     *string
	CreatedAt time.Time
	UpdatedAt time.Time
}
