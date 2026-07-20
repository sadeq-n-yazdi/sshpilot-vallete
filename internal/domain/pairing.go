package domain

import "time"

// PairingID is the opaque, non-guessable identifier for a DevicePairing.
//
// It is also the principal the api-token authentication provider reports, so a
// pairing that has been linked to an owner keeps its identifier for the life of
// the link. The identifier is a lookup key, not a secret: presenting it without
// the matching device code proves nothing.
type PairingID string

// PairingStatus is the lifecycle status of a DevicePairing.
//
// The set is deliberately small and the transitions are one-way. A pairing is
// created either pending (the device-authorization grant, waiting for an owner
// to approve it) or approved (the manual-paste flow, where the owner minting it
// IS the approval), becomes redeemed exactly once, and never moves again.
// Reversing any of these would make a consumed pairing redeemable a second
// time.
type PairingStatus string

// Pairing status values.
const (
	// PairingStatusPending is a device-authorization grant that no owner has
	// approved yet. It carries no owner and cannot be redeemed.
	PairingStatusPending PairingStatus = "pending"
	// PairingStatusApproved is bound to an owner and may be redeemed once.
	PairingStatusApproved PairingStatus = "approved"
	// PairingStatusRedeemed is spent. It is terminal: the device code that
	// reached it will never authenticate again.
	PairingStatusRedeemed PairingStatus = "redeemed"
	// PairingStatusRevoked is a pairing the owner withdrew. It is terminal and
	// is distinct from redeemed so that a listing can tell "this device paired"
	// from "this pairing was cancelled before use".
	PairingStatusRevoked PairingStatus = "revoked"
)

// IsValid reports whether s is a known PairingStatus.
func (s PairingStatus) IsValid() bool {
	switch s {
	case PairingStatusPending, PairingStatusApproved, PairingStatusRedeemed, PairingStatusRevoked:
		return true
	default:
		return false
	}
}

// DevicePairing is one enrollment attempt: the record against which a presented
// device code is verified, and the row whose status makes that verification
// single-use.
//
// # Only hashes are stored
//
// Neither the device code nor the user code is persisted. The row holds their
// digests, and the codes themselves exist only in the response that created
// them. There is no path that recovers either one, which is what makes a stolen
// database backup useless for pairing a device.
//
// Both hash fields are excluded from JSON. They are digests of high-entropy
// values and so are not directly reversible, but a leaked UserCodeHash is
// brute-forceable in moments -- a user code is short by design, because a human
// transcribes it -- and a leaked DeviceCodeHash would let anyone who can also
// write to the store install their own credential.
//
// # Owner binding
//
// OwnerID is empty while the pairing is pending and is set exactly once, by the
// approval, to the owner who approved it. Redemption reads the owner from the
// row rather than from anything the redeeming client says, so a client cannot
// name the account it pairs into.
type DevicePairing struct {
	ID      PairingID
	OwnerID OwnerID

	// DeviceCodeHash is the digest of the secret held by the pairing client.
	DeviceCodeHash []byte `json:"-"`
	// UserCodeHash is the digest of the short code the owner transcribes to
	// approve the pairing. It is nil for a manually minted pairing, which is
	// approved at creation and so never needs one.
	UserCodeHash []byte `json:"-"`

	// ClientLabel is the operator-visible name of the enrolling client
	// ("laptop", "ci runner"). It is carried onto the refresh credential the
	// redemption issues.
	ClientLabel string
	// Scopes is the grant the redemption will carry. It is fixed when the
	// pairing is created so that the authority a device receives is decided by
	// the owner up front, not negotiated by the device at redemption.
	Scopes []Scope

	Status PairingStatus

	// LineageID names the refresh credential lineage the redemption issued, and
	// is empty until then. It is what lets revoking a device reach the tokens
	// that device is holding, rather than only preventing future pairings.
	LineageID LineageID

	// NextPollAt is the earliest time the pairing client may poll again. It is
	// advanced on every poll, so a client that ignores the interval is slowed
	// down rather than served.
	NextPollAt time.Time

	CreatedAt time.Time
	// ExpiresAt is short: a pairing is an interactive act, and the window in
	// which a user code can be guessed is bounded by it.
	ExpiresAt  time.Time
	ApprovedAt *time.Time
	RedeemedAt *time.Time
	RevokedAt  *time.Time
}
