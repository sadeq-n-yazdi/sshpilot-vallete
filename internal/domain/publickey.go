package domain

import "time"

// PublicKeyID is the opaque, non-guessable identifier for a PublicKey.
type PublicKeyID string

// Algorithm is an SSH public key algorithm name as it appears on the wire.
type Algorithm string

// Supported SSH public key algorithms. DSA is intentionally absent.
const (
	AlgEd25519    Algorithm = "ssh-ed25519"
	AlgECDSA256   Algorithm = "ecdsa-sha2-nistp256"
	AlgECDSA384   Algorithm = "ecdsa-sha2-nistp384"
	AlgECDSA521   Algorithm = "ecdsa-sha2-nistp521"
	AlgRSA        Algorithm = "ssh-rsa"
	AlgSKEd25519  Algorithm = "sk-ssh-ed25519@openssh.com"
	AlgSKECDSA256 Algorithm = "sk-ecdsa-sha2-nistp256@openssh.com"
)

// IsValid reports whether a is a known, supported Algorithm.
func (a Algorithm) IsValid() bool {
	switch a {
	case AlgEd25519, AlgECDSA256, AlgECDSA384, AlgECDSA521, AlgRSA, AlgSKEd25519, AlgSKECDSA256:
		return true
	default:
		return false
	}
}

// MinRSABits is the minimum accepted RSA modulus size in bits.
const MinRSABits = 3072

// KeyStatus is the lifecycle status of a PublicKey.
type KeyStatus string

// Key status values.
const (
	KeyStatusActive  KeyStatus = "active"
	KeyStatusRevoked KeyStatus = "revoked"
)

// IsValid reports whether s is a known KeyStatus.
func (s KeyStatus) IsValid() bool {
	switch s {
	case KeyStatusActive, KeyStatusRevoked:
		return true
	default:
		return false
	}
}

// PublicKey is an SSH public key belonging to a device.
type PublicKey struct {
	ID          PublicKeyID
	OwnerID     OwnerID
	DeviceID    DeviceID
	Algorithm   Algorithm
	Blob        []byte
	Comment     string
	Fingerprint string
	BitLen      int
	Status      KeyStatus
	CreatedAt   time.Time
	UpdatedAt   time.Time
	RevokedAt   *time.Time
	Signature   *KeySignature
}

// KeySignature is reserved room for a future certificate authority. It is nil
// in phase 1; no signing or verification is performed by this package.
type KeySignature struct {
	Format   string
	Blob     []byte
	SignedAt time.Time
	SignerID string
}
