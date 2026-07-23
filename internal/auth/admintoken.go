package auth

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/secrets"
)

// adminTokenVersion is the administrator token payload format version.
// Verification requires an exact match, so a future format change cannot be
// presented to a server that would read the new fields under the old meaning.
// It is a version of its own, separate from accessTokenVersion, because the two
// token shapes evolve independently.
const adminTokenVersion = 1

// AdminTokenSigner mints and verifies administrator bearer tokens (ADR-0031).
//
// # Why a separate signer and a separate key from the owner access token
//
// ADR-0018 draws a line this type exists to enforce cryptographically: "owner
// tokens can never grant administrator authority." A distinct signing key --
// never the owner access-token signing key -- means an owner-token key
// compromise cannot forge an administrator token, and an owner access token is
// structurally never an administrator token: different key, different prefix,
// different payload shape, different verifier. Admin authority is not
// expressible on the owner token.
//
// # Why the token is self-contained, and where revocation lives
//
// Like the owner access token, an administrator token carries its own claims
// and a MAC over them, and verification reads nothing from storage. The token
// asserts WHO; the signature proves the assertion is authentic. The authority
// itself is decided one layer up, where listadmin.authorize looks the
// administrator up and refuses anything but an Active row -- so a validly-signed
// token for a disabled or deleted administrator is refused with no code here.
// The consequence is stated plainly (ADR-0031): there is no per-token
// revocation in v1; disabling the administrator row revokes all of that admin's
// tokens at once, and a short configured TTL bounds a leaked token's exposure.
//
// # Why HMAC, no algorithm field, one key
//
// The same server both mints and verifies, so a symmetric MAC is the right
// primitive; the algorithm is fixed in code and named nowhere in the token, so
// a token cannot lie about how to check it; and one key with a short lifetime
// makes rotation "install the new key and wait out the TTL." These are the same
// decisions AccessTokenSigner documents at length, held here for the same
// reasons.
//
// An AdminTokenSigner is immutable after construction and safe for concurrent
// use.
type AdminTokenSigner struct {
	key []byte
}

// NewAdminTokenSigner builds a signer from a symmetric key of at least
// MinSigningKeyLen bytes -- the same floor the owner access-token signer
// enforces, because the key is fed to the same HMAC-SHA256 whose output width
// it must match.
//
// The key is copied so that a caller who reuses or zeroes its buffer cannot
// change the signer's key underneath it.
func NewAdminTokenSigner(key []byte) (*AdminTokenSigner, error) {
	if len(key) < MinSigningKeyLen {
		return nil, fmt.Errorf("auth: admin token signing key must be at least %d bytes: %w", MinSigningKeyLen, domain.ErrInvalidInput)
	}
	k := make([]byte, len(key))
	copy(k, key)
	return &AdminTokenSigner{key: k}, nil
}

// NewAdminTokenID returns a fresh random identifier for the jti claim.
//
// It reuses the package's single crypto/rand path (randomBytes) and the token
// encoding, rather than introducing a second RNG, so there is one audited
// source of random material in this package. The id is 128 bits: it is a lookup
// key for audit and possible future revocation, not a secret, but it is random
// rather than sequential so holding one token reveals nothing about how many
// were issued.
func NewAdminTokenID() string {
	return tokenEncoding.EncodeToString(randomBytes(credentialIDBytes))
}

// redacted is the single rendering used by every formatting path on
// AdminTokenSigner.
//
// The key is unexported, which is no protection: fmt prints unexported fields,
// so a signer caught in a "%+v" of an enclosing config struct, or handed to
// slog, would print the one secret that forges every administrator token this
// service will ever issue. That is a worse leak than any single token, so the
// type redacts itself exactly as AccessTokenSigner and secrets.Redacted do. The
// value receivers make both a signer and a *signer render redacted.
func (s AdminTokenSigner) redacted() string { return "auth.AdminTokenSigner{key:[REDACTED]}" }

// String implements fmt.Stringer.
func (s AdminTokenSigner) String() string { return s.redacted() }

// GoString implements fmt.GoStringer so %#v also redacts.
func (s AdminTokenSigner) GoString() string { return s.redacted() }

// Format implements fmt.Formatter. It takes precedence over String and GoString
// for every verb, which is what catches the realistic leak path: a signer
// printed as a field of a surrounding struct with %v or %+v.
func (s AdminTokenSigner) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte(s.redacted()))
}

// MarshalJSON implements json.Marshaler, emitting a quoted redacted string so
// the output stays valid JSON.
func (s AdminTokenSigner) MarshalJSON() ([]byte, error) {
	return []byte(`"` + s.redacted() + `"`), nil
}

// MarshalText implements encoding.TextMarshaler.
func (s AdminTokenSigner) MarshalText() ([]byte, error) { return []byte(s.redacted()), nil }

// LogValue implements slog.LogValuer, which slog resolves ahead of the
// marshalers above.
func (s AdminTokenSigner) LogValue() slog.Value { return slog.StringValue(s.redacted()) }

// adminClaims is the wire form of an administrator token payload. The field
// names are short because they are copied into every request's Authorization
// header. jti is carried even though v1's Verify does not consult it: it keeps
// parity with accessClaims, gives audit a stable per-token id, and means adding
// per-token revocation later needs no format bump.
type adminClaims struct {
	Ver      int    `json:"v"`
	ID       string `json:"jti"`
	Admin    string `json:"adm"`
	IssuedAt int64  `json:"iat"`
	Expires  int64  `json:"exp"`
}

// Issue mints an administrator token naming id, tagged with jti and valid over
// [issuedAt, expiresAt).
//
// The caller supplies both timestamps and the jti, so this function holds no
// clock and no RNG; see the package documentation on why expiry decisions take
// an explicit time. An empty administrator id or jti is a caller bug and is
// refused rather than minted -- a token naming no administrator would verify to
// the empty id, which listadmin refuses, but emitting one at all is a defect
// this layer will not commit.
func (s *AdminTokenSigner) Issue(id domain.AdministratorID, jti string, issuedAt, expiresAt time.Time) (secrets.Redacted, error) {
	if id == "" || jti == "" {
		return "", fmt.Errorf("auth: admin token is missing an identifier: %w", domain.ErrInvalidInput)
	}
	if !issuedAt.Before(expiresAt) {
		return "", fmt.Errorf("auth: admin token expires at or before it is issued: %w", domain.ErrInvalidInput)
	}

	claims := adminClaims{
		Ver:      adminTokenVersion,
		ID:       jti,
		Admin:    string(id),
		IssuedAt: issuedAt.Unix(),
		Expires:  expiresAt.Unix(),
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("auth: encoding admin token claims: %w", err)
	}

	encoded := tokenEncoding.EncodeToString(payload)
	mac := s.mac([]byte(encoded))
	return secrets.NewRedacted(adminTokenPrefix + encoded + tokenSeparator + tokenEncoding.EncodeToString(mac)), nil
}

// Verify checks a presented administrator token and returns the embedded
// AdministratorID.
//
// Every rejection -- wrong prefix (an owner token, say), wrong shape, bad MAC,
// unknown version, expired, not yet valid, malformed or empty claims -- returns
// bare ErrAuthFailed, for the reason given on that sentinel: an unauthenticated
// caller must not be able to tell a forged admin token from an expired one, nor
// an owner token from a garbage one. The semantics mirror
// AccessTokenSigner.Verify exactly.
//
// now is supplied by the caller; this function never reads the clock.
func (s *AdminTokenSigner) Verify(presented secrets.Redacted, now time.Time) (domain.AdministratorID, error) {
	body, ok := strings.CutPrefix(presented.Reveal(), adminTokenPrefix)
	if !ok {
		return "", ErrAuthFailed
	}
	encoded, macPart, ok := strings.Cut(body, tokenSeparator)
	if !ok || strings.Contains(macPart, tokenSeparator) {
		return "", ErrAuthFailed
	}
	presentedMAC, err := tokenEncoding.DecodeString(macPart)
	if err != nil {
		return "", ErrAuthFailed
	}

	// The MAC is recomputed over the received encoded bytes, exactly as they
	// arrived, and compared before anything in them is interpreted. Decoding
	// first and re-encoding to check would compare a canonicalized form rather
	// than the one that was signed, so two different strings could verify against
	// one MAC. hmac.Equal is the constant-time comparison; a plain == on the MACs
	// is a forgery oracle, since an attacker who can time it can grow a valid MAC
	// one byte at a time.
	if !hmac.Equal(presentedMAC, s.mac([]byte(encoded))) {
		return "", ErrAuthFailed
	}

	payload, err := tokenEncoding.DecodeString(encoded)
	if err != nil {
		return "", ErrAuthFailed
	}
	var claims adminClaims
	dec := json.NewDecoder(bytes.NewReader(payload))
	// An unknown field means the token was produced by something that is not this
	// issuer, or by a version whose extra claims this code would silently ignore.
	// Ignoring a claim you do not understand is how a restriction gets dropped, so
	// it is refused instead.
	dec.DisallowUnknownFields()
	if err := dec.Decode(&claims); err != nil {
		return "", ErrAuthFailed
	}
	if claims.Ver != adminTokenVersion {
		return "", ErrAuthFailed
	}
	if claims.Admin == "" {
		return "", ErrAuthFailed
	}

	issued := time.Unix(claims.IssuedAt, 0).UTC()
	expires := time.Unix(claims.Expires, 0).UTC()
	// Valid while now is at or after issuance and strictly before expiry, so a
	// token presented at the exact expiry instant is refused. Half-open beats
	// closed at both ends: the boundary belongs to the side that denies.
	if now.Before(issued) || !now.Before(expires) {
		return "", ErrAuthFailed
	}

	return domain.AdministratorID(claims.Admin), nil
}

// mac returns HMAC-SHA256 of msg under the signer's key.
func (s *AdminTokenSigner) mac(msg []byte) []byte {
	h := hmac.New(sha256.New, s.key)
	h.Write(msg)
	return h.Sum(nil)
}
