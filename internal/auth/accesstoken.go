package auth

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/secrets"
)

// MinSigningKeyLen is the shortest accepted access-token signing key: 256 bits,
// matching the output width of the HMAC-SHA256 it keys. A shorter key is the
// one weakness in this construction that nothing downstream can compensate for,
// so it is refused at construction rather than warned about.
const MinSigningKeyLen = 32

// accessTokenVersion is the payload format version. Verification requires an
// exact match, so a future format change cannot be presented to a server that
// would read the new fields under the old meaning.
const accessTokenVersion = 1

// AccessTokenSigner mints and verifies access tokens.
//
// # Why the token is self-contained
//
// An access token carries its own claims and a MAC over them, and verification
// reads nothing from storage. domain.AccessToken is deliberately not persisted:
// checking a bearer token against a table on every request puts the database on
// the hot path of every call, and the row would exist only to say "yes, still
// valid" for at most fifteen minutes. The cost of that choice is stated
// plainly: an issued access token cannot be withdrawn before it expires. The
// short lifetime is what makes that acceptable, and B3's denylist is what
// shortens it further.
//
// # Why HMAC and not a signature
//
// The same server both mints and verifies, so there is no third party that
// needs to verify without being able to mint. A public-key signature would buy
// exactly that property and nothing else, in exchange for a larger token and
// slower verification. HMAC-SHA256 is the right primitive for a symmetric
// trust boundary.
//
// # Why there is no algorithm field
//
// The MAC algorithm is fixed in the code and named nowhere in the token. Every
// famous failure of this token shape -- "alg: none", HMAC-verified-with-an-RSA-
// public-key -- comes from letting the token tell the verifier how to check it.
// A token that cannot express an algorithm cannot lie about one.
//
// # Key rotation
//
// One key, no key identifier, no accepted-previous-keys list. With a fifteen
// minute lifetime, rotation is: install the new key, and every token signed by
// the old one has expired a quarter of an hour later. A verification keyring
// would exist solely to avoid that quarter hour, at the cost of a mechanism
// that must itself be kept from ever accepting a key it should have dropped.
//
// An AccessTokenSigner is immutable after construction and safe for concurrent
// use.
type AccessTokenSigner struct {
	key []byte
}

// NewAccessTokenSigner builds a signer from a symmetric key of at least
// MinSigningKeyLen bytes.
//
// The key is copied so that a caller who reuses or zeroes its buffer cannot
// change the signer's key underneath it. Provisioning the key -- from the
// secrets package, in cmd/valletd -- is deployment wiring and is not done here;
// this type only refuses to operate without an adequate one.
func NewAccessTokenSigner(key []byte) (*AccessTokenSigner, error) {
	if len(key) < MinSigningKeyLen {
		return nil, fmt.Errorf("auth: access token signing key must be at least %d bytes: %w", MinSigningKeyLen, domain.ErrInvalidInput)
	}
	k := make([]byte, len(key))
	copy(k, key)
	return &AccessTokenSigner{key: k}, nil
}

// accessClaims is the wire form of an access token payload. The field names are
// short because they are copied into every request's Authorization header.
type accessClaims struct {
	Ver      int         `json:"v"`
	ID       string      `json:"jti"`
	Owner    string      `json:"own"`
	Refresh  string      `json:"ref"`
	Scopes   []wireScope `json:"scp"`
	IssuedAt int64       `json:"iat"`
	Expires  int64       `json:"exp"`
}

// wireScope is the wire form of a domain.Scope.
type wireScope struct {
	Kind     string `json:"k"`
	Resource string `json:"r,omitempty"`
}

// Issue mints an access token for tok.
//
// The caller supplies every field, including both timestamps, so that this
// function holds no clock; see the package documentation on why expiry
// decisions take an explicit time.
func (s *AccessTokenSigner) Issue(tok domain.AccessToken) (secrets.Redacted, error) {
	if tok.ID == "" || tok.OwnerID == "" || tok.RefreshCredentialID == "" {
		return "", fmt.Errorf("auth: access token is missing an identifier: %w", domain.ErrInvalidInput)
	}
	if err := ValidateScopes(tok.Scopes); err != nil {
		return "", err
	}
	if !tok.IssuedAt.Before(tok.ExpiresAt) {
		return "", fmt.Errorf("auth: access token expires at or before it is issued: %w", domain.ErrInvalidInput)
	}

	claims := accessClaims{
		Ver:      accessTokenVersion,
		ID:       tok.ID,
		Owner:    string(tok.OwnerID),
		Refresh:  string(tok.RefreshCredentialID),
		Scopes:   make([]wireScope, 0, len(tok.Scopes)),
		IssuedAt: tok.IssuedAt.Unix(),
		Expires:  tok.ExpiresAt.Unix(),
	}
	for _, sc := range tok.Scopes {
		claims.Scopes = append(claims.Scopes, wireScope{Kind: string(sc.Kind), Resource: sc.ResourceID})
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("auth: encoding access token claims: %w", err)
	}

	encoded := tokenEncoding.EncodeToString(payload)
	mac := s.mac([]byte(encoded))
	return secrets.NewRedacted(accessTokenPrefix + encoded + tokenSeparator + tokenEncoding.EncodeToString(mac)), nil
}

// Verify checks a presented access token and returns its claims.
//
// Every rejection -- wrong prefix, wrong shape, bad MAC, unknown version,
// expired, not yet valid, malformed claims -- returns bare ErrAuthFailed, for
// the reason given on that sentinel: an unauthenticated caller must not be able
// to tell a forged token from an expired one.
//
// now is supplied by the caller; this function never reads the clock.
func (s *AccessTokenSigner) Verify(presented secrets.Redacted, now time.Time) (*domain.AccessToken, error) {
	body, ok := strings.CutPrefix(presented.Reveal(), accessTokenPrefix)
	if !ok {
		return nil, ErrAuthFailed
	}
	encoded, macPart, ok := strings.Cut(body, tokenSeparator)
	if !ok || strings.Contains(macPart, tokenSeparator) {
		return nil, ErrAuthFailed
	}
	presentedMAC, err := tokenEncoding.DecodeString(macPart)
	if err != nil {
		return nil, ErrAuthFailed
	}

	// The MAC is recomputed over the received encoded bytes, exactly as they
	// arrived, and compared before anything in them is interpreted. Decoding
	// first and re-encoding to check would compare a canonicalized form rather
	// than the one that was signed, so two different strings could verify
	// against one MAC. hmac.Equal is the constant-time comparison; a plain ==
	// on the MACs is a forgery oracle, since an attacker who can time it can
	// grow a valid MAC one byte at a time.
	if !hmac.Equal(presentedMAC, s.mac([]byte(encoded))) {
		return nil, ErrAuthFailed
	}

	payload, err := tokenEncoding.DecodeString(encoded)
	if err != nil {
		return nil, ErrAuthFailed
	}
	var claims accessClaims
	dec := json.NewDecoder(bytes.NewReader(payload))
	// An unknown field means the token was produced by something that is not
	// this issuer, or by a version whose extra claims this code would silently
	// ignore. Ignoring a claim you do not understand is how a restriction gets
	// dropped, so it is refused instead.
	dec.DisallowUnknownFields()
	if err := dec.Decode(&claims); err != nil {
		return nil, ErrAuthFailed
	}
	if claims.Ver != accessTokenVersion {
		return nil, ErrAuthFailed
	}
	if claims.ID == "" || claims.Owner == "" || claims.Refresh == "" {
		return nil, ErrAuthFailed
	}

	scopes := make([]domain.Scope, 0, len(claims.Scopes))
	for _, ws := range claims.Scopes {
		scopes = append(scopes, domain.Scope{Kind: domain.ScopeKind(ws.Kind), ResourceID: ws.Resource})
	}
	// A validly signed token with an unusable scope set is still refused. The
	// signature proves this server minted it; it does not prove the set means
	// anything the enforcement layer in B5 can act on, and "signed, so allow"
	// is exactly the reasoning that turns one bad grant into an open door.
	if err := ValidateScopes(scopes); err != nil {
		return nil, ErrAuthFailed
	}

	issued := time.Unix(claims.IssuedAt, 0).UTC()
	expires := time.Unix(claims.Expires, 0).UTC()
	// Valid while now is at or after issuance and strictly before expiry, so a
	// token presented at the exact expiry instant is refused. Half-open beats
	// closed at both ends: the boundary belongs to the side that denies.
	if now.Before(issued) || !now.Before(expires) {
		return nil, ErrAuthFailed
	}

	return &domain.AccessToken{
		ID:                  claims.ID,
		OwnerID:             domain.OwnerID(claims.Owner),
		RefreshCredentialID: domain.RefreshCredentialID(claims.Refresh),
		Scopes:              scopes,
		IssuedAt:            issued,
		ExpiresAt:           expires,
	}, nil
}

// mac returns HMAC-SHA256 of msg under the signer's key.
func (s *AccessTokenSigner) mac(msg []byte) []byte {
	h := hmac.New(sha256.New, s.key)
	h.Write(msg)
	return h.Sum(nil)
}
