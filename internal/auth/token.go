package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/secrets"
)

// Token lifetimes.
const (
	// AccessTokenLifetime bounds how long an access token is accepted. It is
	// short because an access token is verified statelessly: nothing is read
	// from storage during verification, so a token that has been issued cannot
	// be withdrawn before it expires. The window is therefore the exposure of a
	// stolen access token, and fifteen minutes keeps that exposure small enough
	// that stateless verification is an acceptable trade for the round trip it
	// saves on every request. Faster withdrawal arrives with the B3 denylist.
	AccessTokenLifetime = 15 * time.Minute

	// RefreshLineageLifetime is the absolute cap on a rotation lineage: ninety
	// days after the lineage was first issued, every credential descended from
	// it is dead, however recently it was rotated.
	//
	// The cap is what stops a rotating credential from becoming a permanent one.
	// Without it, an attacker who captures a refresh token and keeps rotating it
	// holds the account forever, because each rotation looks exactly like
	// legitimate use.
	RefreshLineageLifetime = 90 * 24 * time.Hour
)

// Sizes and shapes of the random material in a token.
const (
	// credentialIDBytes is the length of the random credential identifier
	// carried in the clear half of a refresh token: 128 bits. The identifier is
	// a lookup key, not a secret -- presenting it without the matching secret
	// proves nothing -- but it is random rather than sequential so that holding
	// one token does not reveal how many exist or let a caller enumerate
	// neighbors.
	credentialIDBytes = 16

	// refreshSecretBytes is the length of the secret half: 256 bits from
	// crypto/rand. At that size guessing is not a threat model anyone needs to
	// reason about further; the entire security of the credential rests on the
	// secret never being stored, logged, or compared non-constant-time.
	refreshSecretBytes = 32

	// credentialIDChars is the encoded length of credentialIDBytes under
	// base64.RawURLEncoding. It is checked on parse so a malformed identifier is
	// rejected before it reaches storage.
	credentialIDChars = 22

	// MaxClientLabelLen bounds the operator-visible label attached to a refresh
	// credential ("laptop", "ci runner"). The label is chosen by the caller, so
	// it is bounded and character-checked rather than trusted.
	MaxClientLabelLen = 64

	// MaxScopes bounds a scope set. Scopes are copied into every access token,
	// so an unbounded set is an unbounded token.
	MaxScopes = 32
)

// Token prefixes. They are not a security control; they exist so a leaked
// string is recognizable in a secret-scanning pipeline and so an access token
// presented where a refresh token belongs is rejected on shape rather than on
// a signature check that happens to fail.
const (
	refreshTokenPrefix = "svr_"
	accessTokenPrefix  = "sva_"
	tokenSeparator     = "."
)

// tokenEncoding is unpadded base64url: URL- and header-safe, and free of the
// '.' used as the segment separator and of '=' padding, so a token is a single
// unambiguous word.
var tokenEncoding = base64.RawURLEncoding

// randomBytes returns n cryptographically random bytes.
//
// If crypto/rand.Read fails (e.g. due to sandbox restrictions or lack of
// system entropy), the function panics immediately rather than returning a
// zeroed or partially populated buffer. math/rand is never acceptable.
func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("auth: crypto/rand.Read failed: %v", err))
	}
	return b
}

// newCredentialID returns a fresh random refresh credential identifier.
func newCredentialID() domain.RefreshCredentialID {
	return domain.RefreshCredentialID(tokenEncoding.EncodeToString(randomBytes(credentialIDBytes)))
}

// hashRefreshSecret returns the digest stored in
// domain.RefreshCredential.SecretHash. The raw secret is never persisted.
//
// The hash is a plain SHA-256, deliberately not bcrypt, scrypt, or Argon2. A
// slow KDF exists to make guessing a *low-entropy* value expensive: human
// passwords occupy a searchable space, so the defense is to raise the cost of
// each guess. This secret is 256 bits from crypto/rand and occupies no
// searchable space at all, so the stretching buys nothing an attacker would
// ever have to overcome. It is not free, either: a KDF tuned to be slow turns
// every token exchange into measurable server work, which an unauthenticated
// caller can trigger at will -- the KDF becomes the denial-of-service amplifier
// it was chosen to prevent. Fast is correct here precisely because the input is
// high entropy.
//
// The digest is not salted for the same reason. A salt defeats precomputation
// across a shared search space; there is no shared search space when every
// secret is independently random.
func hashRefreshSecret(secret []byte) []byte {
	sum := sha256.Sum256(secret)
	return sum[:]
}

// secretMatches reports whether secret hashes to stored.
//
// The comparison is crypto/subtle's constant-time one. A byte-by-byte compare
// -- which is what bytes.Equal and == both compile to -- returns sooner the
// earlier the first differing byte is, and that timing difference is a usable
// oracle: an attacker who can measure it recovers the stored digest one byte at
// a time. Digests are compared rather than raw secrets so a length difference
// in the presented secret cannot leak either; ConstantTimeCompare returns 0 for
// unequal lengths, which also covers a corrupt or truncated stored hash.
func secretMatches(stored, secret []byte) bool {
	return subtle.ConstantTimeCompare(stored, hashRefreshSecret(secret)) == 1
}

// formatRefreshToken renders the one and only string a caller ever receives for
// a refresh credential: "svr_<id>.<secret>".
//
// The identifier travels with the secret so the server can find the row to
// compare against without indexing the secret itself. The result is a
// secrets.Redacted, so from the moment it exists it cannot be logged, printed,
// or marshaled by accident; the caller shows it to the user once and drops it.
func formatRefreshToken(id domain.RefreshCredentialID, secret []byte) secrets.Redacted {
	return secrets.NewRedacted(refreshTokenPrefix + string(id) + tokenSeparator + tokenEncoding.EncodeToString(secret))
}

// parseRefreshToken splits a presented token into its identifier and secret.
//
// Every malformed shape returns ErrAuthFailed, bare: a caller must not learn
// whether its token was the wrong shape, the wrong length, or simply unknown.
// The parse is strict -- exact prefix, exactly one separator, exact decoded
// lengths -- because anything looser hands storage a value the issuer could
// never have produced.
func parseRefreshToken(presented secrets.Redacted) (domain.RefreshCredentialID, []byte, error) {
	body, ok := strings.CutPrefix(presented.Reveal(), refreshTokenPrefix)
	if !ok {
		return "", nil, ErrAuthFailed
	}
	idPart, secretPart, ok := strings.Cut(body, tokenSeparator)
	if !ok || strings.Contains(secretPart, tokenSeparator) {
		return "", nil, ErrAuthFailed
	}
	if len(idPart) != credentialIDChars {
		return "", nil, ErrAuthFailed
	}
	if _, err := tokenEncoding.DecodeString(idPart); err != nil {
		return "", nil, ErrAuthFailed
	}
	secret, err := tokenEncoding.DecodeString(secretPart)
	if err != nil || len(secret) != refreshSecretBytes {
		return "", nil, ErrAuthFailed
	}
	return domain.RefreshCredentialID(idPart), secret, nil
}

// ValidateScopes checks a scope set before it is granted or accepted.
//
// The rules are shaped so that B5 can enforce a set without having to resolve
// an ambiguity at request time. Enforcement there checks the owner binding
// first -- a token is only ever valid for the owner it names -- and only then
// consults the kinds, so these rules only have to make "what do the kinds
// together permit" a question with one answer:
//
//   - The set is non-empty. An empty set is never read as full access; it is
//     rejected outright, so no code path can arrive at "no scopes, allow".
//   - Each scope is individually well formed (domain.Scope.Validate).
//   - No duplicates. A repeated scope means the caller built the set wrong, and
//     silently collapsing it hides that.
//   - The account-wide kinds, full-owner and read-only, must appear alone.
//     Mixing them with each other or with a resource-bound scope has no
//     defensible reading: "read-only plus full-owner" and "read-only plus write
//     access to one set" both ask the enforcement layer to guess, and a guess
//     on a permission check resolves to more access than someone intended.
//   - Resource-bound kinds (single-set, single-device) may be combined freely,
//     because their union is unambiguous: each names exactly one resource.
//
// It returns a wrapped domain.ErrInvalidInput rather than ErrAuthFailed. The
// caller here is trusted server code building a grant, not an unauthenticated
// party probing for a valid credential, so a precise message helps the only
// audience that sees it.
func ValidateScopes(scopes []domain.Scope) error {
	if len(scopes) == 0 {
		return fmt.Errorf("auth: scope set must not be empty: %w", domain.ErrInvalidInput)
	}
	if len(scopes) > MaxScopes {
		return fmt.Errorf("auth: scope set exceeds %d entries: %w", MaxScopes, domain.ErrInvalidInput)
	}
	seen := make(map[domain.Scope]struct{}, len(scopes))
	for _, s := range scopes {
		if err := s.Validate(); err != nil {
			return err
		}
		if _, dup := seen[s]; dup {
			return fmt.Errorf("auth: duplicate scope %q: %w", s.Kind, domain.ErrInvalidInput)
		}
		seen[s] = struct{}{}
		if accountWideScope(s.Kind) && len(scopes) > 1 {
			return fmt.Errorf("auth: scope kind %q must be the only scope in the set: %w", s.Kind, domain.ErrInvalidInput)
		}
	}
	return nil
}

// accountWideScope reports whether the kind grants across the whole account and
// therefore must stand alone.
func accountWideScope(k domain.ScopeKind) bool {
	return k == domain.ScopeFullOwner || k == domain.ScopeReadOnly
}

// cloneScopes copies a scope set so that a stored entity and an issued token
// never share backing array with the caller's slice. It returns nil for an
// empty input, matching the repository convention that an empty list is a nil
// slice.
func cloneScopes(scopes []domain.Scope) []domain.Scope {
	if len(scopes) == 0 {
		return nil
	}
	out := make([]domain.Scope, len(scopes))
	copy(out, scopes)
	return out
}

// validateClientLabel checks the operator-visible label on a credential:
// bounded, valid UTF-8, and free of control characters. The label is echoed
// back in listings and audit records, so a control character in it is a
// terminal-escape and log-forging hazard rather than a cosmetic problem.
func validateClientLabel(label string) error {
	if len(label) > MaxClientLabelLen {
		return fmt.Errorf("auth: client label exceeds %d bytes: %w", MaxClientLabelLen, domain.ErrInvalidInput)
	}
	if !utf8.ValidString(label) {
		return fmt.Errorf("auth: client label must be valid UTF-8: %w", domain.ErrInvalidInput)
	}
	for _, r := range label {
		if unicode.IsControl(r) {
			return fmt.Errorf("auth: client label must not contain control characters: %w", domain.ErrInvalidInput)
		}
	}
	return nil
}
