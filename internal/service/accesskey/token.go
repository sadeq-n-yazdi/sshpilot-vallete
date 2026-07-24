package accesskey

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/secrets"
)

// The bearer token format.
//
//	vak_<id>.<secret>
//
// It carries exactly two things, because verification needs exactly two: the id
// locates the row, and the secret proves the bearer holds the credential that
// row records. The owner is NOT in the token and must not be — it comes from
// the handle in the request path, which the transport has already resolved, and
// a token that named its own owner would be asking the credential to say which
// account it belongs to.
//
// The prefix is fixed, human-readable, and unique to this system so that secret
// scanners and log filters have something to match on; a credential that looks
// like arbitrary base64 is one nobody can grep for. The separator is a
// character that appears in neither of the two alphabets below, so splitting is
// unambiguous rather than a guess about which half is which.
const (
	tokenPrefix    = "vak_"
	tokenSeparator = "."
)

// secretBytes is the entropy in the secret half: 256 bits from crypto/rand.
// This is the credential's entire strength — there is no password stretching
// here and there should not be, because a secret this size is not guessable and
// stretching would only slow down every legitimate request.
const secretBytes = 32

// maxTokenLen bounds what parse will look at. A well-formed token is 74 bytes;
// the ceiling is generous enough to survive a format change and small enough
// that a caller cannot make this service digest a megabyte by putting it in a
// header. Bounding before any work is what keeps a malformed token cheap.
const maxTokenLen = 256

// secretEncoding is unpadded base64url. Padding would put '=' in the token for
// no benefit; unpadded keeps the credential URL-safe and header-safe wherever
// it is carried. The id needs no encoding: rand.Text is already base32 text.
var secretEncoding = base64.RawURLEncoding

// MinPepperLen is the shortest accepted pepper: 256 bits, matching the output
// width of the HMAC-SHA256 it keys. A shorter key is the one weakness in this
// construction nothing downstream can compensate for, so it is refused at
// construction rather than warned about.
const MinPepperLen = 32

// hasher digests access key secrets.
//
// # Why HMAC with a pepper, and not a bare hash
//
// The digest is HMAC-SHA256 keyed by a pepper held outside the database. This
// is the decision the requirement asks to be made explicitly, so: the threat it
// answers is a database-only compromise — a leaked backup, a read-only SQL
// injection, a snapshot on a decommissioned disk. Against a bare SHA-256 of a
// 256-bit random secret, that attacker cannot invert the digest either; what
// they CAN do is verify a guess offline, and — more usefully — mint their own
// row, because computing a valid secret_hash for a secret of their choosing
// needs nothing but the hash function. A digest an attacker can compute is a
// credential an attacker can forge. Keying it means the pepper, which lives in
// the process's configuration and not in any table, is required both to verify
// and to forge, so a database compromise alone yields neither.
//
// # Why not a password KDF
//
// bcrypt, scrypt and Argon2 exist to make LOW-entropy inputs expensive to
// guess. This secret is 256 bits from crypto/rand and is never chosen by a
// human, so there is no guessing to slow down, and per-request stretching would
// buy nothing while putting a deliberate delay on the hot path of every fetch.
//
// # Why the id is bound into the digest
//
// The message is the id and the secret, separated by a byte that cannot occur
// in either. Without the id, a digest would attest only to "this secret is
// valid" and a row's secret_hash could be moved to another row — including
// another key set's — and still verify. Binding the id makes each digest
// meaningful for exactly one credential, so a database write that shuffles
// hashes between rows produces credentials that verify against nothing.
type hasher struct {
	pepper []byte
}

// newHasher builds a hasher, copying the pepper so a caller that reuses or
// zeroes its buffer cannot change the key underneath a running service.
func newHasher(pepper []byte) (*hasher, error) {
	if len(pepper) < MinPepperLen {
		return nil, fmt.Errorf("%w: pepper must be at least %d bytes", ErrMissingDependency, MinPepperLen)
	}
	p := make([]byte, len(pepper))
	copy(p, pepper)
	return &hasher{pepper: p}, nil
}

// hash returns the digest stored in secret_hash for the given id and secret.
func (h *hasher) hash(id domain.AccessKeyID, secret string) []byte {
	m := hmac.New(sha256.New, h.pepper)
	m.Write([]byte(id))
	// A separator that occurs in neither alphabet keeps ("ab", "c") from
	// digesting the same message as ("a", "bc").
	m.Write([]byte{0})
	m.Write([]byte(secret))
	return m.Sum(nil)
}

// equal reports whether a stored digest matches the one computed for id and
// secret.
//
// hmac.Equal is crypto/subtle.ConstantTimeCompare with a length check in front
// of it. The comparison must not short-circuit on the first differing byte: an
// attacker who can time it can grow a matching digest one byte at a time, which
// turns an unguessable secret into a few thousand requests. bytes.Equal and ==
// are both that mistake.
func (h *hasher) equal(stored []byte, id domain.AccessKeyID, secret string) bool {
	return hmac.Equal(stored, h.hash(id, secret))
}

// newToken mints a fresh credential: the plaintext token to hand back once, and
// the id and secret it decomposes into.
//
// The id is rand.Text — 26 base32 characters, about 130 bits — matching the
// identifier convention used for devices, public keys and audit records.
// Unguessability is load-bearing here for the same reason it is there: the id
// is how a revoke names its target and how a verification locates a row, and a
// sequential id would make the cross-owner 404 pointless because an attacker
// would not have to guess.
func newToken() (secrets.Redacted, domain.AccessKeyID, string, error) {
	raw := make([]byte, secretBytes)
	if _, err := rand.Read(raw); err != nil {
		// crypto/rand failing means the process cannot generate a credential
		// that is safe to issue. It is reported, never worked around.
		return "", "", "", fmt.Errorf("accesskey: generating secret: %w", err)
	}
	id := domain.AccessKeyID(rand.Text())
	secret := secretEncoding.EncodeToString(raw)
	return secrets.NewRedacted(tokenPrefix + string(id) + tokenSeparator + secret), id, secret, nil
}

// parseToken splits a presented token into its id and secret.
//
// It is deliberately dull: no decoding, no allocation beyond the split, no
// panics on any input, and a single boolean answer. Every malformed shape —
// wrong prefix, no separator, more than one separator, an empty half, anything
// over maxTokenLen — is rejected the same way, and the caller collapses that
// into the same verdict a wrong secret gets. A parser that reported which part
// was wrong would be a free oracle for shaping guesses.
//
// The length ceiling is checked first so an oversized input is discarded before
// anything scans it.
func parseToken(presented string) (domain.AccessKeyID, string, bool) {
	if len(presented) > maxTokenLen {
		return "", "", false
	}
	body, ok := strings.CutPrefix(presented, tokenPrefix)
	if !ok {
		return "", "", false
	}
	id, secret, ok := strings.Cut(body, tokenSeparator)
	if !ok || id == "" || secret == "" {
		return "", "", false
	}
	// A second separator means this is not a token this service minted. It is
	// refused rather than tolerated, because deciding which of three parts to
	// ignore is a decision an attacker gets to influence.
	if strings.Contains(secret, tokenSeparator) {
		return "", "", false
	}
	return domain.AccessKeyID(id), secret, true
}
