// Package auth defines the authentication port for sshpilot-vallet and the
// resolution of an authenticated principal to an owner.
//
// # The two-step model
//
// Authentication is deliberately split in two, and the split is the whole
// reason this package exists:
//
//  1. An AuthProvider verifies presented credential material and yields a
//     *principal*: a provider-scoped, stable, opaque identifier. A provider
//     never learns or asserts an owner.
//  2. A LinkedIdentity row maps (provider, principal) to a domain.OwnerID. Only
//     that mapping turns a principal into an owner.
//
// Collapsing the two — letting a provider return an owner directly — would make
// every provider a trusted issuer of owner identity, so a single compromised or
// buggy provider could speak for any account. Keeping the indirection means a
// provider can only ever assert "this is principal P in my namespace"; whether
// P is anybody at all is a separate, storage-backed fact. It also lets one owner
// hold several credentials (a hardware key, a phone, a CI token) and lets a
// provider be swapped without re-keying owners.
//
// # Provider-scoped principals
//
// A principal is meaningful ONLY within the provider that issued it. The OIDC
// subject "1234" and the API-token device id "1234" are unrelated values that
// happen to share bytes. Every lookup therefore keys on the pair
// (provider, principal), never on the principal alone, and the two travel
// together in an Identity so they cannot be separated by accident.
//
// The pair is never flattened into a single delimiter-joined string. Joining
// with a separator reintroduces exactly the collision the pairing exists to
// prevent: provider "a" with principal "b:c" and provider "a:b" with principal
// "c" both render as "a:b:c". Where a single key is unavoidable it must be a
// struct key or length-prefixed, never a concatenation. ProviderID is
// additionally constrained to a slug charset that contains no separator
// character, so even an accidental join cannot be made ambiguous.
//
// # Fail closed
//
// Every path in this package denies by default. An unregistered provider, a
// provider error, an unknown principal, a principal with no link, or a
// non-active owner all deny. There is deliberately no "create an owner on the
// fly" and no implicit linking: linking an identity to an owner is an explicit,
// separately authorized act, because an implicit link is an account takeover
// primitive.
//
// Removing a credential is deletion of its LinkedIdentity row, which is
// fail-closed by construction: the mapping is gone, so resolution denies. There
// is deliberately no "disabled" flag on a link yet. A status field that no code
// on the authentication path reads would be worse than none at all — it would
// read as "disabling a link is supported" while nothing enforced it. Revocation
// state arrives with the denylist in track B3, wired and enforced in the same
// change that introduces it.
//
// # Indistinguishable failure
//
// Every denial returns exactly ErrAuthFailed, with no wrapped cause. A caller
// cannot tell an unregistered provider from a rejected credential, from an
// unlinked principal, from a suspended owner. This mirrors the storage-layer
// invariant where domain.ErrNotFound deliberately covers both "missing" and
// "another owner's row": distinguishing them leaks the existence of accounts and
// of registered credentials to an unauthenticated caller.
//
// This is an information-content guarantee, not a timing guarantee. The code
// paths take different numbers of storage round trips, so a determined attacker
// with precise timing may still distinguish some causes. Defending that belongs
// with rate limiting and lockout, which are separate concerns.
//
// Diagnosing a denial is an operator concern served by audit records, not by the
// returned error. Callers MUST NOT relay any richer reason to the client.
package auth

import (
	"context"
	"fmt"
	"regexp"
	"unicode/utf8"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/secrets"
)

// Length bounds for the identifier types in this package.
const (
	// MaxProviderIDLen bounds a provider identifier. Provider ids are chosen by
	// operators wiring the server, not by users, so a short bound is ample.
	MaxProviderIDLen = 32
	// MaxPrincipalLen bounds a principal. It is generous enough for the longest
	// realistic external subject (a base64url WebAuthn credential id, an OIDC
	// "sub" from a provider that emits opaque blobs) while still refusing
	// unbounded input from an external identity provider.
	MaxPrincipalLen = 255
)

// providerIDRe matches a provider id: lowercase [a-z0-9-] with no leading or
// trailing hyphen. It is the same slug rule the domain package applies to
// handles and set names, restated here because auth must not depend on an
// unexported domain helper.
//
// The charset matters for more than tidiness: it excludes ':', '/', '\x00' and
// every other separator, so a provider id can never be crafted to make a
// composed key ambiguous.
var providerIDRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)

// ProviderID names a registered authentication provider, for example
// "api-token", "webauthn" or "oidc". It is part of the identity key, so two
// providers with different ids occupy disjoint principal namespaces.
//
// A ProviderID is always the value an AuthProvider reports for itself. It is
// never taken from client-controlled input, because a caller able to choose the
// provider half of the key could present a principal it controls under one
// provider and have it resolve to an owner linked under another.
type ProviderID string

// String returns the provider id as a string. A provider id is an operator-set
// label, not a secret, so it is safe to render.
func (p ProviderID) String() string { return string(p) }

// Validate reports whether the provider id is well formed: 1-MaxProviderIDLen
// characters of lowercase [a-z0-9-] with no leading or trailing hyphen.
func (p ProviderID) Validate() error {
	if p == "" {
		return fmt.Errorf("auth: provider id must not be empty: %w", domain.ErrInvalidInput)
	}
	if len(p) > MaxProviderIDLen {
		return fmt.Errorf("auth: provider id exceeds %d characters: %w", MaxProviderIDLen, domain.ErrInvalidInput)
	}
	if !providerIDRe.MatchString(string(p)) {
		return fmt.Errorf("auth: provider id must be lowercase [a-z0-9-] with no leading or trailing hyphen: %w", domain.ErrInvalidInput)
	}
	return nil
}

// Principal is a provider-scoped, stable, opaque identifier for the party a
// provider authenticated: an OIDC "sub", a WebAuthn credential id, an
// API-token device id.
//
// Stable means it does not change when the party's email, display name or
// device label changes; opaque means this package never parses or interprets
// it. It is scoped to its issuing provider and is meaningless without it, which
// is why it is only ever carried inside an Identity.
//
// A principal is an identifier, not a secret: it is stored in the clear so it
// can be indexed, and it is not proof of anything on its own. The secret
// material a provider consumes to produce one is Credential, which is
// redaction-safe.
type Principal string

// Validate reports whether the principal is well formed: non-empty, valid
// UTF-8, at most MaxPrincipalLen bytes, and free of NUL.
//
// The content rules are deliberately weak because the value is opaque and
// externally defined: over-constraining it would reject legitimate subjects
// from providers this code has never seen. The bound and the NUL check are the
// two things worth enforcing anyway — an unbounded value is a storage and log
// hazard, and an embedded NUL is the classic truncation trick against any layer
// that later hands the value to a C API.
func (p Principal) Validate() error {
	if p == "" {
		return fmt.Errorf("auth: principal must not be empty: %w", domain.ErrInvalidInput)
	}
	if len(p) > MaxPrincipalLen {
		return fmt.Errorf("auth: principal exceeds %d bytes: %w", MaxPrincipalLen, domain.ErrInvalidInput)
	}
	if !utf8.ValidString(string(p)) {
		return fmt.Errorf("auth: principal must be valid UTF-8: %w", domain.ErrInvalidInput)
	}
	for i := 0; i < len(p); i++ {
		if p[i] == 0 {
			return fmt.Errorf("auth: principal must not contain NUL: %w", domain.ErrInvalidInput)
		}
	}
	return nil
}

// Identity is what an AuthProvider yields on success: the provider that did the
// authenticating, and the principal it authenticated. It is the complete
// identity key, and the two fields are kept in one value precisely so no caller
// can pass a principal onward without the provider that gives it meaning.
//
// An Identity says nothing about which owner, or whether any owner, it belongs
// to. Resolving that is Authenticator's job.
type Identity struct {
	// Provider is the id of the provider that performed the authentication. A
	// provider MUST set this to its own ID; Authenticator rejects any other
	// value rather than trusting it.
	Provider ProviderID
	// Principal is the provider-scoped identifier of the authenticated party.
	Principal Principal
}

// Validate reports whether both halves of the identity key are well formed.
func (i Identity) Validate() error {
	if err := i.Provider.Validate(); err != nil {
		return err
	}
	return i.Principal.Validate()
}

// Credential is the raw, unverified material a caller presents. It is a struct
// rather than a bare string for two reasons.
//
// First, redaction: Secret is a secrets.Redacted, so a Credential printed with
// any fmt verb, logged via slog, or marshaled to JSON renders "[REDACTED]"
// rather than a live bearer token. The methods below extend that to the
// enclosing struct, so the guarantee survives a caller logging the whole value.
//
// Second, evolution: a struct can gain fields without breaking a single
// implementation of AuthProvider. WebAuthn will need the origin and the
// server-held challenge; OIDC will need a nonce and redirect URI. Those arrive
// as new fields here, not as a new method signature that churns every provider.
type Credential struct {
	// Secret is the presented material: a bearer token, a pairing code, an OIDC
	// authorization code, a serialized WebAuthn assertion. Its meaning is the
	// receiving provider's business; this package never inspects it.
	Secret secrets.Redacted
}

// redacted is the single rendering used by every formatting path on Credential,
// so a new path cannot accidentally be added without redaction.
func (c Credential) redacted() string { return "auth.Credential{Secret:[REDACTED]}" }

// String implements fmt.Stringer.
func (c Credential) String() string { return c.redacted() }

// GoString implements fmt.GoStringer so that %#v also redacts.
func (c Credential) GoString() string { return c.redacted() }

// Format implements fmt.Formatter. It takes precedence over String and GoString
// for every verb, which catches the realistic leak path: a Credential printed
// as part of a surrounding struct with %v or %+v.
func (c Credential) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte(c.redacted()))
}

// MarshalJSON implements json.Marshaler, emitting a quoted redacted string so
// the output stays valid JSON.
func (c Credential) MarshalJSON() ([]byte, error) {
	return []byte(`"` + c.redacted() + `"`), nil
}

// MarshalText implements encoding.TextMarshaler.
func (c Credential) MarshalText() ([]byte, error) { return []byte(c.redacted()), nil }

// AuthProvider verifies presented credential material and reports which
// principal it belongs to. It is the extension point for API-token and device
// pairing (first), WebAuthn, and OIDC; all three fit this shape because none of
// them needs to name an owner, only a subject in its own namespace.
//
// Implementations MUST:
//
//   - Return an Identity whose Provider equals the implementation's own ID.
//     Authenticator re-checks this and denies on mismatch, so a provider cannot
//     mint principals in another provider's namespace even if it tries.
//   - Return ErrAuthFailed, unwrapped and carrying no cause, for every
//     authentication denial, however caused. Returning distinguishable errors
//     defeats the indistinguishability guarantee described in the package
//     documentation.
//   - Compare secret material in constant time, and never log, wrap or embed
//     credential material in an error.
//   - Be safe for concurrent use; one instance serves all requests.
//
// An infrastructure fault (the database is down) may be returned as a distinct
// error so it is not silently reported as "wrong password"; Authenticator still
// collapses it to ErrAuthFailed before the caller sees it, because a caller who
// can tell "your token is wrong" from "the store is unreachable" learns whether
// a token was recognized.
type AuthProvider interface {
	// ID returns the provider's own identifier. It MUST be constant for the
	// lifetime of the instance and MUST satisfy ProviderID.Validate.
	ID() ProviderID

	// Authenticate verifies cred and returns the principal it belongs to. It
	// returns ErrAuthFailed on any denial.
	Authenticate(ctx context.Context, cred Credential) (Identity, error)
}
