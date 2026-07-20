package auth

import (
	"context"
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/counter"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
)

// DenylistSkew is the margin added to a denylist entry's lifetime on top of
// AccessTokenLifetime.
//
// An entry only has to outlive the tokens it denies, and the newest token
// derived from a credential expires AccessTokenLifetime after that credential
// was issued, which is never later than AccessTokenLifetime after the
// revocation. So the exact requirement is AccessTokenLifetime, and this margin
// covers the one thing that arithmetic assumes: that the instance recording the
// revocation and the instance verifying the token agree on the time. They are
// different machines in a multi-instance deployment, and if the verifier's
// clock runs behind, a token this instance considers expired is still being
// accepted over there. A minute is far more skew than a deployment with working
// time sync ever has, and the cost of the margin is one extra minute of a small
// entry.
const DenylistSkew = time.Minute

// denylistKeyPrefix domain-separates this package's keys in a counter store
// that is shared with the rate limiter (ADR-0023). Without it, a limiter key
// and a denylist key could collide, and a collision here is a revocation that
// silently disappears or an identifier that is denied because someone
// rate-limited an unrelated thing.
const denylistKeyPrefix = "vallet.auth.denylist.v1"

// denylistSubjectCredential is the subject kind for a refresh credential id. It
// is part of the hashed key, so a future kind cannot collide with this one.
const denylistSubjectCredential = "cred"

// Denylist records identifiers whose access tokens must stop being accepted
// before they expire on their own.
//
// # Why this exists
//
// Access tokens are verified statelessly, so an issued one cannot be withdrawn:
// it is good until its fifteen minutes are up. ADR-0018 accepts that for the
// ordinary case and adds this denylist for the high-value events -- logout,
// device or credential removal, scope change, and refresh-reuse theft detection
// -- where waiting out the TTL is not acceptable. It is consulted in addition
// to the signature and expiry checks, never instead of them.
//
// # What is denied
//
// Entries name a refresh credential id, which every access token carries in its
// "ref" claim. That is the only identifier that works, and the reason is worth
// stating: an access token's own id exists nowhere but inside the token, since
// access tokens are never persisted, so there is no way to enumerate "every
// live access token" of anything by that id. Refresh credentials are rows, and
// a lineage's rows are enumerable, so denying the credential denies every
// access token minted from it -- which is exactly the granularity ADR-0018 asks
// for when it says revoking a refresh credential invalidates its whole rotation
// lineage.
//
// # Keys are hashed
//
// The stored key is a digest of the subject, not the subject itself. The store
// may be shared infrastructure -- one Redis holding the rate limiter's counters
// too -- so anyone who can dump it must not thereby learn which credentials the
// system has revoked, which would be a map of recent security incidents. The
// digest is a plain SHA-256 because a credential id is 128 bits from
// crypto/rand: there is no searchable space for a slow KDF to protect, and
// preimage resistance is the whole requirement.
//
// Note that no comparison of secret-derived material happens anywhere in this
// type; lookups are exact-key, so there is nothing here for a timing attack to
// walk. The constant-time comparisons in this package are on the paths that do
// compare secrets: secretMatches and the access token's MAC check.
//
// A Denylist is immutable after construction and safe for concurrent use.
type Denylist struct {
	store counter.Store
}

// NewDenylist builds a Denylist over store.
//
// A nil store is refused. Tolerating one would produce a Denylist whose Check
// always permits -- a revocation control that is wired up, looks enforced, and
// enforces nothing. That is the failure this whole type exists to prevent, so
// it stops the process at startup instead.
func NewDenylist(store counter.Store) (*Denylist, error) {
	if store == nil {
		return nil, fmt.Errorf("auth: nil counter store: %w", domain.ErrInvalidInput)
	}
	return &Denylist{store: store}, nil
}

// Check reports whether tok is still acceptable.
//
// It returns nil if and only if the token is permitted. EVERY non-nil error
// means denied, and there is no error class a caller may read as permitted.
// That is the entire contract, and the signature is chosen to enforce it: a
// (bool, error) shape invites the caller to inspect the bool and let the error
// fall through to a default of "allowed", which is the fail-open bug this
// control cannot survive.
//
// # Fail closed
//
// If the store cannot be consulted -- down, timed out, context canceled -- the
// answer is denied. A denylist that failed open would be worse than no denylist
// at all: it would convert an outage of an auxiliary store into a silent,
// system-wide authentication bypass, arriving exactly when an attacker who
// could cause the outage would want it, and it would do so while every
// dashboard still showed revocation as an enforced control. Denying instead
// turns that same outage into an availability incident, which is loud, bounded
// by the fifteen-minute token lifetime, and cannot be mistaken for normal
// operation.
//
// The two causes are distinguishable to server code -- a listed identifier
// returns bare ErrAuthFailed, a store fault wraps counter.ErrStoreUnavailable
// -- so an operator can tell a revocation from an outage in the logs. They are
// not distinguishable to the caller of the API, because the token service maps
// both to ErrAuthFailed before anything reaches a client.
func (d *Denylist) Check(ctx context.Context, tok *domain.AccessToken) error {
	if tok == nil {
		// A nil token on a revocation check is a programming error, and the
		// safe reading of one on an authentication path is "denied" rather than
		// "dereference and panic" -- the same posture the authenticator takes
		// on a port contract violation.
		return ErrAuthFailed
	}
	if tok.RefreshCredentialID == "" {
		// A token with no credential id cannot be checked against the denylist
		// at all, so it cannot be permitted by it. The access token verifier
		// already refuses this shape; denying again here means the guarantee
		// holds locally instead of being inherited from a caller.
		return ErrAuthFailed
	}

	got, err := d.store.Get(ctx, credentialKey(tok.RefreshCredentialID))
	if err != nil {
		// The fail-closed branch. It must stay a denial: replacing this with a
		// permit -- or with a nil return "until the store comes back" -- is the
		// bypass described above.
		return fmt.Errorf("auth: denylist unavailable: %w", err)
	}
	if got.Value > 0 {
		// Bare, per the sentinel's contract: a revoked credential must be
		// indistinguishable from a forged or expired token to the caller.
		return ErrAuthFailed
	}
	return nil
}

// RevokeCredential lists id, so that access tokens minted from that refresh
// credential stop being accepted within DenylistSkew of now.
//
// The entry lives for AccessTokenLifetime plus the skew margin and then expires
// on its own. There is no delete: an entry is retracted only by expiring, and
// by then every token it could have denied is already dead of its own expiry.
// This is what keeps the denylist small however many revocations pass through
// it, and it is why the store's active expiry is a requirement of the port
// rather than a nicety.
func (d *Denylist) RevokeCredential(ctx context.Context, id domain.RefreshCredentialID) error {
	if id == "" {
		return fmt.Errorf("auth: empty refresh credential id: %w", domain.ErrInvalidInput)
	}
	if _, err := d.store.Increment(ctx, credentialKey(id), 1, denylistEntryTTL()); err != nil {
		return fmt.Errorf("auth: listing refresh credential: %w", err)
	}
	return nil
}

// RevokeLineage lists every credential in creds whose access tokens may still
// be live at now.
//
// creds is the lineage as returned by
// RefreshCredentialRepository.ListByLineage. The caller passes the rows rather
// than a lineage id because the denylist holds no repository: it is a small
// fast store in front of one, and giving it a way to query the database would
// put the database back on the path this exists to keep off it.
//
// # Why the filter is safe
//
// Only credentials issued within the last AccessTokenLifetime (plus the skew
// margin) are listed. That is not a shortcut that leaves a hole: an access
// token minted from an older credential has already passed its own expiry, and
// the stateless expiry check in AccessTokenSigner.Verify refuses it without the
// denylist being involved at all. Listing those credentials would add entries
// that can only ever match a token that is already refused.
//
// The filter is what bounds the work. A ninety-day lineage that rotated every
// few minutes holds thousands of rows, and writing an entry for every one of
// them on each theft detection would make the denylist's size a function of how
// long the victim had been a user.
//
// # Errors are for the caller to weigh
//
// It returns the first error and stops. The caller must not roll back a
// database revocation because this failed: the rows being revoked is the
// durable, authoritative part, and undoing it to keep the two consistent would
// un-revoke a credential that was just detected as stolen. A failure here costs
// at most the fifteen minutes the denylist exists to save; a rollback costs the
// account.
func (d *Denylist) RevokeLineage(ctx context.Context, creds []domain.RefreshCredential, now time.Time) error {
	cutoff := now.Add(-denylistEntryTTL())
	for i := range creds {
		if !creds[i].IssuedAt.After(cutoff) {
			continue
		}
		if creds[i].ID == "" {
			// A malformed row. Skipping it is right -- there is no identifier
			// to list -- but it must not silently pass for success, or a
			// database that started returning empty ids would look like a
			// working denylist.
			return fmt.Errorf("auth: refresh credential with an empty id in lineage: %w", domain.ErrInvalidInput)
		}
		if err := d.RevokeCredential(ctx, creds[i].ID); err != nil {
			return err
		}
	}
	return nil
}

// denylistEntryTTL is how long an entry lives: long enough to outlive every
// access token it could be asked about. See DenylistSkew.
func denylistEntryTTL() time.Duration {
	return AccessTokenLifetime + DenylistSkew
}

// credentialKey derives the store key for a refresh credential id.
//
// The subject kind and the id are joined with NUL bytes rather than
// concatenated, so that no two distinct subjects can produce the same input:
// under a plain concatenation "cred" + "ab" and "creda" + "b" are one string,
// and a key collision on a denylist is a revocation applied to the wrong
// identifier. The prefix is inside the digest, not outside it, so the whole key
// is fixed-length and reveals nothing about what it names.
func credentialKey(id domain.RefreshCredentialID) string {
	sum := sha256.Sum256([]byte(denylistKeyPrefix + "\x00" + denylistSubjectCredential + "\x00" + string(id)))
	return tokenEncoding.EncodeToString(sum[:])
}
