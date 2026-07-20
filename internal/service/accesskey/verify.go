package accesskey

import (
	"context"
	"errors"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/secrets"
)

// Verify decides whether a presented bearer token unlocks the given key set,
// and returns the credential it resolved to.
//
// ownerID comes from the handle in the request path, which the transport has
// already resolved; setID is the set being fetched. The token supplies only an
// id and a secret. Every one of the four checks below must pass, and a failure
// of any of them is reported as ErrNotFound with nothing to tell them apart —
// unknown id, wrong secret, revoked, closed grace window, wrong key set, and
// unparseable token are one answer, so that the transport can return one 404
// and an attacker probing a protected set learns nothing from the response
// (ADR-0019).
//
// A storage fault is not one of those answers and propagates unchanged. A
// database that could not be read has not decided that the caller is
// unauthorized, and reporting a denial for it would make an outage look exactly
// like normal operation while quietly failing closed for everyone.
//
// Verify performs no audit emission. It runs on every fetch of every protected
// set, so recording it would turn a read path into a write path and make an
// unauthenticated caller able to fill the audit table on demand. Access to
// protected sets is observable in the request log; the audit trail records the
// changes to credentials, which is what ADR-0007 asks of it.
func (s *Service) Verify(ctx context.Context, ownerID domain.OwnerID, setID domain.KeySetID, presented secrets.Redacted) (*domain.AccessKey, error) {
	// An empty owner or set here is a bug in the caller, but it is answered
	// with the verdict rather than an invalid-input error: this is the
	// unauthenticated path, and a second distinguishable outcome on it is a
	// second signal to read. Refusing is also the safe direction — an empty
	// owner must never be allowed to match a row.
	if ownerID == "" || setID == "" {
		return nil, ErrNotFound
	}

	id, secret, ok := parseToken(presented.Reveal())
	if !ok {
		return nil, ErrNotFound
	}

	k, err := s.keys.Get(ctx, ownerID, id)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	// A nil credential with a nil error violates the port contract, so no adapter
	// in this tree reaches here. It is guarded because the two readings of a
	// contract violation on this path are "dereference and panic" and "refuse",
	// and only one of those is safe: Verify runs on every request for a protected
	// set, so a panic here is reachable by anyone who can send a Bearer token and
	// would take the process down rather than refuse one call.
	if k == nil {
		return nil, ErrNotFound
	}

	// THE SET-SCOPE CHECK. Get filtered by owner and id and not by key set, so
	// at this point the caller has proven only that the id names one of this
	// owner's credentials — which a token minted for the owner's PUBLIC set
	// does too. Access keys are per-set (ADR-0016), and without this comparison
	// any of the owner's tokens would open every one of the owner's protected
	// sets. It is checked before the secret so that a token for the wrong set
	// is refused whether or not it is otherwise valid.
	if k.KeySetID != setID {
		return nil, ErrNotFound
	}

	// The status check runs before the digest comparison so that a revoked
	// credential is refused even when the secret presented is the correct one.
	// That ordering is the whole meaning of revocation.
	if !s.usable(k) {
		return nil, ErrNotFound
	}

	if !s.hasher.equal(k.SecretHash, id, secret) {
		return nil, ErrNotFound
	}
	return k, nil
}

// usable reports whether a credential's lifecycle state permits verification.
//
//   - active verifies.
//   - grace verifies while now is at or before GraceUntil. The boundary is
//     INCLUSIVE: a rotation promises the old credential remains usable until the
//     stated deadline, and a deadline that denied at its own instant would be a
//     window one moment shorter than the one the owner was shown. The
//     half-open convention used for access tokens elsewhere answers a different
//     question — there the deadline is when a grant ends, here it is the last
//     moment a superseded grant is honored.
//   - revoked never verifies, at any time. Revocation is terminal, and it is
//     checked as an explicit deny rather than falling out of the default so
//     that a future status added to the domain cannot quietly become usable.
//
// A grace row with no deadline is refused. It should not exist — the
// repository writes GraceUntil and the status together — but a credential whose
// window cannot be evaluated is not a credential that should open anything, and
// treating a missing deadline as "no expiry" would turn a data fault into an
// immortal token.
func (s *Service) usable(k *domain.AccessKey) bool {
	switch k.Status {
	case domain.AccessKeyStatusActive:
		return true
	case domain.AccessKeyStatusGrace:
		if k.GraceUntil == nil {
			return false
		}
		return !s.now().UTC().After(*k.GraceUntil)
	default:
		// Revoked, and anything unrecognized. An unknown status is a row this
		// code does not understand, and the safe reading of a credential you do
		// not understand is no.
		return false
	}
}
