package auth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/repository"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/secrets"
)

// Issued is the result of minting or rotating a credential pair. Both tokens
// are secrets.Redacted, so the whole struct is safe to print or log; the raw
// values leave only through Reveal, and only where a caller deliberately hands
// them to the user.
//
// The refresh token in particular exists in this struct and nowhere else. It is
// never stored, and there is no second chance to read it: if the caller loses
// it, the credential must be reissued.
type Issued struct {
	// RefreshToken is the rotatable credential, shown to the user exactly once.
	RefreshToken secrets.Redacted
	// RefreshExpiresAt is the absolute end of the lineage. Rotation does not
	// move it; see TokenService.Exchange.
	RefreshExpiresAt time.Time
	// AccessToken is the short-lived bearer token.
	AccessToken secrets.Redacted
	// AccessExpiresAt is when the access token stops being accepted.
	AccessExpiresAt time.Time
	// OwnerID is the account both tokens speak for.
	OwnerID domain.OwnerID
	// Scopes is the grant carried by both tokens.
	Scopes []domain.Scope
}

// redacted is the single rendering used by every formatting path on Issued, so
// a new path cannot be added without redaction.
func (i Issued) redacted() string {
	return fmt.Sprintf("auth.Issued{OwnerID:%s, RefreshToken:[REDACTED], AccessToken:[REDACTED]}", i.OwnerID)
}

// String implements fmt.Stringer.
func (i Issued) String() string { return i.redacted() }

// GoString implements fmt.GoStringer so %#v also redacts.
func (i Issued) GoString() string { return i.redacted() }

// Format implements fmt.Formatter. It takes precedence over String and GoString
// for every verb, which is what catches the realistic leak path: an Issued
// printed as part of a surrounding value with %v or %+v.
func (i Issued) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte(i.redacted()))
}

// MarshalJSON implements json.Marshaler, emitting a quoted redacted string so
// the output stays valid JSON. An API handler that needs to return the tokens
// must build its own response type and Reveal deliberately.
func (i Issued) MarshalJSON() ([]byte, error) { return []byte(`"` + i.redacted() + `"`), nil }

// MarshalText implements encoding.TextMarshaler.
func (i Issued) MarshalText() ([]byte, error) { return []byte(i.redacted()), nil }

// LogValue implements slog.LogValuer. The text and JSON handlers would already
// route through MarshalText and MarshalJSON, but a custom handler need not, and
// LogValuer is the interface slog resolves before any of them.
func (i Issued) LogValue() slog.Value { return slog.StringValue(i.redacted()) }

// TokenService issues refresh credentials, rotates them, and mints the access
// tokens derived from them.
//
// # Rotation
//
// A refresh token is single-use. Every successful exchange consumes the
// presented credential and returns a new one in the same lineage. The point is
// detection, not prevention: rotation does not stop a token from being stolen,
// it makes a stolen token's use visible, because a captured token is eventually
// presented after the legitimate holder has already spent it.
//
// # Reuse means theft
//
// Presenting a consumed credential -- with the correct secret -- means two
// parties hold it, and there is no way to tell which one is presenting. So the
// response is not "reject this token": it is to revoke the entire lineage, the
// current credential included, and force re-authentication. Revoking only the
// presented token would leave whichever party holds the newest one in
// possession of the account, and that is as likely to be the attacker as the
// user.
//
// A consequence worth naming: an honest client that submits the same exchange
// twice -- a retry after a timeout, two tabs racing -- kills its own lineage and
// has to log in again. That is the intended posture, not a defect. The server
// cannot distinguish that retry from a thief replaying a captured token, and of
// the two possible mistakes, "an honest user re-authenticates" is the one to
// choose.
//
// # The absolute cap
//
// A lineage expires RefreshLineageLifetime after it was first issued, and no
// rotation extends that. This is enforced structurally rather than by
// arithmetic at each step: the child credential inherits its parent's ExpiresAt
// verbatim, so the ordinary "has this expired" check is the cap. See Exchange.
//
// A TokenService is immutable after construction and safe for concurrent use.
type TokenService struct {
	store  repository.Store
	signer *AccessTokenSigner
}

// NewTokenService builds a TokenService. Both dependencies are required: a nil
// one is a wiring bug, and tolerating it would mean an authentication path that
// silently skips whichever check the missing dependency performed.
func NewTokenService(store repository.Store, signer *AccessTokenSigner) (*TokenService, error) {
	if store == nil {
		return nil, fmt.Errorf("auth: nil store: %w", domain.ErrInvalidInput)
	}
	if signer == nil {
		return nil, fmt.Errorf("auth: nil access token signer: %w", domain.ErrInvalidInput)
	}
	return &TokenService{store: store, signer: signer}, nil
}

// Issue starts a new rotation lineage for ownerID and returns the first
// credential pair.
//
// This is the post-authentication step: the caller has already resolved an
// owner through Authenticator, so ownerID is trusted here and no credential is
// verified. Errors are wrapped and descriptive rather than collapsed to
// ErrAuthFailed, because the audience for them is server code building a grant,
// not an unauthenticated party probing for what exists.
//
// now is supplied by the caller and is the only clock reading involved.
func (s *TokenService) Issue(ctx context.Context, ownerID domain.OwnerID, scopes []domain.Scope, clientLabel string, now time.Time) (*Issued, error) {
	if ownerID == "" {
		return nil, fmt.Errorf("auth: owner id must not be empty: %w", domain.ErrInvalidInput)
	}
	if err := ValidateScopes(scopes); err != nil {
		return nil, err
	}
	if err := validateClientLabel(clientLabel); err != nil {
		return nil, err
	}

	id := newCredentialID()
	secret := randomBytes(refreshSecretBytes)
	cred := &domain.RefreshCredential{
		ID:      id,
		OwnerID: ownerID,
		// The root credential's own id names the lineage. A separate random
		// value would say the same thing while allowing the two to disagree.
		LineageID:   domain.LineageID(id),
		SecretHash:  hashRefreshSecret(secret),
		Scopes:      cloneScopes(scopes),
		ClientLabel: clientLabel,
		// Nothing rotated into this credential; it is the root.
		RotatedFromID: nil,
		IssuedAt:      now,
		// This is the lineage deadline, and every descendant copies it.
		ExpiresAt: now.Add(RefreshLineageLifetime),
		Status:    domain.CredentialStatusActive,
	}
	if err := s.store.Repos().RefreshCredentials.Create(ctx, cred); err != nil {
		return nil, fmt.Errorf("auth: creating refresh credential: %w", err)
	}
	return s.mint(cred, secret, now)
}

// Exchange consumes a presented refresh token and returns a fresh pair.
//
// Every denial returns bare ErrAuthFailed: an unknown credential, a wrong
// secret, an expired lineage, a revoked one, a suspended owner, and a detected
// reuse are all indistinguishable to the caller. As in the rest of this
// package, that is an information-content guarantee and not a timing one -- an
// unknown identifier costs one storage round trip and a valid one costs
// several, and no artificial delay is inserted to hide that.
//
// now is supplied by the caller; nothing in this path reads the clock.
func (s *TokenService) Exchange(ctx context.Context, presented secrets.Redacted, now time.Time) (*Issued, error) {
	id, secret, err := parseRefreshToken(presented)
	if err != nil {
		return nil, ErrAuthFailed
	}

	var out *Issued
	// The whole exchange runs in one transaction so that consuming the old
	// credential and creating its replacement cannot be observed or interrupted
	// half-done. A crash between the two outside a transaction would destroy a
	// valid credential without issuing its successor, logging the user out; a
	// concurrent exchange would see the old credential still active and mint a
	// second successor, leaving two live tokens in one lineage.
	//
	// A denial inside fn returns nil, not an error, whenever it has already
	// written something that must survive -- specifically the lineage
	// revocation. Rolling that back would mean detecting a theft and then
	// forgetting it. The caller is told nothing either way: out stays nil, and
	// nil out means ErrAuthFailed.
	txErr := s.store.WithTx(ctx, func(ctx context.Context, r repository.Repos) error {
		cred, err := r.RefreshCredentials.GetByID(ctx, id)
		if err != nil {
			if errors.Is(err, domain.ErrNotFound) {
				// No such credential: a denial, and nothing has been written,
				// so let the transaction close normally.
				return nil
			}
			// A storage fault is not a denial. Propagating it rolls the
			// transaction back and lets the fault reach logs and monitoring,
			// matching how MarkRotated, Create and mint below already treat
			// one. Swallowing it here made a database outage indistinguishable
			// from an unknown token in the operator's view -- while remaining
			// indistinguishable to the caller either way, since Exchange maps
			// any transaction error to ErrAuthFailed.
			return err
		}
		if cred == nil {
			// The (nil, nil) port violation, read as "denied" rather than
			// dereferenced.
			return nil
		}
		// Defense in depth: confirm the row returned is the row asked for. This
		// lookup is UNSCOPED -- the exchange is the authentication step, so no
		// owner is established yet -- which makes it one of the few queries that
		// cannot be constrained by the owner boundary, and therefore one where a
		// loosely keyed cache or a case-insensitive collation would hand back a
		// neighboring credential.
		if cred.ID != id {
			return nil
		}

		// The secret is verified before anything else acts on this row, and
		// this ordering is load-bearing. Reuse detection revokes a whole
		// lineage; if it ran on the identifier alone, anyone who learned an
		// identifier -- from a log, a database backup, an error message -- could
		// log any user out at will by replaying it. Possession of the secret is
		// what makes "this token was captured" the right conclusion.
		if !secretMatches(cred.SecretHash, secret) {
			return nil
		}
		if cred.OwnerID == "" || cred.LineageID == "" {
			// A malformed row: both columns are NOT NULL. Deny before either is
			// used as a lookup or revocation key, so that "an empty id is never
			// a query key" holds here rather than being inferred from what some
			// store happens to do with one.
			return nil
		}

		// The credential outlives the account's good standing, so the owner's
		// own status is authoritative and is re-checked on every exchange.
		owner, err := r.Owners.Get(ctx, cred.OwnerID)
		if err != nil {
			if errors.Is(err, domain.ErrNotFound) {
				return nil
			}
			// A storage fault, not a denial; see GetByID above.
			return err
		}
		if owner == nil || owner.ID != cred.OwnerID {
			return nil
		}
		if owner.Status != domain.OwnerStatusActive || owner.DeletedAt != nil {
			return nil
		}

		// Reuse: the correct secret for a credential that is no longer active.
		// Two parties hold this token and there is no way to tell them apart, so
		// the lineage dies. The revocation must be committed, hence the nil
		// return on success below.
		if cred.Status != domain.CredentialStatusActive {
			return s.revokeLineage(ctx, r, cred, now)
		}

		// The expiry check is also the ninety-day cap, because a rotated
		// credential inherits its parent's ExpiresAt unchanged. Nothing here
		// re-bases the deadline on now, and nothing should: that single
		// assignment below is what makes the cap unextendable.
		if !now.Before(cred.ExpiresAt) {
			return nil
		}
		// A stored scope set that no longer validates is refused rather than
		// carried into a new token. It should be impossible -- Issue validated
		// it -- so it means the row was written by something else.
		if err := ValidateScopes(cred.Scopes); err != nil {
			return nil
		}

		// Consume the presented credential. MarkRotated is a conditional
		// transition: it reports domain.ErrConflict if the credential is no
		// longer active, which is how two concurrent exchanges of the same token
		// are resolved. Exactly one wins; the loser is a reuse, and is treated
		// as one.
		if err := r.RefreshCredentials.MarkRotated(ctx, cred.OwnerID, cred.ID, now); err != nil {
			if errors.Is(err, domain.ErrConflict) {
				return s.revokeLineage(ctx, r, cred, now)
			}
			// A storage fault: roll back and deny.
			return err
		}

		childID := newCredentialID()
		childSecret := randomBytes(refreshSecretBytes)
		child := &domain.RefreshCredential{
			ID:      childID,
			OwnerID: cred.OwnerID,
			// Same lineage: a rotation is a new link in one chain, not a new
			// chain. If it started a new lineage, revoking on reuse would only
			// reach the tokens after the theft.
			LineageID:   cred.LineageID,
			SecretHash:  hashRefreshSecret(childSecret),
			Scopes:      cloneScopes(cred.Scopes),
			ClientLabel: cred.ClientLabel,
			RotatedFromID: func() *domain.RefreshCredentialID {
				parent := cred.ID
				return &parent
			}(),
			IssuedAt: now,
			// Inherited verbatim. This one line is the absolute cap: the
			// deadline is a property of the lineage, and a rotation may not move
			// it. Recomputing it from now would let an attacker hold a stolen
			// lineage indefinitely by rotating it, which is the failure this cap
			// exists to prevent.
			ExpiresAt: cred.ExpiresAt,
			Status:    domain.CredentialStatusActive,
		}
		if err := r.RefreshCredentials.Create(ctx, child); err != nil {
			return err
		}

		issued, err := s.mint(child, childSecret, now)
		if err != nil {
			return err
		}
		out = issued
		return nil
	})
	if txErr != nil || out == nil {
		return nil, ErrAuthFailed
	}
	return out, nil
}

// Verify checks a presented access token and returns its claims. It reads no
// storage; see AccessTokenSigner for what that buys and what it costs.
func (s *TokenService) Verify(presented secrets.Redacted, now time.Time) (*domain.AccessToken, error) {
	return s.signer.Verify(presented, now)
}

// revokeLineage kills every credential in cred's lineage. It returns nil on
// success so the enclosing transaction commits the revocation; the caller
// denies regardless, because out is left nil.
func (s *TokenService) revokeLineage(ctx context.Context, r repository.Repos, cred *domain.RefreshCredential, now time.Time) error {
	if _, err := r.RefreshCredentials.RevokeLineage(ctx, cred.OwnerID, cred.LineageID, now); err != nil {
		// The revocation failed, so there is nothing worth committing. Returning
		// the error rolls back and still denies.
		return err
	}
	return nil
}

// mint derives an access token from a refresh credential and packages both into
// an Issued. The refresh secret is passed in rather than read back from the
// credential, because the credential only ever holds its hash.
func (s *TokenService) mint(cred *domain.RefreshCredential, secret []byte, now time.Time) (*Issued, error) {
	access := domain.AccessToken{
		ID:                  tokenEncoding.EncodeToString(randomBytes(credentialIDBytes)),
		OwnerID:             cred.OwnerID,
		RefreshCredentialID: cred.ID,
		Scopes:              cloneScopes(cred.Scopes),
		IssuedAt:            now,
		ExpiresAt:           now.Add(AccessTokenLifetime),
	}
	raw, err := s.signer.Issue(access)
	if err != nil {
		return nil, fmt.Errorf("auth: issuing access token: %w", err)
	}
	return &Issued{
		RefreshToken:     formatRefreshToken(cred.ID, secret),
		RefreshExpiresAt: cred.ExpiresAt,
		AccessToken:      raw,
		AccessExpiresAt:  access.ExpiresAt,
		OwnerID:          cred.OwnerID,
		Scopes:           cloneScopes(cred.Scopes),
	}, nil
}
