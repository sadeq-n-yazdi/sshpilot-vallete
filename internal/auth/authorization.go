package auth

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/secrets"
)

// ErrForbidden is returned when a request was authenticated -- the token
// verified, was not revoked, and names a live owner -- but the grant it carries
// does not cover what the request is trying to do.
//
// It is deliberately a separate sentinel from ErrAuthFailed, and the separation
// does not weaken the indistinguishability guarantee that sentinel exists to
// provide. ErrAuthFailed erases distinctions between causes that would tell an
// UNAUTHENTICATED caller what exists. ErrForbidden is only ever reached by a
// caller holding a valid token, and the verdict is computed from that token's
// own claims and from the request the caller just made -- no storage is read,
// no resource is looked up, nothing about the system's contents participates.
// So the caller learns exactly one thing: the grant it already holds does not
// cover the request it already composed. That is not an oracle; it is the
// caller's own two inputs compared to each other.
//
// ADR-0019 requires precisely this shape: "a valid token for a different
// set/scope (authenticated but not authorized for this set) -> 403".
var ErrForbidden = errors.New("auth: not authorized")

// ResourceKind names the type of resource a request addresses. It exists so a
// resource-bound scope cannot be satisfied by an identifier of the wrong type:
// without it, a single-device token whose device id happened to equal some key
// set's id would reach that key set.
type ResourceKind string

// Resource kinds. ResourceNone means the request addresses no single resource
// -- an account-wide listing, say -- which is a distinct case from addressing
// one, not a wildcard.
const (
	ResourceNone   ResourceKind = ""
	ResourceKeySet ResourceKind = "key-set"
	ResourceDevice ResourceKind = "device"
)

// isValid reports whether k is a resource kind this package can reason about.
// An unrecognized kind is refused rather than treated as ResourceNone, because
// "I do not know what this request touches" must never resolve to "allow".
func (k ResourceKind) isValid() bool {
	switch k {
	case ResourceNone, ResourceKeySet, ResourceDevice:
		return true
	default:
		return false
	}
}

// Access describes what a request is trying to do, in the only terms
// authorization needs: whose resources, which resource, and whether the request
// changes anything.
//
// It is supplied by the transport for each route. Every field is a statement
// about the REQUEST, never about the caller: nothing here is trusted as
// identity, and in particular Owner is not "who is asking" -- it is "whose
// resources this request names", which is exactly the value that must be
// checked against the token rather than believed.
type Access struct {
	// Owner is the owner the request names, when the route names one at all.
	//
	// It is empty for the routes that do not -- the management API addresses
	// resources by their own non-guessable identifiers and takes the owner from
	// the token, per ADR-0004 -- and an empty value means "no owner asserted by
	// the request", never "any owner". A non-empty value MUST equal the token's
	// owner or the request is refused; see Guard.Authorize.
	Owner domain.OwnerID

	// Resource and ResourceID name the single resource the request addresses,
	// or ResourceNone and "" if it addresses none. The two must agree: a kind
	// without an id, or an id without a kind, is a malformed Access and is
	// refused.
	Resource   ResourceKind
	ResourceID string

	// Mutating reports whether the request changes state. It is derived from
	// the HTTP method by the transport rather than declared per route, so a new
	// route cannot forget to set it and thereby become writable to a read-only
	// token.
	Mutating bool
}

// validate checks that an Access is internally coherent before it is used to
// make a decision. An incoherent one is refused: a permission check on a
// request whose target cannot be named is a check on nothing.
func (a Access) validate() error {
	if !a.Resource.isValid() {
		return fmt.Errorf("auth: unknown resource kind %q: %w", a.Resource, domain.ErrInvalidInput)
	}
	if (a.Resource == ResourceNone) != (a.ResourceID == "") {
		return fmt.Errorf("auth: resource kind and id must be set together: %w", domain.ErrInvalidInput)
	}
	return nil
}

// Authorization is the verified outcome of a request's authorization: the owner
// the caller may act as, and the grant it holds.
//
// # Why the owner is a method and not a field
//
// This is the type that decides whether Track C can introduce a cross-owner
// leak, so its shape is the control. Every repository port in this codebase is
// owner-scoped by an explicit ownerID parameter (see repository.KeySetRepository
// and repository.DeviceRepository, whose every method takes one and MUST filter
// by it), which means every handler must produce a domain.OwnerID from
// somewhere. The whole question is: from where?
//
// The dangerous answer is "from the URL" -- r.PathValue("handle"), a body field,
// a header -- because that value is attacker-chosen and a handler that reaches
// for it has silently made the owner boundary a suggestion. So:
//
//   - The fields are unexported and there is no exported constructor. Outside
//     this package an Authorization can only be obtained from Guard.Authorize
//     or from the context it was put in, and the only Authorization a caller
//     can write down itself is the zero value, whose Owner is empty -- which
//     every repository and every domain validator refuses.
//   - Owner() is the only route to a domain.OwnerID on an authorized path, and
//     it returns the token's owner. It cannot be made to return anything a
//     request supplied, because the request's owner never enters this struct.
//   - The transport hands the Authorization to the handler as a parameter
//     (see the ScopedHandler type in the transport package), so a protected
//     handler receives the verified owner whether or not it thought to ask.
//     Forgetting to scope a query is then not a matter of omitting a lookup; it
//     requires ignoring an argument that is already in hand and going to fetch
//     an owner from somewhere else instead, which is visible in review as a
//     deliberate act rather than invisible as an omission.
//
// An Authorization is immutable after construction and safe for concurrent use.
type Authorization struct {
	owner      domain.OwnerID
	tokenID    string
	credential domain.RefreshCredentialID
	scopes     []domain.Scope
}

// Owner returns the owner the caller is authorized to act as. It is the owner
// named by the verified token and by nothing else.
//
// The zero Authorization returns the empty owner, which is not a wildcard:
// domain validation and every repository reject it. A nil receiver does the
// same rather than panicking, so a handler that was somehow reached without
// authorization fails closed instead of taking the process down.
func (a *Authorization) Owner() domain.OwnerID {
	if a == nil {
		return ""
	}
	return a.owner
}

// TokenID returns the access token's id, for audit records. It identifies the
// token, not the credential behind it, and is not a secret: access tokens are
// never persisted, so this value names nothing that can be looked up.
func (a *Authorization) TokenID() string {
	if a == nil {
		return ""
	}
	return a.tokenID
}

// CredentialID returns the refresh credential the access token was minted from.
// It is the identifier a revocation acts on, so an audit record that carries it
// lets an operator revoke the lineage behind a request after the fact.
func (a *Authorization) CredentialID() domain.RefreshCredentialID {
	if a == nil {
		return ""
	}
	return a.credential
}

// Scopes returns a copy of the grant. The copy is not politeness: the slice is
// shared by every request served under this Authorization, and a caller that
// appended to or sorted the original would be editing a live permission set.
func (a *Authorization) Scopes() []domain.Scope {
	if a == nil {
		return nil
	}
	return cloneScopes(a.scopes)
}

// redacted is the single rendering used by every formatting path. An
// Authorization holds no secret -- the token itself never enters it -- but the
// owner id is an internal, non-guessable identifier (ADR-0004) and an access
// log is copied far more widely than the request it describes, so the rendering
// names the owner and nothing else.
func (a *Authorization) redacted() string {
	return fmt.Sprintf("auth.Authorization{Owner:%s}", a.Owner())
}

// String implements fmt.Stringer.
func (a *Authorization) String() string { return a.redacted() }

// GoString implements fmt.GoStringer so %#v does not dump the scope set.
func (a *Authorization) GoString() string { return a.redacted() }

// LogValue implements slog.LogValuer, which slog resolves ahead of Stringer.
func (a *Authorization) LogValue() slog.Value { return slog.StringValue(a.redacted()) }

// authorizationContextKey is the unexported context key type. It is unexported
// so no other package can write an Authorization into a context under this key:
// if the key were exported or a bare string, any code in the process could
// forge an authorization by putting one there, and the guarantee that the
// context's owner came from a verified token would be worth nothing.
type authorizationContextKey struct{}

// ContextWithAuthorization returns a context carrying a. It is exported for the
// transport layer, which is the only legitimate caller: a is the value
// Guard.Authorize just returned, and there is no way to obtain one otherwise.
func ContextWithAuthorization(ctx context.Context, a *Authorization) context.Context {
	return context.WithValue(ctx, authorizationContextKey{}, a)
}

// AuthorizationFromContext returns the Authorization carried by ctx.
//
// The second result is false when there is none, and callers MUST check it. It
// is a two-value return rather than a nil-or-not so that "this request was
// never authorized" cannot be mistaken for "this request was authorized as
// nobody" -- the same reason Denylist.Check has no bool in its signature.
func AuthorizationFromContext(ctx context.Context) (*Authorization, bool) {
	a, ok := ctx.Value(authorizationContextKey{}).(*Authorization)
	if !ok || a == nil {
		return nil, false
	}
	return a, true
}

// Guard turns a presented bearer token into an Authorization, or refuses.
//
// It is the single place where the three checks that gate every owner-facing
// request are composed, in a fixed order that is part of the contract:
//
//  1. The token verifies -- prefix, shape, MAC, version, claim shape, scope
//     shape, and validity window. See AccessTokenSigner.Verify.
//  2. The token is not revoked. The denylist is consulted on every request and
//     FAILS CLOSED: a store that cannot be reached denies, because a revocation
//     control that opens during an outage is worse than none at all.
//  3. The owner boundary, then the finer scopes -- in that order, and never the
//     reverse. See Authorize.
//
// A Guard is immutable after construction and safe for concurrent use.
type Guard struct {
	signer   *AccessTokenSigner
	denylist *Denylist
}

// NewGuard builds a Guard. Both dependencies are required.
//
// A nil denylist is refused rather than tolerated as "revocation is optional".
// A Guard without one would verify and admit tokens that had been revoked,
// while every route it protected still looked guarded -- the exact failure mode
// NewDenylist refuses a nil store to prevent, restated one layer up so it
// cannot be reintroduced by wiring.
func NewGuard(signer *AccessTokenSigner, denylist *Denylist) (*Guard, error) {
	if signer == nil {
		return nil, fmt.Errorf("auth: nil access token signer: %w", domain.ErrInvalidInput)
	}
	if denylist == nil {
		return nil, fmt.Errorf("auth: nil denylist: %w", domain.ErrInvalidInput)
	}
	return &Guard{signer: signer, denylist: denylist}, nil
}

// Authorize verifies presented and decides whether it permits acc.
//
// # Order of checks
//
// Authentication first, then the owner boundary, then the finer scopes. The
// owner check being ahead of the scope check is not a stylistic preference: a
// token carrying single-set scope for a set id that belongs to a DIFFERENT
// owner would, under the reverse order, pass the fine-grained test on a
// matching id and only then be asked whose it was. Checking the owner first
// means no scope kind, present or future, can be the reason a request crosses
// the owner boundary -- the boundary is settled before the kinds are read.
//
// # What each failure returns
//
//   - Anything short of a valid, unrevoked token: bare ErrAuthFailed. Malformed,
//     forged, expired, not yet valid, revoked, and "the denylist is down" are
//     one indistinguishable answer, per that sentinel's contract.
//   - A valid token whose grant does not cover acc: ErrForbidden.
//
// now is supplied by the caller; nothing here reads the clock. This function
// performs no storage lookup other than the denylist, and in particular never
// asks whether acc's resource exists -- which is what makes its verdicts safe
// to distinguish on the wire.
func (g *Guard) Authorize(ctx context.Context, presented secrets.Redacted, acc Access, now time.Time) (*Authorization, error) {
	if err := acc.validate(); err != nil {
		// An Access the transport could not describe coherently is refused as
		// an authorization failure, not reported as a bad request: the caller
		// is unauthenticated at this point and must learn nothing, and a route
		// with a broken Access extractor must not serve.
		return nil, ErrAuthFailed
	}

	tok, err := g.signer.Verify(presented, now)
	if err != nil {
		return nil, ErrAuthFailed
	}
	if err := g.decide(ctx, tok, acc); err != nil {
		return nil, err
	}

	return &Authorization{
		owner:      tok.OwnerID,
		tokenID:    tok.ID,
		credential: tok.RefreshCredentialID,
		scopes:     cloneScopes(tok.Scopes),
	}, nil
}

// decide runs the three post-authentication checks on an already-verified
// token, in the order Authorize documents: revocation, then the owner
// boundary, then the finer scopes. It returns nil if and only if the request is
// permitted.
//
// It is separated from Authorize so the order is one readable sequence with no
// token parsing in the way, and so the defensive branches below -- which the
// verifier already makes unreachable from outside -- can be exercised
// directly rather than being carried untested.
func (g *Guard) decide(ctx context.Context, tok *domain.AccessToken, acc Access) error {
	// Defensive: Verify already refuses a token with an empty owner, and a nil
	// one cannot come back from a successful Verify. Repeating both here means
	// the owner check below can never compare against an empty string, or
	// dereference nothing, because some future change upstream let one through.
	if tok == nil || tok.OwnerID == "" {
		return ErrAuthFailed
	}

	// Fail closed. Check returns nil if and ONLY if the token is permitted;
	// every non-nil error -- listed credential or unreachable store -- is a
	// denial, and there is no error class this may treat as allowed.
	if err := g.denylist.Check(ctx, tok); err != nil {
		return ErrAuthFailed
	}

	// THE OWNER BOUNDARY. It comes before any scope kind is examined and is not
	// reachable around: every protected route runs this function, and this
	// function has no branch that skips this comparison.
	//
	// Note what this comparison is and is not. It fires only for a route that
	// populates Access.Owner -- one that echoes an owner back from the request.
	// The management API's shape is to address resources by their own
	// identifiers and take the owner from the token, so for a by-id route
	// Access.Owner is empty and this branch does not run. That is not a gap.
	// For those routes the isolation is structural rather than comparative:
	// Authorization.Owner() can only be the token's owner, and every repository
	// port takes that owner and filters by it (ADR-0004). This comparison is
	// defense in depth for the routes that do name an owner, and it is what
	// stops a request naming owner B under owner A's token. It is not the sole
	// mechanism, and a route must not be written as though it were.
	//
	// The comparison is constant time. Owner ids are internal, non-guessable
	// identifiers and this is the one place a caller can submit a candidate and
	// observe an outcome, so a byte-by-byte compare would let an attacker walk
	// an owner id one byte at a time out of the timing.
	if acc.Owner != "" && !constantTimeEqual(string(acc.Owner), string(tok.OwnerID)) {
		return ErrForbidden
	}

	if !permitsAccess(tok.Scopes, acc) {
		return ErrForbidden
	}
	return nil
}

// permitsAccess reports whether the scope set as a whole covers acc.
//
// read-only is a MODIFIER over the rest of the set, not an independent grant
// (ADR-0018: "read-only + single-set"). Composing it correctly is the whole
// point of evaluating the set here rather than scope-by-scope, so the union
// cannot let one half undo the other:
//
//   - If read-only is present, a mutating request is refused BEFORE any positive
//     grant is consulted. A single-set scope paired with read-only therefore
//     cannot restore the write the modifier removed -- the intersection can only
//     narrow, never widen back to the binding's own read+write authority.
//   - read-only standing alone IS the grant: read of any of the owner's
//     resources. Paired with a resource binding it contributes no positive
//     authority of its own -- the binding alone decides which resource is
//     reachable -- so a read of a DIFFERENT resource is refused, not widened to
//     "read anything".
//
// ValidateScopes has already refused every set this evaluation cannot read
// unambiguously: full-owner stands alone, read-only appears at most once, and at
// most one resource binding is present. So the loop below is a union of at most
// one positive grant, never two that could silently widen one another.
//
// An empty set permits nothing. ValidateScopes refuses one at issuance and
// Verify refuses one on presentation, but stating it here keeps the guarantee
// local: the code must not be rewritten into "no objections, so allow".
func permitsAccess(scopes []domain.Scope, acc Access) bool {
	readOnly := false
	grants := 0
	for _, s := range scopes {
		if s.Kind == domain.ScopeReadOnly {
			readOnly = true
			continue
		}
		grants++
	}

	// The read-only cap. It is checked before any grant so that no positive
	// scope in the set -- present or added later -- can be the reason a mutation
	// under a read-only token succeeds.
	if readOnly && acc.Mutating {
		return false
	}

	// read-only alone: any non-mutating request against the owner's resources is
	// permitted. Mutation was already refused above, and the owner boundary was
	// settled before this function ran. Paired with a binding (grants > 0),
	// read-only adds nothing here and the binding below is consulted instead.
	if readOnly && grants == 0 {
		return true
	}

	for _, s := range scopes {
		if s.Kind == domain.ScopeReadOnly {
			// A modifier, already accounted for above; it grants no resource of
			// its own once a binding is present.
			continue
		}
		if scopePermits(s, acc) {
			return true
		}
	}
	return false
}

// scopePermits reports whether a single positive grant covers acc.
//
// read-only is deliberately absent: it is a modifier handled in permitsAccess,
// not a grant, so it never reaches here. The switch has no default that allows,
// so an unknown kind -- a scope minted by a future version, a corrupted one, or
// a read-only that somehow arrives here -- permits nothing and can never be the
// reason a request succeeds.
func scopePermits(s domain.Scope, acc Access) bool {
	switch s.Kind {
	case domain.ScopeFullOwner:
		// Everything, within the owner. The owner boundary was settled before
		// this function was called, so "everything" is not open-ended.
		return true

	case domain.ScopeSingleSet:
		return boundScopePermits(s, acc, ResourceKeySet)

	case domain.ScopeSingleDevice:
		return boundScopePermits(s, acc, ResourceDevice)

	default:
		return false
	}
}

// boundScopePermits is the shared rule for the resource-bound kinds: the
// request must address exactly the one resource the scope names, of exactly the
// kind the scope binds.
//
// A request that addresses no resource at all is refused. A single-set token
// asking for "all of this owner's key sets" is asking for more than its grant,
// and reading ResourceNone as "nothing specific, so fine" would turn every
// narrow token into an account-wide read.
//
// The kind check is what stops an identifier collision from crossing resource
// types, and it is checked before the id so a mismatched kind cannot even reach
// the comparison.
func boundScopePermits(s domain.Scope, acc Access, want ResourceKind) bool {
	if acc.Resource != want || acc.ResourceID == "" || s.ResourceID == "" {
		return false
	}
	return constantTimeEqual(s.ResourceID, acc.ResourceID)
}

// constantTimeEqual compares two identifiers without leaking their contents
// through timing. subtle.ConstantTimeCompare returns 0 for unequal lengths, so
// a length difference is not an early exit either.
func constantTimeEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
