package publish

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/keys"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/repository"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/secrets"
)

// ErrNotFound is the single negative verdict of the publish path. See the
// package doc: every reason a request cannot be served — unknown, inactive,
// another owner's, or not public — collapses into this one sentinel so that no
// caller can distinguish them.
var ErrNotFound = errors.New("publish: not found")

// ErrMissingRepository is returned by New when a required repository port is
// absent. It is a construction-time programming error: the service fails to
// build rather than nil-panicking on the first request.
var ErrMissingRepository = errors.New("publish: missing repository")

// Verifier decides whether a presented bearer token unlocks a protected key
// set. *accesskey.Service satisfies it.
//
// It is declared here, at the point of use, rather than imported from the
// access key package: this package depends on a method set, not on a concrete
// service, and the dependency arrow stays pointed the way the rest of the tree
// points it.
//
// The contract this package relies on, and which its own behavior is only as
// safe as: EVERY negative verdict — unknown id, wrong secret, revoked, closed
// grace window, a token minted for a different key set, an unparseable token —
// is reported as an error wrapping domain.ErrNotFound, with nothing to tell
// them apart. Anything that does NOT wrap domain.ErrNotFound is a storage
// fault, not a denial, and this package must not turn it into one.
type Verifier interface {
	Verify(ctx context.Context, ownerID domain.OwnerID, setID domain.KeySetID, presented secrets.Redacted) (*domain.AccessKey, error)
}

// Option configures a Service at construction.
type Option func(*Service)

// WithVerifier supplies the access key verifier that unlocks protected sets.
//
// It is an option rather than a required parameter because an embedder may
// serve only the public path, and because the absence of a verifier has exactly
// one meaning here and it is the safe one: without it no protected set resolves
// for anybody, which is a feature that is switched off rather than a gate that
// is open. See resolveAccess for why that is a refusal and not a panic.
func WithVerifier(v Verifier) Option {
	return func(s *Service) { s.verifier = v }
}

// Result is what a successful resolution yields: the body to serve, and whether
// the set it came from was access-gated.
//
// Protected exists so the transport can apply the caching rules ADR-0019
// requires of access-gated content without itself knowing anything about
// visibility or credentials. It is meaningful ONLY on the success path — every
// negative verdict returns the zero Result alongside ErrNotFound, so there is
// no failure response whose shape could depend on whether the set that was not
// served happened to be protected. That is what makes the uniform 404
// structural rather than a discipline the transport has to keep.
type Result struct {
	Body      []byte
	Protected bool
}

// Service resolves handles to publishable authorized_keys bodies. It is
// stateless and safe for concurrent use by many requests.
type Service struct {
	repos    repository.Repos
	verifier Verifier
}

// New builds a Service over the given repositories.
//
// It fails closed: the four ports the resolution path actually calls must all
// be present. A partially populated Repos is a wiring bug, and catching it at
// startup is strictly better than discovering it as a panic on a live request.
func New(repos repository.Repos, opts ...Option) (*Service, error) {
	switch {
	case repos.Handles == nil:
		return nil, fmt.Errorf("%w: handles", ErrMissingRepository)
	case repos.Owners == nil:
		return nil, fmt.Errorf("%w: owners", ErrMissingRepository)
	case repos.KeySets == nil:
		return nil, fmt.Errorf("%w: key sets", ErrMissingRepository)
	case repos.PublicKeys == nil:
		return nil, fmt.Errorf("%w: public keys", ErrMissingRepository)
	}
	s := &Service{repos: repos}
	for i, opt := range opts {
		// A nil option is rejected rather than skipped, matching the other
		// services: skipping it would leave a Service that looks configured and
		// is not — here, one an operator believes serves protected sets and
		// which silently answers 404 for every one of them.
		if opt == nil {
			return nil, fmt.Errorf("%w: nil option at index %d", ErrMissingRepository, i)
		}
		opt(s)
	}
	return s, nil
}

// Resolve returns the canonical authorized_keys body published at
// /{handle} (setName == "") or /{handle}/{setName}.
//
// An empty setName selects the owner's default key set.
//
// presented is the bearer token the caller supplied, or the empty Redacted when
// it supplied none. It is consulted ONLY for a protected set; a public set
// resolves identically whether a token was sent, was garbage, or was absent, so
// nothing about the credential can change a public answer.
//
// The gate order is fail-closed and every gate funnels into ErrNotFound; see
// the package doc for why they are indistinguishable. Only once the handle,
// the owner, the set, AND the access gate have all passed does the key listing
// happen, so a caller can never observe key data for anything it was not
// entitled to name — and, for a protected set, no storage read that could be
// timed against the set's contents happens before the credential is checked.
func (s *Service) Resolve(ctx context.Context, handle, setName string, presented secrets.Redacted) (Result, error) {
	// Format validation folds into the same 404 as everything else. A
	// malformed name cannot identify a real handle, so answering "invalid"
	// rather than "not found" would tell a prober which of its guesses were
	// well-formed — a free lesson in the namespace's shape.
	if domain.ValidateHandle(handle) != nil {
		return Result{}, ErrNotFound
	}
	if setName != "" && domain.ValidateSetName(setName) != nil {
		return Result{}, ErrNotFound
	}

	ownerID, err := s.resolveOwner(ctx, handle)
	if err != nil {
		return Result{}, err
	}

	set, err := s.resolveSet(ctx, ownerID, setName)
	if err != nil {
		return Result{}, err
	}

	protected, err := s.resolveAccess(ctx, ownerID, set, presented)
	if err != nil {
		return Result{}, err
	}

	// The owner-scoped, active-only membership query. It is called with the
	// owner ID derived from the handle, never one supplied by the caller, and
	// its own pk.owner_id and status='active' predicates are the storage-layer
	// backstop for tenant isolation and revocation.
	active, err := s.repos.PublicKeys.ListActiveByKeySet(ctx, ownerID, set.ID)
	if err != nil {
		return Result{}, fmt.Errorf("publish: list active keys: %w", err)
	}

	body, err := render(ownerID, active)
	if err != nil {
		return Result{}, err
	}
	return Result{Body: body, Protected: protected}, nil
}

// resolveAccess applies the visibility gate, and reports whether the set that
// passed it was access-gated.
//
// # THE STATE CHECK BELONGS HERE, NOT IN Verify
//
// Verify is handed an owner id and a key set id and loads the ACCESS KEY; it
// never loads the KeySet, so it structurally cannot look at the set's
// lifecycle state. It answers exactly one question — does this token name a
// live credential minted for this set — and a valid credential naming a
// quarantined or retired set answers that question "yes". This is the classic
// two-sided omission: each side can plausibly be believed to check the state,
// and if both believe it of the other a tombstoned set keeps publishing to
// anyone still holding its token.
//
// This package is the side that checks it, and it does so in resolveSet, which
// runs BEFORE this function is ever called. The ordering is the invariant: a
// non-active set is refused before a token is even looked at, so there is no
// credential good enough to resurrect one. Do not move the Verify call above
// the state check to "fail faster" — that reverses the guarantee.
//
// # Why the service calls Verify rather than the transport
//
// Mapping every negative verdict onto ErrNotFound here leaves the transport
// with exactly two outcomes to distinguish, neither of which knows anything
// about credentials or visibility. The transport is then INCAPABLE of emitting
// a distinguishable protected-miss response, rather than merely disciplined
// about not doing so. The verdict itself is Verify's and is not re-derived: a
// refusal is passed along unchanged, never inspected for why.
func (s *Service) resolveAccess(ctx context.Context, ownerID domain.OwnerID, set *domain.KeySet, presented secrets.Redacted) (bool, error) {
	// Equality with public, not inequality with protected. A visibility value
	// added to the domain later is then unreachable through this endpoint until
	// someone decides what it means, rather than defaulting to published.
	if set.Visibility == domain.VisibilityPublic {
		return false, nil
	}
	// Likewise: only the one value this code understands reaches the gate. An
	// unrecognized visibility is not handed to the verifier, because "some
	// credential may open it" is a decision this code has not been told to make.
	if set.Visibility != domain.VisibilityProtected {
		return false, ErrNotFound
	}

	// No verifier configured means protected sets do not resolve, for anyone.
	// It is answered with the ordinary negative verdict rather than an internal
	// error: this is the unauthenticated path, and a deployment that has not
	// enabled the feature must not be distinguishable from one where the set
	// does not exist. A panic is not an option for the same reason — it would
	// be reachable by an unauthenticated request naming any protected set.
	if s.verifier == nil {
		return false, ErrNotFound
	}

	// The verdict, taken as given. A storage fault is deliberately NOT folded
	// into ErrNotFound: a database that could not be read has not decided the
	// caller is unauthorized, and reporting a denial for it would make an
	// outage look exactly like normal operation while failing closed for
	// everyone. accesskey.ErrNotFound wraps domain.ErrNotFound, so the denial
	// is caught by the sentinel test and the fault is not.
	if _, err := s.verifier.Verify(ctx, ownerID, set.ID, presented); err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return false, ErrNotFound
		}
		return false, fmt.Errorf("publish: verify access key: %w", err)
	}
	return true, nil
}

// resolveOwner maps a handle name to the owner that may publish under it.
//
// The handle must be claimed AND active: GetByName deliberately returns
// quarantined and retired name-claims too, and publishing under a name whose
// claim has lapsed would let a previous holder's keys keep answering for a name
// that is on its way to someone else.
func (s *Service) resolveOwner(ctx context.Context, handle string) (domain.OwnerID, error) {
	h, err := s.repos.Handles.GetByName(ctx, handle)
	if err != nil {
		return "", notFoundOr(err, "publish: get handle")
	}
	// The nil check is a port contract guard, not a lookup. A nil row with a nil
	// error is a violation no adapter in this tree commits, so the two readings
	// available are "dereference and panic" and "refuse" — and this is the
	// UNAUTHENTICATED publish path, reachable by anyone who can send a GET. A
	// panic here would be a remote denial of service against the whole process,
	// where a refusal costs one request. It folds into the state check because
	// the verdict is the same one: not publishable.
	if h == nil || h.State != domain.NameStateActive {
		return "", ErrNotFound
	}

	// A suspended or soft-deleted owner stops publishing immediately. Suspension
	// is a moderation action and deletion is a user request; either one leaving
	// keys live would make the control meaningless.
	o, err := s.repos.Owners.Get(ctx, h.OwnerID)
	if err != nil {
		return "", notFoundOr(err, "publish: get owner")
	}
	// Guarded for the same reason as the handle above, and it matters more here:
	// this is the check that enforces suspension and deletion, so a nil row that
	// panicked would take down the process on exactly the path that exists to
	// stop a suspended owner from publishing.
	if o == nil || o.Status != domain.OwnerStatusActive || o.DeletedAt != nil {
		return "", ErrNotFound
	}
	return o.ID, nil
}

// resolveSet returns the key set to publish: the named one, or the owner's
// default when name is empty.
//
// Both lookups are owner-scoped, which is what makes "another owner's set"
// indistinguishable from "no such set" without an explicit comparison: the
// other owner's row is simply not visible to this query.
func (s *Service) resolveSet(ctx context.Context, ownerID domain.OwnerID, name string) (*domain.KeySet, error) {
	var (
		set *domain.KeySet
		err error
	)
	if name == "" {
		set, err = s.repos.KeySets.GetDefault(ctx, ownerID)
	} else {
		set, err = s.repos.KeySets.GetByName(ctx, ownerID, name)
	}
	if err != nil {
		return nil, notFoundOr(err, "publish: get key set")
	}

	// A quarantined row is a freed-name tombstone, not a publishable set.
	//
	// THIS CHECK IS THE ONE THAT GATES PROTECTED SETS TOO, and it is why it
	// lives here rather than beside the visibility gate. Verify matches a
	// token against a key set ID and never reads the KeySet row, so it cannot
	// see this field; refusing a non-active set BEFORE any credential is
	// consulted is what stops a still-valid token from resurrecting a
	// tombstoned set. See resolveAccess for the full argument.
	// The nil guard rides along with the state check for the reason given in
	// resolveOwner, and this site carries the sharpest version of it: a nil row
	// reaching the dereference below would panic BEFORE the state check that
	// gates protected sets ever ran, so the failure mode is not only a crash but
	// a crash on the security check itself.
	if set == nil || set.State != domain.NameStateActive {
		return nil, ErrNotFound
	}
	return set, nil
}

// render builds the authorized_keys body from the resolved keys.
//
// Ordering is made explicit here rather than inherited from the adapter. The
// repository contract already promises id order, but the ETag over this body is
// only stable if the order is, so the guarantee is restated at the layer that
// depends on it: a future adapter (or a query planner that ignores an ORDER BY
// hint) cannot silently start returning rows in a different sequence and turn
// every conditional request into a cache miss.
func render(ownerID domain.OwnerID, active []domain.PublicKey) ([]byte, error) {
	sorted := make([]domain.PublicKey, len(active))
	copy(sorted, active)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].ID < sorted[j].ID })

	var buf bytes.Buffer
	for i := range sorted {
		k := &sorted[i]

		// Defense in depth against a storage layer that returns more than it
		// was asked for. These two invariants are already enforced by the SQL
		// predicates; re-checking them here means a regression in the query (or
		// a different adapter) cannot publish a revoked key or cross the owner
		// boundary, which are the two failures this endpoint must never have.
		if k.OwnerID != ownerID {
			return nil, fmt.Errorf("publish: key %q crosses owner boundary", k.ID)
		}
		if k.Status != domain.KeyStatusActive {
			return nil, fmt.Errorf("publish: key %q is not active", k.ID)
		}

		// The line is REBUILT from the algorithm, wire blob, and comment; the
		// stored comment is never interpolated into output that has not been
		// re-validated. AuthorizedKeyLineFrom re-parses the blob, re-checks the
		// algorithm and strength, and rejects a comment containing CR or LF, so
		// a comment cannot terminate its line and forge an extra entry.
		//
		// An error here fails the whole response. Skipping the key would emit a
		// silently short authorized_keys file, and nothing downstream could tell
		// that apart from a legitimately shorter one.
		line, err := keys.AuthorizedKeyLineFrom(k.Algorithm, k.Blob, k.Comment)
		if err != nil {
			return nil, fmt.Errorf("publish: render key %q: %w", k.ID, err)
		}
		buf.WriteString(line)
	}
	return buf.Bytes(), nil
}

// notFoundOr collapses a repository domain.ErrNotFound into the publish
// sentinel and wraps anything else as an internal fault.
//
// domain.ErrNotFound already covers both "no such row" and "row belongs to
// another owner" by repository contract, so this single mapping is what makes
// the cross-owner case indistinguishable from the missing case all the way up
// to the wire.
func notFoundOr(err error, context string) error {
	if errors.Is(err, domain.ErrNotFound) {
		return ErrNotFound
	}
	return fmt.Errorf("%s: %w", context, err)
}
