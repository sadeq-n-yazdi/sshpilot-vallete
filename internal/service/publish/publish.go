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

// Service resolves handles to publishable authorized_keys bodies. It is
// stateless and safe for concurrent use by many requests.
type Service struct {
	repos repository.Repos
}

// New builds a Service over the given repositories.
//
// It fails closed: the three ports the resolution path actually calls must all
// be present. A partially populated Repos is a wiring bug, and catching it at
// startup is strictly better than discovering it as a panic on a live request.
func New(repos repository.Repos) (*Service, error) {
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
	return &Service{repos: repos}, nil
}

// Resolve returns the canonical authorized_keys body published at
// /{handle} (setName == "") or /{handle}/{setName}.
//
// An empty setName selects the owner's default key set.
//
// The gate order is fail-closed and every gate funnels into ErrNotFound; see
// the package doc for why they are indistinguishable. Only once the handle,
// the owner, and the set have all passed does the key listing happen, so a
// caller can never observe key data for anything it was not entitled to name.
func (s *Service) Resolve(ctx context.Context, handle, setName string) ([]byte, error) {
	// Format validation folds into the same 404 as everything else. A
	// malformed name cannot identify a real handle, so answering "invalid"
	// rather than "not found" would tell a prober which of its guesses were
	// well-formed — a free lesson in the namespace's shape.
	if domain.ValidateHandle(handle) != nil {
		return nil, ErrNotFound
	}
	if setName != "" && domain.ValidateSetName(setName) != nil {
		return nil, ErrNotFound
	}

	ownerID, err := s.resolveOwner(ctx, handle)
	if err != nil {
		return nil, err
	}

	set, err := s.resolveSet(ctx, ownerID, setName)
	if err != nil {
		return nil, err
	}

	// The owner-scoped, active-only membership query. It is called with the
	// owner ID derived from the handle, never one supplied by the caller, and
	// its own pk.owner_id and status='active' predicates are the storage-layer
	// backstop for tenant isolation and revocation.
	active, err := s.repos.PublicKeys.ListActiveByKeySet(ctx, ownerID, set.ID)
	if err != nil {
		return nil, fmt.Errorf("publish: list active keys: %w", err)
	}

	return render(ownerID, active)
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
	if h.State != domain.NameStateActive {
		return "", ErrNotFound
	}

	// A suspended or soft-deleted owner stops publishing immediately. Suspension
	// is a moderation action and deletion is a user request; either one leaving
	// keys live would make the control meaningless.
	o, err := s.repos.Owners.Get(ctx, h.OwnerID)
	if err != nil {
		return "", notFoundOr(err, "publish: get owner")
	}
	if o.Status != domain.OwnerStatusActive || o.DeletedAt != nil {
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
	if set.State != domain.NameStateActive {
		return nil, ErrNotFound
	}

	// Visibility gate, failing closed. Bearer-authenticated access to protected
	// sets is a later slice; until it exists, a non-public set must be
	// unreachable rather than accidentally public. The test for equality with
	// VisibilityPublic (rather than inequality with VisibilityProtected) means a
	// future visibility value defaults to private, not to published.
	if set.Visibility != domain.VisibilityPublic {
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
