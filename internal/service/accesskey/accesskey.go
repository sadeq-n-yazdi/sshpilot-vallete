// Package accesskey is the owner-facing service for the bearer credentials that
// unlock an access-key-protected key set: mint, list, revoke, and the bearer
// verification itself.
//
// A key set may be public or protected (ADR-0010), and protection is decided
// per set rather than per handle (ADR-0016). A protected set is resolved by
// presenting an access key as an `Authorization: Bearer` header. This package
// owns every part of that credential's life except the transport that carries
// it: it mints the id, the secret, and the digest, it decides what a presented
// token means, and it is the only place that compares one.
//
// # Verification lives here, not at the transport
//
// Verify is in this package deliberately. The check that decides whether a
// token unlocks THIS key set is one line, and putting it on the seam between a
// handler and a service is how it gets lost — each side plausibly believing the
// other performs it. Keeping it inside a package held to full coverage means it
// is exercised by tests that can see it, and a mutation that removes it fails
// them. The route layer will call Verify and act on its verdict; it will not
// re-derive one.
//
// # The set-scope check is the whole point
//
// The repository's Get is scoped by owner and id, and NOT by key set: it
// answers "does this owner have a key with this id", which is the correct
// question for management and only half the question for verification. An owner
// holding a key minted for their public set `test` presents a token whose id is
// genuinely theirs; without an explicit comparison of the loaded key's KeySetID
// against the set being requested, that token would resolve their protected set
// `prod`. Per-set access keys are the guarantee ADR-0016 makes, so Verify
// compares the two ids and treats a mismatch as no different from a token that
// was invented.
//
// The mirror-image check is enforced at Mint: the schema's key_set_id foreign
// key references key_sets(id) alone, not the composite (id, owner_id), so
// nothing in the database stops a row that names one owner and another owner's
// key set. The migration says so and hands the responsibility to its caller,
// which is this package. Mint therefore resolves the set through the
// owner-scoped key set port before writing anything, exactly as the public key
// service resolves a device.
//
// # One negative verdict
//
// Every reason a request cannot be satisfied collapses into ErrNotFound: an
// unknown id, another owner's id, a wrong secret, a revoked key, a key whose
// grace window has closed, a key minted for a different set, and a token whose
// shape this package does not recognize. They are one value so the transport
// can map them to one uniform 404 (ADR-0019), which is what stops an attacker
// probing with a garbage Bearer token from reading the existence of a protected
// set off a 401-vs-404 difference. A verdict that encoded why would answer
// "that set exists, your credential is wrong" — the exact fact the uniform
// response exists to withhold.
//
// A storage fault is NOT a negative verdict. A database that could not be
// reached has not decided anything, and reporting "no" for it would turn an
// outage into a silent, uniform denial that looks identical to correct
// operation. Those errors propagate unchanged.
//
// # The owner is a parameter, never a lookup
//
// Every exported method takes a domain.OwnerID and passes it to the
// owner-scoped ports. The service never derives an owner from anything about
// the request. For management calls the transport supplies it from the verified
// token (ADR-0004); for Verify it comes from resolving the handle in the
// request path, which is why the bearer token itself does not carry an owner
// and could not be trusted if it did.
//
// # The plaintext is returned once
//
// Mint is the only function that ever holds the plaintext token, and it returns
// it as a secrets.Redacted so that a caller who logs it prints a marker rather
// than a credential. Nothing here stores it, records it in the audit trail, or
// places it in an error string. An owner who loses it rotates; there is no
// recovery path, because a recovery path is a second way to obtain a live
// credential.
package accesskey

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/audit"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/repository"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/secrets"
)

// ErrNotFound is the single negative verdict, for management calls and for
// Verify alike. See the package doc for why they are deliberately one value and
// not two: a transport that had two could map them to two statuses, and the
// uniform 404 ADR-0019 requires would be gone.
//
// It wraps domain.ErrNotFound so callers that branch on the domain sentinel
// keep working.
var ErrNotFound = fmt.Errorf("accesskey: not found: %w", domain.ErrNotFound)

// ErrMissingDependency is returned by New when a required collaborator or the
// pepper is absent. It is a construction-time programming error: the service
// fails to build rather than nil-panicking on the first request, or — worse for
// the pepper — quietly minting digests under a zero-length key.
var ErrMissingDependency = errors.New("accesskey: missing dependency")

// maxNameLen bounds the human label attached to a key, in runes. The label is
// the owner's own text and is echoed into the audit trail, so it is bounded
// here rather than left to the column definition.
const maxNameLen = 64

// Auditor is the audit dependency, declared at the point of use so this package
// depends on a method set rather than a concrete type. *audit.Emitter satisfies
// it.
type Auditor interface {
	Emit(ctx context.Context, ev audit.Event) error
}

// Service implements access key management and bearer verification. It is
// immutable after construction and safe for concurrent use if its collaborators
// are.
type Service struct {
	keys    repository.AccessKeyRepository
	keySets repository.KeySetRepository
	auditor Auditor
	hasher  *hasher
	now     func() time.Time
}

// Option customizes a Service.
type Option func(*Service)

// WithClock overrides the clock used to stamp CreatedAt, RevokedAt, and — the
// one that matters — the instant a grace window is measured against. A clock is
// behavior a test needs to control, not a security control.
func WithClock(now func() time.Time) Option {
	return func(s *Service) {
		if now != nil {
			s.now = now
		}
	}
}

// There is deliberately no option overriding the id or secret generators. Both
// come from crypto/rand and both are load-bearing: a predictable id defeats the
// cross-owner 404, and a predictable secret defeats everything. A seam that let
// any caller weaken them would be a seam worth attacking, so the tests assert
// the generators' properties instead of replacing them.

// New builds a Service.
//
// pepper keys the digest of every secret; see hasher for why the digest is
// keyed at all. It must be at least MinPepperLen bytes and is copied, so a
// caller that reuses or zeroes its buffer cannot change the key underneath a
// running service. Resolving it from the secrets package is deployment wiring
// and happens in cmd/valletd, not here; this package only refuses to operate
// without an adequate one.
//
// The key set repository is required rather than optional because it is what
// makes Mint's owner check a query rather than a hope — see the package doc on
// the non-composite foreign key. The auditor likewise: a Service without one
// would look wired up and would mint and revoke credentials leaving no trace,
// which is worse than failing to start.
func New(keys repository.AccessKeyRepository, keySets repository.KeySetRepository, auditor Auditor, pepper []byte, opts ...Option) (*Service, error) {
	if keys == nil {
		return nil, fmt.Errorf("%w: access key repository", ErrMissingDependency)
	}
	if keySets == nil {
		return nil, fmt.Errorf("%w: key set repository", ErrMissingDependency)
	}
	if auditor == nil {
		return nil, fmt.Errorf("%w: auditor", ErrMissingDependency)
	}
	h, err := newHasher(pepper)
	if err != nil {
		return nil, err
	}
	s := &Service{keys: keys, keySets: keySets, auditor: auditor, hasher: h, now: time.Now}
	for i, opt := range opts {
		// A nil option is rejected rather than skipped, matching the other
		// services: skipping it would leave a Service that looks configured and
		// is not.
		if opt == nil {
			return nil, fmt.Errorf("%w: nil option at index %d", ErrMissingDependency, i)
		}
		opt(s)
	}
	return s, nil
}

// Mint issues a new access key for one of the owner's key sets and returns both
// the stored record and the plaintext bearer token.
//
// The token is the ONLY copy: it is derived from a secret this function
// generates, digested, and then drops. It is returned as a secrets.Redacted so
// an accidental log line prints a marker. Nothing downstream can recover it.
//
// The key set is resolved through the owner-scoped port first, so a set that
// does not exist, belongs to another owner, or is not active yields ErrNotFound
// and no row is written. A quarantined or retired set is refused for the same
// reason the public key service refuses a retired device: a name that is out of
// service must not gain fresh credentials that would outlive its return.
//
// requestID correlates the audit record with the request log; it may be empty.
func (s *Service) Mint(ctx context.Context, ownerID domain.OwnerID, setID domain.KeySetID, name, requestID string) (*domain.AccessKey, secrets.Redacted, error) {
	if ownerID == "" {
		// An empty owner would produce a credential belonging to nobody,
		// reachable by any other request that also failed to carry an owner.
		// Refusing here means the write is never attempted.
		return nil, "", fmt.Errorf("accesskey: missing owner: %w", domain.ErrInvalidInput)
	}
	clean, err := cleanName(name)
	if err != nil {
		return nil, "", err
	}

	set, err := s.keySet(ctx, ownerID, setID)
	if err != nil {
		return nil, "", err
	}

	// The audit details are built BEFORE the write: a detail the audit screen
	// refuses must not be able to leave a committed credential unrecorded.
	details, err := keyDetails(clean, set.Name, requestID)
	if err != nil {
		return nil, "", err
	}

	token, id, secret, err := newToken()
	if err != nil {
		return nil, "", err
	}
	k := &domain.AccessKey{
		ID:         id,
		OwnerID:    ownerID,
		KeySetID:   set.ID,
		Name:       clean,
		SecretHash: s.hasher.hash(id, secret),
		Status:     domain.AccessKeyStatusActive,
		CreatedAt:  s.now().UTC(),
	}
	if err := s.keys.Create(ctx, k); err != nil {
		return nil, "", err
	}

	if err := s.emit(ctx, domain.AuditActionAccessKeyCreated, ownerID, k.ID, details); err != nil {
		// The credential exists and the trail does not, so it is not handed
		// back: a caller that never receives the token cannot use it, and the
		// row it left behind is inert until someone rotates or revokes it.
		return nil, "", err
	}
	return k, token, nil
}

// keySet resolves the key set a credential is being minted for, through the
// owner-scoped port.
//
// Every failure is ErrNotFound: an empty id, an unknown id, another owner's id,
// and a set that is not active are one answer, so a caller cannot use Mint to
// discover which key set ids exist under owners it does not control.
func (s *Service) keySet(ctx context.Context, ownerID domain.OwnerID, setID domain.KeySetID) (*domain.KeySet, error) {
	if setID == "" {
		return nil, ErrNotFound
	}
	set, err := s.keySets.Get(ctx, ownerID, setID)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if set.State != domain.NameStateActive {
		return nil, ErrNotFound
	}
	return set, nil
}

// List returns all of the owner's access keys, including revoked ones and ones
// still in a grace window.
//
// The full lifecycle is shown because this is the owner's own inventory and the
// owner is entitled to the difference between a credential that was revoked and
// one that never existed. The collapse described in the package doc is about
// what a DIFFERENT owner can observe, and no other owner's key can appear here:
// the repository filters by ownerID.
//
// domain.AccessKey carries SecretHash, which the domain type keeps out of JSON.
// It is a digest and not a credential, but there is no question a caller of this
// method asks that it answers, so a transport should drop it rather than rely on
// that tag.
func (s *Service) List(ctx context.Context, ownerID domain.OwnerID) ([]domain.AccessKey, error) {
	if ownerID == "" {
		return nil, fmt.Errorf("accesskey: missing owner: %w", domain.ErrInvalidInput)
	}
	return s.keys.ListByOwner(ctx, ownerID)
}

// ListBySet returns the owner's access keys for one key set.
//
// The set is not resolved first. The repository query is scoped by owner AND by
// set, so an unknown set id and another owner's set id both return no rows —
// the same empty answer, which is what a set holding no credentials returns
// too. Looking the set up to distinguish those cases would create exactly the
// three-way answer the package doc removes.
func (s *Service) ListBySet(ctx context.Context, ownerID domain.OwnerID, setID domain.KeySetID) ([]domain.AccessKey, error) {
	if ownerID == "" {
		return nil, fmt.Errorf("accesskey: missing owner: %w", domain.ErrInvalidInput)
	}
	if setID == "" {
		return nil, fmt.Errorf("accesskey: missing key set: %w", domain.ErrInvalidInput)
	}
	return s.keys.ListByKeySet(ctx, ownerID, setID)
}

// Revoke takes one of the owner's access keys permanently out of service.
//
// It returns ErrNotFound for an unknown id, another owner's id, AND a key that
// is already revoked — one answer for all three. Repeating a revoke is
// therefore safe: the second call changes nothing and reports what a stranger's
// id reports. It deliberately is not the REST convention of answering the
// repeat with success, because that would make a credential's lifecycle state
// observable as a third answer.
//
// A key in its grace window IS revocable, and that is the point: rotation
// leaves an old credential briefly live, and revocation is the control that
// ends it early. The repository's Revoke clears the grace deadline, so no later
// sweep acts on a key that has already been shut down.
func (s *Service) Revoke(ctx context.Context, ownerID domain.OwnerID, id domain.AccessKeyID, requestID string) error {
	if ownerID == "" {
		return fmt.Errorf("accesskey: missing owner: %w", domain.ErrInvalidInput)
	}
	if id == "" {
		// An empty id names no key. It collapses into the same verdict as a
		// wrong one so a caller cannot learn which shapes are well formed.
		return ErrNotFound
	}

	k, err := s.keys.Get(ctx, ownerID, id)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return ErrNotFound
		}
		return err
	}
	if k.Status == domain.AccessKeyStatusRevoked {
		return ErrNotFound
	}

	// As in Mint the details are built before the write. Unlike Mint the name
	// was stored earlier rather than supplied by this caller, so a refusal here
	// is a server fault the caller cannot fix, not invalid input — and the
	// rejected value is not quoted back into an error bound for a log.
	details, err := keyDetails(k.Name, "", requestID)
	if err != nil {
		return errors.New("accesskey: stored key cannot be recorded")
	}

	if err := s.keys.Revoke(ctx, ownerID, id, s.now().UTC()); err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return ErrNotFound
		}
		return err
	}
	return s.emit(ctx, domain.AuditActionAccessKeyRevoked, ownerID, id, details)
}

// cleanName validates the human label attached to a key.
//
// The label is the one field on an access key the owner chooses, and it ends up
// in an audit record, so it is bounded and required to be well-formed UTF-8
// here. The rejected text is never quoted back: this error is destined for a
// log, and a caller that pasted a token into the name field must not have it
// copied there.
func cleanName(name string) (string, error) {
	clean := strings.TrimSpace(name)
	switch {
	case clean == "":
		return "", fmt.Errorf("accesskey: name is required: %w", domain.ErrInvalidInput)
	case utf8.RuneCountInString(clean) > maxNameLen:
		return "", fmt.Errorf("accesskey: name is longer than %d characters: %w", maxNameLen, domain.ErrInvalidInput)
	case !utf8.ValidString(clean):
		return "", fmt.Errorf("accesskey: name is not valid UTF-8: %w", domain.ErrInvalidInput)
	}
	return clean, nil
}

// keyDetails builds the audit details for a credential change.
//
// What is recorded is the label, the key set's name when the caller has it, and
// the request id. What is not recorded, ever, is the plaintext token or its
// digest: an audit record is an access-controlled artifact, but there is no
// incident question either value answers that the credential's id does not, and
// a digest in a log is an offline guessing target that need not exist.
func keyDetails(name, setName, requestID string) (audit.Details, error) {
	d := audit.Details{}.Set(audit.DetailClientLabel, name)
	if setName != "" {
		d = d.Set(audit.DetailKeySetName, setName)
	}
	if requestID != "" {
		d = d.Set(audit.DetailRequestID, requestID)
	}
	if err := d.Err(); err != nil {
		return audit.Details{}, fmt.Errorf("accesskey: key cannot be recorded: %w", domain.ErrInvalidInput)
	}
	return d, nil
}

// emit records an access-affecting credential change. A failure to record is
// returned to the caller rather than swallowed: a credential minted or revoked
// with no accountability trail is precisely the state an audit log exists to
// make impossible (ADR-0007).
func (s *Service) emit(ctx context.Context, action domain.AuditAction, ownerID domain.OwnerID, id domain.AccessKeyID, details audit.Details) error {
	return s.auditor.Emit(ctx, audit.Event{
		ActorType:  domain.ActorTypeOwner,
		ActorID:    string(ownerID),
		Action:     action,
		TargetType: domain.TargetTypeAccessKey,
		TargetID:   string(id),
		Details:    details,
	})
}
