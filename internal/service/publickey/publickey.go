// Package publickey is the owner-facing public key management service: add,
// list, and revoke.
//
// # Public keys only
//
// This package never decides what a valid key is. Every submission goes through
// internal/keys, which is the single ingest authority (ADR-0002, ADR-0006): it
// rejects private key material before parsing, refuses authorized_keys options,
// enforces the algorithm allowlist and the RSA strength floor, and returns
// errors whose text never reflects the caller's bytes. There is deliberately no
// second parser, no "trusted" path that skips it, and nothing here that
// inspects the raw submission itself — a second place that decides validity is
// a second place that can be made to disagree with the first.
//
// The raw submission is never logged, never echoed, and never recorded. What
// reaches the audit log is derived: the fingerprint and the algorithm, both
// computed by internal/keys from the parsed key, never the bytes that arrived.
//
// # The owner is a parameter, never a lookup
//
// Every exported method takes a domain.OwnerID as its first meaningful
// argument and passes it straight through to the owner-scoped repository ports.
// The service never derives an owner from anything it was given about the
// request. The transport obtains the owner from the verified token
// (auth.Authorization.Owner) and hands it in, so the boundary is established
// before this package's first line runs (ADR-0004).
//
// # One negative verdict
//
// Every reason a key cannot be acted on collapses into ErrNotFound: the key id
// is unknown, it belongs to another owner, it is already revoked, or — on Add —
// the named device is unknown, belongs to another owner, or is revoked. The
// device cases collapse into the same answer for the same reason the key cases
// do: a caller holding a valid token for owner B must not be able to tell owner
// A's device id apart from a string it invented. The repositories already
// return domain.ErrNotFound for both "absent" and "another owner's", and this
// package extends the same treatment to the lifecycle states so that neither a
// key's nor a device's status is observable as a third answer.
//
// # Why a device is required
//
// A public_keys row carries a NOT NULL device_id under a composite foreign key
// to devices(id, owner_id), so a key cannot exist without a device of the same
// owner (ADR-0004: a device groups the keys it generated so a lost device can
// be revoked as a unit). The device is therefore checked here, through the
// owner-scoped port, rather than left to the foreign key: a constraint failure
// maps to a generic storage error and would surface as a 500, which both reads
// as a server fault and is a different response from the one an unknown key
// gets — reintroducing the very distinction the collapse above removes.
//
// # Audit is not optional
//
// Add and Revoke are access-affecting changes, so each emits an audit record
// (ADR-0007). A failure to record is returned to the caller rather than
// swallowed: a key that was added or revoked with no accountability trail is
// precisely the state an audit log exists to make impossible.
package publickey

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/audit"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/keys"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/repository"
)

// ErrNotFound is the single negative verdict for addressing a key or the device
// a key is being added to: unknown id, another owner's id, or a revoked
// resource. See the package doc for why they are one answer.
//
// It wraps domain.ErrNotFound so callers that already branch on the domain
// sentinel keep working, and so the transport can map one error to one status.
var ErrNotFound = fmt.Errorf("publickey: not found: %w", domain.ErrNotFound)

// ErrDuplicate is returned when the owner already holds a key with the same
// fingerprint.
//
// Unlike the verdicts above this one is NOT collapsed, and the difference is
// safe: the unique index is on (owner_id, fingerprint), so the only key this
// can report on is one the caller already owns and can already see in its own
// list. It leaks nothing about any other owner, and telling the caller its key
// is already enrolled is what stops a client from retrying forever.
var ErrDuplicate = fmt.Errorf("publickey: key already enrolled: %w", domain.ErrConflict)

// ErrMissingDependency is returned by New when a required collaborator is
// absent. It is a construction-time programming error: the service fails to
// build rather than nil-panicking on the first request, and in the audit
// emitter's case rather than serving mutations that record nothing.
var ErrMissingDependency = errors.New("publickey: missing dependency")

// Auditor is the audit dependency, declared at the point of use so this package
// depends on a method set rather than a concrete type. *audit.Emitter satisfies
// it.
type Auditor interface {
	Emit(ctx context.Context, ev audit.Event) error
}

// Service implements public key management. It is immutable after construction
// and safe for concurrent use if its collaborators are.
type Service struct {
	keys    repository.PublicKeyRepository
	devices repository.DeviceRepository
	auditor Auditor
	now     func() time.Time
	newID   func() string
}

// Option customizes a Service.
type Option func(*Service)

// WithClock overrides the clock used to stamp key timestamps. A clock is
// behavior a test needs to control, not a security control.
func WithClock(now func() time.Time) Option {
	return func(s *Service) {
		if now != nil {
			s.now = now
		}
	}
}

// There is deliberately no option overriding the key ID generator, matching the
// device service. A key ID is how a revoke names its target, so a seam that let
// any caller make IDs predictable would be a seam worth attacking. Tests assert
// the generator's properties instead of replacing it.

// New builds a Service.
//
// All three collaborators are required. The device repository especially: it is
// what makes the owner check on Add a query rather than a hope, and a Service
// without it could not perform that check at all. The auditor likewise — a
// Service without one would look wired up and would add and revoke keys leaving
// no trace, which is worse than not starting.
func New(publicKeys repository.PublicKeyRepository, devices repository.DeviceRepository, auditor Auditor, opts ...Option) (*Service, error) {
	if publicKeys == nil {
		return nil, fmt.Errorf("%w: public key repository", ErrMissingDependency)
	}
	if devices == nil {
		return nil, fmt.Errorf("%w: device repository", ErrMissingDependency)
	}
	if auditor == nil {
		return nil, fmt.Errorf("%w: auditor", ErrMissingDependency)
	}
	s := &Service{keys: publicKeys, devices: devices, auditor: auditor, now: time.Now, newID: newKeyID}
	for i, opt := range opts {
		// A nil option is rejected rather than skipped, matching audit.NewEmitter
		// and the device service: skipping it would leave a Service that looks
		// configured and is not.
		if opt == nil {
			return nil, fmt.Errorf("%w: nil option at index %d", ErrMissingDependency, i)
		}
		opt(s)
	}
	return s, nil
}

// newKeyID returns a fresh, unguessable public key ID. crypto/rand.Text yields
// 26 base32 characters (~130 bits), matching the identifier convention used for
// devices, audit records, and request IDs. Unguessability is load-bearing: key
// IDs are how the management API addresses a key, and a sequential id would make
// the cross-owner 404 pointless — an attacker would not need to guess.
func newKeyID() string {
	return rand.Text()
}

// Add enrolls a public key on one of the owner's devices.
//
// raw is the caller's submission, exactly as it arrived. It is handed to
// keys.Parse unmodified and is not otherwise read: this function does not
// inspect it, log it, or retain it, and no error returned from here contains any
// of its bytes. A private key, an options-bearing line, a weak or unsupported
// algorithm, a multi-key paste, and an oversized submission are all rejected by
// that call, each as an error wrapping domain.ErrInvalidInput.
//
// requestID correlates the audit record with the request log; it may be empty,
// in which case no correlation detail is recorded.
func (s *Service) Add(ctx context.Context, ownerID domain.OwnerID, deviceID domain.DeviceID, raw []byte, requestID string) (*domain.PublicKey, error) {
	if ownerID == "" {
		// An empty owner would produce a key belonging to nobody, reachable by
		// any other request that also failed to carry an owner. Refusing here
		// means the write is never attempted.
		return nil, fmt.Errorf("publickey: missing owner: %w", domain.ErrInvalidInput)
	}

	// Parsing runs before any storage is touched, so a submission that must
	// never be stored is refused before anything has a chance to store it.
	parsed, err := keys.Parse(raw)
	if err != nil {
		// Returned verbatim. The keys package's sentinels are fixed strings
		// that never reflect input, which is exactly why they can be surfaced
		// to the caller — the private-key message in particular is a fixed
		// instruction and carries none of the material it detected.
		return nil, err
	}

	device, err := s.device(ctx, ownerID, deviceID)
	if err != nil {
		return nil, err
	}

	// The audit details are built BEFORE the write, matching the device service:
	// a detail the audit screen refuses must not be able to leave a committed
	// key unrecorded. Both values are derived by keys.Parse from the parsed key
	// — never the caller's bytes.
	details, err := keyDetails(parsed.Fingerprint, parsed.Algorithm, requestID)
	if err != nil {
		return nil, err
	}

	now := s.now().UTC()
	k := &domain.PublicKey{
		ID:          domain.PublicKeyID(s.newID()),
		OwnerID:     ownerID,
		DeviceID:    device.ID,
		Algorithm:   parsed.Algorithm,
		Blob:        parsed.Blob,
		Comment:     parsed.Comment,
		Fingerprint: parsed.Fingerprint,
		BitLen:      parsed.BitLen,
		Status:      domain.KeyStatusActive,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if err := s.keys.Create(ctx, k); err != nil {
		if errors.Is(err, domain.ErrConflict) {
			return nil, ErrDuplicate
		}
		return nil, err
	}

	if err := s.emit(ctx, domain.AuditActionKeyAdded, ownerID, k.ID, details); err != nil {
		return nil, err
	}
	return k, nil
}

// device resolves the device a key is being added to, through the owner-scoped
// port.
//
// Every failure is ErrNotFound: an empty id, an unknown id, another owner's id,
// and a revoked device are one answer. The revoked case is folded in
// deliberately — a retired device must not gain new keys, and answering that
// distinctly would make a stranger's device lifecycle observable to any caller
// willing to guess ids.
func (s *Service) device(ctx context.Context, ownerID domain.OwnerID, deviceID domain.DeviceID) (*domain.Device, error) {
	if deviceID == "" {
		return nil, ErrNotFound
	}
	d, err := s.devices.Get(ctx, ownerID, deviceID)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if d.Status != domain.DeviceStatusActive {
		return nil, ErrNotFound
	}
	return d, nil
}

// keyDetails builds the audit details for a key change.
//
// The fingerprint and algorithm are the two allowlisted, non-secret facts that
// make a record readable in an incident review; the raw submission and the key
// blob are not recorded at all. Both inputs are derived from the parsed key, so
// the error path here is defense in depth rather than an expected outcome.
func keyDetails(fingerprint string, alg domain.Algorithm, requestID string) (audit.Details, error) {
	d := audit.Details{}.
		Set(audit.DetailFingerprint, fingerprint).
		Set(audit.DetailAlgorithm, string(alg))
	if requestID != "" {
		d = d.Set(audit.DetailRequestID, requestID)
	}
	if err := d.Err(); err != nil {
		// The rejected values are not quoted back. A fingerprint and an
		// algorithm name are not secrets, but this error is destined for a log
		// and there is no reason for it to carry content it does not need.
		return audit.Details{}, fmt.Errorf("publickey: key cannot be recorded: %w", domain.ErrInvalidInput)
	}
	return d, nil
}

// List returns the owner's public keys, including revoked ones.
//
// Revoked keys are included because this is the owner's own inventory and
// hiding them would make a revoked key indistinguishable from one that was
// never enrolled — for the owner, who is entitled to the difference. The
// cross-owner collapse in the package doc is about what a DIFFERENT owner can
// observe, and no other owner's key can appear here at all: the repository
// filters by ownerID.
//
// An owner with no keys gets a nil slice, per the repository's nil-collection
// convention. The transport, not this package, decides what nil looks like on
// the wire.
func (s *Service) List(ctx context.Context, ownerID domain.OwnerID) ([]domain.PublicKey, error) {
	if ownerID == "" {
		return nil, fmt.Errorf("publickey: missing owner: %w", domain.ErrInvalidInput)
	}
	return s.keys.ListByOwner(ctx, ownerID)
}

// Revoke marks the owner's key revoked.
//
// It returns ErrNotFound for an unknown id, another owner's id, AND a key that
// is already revoked — one answer for all three, per the package doc.
//
// Repeating a revoke is therefore safe: the second call changes nothing and
// reports the same 404 a stranger's id reports. That is the sense in which this
// is idempotent-safe. It deliberately is not the REST convention of answering
// the repeat with success, because doing so would make a key's lifecycle state
// observable as a third answer, distinct from absent.
//
// The read-then-write is not atomic, and does not need to be: two concurrent
// revokes of the same active key may both observe it active and both succeed,
// which converges on the identical end state and leaks nothing. There is no
// interleaving that revokes a key for the wrong owner, because the ownerID
// passed to Revoke is the same one Get filtered on.
func (s *Service) Revoke(ctx context.Context, ownerID domain.OwnerID, id domain.PublicKeyID, requestID string) error {
	if ownerID == "" {
		return fmt.Errorf("publickey: missing owner: %w", domain.ErrInvalidInput)
	}
	if id == "" {
		// An empty id names no key. It collapses into the same verdict as a
		// wrong one so that a caller cannot learn which shapes are well formed.
		return ErrNotFound
	}

	k, err := s.keys.Get(ctx, ownerID, id)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return ErrNotFound
		}
		return err
	}
	if k.Status != domain.KeyStatusActive {
		return ErrNotFound
	}

	// As in Add, the details are built before the write. Unlike Add the values
	// were stored earlier rather than supplied by this caller, so a refusal here
	// is not the caller's fault and is not reported as invalid input: it is a
	// server fault the caller cannot fix.
	details, err := keyDetails(k.Fingerprint, k.Algorithm, requestID)
	if err != nil {
		return errors.New("publickey: stored key cannot be recorded for " + strconv.Quote(string(id)))
	}

	if err := s.keys.Revoke(ctx, ownerID, id, s.now().UTC()); err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return ErrNotFound
		}
		return err
	}
	return s.emit(ctx, domain.AuditActionKeyRevoked, ownerID, id, details)
}

// emit records an access-affecting key change.
//
// The details are built by the caller, before its write, so that a value the
// audit screen refuses cannot leave a committed change unrecorded. The key blob
// is never included: an audit record is an access-controlled artifact, but
// there is no incident question a full key blob answers that its fingerprint
// does not.
func (s *Service) emit(ctx context.Context, action domain.AuditAction, ownerID domain.OwnerID, id domain.PublicKeyID, details audit.Details) error {
	return s.auditor.Emit(ctx, audit.Event{
		ActorType:  domain.ActorTypeOwner,
		ActorID:    string(ownerID),
		Action:     action,
		TargetType: domain.TargetTypePublicKey,
		TargetID:   string(id),
		Details:    details,
	})
}
