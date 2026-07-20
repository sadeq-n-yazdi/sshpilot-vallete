// Package device is the owner-facing device management service: register,
// list, and revoke.
//
// # The owner is a parameter, never a lookup
//
// Every exported method takes a domain.OwnerID as its first meaningful
// argument, and every repository call this package makes passes that value
// straight through to the owner-scoped port. The service never derives an owner
// from anything it was given about the request — there is no handle, no name,
// and no identifier here from which an owner could be inferred. The transport
// obtains the owner from the verified token (auth.Authorization.Owner) and
// hands it in, so the boundary is established before this package's first line
// runs.
//
// # One negative verdict
//
// Every reason a device cannot be acted on collapses into ErrNotFound: the id
// is unknown, the id belongs to another owner, or the device is already
// revoked. Collapsing them is the point. A caller holding a valid token for
// owner B must not be able to tell owner A's device id apart from a string it
// invented, because the difference is an enumeration oracle over the whole
// device namespace. The repository already returns domain.ErrNotFound for both
// "absent" and "another owner's" (see repository.DeviceRepository), and this
// package extends the same treatment to "already revoked" so that the lifecycle
// state of a device is not observable as a third answer.
//
// # Audit is not optional
//
// Register and Revoke are access-affecting changes, so each emits an audit
// record (ADR-0007). A failure to record is returned to the caller rather than
// swallowed: a device that was created or revoked with no accountability trail
// is precisely the state an audit log exists to make impossible, so the
// operation is reported as failed instead of silently proceeding unrecorded.
package device

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/audit"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/repository"
)

// ErrNotFound is the single negative verdict for addressing a device: unknown
// id, another owner's id, or an already-revoked device. See the package doc for
// why the three are one answer.
//
// It wraps domain.ErrNotFound so callers that already branch on the domain
// sentinel keep working, and so the transport can map one error to one status.
var ErrNotFound = fmt.Errorf("device: not found: %w", domain.ErrNotFound)

// ErrMissingDependency is returned by New when a required collaborator is
// absent. It is a construction-time programming error: the service fails to
// build rather than nil-panicking on the first request, and in the audit
// emitter's case rather than serving mutations that record nothing.
var ErrMissingDependency = errors.New("device: missing dependency")

// Auditor is the audit dependency, declared at the point of use so this package
// depends on a method set rather than a concrete type. *audit.Emitter satisfies
// it.
type Auditor interface {
	Emit(ctx context.Context, ev audit.Event) error
}

// Service implements device management. It is immutable after construction and
// safe for concurrent use if its collaborators are.
type Service struct {
	devices repository.DeviceRepository
	auditor Auditor
	now     func() time.Time
	newID   func() string
}

// Option customizes a Service.
type Option func(*Service)

// WithClock overrides the clock used to stamp device timestamps. A clock is
// behavior a test needs to control, not a security control.
func WithClock(now func() time.Time) Option {
	return func(s *Service) {
		if now != nil {
			s.now = now
		}
	}
}

// There is deliberately no option overriding the device ID generator. A device
// ID is the resource identifier a single-device token is bound to and the only
// thing standing between an outsider and another owner's device, so a seam that
// let any caller make IDs predictable would be a seam worth attacking. Tests
// assert the generator's properties (distinctness, length) instead of replacing
// it.

// New builds a Service.
//
// Both the repository and the auditor are required. The auditor especially: a
// Service without one would look wired up and would register and revoke devices
// leaving no trace, which is worse than not starting.
func New(devices repository.DeviceRepository, auditor Auditor, opts ...Option) (*Service, error) {
	if devices == nil {
		return nil, fmt.Errorf("%w: device repository", ErrMissingDependency)
	}
	if auditor == nil {
		return nil, fmt.Errorf("%w: auditor", ErrMissingDependency)
	}
	s := &Service{devices: devices, auditor: auditor, now: time.Now, newID: newDeviceID}
	for i, opt := range opts {
		// A nil option is rejected rather than skipped, matching audit.NewEmitter:
		// skipping it would leave a Service that looks configured and is not.
		if opt == nil {
			return nil, fmt.Errorf("%w: nil option at index %d", ErrMissingDependency, i)
		}
		opt(s)
	}
	return s, nil
}

// newDeviceID returns a fresh, unguessable device ID. crypto/rand.Text yields
// 26 base32 characters (~130 bits), matching the identifier convention used for
// audit records and request IDs. Unguessability is load-bearing here rather than
// cosmetic: device IDs are the addressing scheme of the management API, and a
// sequential id would make the cross-owner 404 above pointless — an attacker
// would not need to guess.
func newDeviceID() string {
	return rand.Text()
}

// Register creates a device owned by ownerID.
//
// requestID correlates the audit record with the request log; it may be empty,
// in which case no correlation detail is recorded.
//
// The name is validated before anything is written, and a rejected name is
// returned as domain.ErrInvalidInput rather than collapsed into ErrNotFound:
// the caller is an authenticated owner creating its own resource, so there is
// no namespace to probe and no existence to leak — the input is simply wrong
// and saying so is what lets a client fix it.
func (s *Service) Register(ctx context.Context, ownerID domain.OwnerID, name, requestID string) (*domain.Device, error) {
	if ownerID == "" {
		// An empty owner would produce a device belonging to nobody, reachable
		// by any other request that also failed to carry an owner. The
		// repository refuses it too; refusing here means the write is never
		// attempted.
		return nil, fmt.Errorf("device: missing owner: %w", domain.ErrInvalidInput)
	}
	if err := domain.ValidateDeviceName(name); err != nil {
		return nil, err
	}

	// The audit details are built BEFORE the write, not after it.
	//
	// audit.Details screens every value for credential shapes, and that screen is
	// broader than domain.ValidateDeviceName: a name like "my basic laptop"
	// contains a credential marker ("basic ") while being a perfectly valid
	// device name. Emitting after Create would mean such a name commits the
	// device, then fails the audit, and returns an error to a caller whose device
	// nevertheless exists and is unrecorded -- the exact state the "audit is not
	// optional" rule exists to prevent. Building the details first turns that into
	// a plain rejection with nothing written.
	//
	// It is reported as ErrInvalidInput because it is a property of the name the
	// caller just sent, and one the caller can fix by choosing another.
	details, err := registerDetails(name, requestID)
	if err != nil {
		return nil, err
	}

	now := s.now().UTC()
	d := &domain.Device{
		ID:        domain.DeviceID(s.newID()),
		OwnerID:   ownerID,
		Name:      name,
		Status:    domain.DeviceStatusActive,
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := s.devices.Create(ctx, d); err != nil {
		return nil, err
	}

	if err := s.emit(ctx, domain.AuditActionDeviceRegistered, ownerID, d, details); err != nil {
		return nil, err
	}
	return d, nil
}

// registerDetails builds the audit details for a registration, or reports why
// the name cannot be recorded. See Register for why this runs before the write.
func registerDetails(name, requestID string) (audit.Details, error) {
	d := audit.Details{}.Set(audit.DetailDeviceName, name)
	if requestID != "" {
		d = d.Set(audit.DetailRequestID, requestID)
	}
	if err := d.Err(); err != nil {
		return audit.Details{}, fmt.Errorf("device: name cannot be recorded: %w", domain.ErrInvalidInput)
	}
	return d, nil
}

// List returns the owner's devices, including revoked ones.
//
// Revoked devices are included because this is the owner's own inventory and
// hiding them would make a revoked device indistinguishable from one that was
// never registered — for the owner, who is entitled to the difference. The
// cross-owner collapse in the package doc is about what a DIFFERENT owner can
// observe, and no other owner's device can appear here at all: the repository
// filters by ownerID.
func (s *Service) List(ctx context.Context, ownerID domain.OwnerID) ([]domain.Device, error) {
	if ownerID == "" {
		return nil, fmt.Errorf("device: missing owner: %w", domain.ErrInvalidInput)
	}
	return s.devices.ListByOwner(ctx, ownerID)
}

// Revoke marks the owner's device revoked.
//
// It returns ErrNotFound for an unknown id, another owner's id, AND a device
// that is already revoked — one answer for all three, per the package doc.
//
// Repeating a revoke is therefore safe: the second call changes nothing and
// reports the same 404 a stranger's id reports. That is the sense in which this
// is idempotent-safe. It deliberately is not the REST convention of answering
// the repeat with success, because doing so would make a device's lifecycle
// state observable as a third answer, distinct from absent — which is exactly
// the oracle the collapse exists to close.
//
// The read-then-write is not atomic, and does not need to be: two concurrent
// revokes of the same active device may both observe it active and both
// succeed, which converges on the identical end state and leaks nothing. There
// is no interleaving that revokes a device for the wrong owner, because the
// ownerID passed to Revoke is the same one Get filtered on.
func (s *Service) Revoke(ctx context.Context, ownerID domain.OwnerID, id domain.DeviceID, requestID string) error {
	if ownerID == "" {
		return fmt.Errorf("device: missing owner: %w", domain.ErrInvalidInput)
	}
	if id == "" {
		// An empty id names no device. It collapses into the same verdict as a
		// wrong one so that a caller cannot learn which shapes are well formed.
		return ErrNotFound
	}

	d, err := s.devices.Get(ctx, ownerID, id)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return ErrNotFound
		}
		return err
	}
	if d.Status == domain.DeviceStatusRevoked {
		return ErrNotFound
	}

	// As in Register, the audit details are built before the write so a name the
	// audit screen refuses cannot produce a revoked-but-unrecorded device. Unlike
	// Register the name is not this caller's input -- it was stored earlier -- so
	// this is not reported as ErrInvalidInput: the caller did nothing wrong and
	// cannot fix it, which makes it a server fault (500) rather than a bad
	// request. Post-fix such a name cannot be stored, so this is a guard against
	// rows written before that rule existed, not an expected path.
	details, err := registerDetails(d.Name, requestID)
	if err != nil {
		return fmt.Errorf("device: stored name cannot be recorded for %s", id)
	}

	if err := s.devices.Revoke(ctx, ownerID, id, s.now().UTC()); err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return ErrNotFound
		}
		return err
	}
	return s.emit(ctx, domain.AuditActionDeviceRevoked, ownerID, d, details)
}

// emit records an access-affecting device change.
//
// The device NAME is recorded, deliberately: audit.DetailDeviceName is on the
// allowlist precisely because an opaque ID is unreadable in an incident review.
// That is a different decision from what the request LOG may carry — an audit
// record is an access-controlled, retention-governed artifact, whereas the
// request log is not, which is why nothing in this package logs the name.
// The details are built by the caller, before its write, so that a name the
// audit screen refuses cannot leave a committed change unrecorded.
func (s *Service) emit(ctx context.Context, action domain.AuditAction, ownerID domain.OwnerID, d *domain.Device, details audit.Details) error {
	return s.auditor.Emit(ctx, audit.Event{
		ActorType:  domain.ActorTypeOwner,
		ActorID:    string(ownerID),
		Action:     action,
		TargetType: domain.TargetTypeDevice,
		TargetID:   string(d.ID),
		Details:    details,
	})
}
