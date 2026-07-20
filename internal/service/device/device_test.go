package device_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/audit"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/service/device"
)

func TestNewRequiresCollaborators(t *testing.T) {
	t.Parallel()

	if _, err := device.New(nil, &fakeAuditor{}); !errors.Is(err, device.ErrMissingDependency) {
		t.Errorf("nil repository: err = %v, want ErrMissingDependency", err)
	}
	// A Service with no auditor would register and revoke devices leaving no
	// trace, which is the one failure the audit log exists to prevent.
	if _, err := device.New(newFakeRepo(), nil); !errors.Is(err, device.ErrMissingDependency) {
		t.Errorf("nil auditor: err = %v, want ErrMissingDependency", err)
	}
	if _, err := device.New(newFakeRepo(), &fakeAuditor{}, nil); !errors.Is(err, device.ErrMissingDependency) {
		t.Errorf("nil option: err = %v, want ErrMissingDependency", err)
	}
}

func TestRegisterStampsOwnerFromArgument(t *testing.T) {
	t.Parallel()

	repo, auditor, svc := newService(t)
	d, err := svc.Register(t.Context(), "owner-a", "laptop", "req-1")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	if d.OwnerID != "owner-a" {
		t.Errorf("OwnerID = %q, want owner-a", d.OwnerID)
	}
	if d.Status != domain.DeviceStatusActive {
		t.Errorf("Status = %q, want active", d.Status)
	}
	if d.ID == "" {
		t.Error("ID is empty; a device must get an unguessable identifier")
	}
	// The stored row must carry the same owner the caller passed. A service
	// that returned the right owner but persisted another would pass a check
	// on the return value alone.
	stored, ok := repo.devices[d.ID]
	if !ok {
		t.Fatalf("device %q was not persisted", d.ID)
	}
	if stored.OwnerID != "owner-a" {
		t.Errorf("persisted OwnerID = %q, want owner-a", stored.OwnerID)
	}

	assertEvent(t, auditor, domain.AuditActionDeviceRegistered, "owner-a", string(d.ID))
}

func TestRegisterIDsAreUnguessableAndDistinct(t *testing.T) {
	t.Parallel()

	_, _, svc := newService(t)
	seen := map[domain.DeviceID]bool{}
	for range 32 {
		d, err := svc.Register(t.Context(), "owner-a", "laptop", "")
		if err != nil {
			t.Fatalf("Register: %v", err)
		}
		if seen[d.ID] {
			t.Fatalf("device id %q reissued; ids must not repeat", d.ID)
		}
		if len(d.ID) < 20 {
			t.Fatalf("device id %q is only %d chars; too short to resist guessing", d.ID, len(d.ID))
		}
		seen[d.ID] = true
	}
}

func TestRegisterRejectsBadInput(t *testing.T) {
	t.Parallel()

	repo, _, svc := newService(t)
	tests := map[string]struct {
		owner domain.OwnerID
		name  string
	}{
		"empty owner":       {owner: "", name: "laptop"},
		"empty name":        {owner: "owner-a", name: ""},
		"control character": {owner: "owner-a", name: "lap\ntop"},
		"leading space":     {owner: "owner-a", name: " laptop"},
		"over length":       {owner: "owner-a", name: longName()},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			if _, err := svc.Register(t.Context(), tc.owner, tc.name, ""); !errors.Is(err, domain.ErrInvalidInput) {
				t.Fatalf("err = %v, want ErrInvalidInput", err)
			}
		})
	}
	// Nothing may be written for a rejected registration.
	if len(repo.devices) != 0 {
		t.Errorf("%d devices persisted despite every registration being rejected", len(repo.devices))
	}
}

func TestRegisterFailsWhenAuditFails(t *testing.T) {
	t.Parallel()

	repo := newFakeRepo()
	auditor := &fakeAuditor{err: errors.New("sink down")}
	svc := mustService(t, repo, auditor)

	// An access-affecting change that recorded nothing must be reported as a
	// failure, not returned as a success with a missing trail.
	if _, err := svc.Register(t.Context(), "owner-a", "laptop", ""); err == nil {
		t.Fatal("Register succeeded although the audit sink failed")
	}
}

func TestRegisterPropagatesRepositoryFailure(t *testing.T) {
	t.Parallel()

	repo := newFakeRepo()
	repo.err = errors.New("datastore down")
	auditor := &fakeAuditor{}
	svc := mustService(t, repo, auditor)

	if _, err := svc.Register(t.Context(), "owner-a", "laptop", ""); err == nil {
		t.Fatal("Register succeeded although the repository failed")
	}
	if len(auditor.events) != 0 {
		t.Error("an audit record was emitted for a registration that never happened")
	}
}

func TestListIsOwnerScoped(t *testing.T) {
	t.Parallel()

	_, _, svc := newService(t)
	mine, err := svc.Register(t.Context(), "owner-a", "mine", "")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if _, err := svc.Register(t.Context(), "owner-b", "theirs", ""); err != nil {
		t.Fatalf("Register: %v", err)
	}

	got, err := svc.List(t.Context(), "owner-a")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 1 || got[0].ID != mine.ID {
		t.Fatalf("List returned %d devices %v, want only owner-a's %q", len(got), got, mine.ID)
	}
}

func TestListRejectsEmptyOwner(t *testing.T) {
	t.Parallel()

	_, _, svc := newService(t)
	if _, err := svc.List(t.Context(), ""); !errors.Is(err, domain.ErrInvalidInput) {
		t.Fatalf("err = %v, want ErrInvalidInput", err)
	}
}

func TestListIncludesRevokedDevices(t *testing.T) {
	t.Parallel()

	_, _, svc := newService(t)
	d, err := svc.Register(t.Context(), "owner-a", "laptop", "")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := svc.Revoke(t.Context(), "owner-a", d.ID, ""); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	got, err := svc.List(t.Context(), "owner-a")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	// The owner is entitled to see its own revoked devices; the collapse to
	// ErrNotFound is about what a DIFFERENT owner can observe.
	if len(got) != 1 || got[0].Status != domain.DeviceStatusRevoked {
		t.Fatalf("List = %v, want one revoked device", got)
	}
}

func TestRevokeMarksTheDeviceAndAudits(t *testing.T) {
	t.Parallel()

	repo, auditor, svc := newService(t)
	d, err := svc.Register(t.Context(), "owner-a", "laptop", "")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	auditor.reset()

	if err := svc.Revoke(t.Context(), "owner-a", d.ID, "req-2"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if got := repo.devices[d.ID].Status; got != domain.DeviceStatusRevoked {
		t.Errorf("status = %q, want revoked", got)
	}
	if repo.devices[d.ID].RevokedAt == nil {
		t.Error("RevokedAt was not stamped")
	}
	assertEvent(t, auditor, domain.AuditActionDeviceRevoked, "owner-a", string(d.ID))
}

// TestRevokeCollapsesEveryNegativeVerdict is the oracle test. The three reasons
// a revoke cannot proceed must be one error, byte for byte, or the difference
// between them is an enumeration oracle over the device namespace.
func TestRevokeCollapsesEveryNegativeVerdict(t *testing.T) {
	t.Parallel()

	_, _, svc := newService(t)
	ownersDevice, err := svc.Register(t.Context(), "owner-a", "mine", "")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := svc.Revoke(t.Context(), "owner-a", ownersDevice.ID, ""); err != nil {
		t.Fatalf("first Revoke: %v", err)
	}
	otherOwners, err := svc.Register(t.Context(), "owner-b", "theirs", "")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	cases := map[string]domain.DeviceID{
		"already revoked":       ownersDevice.ID,
		"another owner's":       otherOwners.ID,
		"never existed":         "ZZZZZZZZZZZZZZZZZZZZZZZZZZ",
		"empty identifier":      "",
		"syntactically bizarre": "../../etc/passwd",
	}
	for name, id := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			err := svc.Revoke(t.Context(), "owner-a", id, "")
			if !errors.Is(err, device.ErrNotFound) {
				t.Fatalf("err = %v, want ErrNotFound", err)
			}
			// Same sentinel is not enough: the message is what a transport
			// could accidentally surface, so it must not vary either.
			if got, want := err.Error(), device.ErrNotFound.Error(); got != want {
				t.Fatalf("error text = %q, want %q; a differing message is the oracle", got, want)
			}
		})
	}
}

func TestRevokeDoesNotTouchAnotherOwnersDevice(t *testing.T) {
	t.Parallel()

	repo, auditor, svc := newService(t)
	victim, err := svc.Register(t.Context(), "owner-a", "victim", "")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	auditor.reset()

	if err := svc.Revoke(t.Context(), "owner-b", victim.ID, ""); !errors.Is(err, device.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
	if got := repo.devices[victim.ID].Status; got != domain.DeviceStatusActive {
		t.Errorf("owner-a's device status = %q after owner-b's revoke; want untouched active", got)
	}
	if len(auditor.events) != 0 {
		t.Errorf("a refused cross-owner revoke emitted %d audit events, want 0", len(auditor.events))
	}
}

func TestRevokeRejectsEmptyOwner(t *testing.T) {
	t.Parallel()

	_, _, svc := newService(t)
	if err := svc.Revoke(t.Context(), "", "anything", ""); !errors.Is(err, domain.ErrInvalidInput) {
		t.Fatalf("err = %v, want ErrInvalidInput", err)
	}
}

func TestRevokeFailsWhenAuditFails(t *testing.T) {
	t.Parallel()

	repo := newFakeRepo()
	auditor := &fakeAuditor{}
	svc := mustService(t, repo, auditor)
	d, err := svc.Register(t.Context(), "owner-a", "laptop", "")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	auditor.err = errors.New("sink down")
	if err := svc.Revoke(t.Context(), "owner-a", d.ID, ""); err == nil {
		t.Fatal("Revoke succeeded although the audit sink failed")
	}
}

func TestRevokePropagatesNonNotFoundRepositoryFailure(t *testing.T) {
	t.Parallel()

	repo := newFakeRepo()
	auditor := &fakeAuditor{}
	svc := mustService(t, repo, auditor)
	d, err := svc.Register(t.Context(), "owner-a", "laptop", "")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	repo.err = errors.New("datastore down")
	err = svc.Revoke(t.Context(), "owner-a", d.ID, "")
	// A storage outage must not masquerade as "not found": that would hide an
	// incident behind an answer meaning the device is gone.
	if err == nil || errors.Is(err, device.ErrNotFound) {
		t.Fatalf("err = %v, want a non-ErrNotFound failure", err)
	}
}

func TestAuditRecordsNameAndRequestID(t *testing.T) {
	t.Parallel()

	_, auditor, svc := newService(t)
	if _, err := svc.Register(t.Context(), "owner-a", "laptop", "req-9"); err != nil {
		t.Fatalf("Register: %v", err)
	}

	// Details.Set records the first rejection rather than panicking, so an
	// off-allowlist key or a value that tripped the credential screen shows up
	// here as a retained error. A clean Err() is the proof that the keys this
	// service uses are ones the audit package actually accepts.
	if err := auditor.events[0].Details.Err(); err != nil {
		t.Fatalf("audit rejected the details this service records: %v", err)
	}

	// And the emitter must accept the whole event end to end, which is the
	// check that would fail if the service ever recorded an unallowlisted key.
	emitter, err := audit.NewEmitter(appenderFunc(func(context.Context, *domain.AuditRecord) error { return nil }))
	if err != nil {
		t.Fatalf("audit.NewEmitter: %v", err)
	}
	if err := emitter.Emit(t.Context(), auditor.events[0]); err != nil {
		t.Fatalf("real emitter refused the event: %v", err)
	}
}

// appenderFunc adapts a function to repository.AuditAppender.
type appenderFunc func(context.Context, *domain.AuditRecord) error

func (f appenderFunc) Append(ctx context.Context, rec *domain.AuditRecord) error { return f(ctx, rec) }

// --- helpers ---

func newService(t *testing.T) (*fakeRepo, *fakeAuditor, *device.Service) {
	t.Helper()

	repo := newFakeRepo()
	auditor := &fakeAuditor{}
	return repo, auditor, mustService(t, repo, auditor)
}

func mustService(t *testing.T, repo *fakeRepo, auditor device.Auditor) *device.Service {
	t.Helper()

	svc, err := device.New(repo, auditor, device.WithClock(func() time.Time {
		return time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	}))
	if err != nil {
		t.Fatalf("device.New: %v", err)
	}
	return svc
}

func assertEvent(t *testing.T, a *fakeAuditor, action domain.AuditAction, actor, target string) {
	t.Helper()

	if len(a.events) != 1 {
		t.Fatalf("emitted %d audit events, want 1", len(a.events))
	}
	ev := a.events[0]
	switch {
	case ev.Action != action:
		t.Errorf("action = %q, want %q", ev.Action, action)
	case ev.ActorType != domain.ActorTypeOwner:
		t.Errorf("actor type = %q, want owner", ev.ActorType)
	case ev.ActorID != actor:
		t.Errorf("actor id = %q, want %q", ev.ActorID, actor)
	case ev.TargetType != domain.TargetTypeDevice:
		t.Errorf("target type = %q, want device", ev.TargetType)
	case ev.TargetID != target:
		t.Errorf("target id = %q, want %q", ev.TargetID, target)
	}
}

func longName() string {
	b := make([]byte, 65)
	for i := range b {
		b[i] = 'a'
	}
	return string(b)
}

// fakeRepo is an in-memory DeviceRepository that enforces the owner scoping the
// real adapters promise, so a service that dropped the owner filter fails here
// rather than only against SQLite.
type fakeRepo struct {
	devices map[domain.DeviceID]*domain.Device
	err     error
}

func newFakeRepo() *fakeRepo {
	return &fakeRepo{devices: map[domain.DeviceID]*domain.Device{}}
}

func (r *fakeRepo) Create(_ context.Context, d *domain.Device) error {
	if r.err != nil {
		return r.err
	}
	clone := *d
	r.devices[d.ID] = &clone
	return nil
}

func (r *fakeRepo) Get(_ context.Context, ownerID domain.OwnerID, id domain.DeviceID) (*domain.Device, error) {
	if r.err != nil {
		return nil, r.err
	}
	d, ok := r.devices[id]
	if !ok || d.OwnerID != ownerID {
		return nil, domain.ErrNotFound
	}
	clone := *d
	return &clone, nil
}

func (r *fakeRepo) ListByOwner(_ context.Context, ownerID domain.OwnerID) ([]domain.Device, error) {
	if r.err != nil {
		return nil, r.err
	}
	var out []domain.Device
	for _, d := range r.devices {
		if d.OwnerID == ownerID {
			out = append(out, *d)
		}
	}
	return out, nil
}

func (r *fakeRepo) Rename(_ context.Context, ownerID domain.OwnerID, id domain.DeviceID, name string, now time.Time) error {
	if r.err != nil {
		return r.err
	}
	d, ok := r.devices[id]
	if !ok || d.OwnerID != ownerID {
		return domain.ErrNotFound
	}
	d.Name, d.UpdatedAt = name, now
	return nil
}

func (r *fakeRepo) Revoke(_ context.Context, ownerID domain.OwnerID, id domain.DeviceID, now time.Time) error {
	if r.err != nil {
		return r.err
	}
	d, ok := r.devices[id]
	if !ok || d.OwnerID != ownerID {
		return domain.ErrNotFound
	}
	// Deliberately mirrors the SQLite adapter, which does NOT filter on
	// revoked_at: a repeat revoke succeeds at the port. The collapse to
	// ErrNotFound is the service's decision, and this fake must not do it for
	// the service or the test would be asserting its own helper.
	d.Status, d.UpdatedAt, d.RevokedAt = domain.DeviceStatusRevoked, now, &now
	return nil
}

// fakeAuditor records emitted events and can be made to fail.
type fakeAuditor struct {
	events []audit.Event
	err    error
}

func (a *fakeAuditor) Emit(_ context.Context, ev audit.Event) error {
	if a.err != nil {
		return a.err
	}
	a.events = append(a.events, ev)
	return nil
}

func (a *fakeAuditor) reset() { a.events = nil }
