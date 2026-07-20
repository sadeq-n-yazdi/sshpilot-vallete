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

// screeningAuditor is the auditor these tests use: it records the event for
// inspection AND runs it through the real audit.Emitter, so the emitter's
// credential screen is in the path. Recording without screening (the plain
// fakeAuditor) is what let the write-then-fail defect look like a passing test.
type screeningAuditor struct {
	recorder *fakeAuditor
	emitter  *audit.Emitter
}

func (a screeningAuditor) Emit(ctx context.Context, ev audit.Event) error {
	if err := a.emitter.Emit(ctx, ev); err != nil {
		return err
	}
	return a.recorder.Emit(ctx, ev)
}

func realEmitter(t *testing.T) *audit.Emitter {
	t.Helper()

	e, err := audit.NewEmitter(appenderFunc(func(context.Context, *domain.AuditRecord) error { return nil }))
	if err != nil {
		t.Fatalf("audit.NewEmitter: %v", err)
	}
	return e
}

// auditUnsafeName is a device name that domain.ValidateDeviceName accepts and
// audit.Details refuses.
//
// The audit screen looks for credential markers, and "basic " is one of them --
// it is how a Basic authorization header begins. A person naming a machine "my
// basic laptop" trips it while doing nothing wrong. This constant exists so the
// gap between the two validators is exercised by name rather than discovered in
// production.
const auditUnsafeName = "my basic laptop"

// TestRegisterNeverCommitsADeviceItCannotAudit is the regression test for a real
// defect: the audit details used to be built AFTER devices.Create, so a name in
// the gap above committed the device, failed the audit, and returned an error to
// a caller whose device nevertheless existed with no audit record. That is the
// precise state the "audit is not optional" rule exists to forbid, and the
// caller could not tell it had happened.
//
// The assertion that matters is the second one. A test that only checked the
// error would have passed against the buggy code, because the buggy code also
// returned an error -- it just left a device behind first.
//
// The service is built with the REAL audit.Emitter, not the recording fake. The
// fake accepts any details, so against it the buggy ordering looked harmless --
// which is how the defect survived the original suite. Only the real emitter
// applies the screen that makes the write-then-fail sequence observable.
func TestRegisterNeverCommitsADeviceItCannotAudit(t *testing.T) {
	t.Parallel()

	repo := newFakeRepo()
	auditor := &fakeAuditor{}
	svc := mustService(t, repo, screeningAuditor{recorder: auditor, emitter: realEmitter(t)})

	d, err := svc.Register(context.Background(), "owner-a", auditUnsafeName, "req-1")
	if !errors.Is(err, domain.ErrInvalidInput) {
		t.Fatalf("Register(unauditable name) error = %v, want ErrInvalidInput", err)
	}
	if d != nil {
		t.Errorf("Register returned a device alongside its error: %+v", d)
	}
	// The whole point: nothing was written.
	if len(repo.devices) != 0 {
		t.Errorf("Register persisted %d devices despite failing; want 0 -- an unaudited device is the state this forbids", len(repo.devices))
	}
	if len(auditor.events) != 0 {
		t.Errorf("emitted %d audit events, want 0", len(auditor.events))
	}
}

// TestRegisterSucceedsForANameTheAuditScreenAccepts is the control for the test
// above: it pins that the fix rejects only the unauditable name and has not
// quietly broken ordinary registration.
func TestRegisterSucceedsForANameTheAuditScreenAccepts(t *testing.T) {
	t.Parallel()

	repo := newFakeRepo()
	auditor := &fakeAuditor{}
	svc := mustService(t, repo, screeningAuditor{recorder: auditor, emitter: realEmitter(t)})

	if _, err := svc.Register(context.Background(), "owner-a", "my laptop", "req-1"); err != nil {
		t.Fatalf("Register(ordinary name) = %v, want nil", err)
	}
	if len(repo.devices) != 1 {
		t.Errorf("persisted %d devices, want 1", len(repo.devices))
	}
	if len(auditor.events) != 1 {
		t.Errorf("emitted %d audit events, want 1", len(auditor.events))
	}
}

// TestRevokeNeverRevokesADeviceItCannotAudit covers the same ordering on the
// revoke path. The name here was stored before the Register-side check existed,
// which this test simulates by writing it straight into the repository.
//
// It must NOT be ErrInvalidInput: the caller supplied only an id, so blaming its
// request would be wrong, and it must not be ErrNotFound either -- collapsing a
// server fault into the not-found verdict would tell the owner its own device is
// gone when it is not.
func TestRevokeNeverRevokesADeviceItCannotAudit(t *testing.T) {
	t.Parallel()

	repo := newFakeRepo()
	auditor := &fakeAuditor{}
	svc := mustService(t, repo, screeningAuditor{recorder: auditor, emitter: realEmitter(t)})
	stored := &domain.Device{
		ID:      "dev-1",
		OwnerID: "owner-a",
		Name:    auditUnsafeName,
		Status:  domain.DeviceStatusActive,
	}
	repo.devices[stored.ID] = stored

	err := svc.Revoke(context.Background(), "owner-a", "dev-1", "req-1")
	if err == nil {
		t.Fatal("Revoke(unauditable stored name) = nil, want an error")
	}
	if errors.Is(err, device.ErrNotFound) {
		t.Error("Revoke returned ErrNotFound; a server fault must not read as 'your device does not exist'")
	}
	if errors.Is(err, domain.ErrInvalidInput) {
		t.Error("Revoke returned ErrInvalidInput; the caller sent only an id and cannot fix a stored name")
	}
	if repo.devices["dev-1"].Status != domain.DeviceStatusActive {
		t.Error("device was revoked despite the audit failing; the write must not outlive its record")
	}
	if len(auditor.events) != 0 {
		t.Errorf("emitted %d audit events, want 0", len(auditor.events))
	}
}

// TestRevokeSurfacesRepositoryFailuresAsThemselves pins that a storage fault is
// not laundered into the not-found verdict. The collapse exists to hide the
// difference between owners, not to hide a broken database: reporting "no such
// device" when the truth is "the query failed" would tell an owner its device
// was gone and leave the operator with no signal at all.
func TestRevokeSurfacesRepositoryFailuresAsThemselves(t *testing.T) {
	t.Parallel()

	repo, _, svc := newService(t)
	boom := errors.New("storage unavailable")
	repo.err = boom

	err := svc.Revoke(context.Background(), "owner-a", "dev-1", "req-1")
	if !errors.Is(err, boom) {
		t.Fatalf("Revoke with a failing repository = %v, want the storage error", err)
	}
	if errors.Is(err, device.ErrNotFound) {
		t.Error("a storage failure was reported as ErrNotFound")
	}
}

// revokeFailingRepo succeeds on Get and fails on Revoke, which is the shape of
// the read-then-write window: the device was there when it was read and is not
// revocable when the write lands.
type revokeFailingRepo struct {
	*fakeRepo
	revokeErr error
}

func (r revokeFailingRepo) Revoke(context.Context, domain.OwnerID, domain.DeviceID, time.Time) error {
	return r.revokeErr
}

// TestRevokeHandlesTheWriteFailingAfterTheReadSucceeded covers both arms of the
// window between Get and Revoke.
//
// The ErrNotFound arm is the interesting one: it is what happens when the device
// is removed concurrently, and it must collapse into the same verdict every
// other "you cannot act on this" answer uses. If it leaked through as a distinct
// error the transport would answer 500, and a caller could tell a concurrent
// deletion apart from a device that was never theirs -- reintroducing the oracle
// through a timing window rather than through a status code.
func TestRevokeHandlesTheWriteFailingAfterTheReadSucceeded(t *testing.T) {
	t.Parallel()

	other := errors.New("storage unavailable")
	for _, tc := range []struct {
		name    string
		fail    error
		wantIs  error
		wantNot error
	}{
		{"vanished between read and write", domain.ErrNotFound, device.ErrNotFound, nil},
		{"storage fault", other, other, device.ErrNotFound},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			base := newFakeRepo()
			base.devices["dev-1"] = &domain.Device{
				ID: "dev-1", OwnerID: "owner-a", Name: "laptop", Status: domain.DeviceStatusActive,
			}
			repo := revokeFailingRepo{fakeRepo: base, revokeErr: tc.fail}
			svc, err := device.New(repo, &fakeAuditor{})
			if err != nil {
				t.Fatalf("device.New: %v", err)
			}

			gotErr := svc.Revoke(context.Background(), "owner-a", "dev-1", "req-1")
			if !errors.Is(gotErr, tc.wantIs) {
				t.Fatalf("Revoke = %v, want an error matching %v", gotErr, tc.wantIs)
			}
			if tc.wantNot != nil && errors.Is(gotErr, tc.wantNot) {
				t.Errorf("Revoke = %v, must not match %v", gotErr, tc.wantNot)
			}
		})
	}
}
