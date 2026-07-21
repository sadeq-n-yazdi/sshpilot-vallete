package accesskey

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
)

// graceDeadline is the rotation deadline these tests place a credential under.
var graceDeadline = fixedNow.Add(time.Hour)

// rotate moves a minted credential into the grace state with the shared
// deadline, through the repository — the service has no Rotate yet, and the
// sweep's subject is a row in that state however it got there.
func (f *fixture) rotate(ownerID domain.OwnerID, id domain.AccessKeyID) {
	f.t.Helper()

	if err := f.store.Repos().AccessKeys.MarkRotated(context.Background(), ownerID, id, "replacement", graceDeadline); err != nil {
		f.t.Fatalf("MarkRotated: %v", err)
	}
}

// status reads a credential's stored lifecycle state.
func (f *fixture) status(ownerID domain.OwnerID, id domain.AccessKeyID) domain.AccessKeyStatus {
	f.t.Helper()

	k, err := f.store.Repos().AccessKeys.Get(context.Background(), ownerID, id)
	if err != nil {
		f.t.Fatalf("Get(%q): %v", id, err)
	}
	if k == nil {
		f.t.Fatalf("Get(%q) returned no row and no error", id)
	}
	return k.Status
}

// TestPastGraceIsRefusedWithoutTheSweep is the fail-closed property, and the
// most important test in this file.
//
// The sweep NEVER RUNS here. A credential whose grace window closed an hour ago
// is presented on the real verification path and must be refused anyway,
// because Verify compares the deadline against the clock at time of use. If
// this ever fails, the deadline has become something only a background job
// enforces — and a delayed or disabled job would then be a live authentication
// window for a credential its owner believes they retired.
func TestPastGraceIsRefusedWithoutTheSweep(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	owner := f.seedOwner("alice")
	k, token := f.mint(owner.OwnerID, owner.KeySetID, "ci")
	f.rotate(owner.OwnerID, k.ID)

	f.now = graceDeadline.Add(time.Hour)

	_, err := f.svc.Verify(context.Background(), owner.OwnerID, owner.KeySetID, token)
	denied(t, "Verify past the grace deadline with no sweep having run", err)

	// And the row is untouched, which is what makes the refusal above a
	// statement about Verify rather than about some other code having already
	// cleaned up behind it.
	if got := f.status(owner.OwnerID, k.ID); got != domain.AccessKeyStatusGrace {
		t.Fatalf("status = %q, want %q; the row must still be in grace for this test to mean anything",
			got, domain.AccessKeyStatusGrace)
	}
}

// TestWithinGraceIsAccepted is the other side of the same boundary: the sweep
// must not be able to claim credit for a refusal that should not happen at all.
func TestWithinGraceIsAccepted(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	owner := f.seedOwner("alice")
	k, token := f.mint(owner.OwnerID, owner.KeySetID, "ci")
	f.rotate(owner.OwnerID, k.ID)

	f.now = graceDeadline.Add(-time.Minute)

	if _, err := f.svc.Verify(context.Background(), owner.OwnerID, owner.KeySetID, token); err != nil {
		t.Fatalf("Verify inside the grace window: %v, want acceptance", err)
	}

	// A pass before the deadline must leave it alone. Retiring a credential
	// inside the window the owner was promised is the one way this sweep could
	// break a working deployment.
	retired, err := f.svc.ExpireGrace(context.Background(), 10)
	if err != nil {
		t.Fatalf("ExpireGrace: %v", err)
	}
	if retired != 0 {
		t.Errorf("ExpireGrace retired %d credentials inside the grace window, want 0", retired)
	}
	if _, err := f.svc.Verify(context.Background(), owner.OwnerID, owner.KeySetID, token); err != nil {
		t.Fatalf("Verify after a sweep pass inside the window: %v, want acceptance", err)
	}
}

// TestExpireGraceRetiresThePastGraceRow pins what the sweep is actually for:
// the stored state stops claiming a window that has closed. The credential was
// already refused before this ran (see the test above); what changes is that
// the row now says so.
func TestExpireGraceRetiresThePastGraceRow(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	owner := f.seedOwner("alice")
	k, token := f.mint(owner.OwnerID, owner.KeySetID, "ci")
	f.rotate(owner.OwnerID, k.ID)

	f.now = graceDeadline.Add(time.Nanosecond)

	retired, err := f.svc.ExpireGrace(context.Background(), 10)
	if err != nil {
		t.Fatalf("ExpireGrace: %v", err)
	}
	if retired != 1 {
		t.Fatalf("ExpireGrace retired %d, want 1", retired)
	}

	// Revoked, not deleted. The row survives so the audit trail's target id
	// still resolves to a credential.
	if got := f.status(owner.OwnerID, k.ID); got != domain.AccessKeyStatusRevoked {
		t.Errorf("status after the sweep = %q, want %q", got, domain.AccessKeyStatusRevoked)
	}
	// And it stays refused, now for the terminal reason rather than the clock.
	_, err = f.svc.Verify(context.Background(), owner.OwnerID, owner.KeySetID, token)
	denied(t, "Verify after the sweep retired the credential", err)
}

// TestExpireGraceRecordsASystemActor pins the accountability shape. The action
// is the existing revocation action, because that is what happened to the
// credential; the actor is the system with no id, because no owner asked for
// it. Recording it under the owner would put a change in the trail beneath a
// principal who did not make it.
func TestExpireGraceRecordsASystemActor(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	owner := f.seedOwner("alice")
	k, _ := f.mint(owner.OwnerID, owner.KeySetID, "ci")
	f.rotate(owner.OwnerID, k.ID)

	f.now = graceDeadline.Add(time.Hour)
	f.audit.events = nil

	if _, err := f.svc.ExpireGrace(context.Background(), 10); err != nil {
		t.Fatalf("ExpireGrace: %v", err)
	}

	if len(f.audit.events) != 1 {
		t.Fatalf("emitted %d audit events, want exactly 1", len(f.audit.events))
	}
	ev := f.audit.events[0]
	if ev.ActorType != domain.ActorTypeSystem {
		t.Errorf("actor type = %q, want %q", ev.ActorType, domain.ActorTypeSystem)
	}
	if ev.ActorID != "" {
		t.Errorf("actor id = %q, want empty: no principal performed this", ev.ActorID)
	}
	if ev.Action != domain.AuditActionAccessKeyRevoked {
		t.Errorf("action = %q, want %q", ev.Action, domain.AuditActionAccessKeyRevoked)
	}
	if ev.TargetType != domain.TargetTypeAccessKey || ev.TargetID != string(k.ID) {
		t.Errorf("target = %q/%q, want %q/%q", ev.TargetType, ev.TargetID, domain.TargetTypeAccessKey, k.ID)
	}
}

// TestExpireGraceReturnsTheAuditFailure pins that a credential is never retired
// with no record of it. The emit fails, so the pass reports the failure rather
// than counting a silent retirement.
func TestExpireGraceReturnsTheAuditFailure(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	owner := f.seedOwner("alice")
	k, _ := f.mint(owner.OwnerID, owner.KeySetID, "ci")
	f.rotate(owner.OwnerID, k.ID)

	f.now = graceDeadline.Add(time.Hour)
	sentinel := errors.New("audit sink is down")
	f.audit.err = sentinel

	retired, err := f.svc.ExpireGrace(context.Background(), 10)
	if !errors.Is(err, sentinel) {
		t.Fatalf("ExpireGrace with a failing audit sink = %v, want the sink's error", err)
	}
	if retired != 0 {
		t.Errorf("ExpireGrace counted %d retirements despite the unrecorded write, want 0", retired)
	}
}

// TestExpireGraceLeavesRevokedRowsAlone pins that a credential its owner
// already revoked is not swept a second time, which is what keeps a repeated
// pass from filling the trail with revocations of one dead key.
func TestExpireGraceLeavesRevokedRowsAlone(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	owner := f.seedOwner("alice")
	k, _ := f.mint(owner.OwnerID, owner.KeySetID, "ci")
	f.rotate(owner.OwnerID, k.ID)

	if err := f.svc.Revoke(context.Background(), owner.OwnerID, k.ID, "req-1"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	f.now = graceDeadline.Add(time.Hour)
	f.audit.events = nil

	retired, err := f.svc.ExpireGrace(context.Background(), 10)
	if err != nil {
		t.Fatalf("ExpireGrace: %v", err)
	}
	if retired != 0 {
		t.Errorf("ExpireGrace retired %d already-revoked credentials, want 0", retired)
	}
	if len(f.audit.events) != 0 {
		t.Errorf("emitted %d audit events for an already-revoked credential, want 0", len(f.audit.events))
	}
}

// TestExpireGraceHonorsTheBatch pins that the caller's bound reaches the query.
// A sweep that ignored it would read every expired row in one pass the first
// time a deployment fell behind.
func TestExpireGraceHonorsTheBatch(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	owner := f.seedOwner("alice")
	for _, name := range []string{"a", "b", "c"} {
		k, _ := f.mint(owner.OwnerID, owner.KeySetID, name)
		f.rotate(owner.OwnerID, k.ID)
	}

	f.now = graceDeadline.Add(time.Hour)

	retired, err := f.svc.ExpireGrace(context.Background(), 2)
	if err != nil {
		t.Fatalf("ExpireGrace: %v", err)
	}
	if retired != 2 {
		t.Fatalf("ExpireGrace(2) retired %d, want 2", retired)
	}
	// The remainder is picked up by the next pass rather than lost.
	retired, err = f.svc.ExpireGrace(context.Background(), 2)
	if err != nil {
		t.Fatalf("ExpireGrace (second pass): %v", err)
	}
	if retired != 1 {
		t.Errorf("second pass retired %d, want the remaining 1", retired)
	}
}

// TestExpireGraceRejectsANonPositiveBatch pins that an unbounded sweep is
// refused at this boundary rather than left to whatever the repository happens
// to do with a zero — which differs between the primitives in this tree.
func TestExpireGraceRejectsANonPositiveBatch(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	for _, limit := range []int{0, -1} {
		retired, err := f.svc.ExpireGrace(context.Background(), limit)
		if !errors.Is(err, domain.ErrInvalidInput) {
			t.Errorf("ExpireGrace(%d) = %v, want ErrInvalidInput", limit, err)
		}
		if retired != 0 {
			t.Errorf("ExpireGrace(%d) retired %d, want 0", limit, retired)
		}
	}
}
