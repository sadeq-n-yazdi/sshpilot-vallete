package handle_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/audit"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/repository"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/service/handle"
)

// TestRenameQuarantinesTheOldName is the core of ADR-0026. Renaming must not
// return the old name to the pool: every server still polling
// GET /{old-name}/{set} would start trusting whoever grabbed it next.
func TestRenameQuarantinesTheOldName(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.seed(ownerA, "alice")

	got, err := f.svc.Rename(context.Background(), ownerA, "alicia", "req-1")
	if err != nil {
		t.Fatalf("Rename: %v", err)
	}
	if got.Name != "alicia" || got.State != domain.NameStateActive {
		t.Fatalf("Rename returned %+v, want active alicia", got)
	}

	old, err := f.byName("alice")
	if err != nil {
		t.Fatalf("old name should still be claimed: %v", err)
	}
	if old.State != domain.NameStateQuarantined {
		t.Errorf("old claim state = %q, want quarantined", old.State)
	}
	if old.QuarantineUntil == nil {
		t.Fatal("old claim has no quarantine deadline")
	}
	if want := fixedNow.Add(handle.DefaultQuarantineWindow); !old.QuarantineUntil.Equal(want) {
		t.Errorf("QuarantineUntil = %v, want %v", old.QuarantineUntil, want)
	}
}

// TestQuarantinedNameRefusesEveryOtherOwner is the account-takeover case
// itself: for the whole cooling-off window the vacated name must be
// unavailable to anyone else.
func TestQuarantinedNameRefusesEveryOtherOwner(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.seed(ownerA, "alice")
	f.seed(ownerB, "bob")

	if _, err := f.svc.Rename(context.Background(), ownerA, "alicia", "req-1"); err != nil {
		t.Fatalf("Rename: %v", err)
	}

	// Right up to the last instant of the hold.
	f.clock.advance(handle.DefaultQuarantineWindow - time.Second)
	_, err := f.svc.Rename(context.Background(), ownerB, "alice", "req-2")
	if !errors.Is(err, handle.ErrNameTaken) {
		t.Fatalf("second owner claiming a quarantined name = %v, want ErrNameTaken", err)
	}
	// And B's own handle must be untouched by the refused attempt.
	bob, err := f.byName("bob")
	if err != nil || bob.State != domain.NameStateActive {
		t.Fatalf("refused rename disturbed the caller's own handle: %+v %v", bob, err)
	}
}

// TestQuarantineExpiryReleasesTheName covers the other end of the window: once
// the hold elapses the sweep frees the name and a different owner may take it.
// A quarantine that never ended would be indistinguishable from a permanent
// reservation.
func TestQuarantineExpiryReleasesTheName(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newFixture(t)
	f.seed(ownerA, "alice")
	f.seed(ownerB, "bob")

	if _, err := f.svc.Rename(ctx, ownerA, "alicia", "req-1"); err != nil {
		t.Fatalf("Rename: %v", err)
	}

	// Before the deadline the sweep must free nothing.
	f.clock.advance(handle.DefaultQuarantineWindow - time.Second)
	if n, err := f.svc.ReleaseExpired(ctx, 10); err != nil || n != 0 {
		t.Fatalf("ReleaseExpired before deadline = (%d, %v), want (0, nil)", n, err)
	}
	if _, err := f.byName("alice"); err != nil {
		t.Fatalf("claim freed early: %v", err)
	}

	f.clock.advance(time.Second)
	n, err := f.svc.ReleaseExpired(ctx, 10)
	if err != nil {
		t.Fatalf("ReleaseExpired: %v", err)
	}
	if n != 1 {
		t.Fatalf("ReleaseExpired released %d, want 1", n)
	}
	if _, err := f.byName("alice"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("after release GetByName = %v, want ErrNotFound", err)
	}

	// The point of releasing: somebody else may now have it.
	if _, err := f.svc.Rename(ctx, ownerB, "alice", "req-2"); err != nil {
		t.Fatalf("claim after release: %v", err)
	}
}

// TestRenameRefusesLookAlikeOfAnotherOwner is the normalized-form half of
// ADR-0026's uniqueness rule, at the service boundary. "b0b" and "b-ob" are
// distinct valid slugs, so only the fold sees that they imitate a live handle.
func TestRenameRefusesLookAlikeOfAnotherOwner(t *testing.T) {
	t.Parallel()

	for _, lookAlike := range []string{"b0b", "b-ob"} {
		t.Run(lookAlike, func(t *testing.T) {
			t.Parallel()
			f := newFixture(t)
			f.seed(ownerA, "alice")
			f.seed(ownerB, "bob")

			_, err := f.svc.Rename(context.Background(), ownerA, lookAlike, "req-1")
			if !errors.Is(err, handle.ErrNameTaken) {
				t.Fatalf("Rename to %q while %q is live = %v, want ErrNameTaken",
					lookAlike, "bob", err)
			}
			// The refusal must be total: A must still hold its original name,
			// not be left with none.
			if _, err := f.byName("alice"); err != nil {
				t.Fatalf("refused rename left the caller without a handle: %v", err)
			}
		})
	}
}

// TestOwnerMayReclaimTheirOwnHold records the one exception to the hold. The
// quarantine protects consumers from a name changing HANDS; an owner taking
// back a name they vacated hands it to nobody, so there is no one for the hold
// to protect and refusing would be pure obstruction.
func TestOwnerMayReclaimTheirOwnHold(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newFixture(t)
	f.seed(ownerA, "alice")

	if _, err := f.svc.Rename(ctx, ownerA, "alicia", "req-1"); err != nil {
		t.Fatalf("Rename away: %v", err)
	}
	got, err := f.svc.Rename(ctx, ownerA, "alice", "req-2")
	if err != nil {
		t.Fatalf("Rename back: %v", err)
	}
	if got.Name != "alice" || got.State != domain.NameStateActive {
		t.Fatalf("reclaimed handle = %+v, want active alice", got)
	}
	if got.QuarantineUntil != nil {
		t.Errorf("reclaimed handle still carries a deadline: %v", got.QuarantineUntil)
	}

	// A reclaim is recorded as its own action: an incident review reading
	// "renamed" would miss that a name left quarantine early.
	if want := domain.AuditActionHandleReclaimed; !hasAction(f.auditor.actions(), want) {
		t.Errorf("actions = %v, want one %q", f.auditor.actions(), want)
	}
}

// TestReclaimCannotBeUsedOnAnotherOwnersHold is the abuse case the reclaim
// exception could otherwise open. If "may take a quarantined name" were checked
// without also checking WHOSE it is, the exception would delete the protection
// entirely.
func TestReclaimCannotBeUsedOnAnotherOwnersHold(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newFixture(t)
	f.seed(ownerA, "alice")
	f.seed(ownerB, "bob")

	if _, err := f.svc.Rename(ctx, ownerA, "alicia", "req-1"); err != nil {
		t.Fatalf("Rename: %v", err)
	}

	if _, err := f.svc.Rename(ctx, ownerB, "alice", "req-2"); !errors.Is(err, handle.ErrNameTaken) {
		t.Fatalf("B reclaiming A's hold = %v, want ErrNameTaken", err)
	}
	// A's hold must be intact — same owner, same state, same deadline.
	held, err := f.byName("alice")
	if err != nil {
		t.Fatalf("A's hold vanished: %v", err)
	}
	if held.OwnerID != ownerA || held.State != domain.NameStateQuarantined {
		t.Errorf("A's hold = %+v, want quarantined and owned by A", held)
	}
}

// TestRenameCyclingCannotSquatNames is the squatting abuse case. Every rename
// parks the vacated name in a hold nobody else can claim, so without a cap an
// owner could loop and accumulate reserved names for free while publishing
// under only one.
func TestRenameCyclingCannotSquatNames(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newFixture(t, handle.WithMaxHeldNames(3))
	f.seed(ownerA, "n0")

	// Two renames take the owner to three claims: one active, two held.
	for i := 1; i <= 2; i++ {
		if _, err := f.svc.Rename(ctx, ownerA, fmt.Sprintf("n%d", i), "req"); err != nil {
			t.Fatalf("Rename %d: %v", i, err)
		}
	}

	_, err := f.svc.Rename(ctx, ownerA, "n3", "req")
	if !errors.Is(err, handle.ErrTooManyNames) {
		t.Fatalf("rename past the cap = %v, want ErrTooManyNames", err)
	}
	// And the name the loop tried to grab must not have been claimed anyway.
	if _, err := f.byName("n3"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("refused rename still claimed the name: %v", err)
	}

	// Once a hold elapses and is swept, the owner is under the cap again: the
	// cap throttles squatting, it does not permanently freeze the owner.
	f.clock.advance(handle.DefaultQuarantineWindow + time.Second)
	if _, err := f.svc.ReleaseExpired(ctx, 10); err != nil {
		t.Fatalf("ReleaseExpired: %v", err)
	}
	if _, err := f.svc.Rename(ctx, ownerA, "n3", "req"); err != nil {
		t.Fatalf("rename after a hold elapsed: %v", err)
	}
}

// TestReclaimIsAllowedAtTheCap covers the one rename the cap must not refuse.
//
// The cap bounds how many name-claims an owner holds. Taking back their own
// quarantined hold does not add one — the row is already held and already
// counted, and it is reactivated in place — so refusing it would strand an
// owner at the limit: unable to return to a name they still hold, and unable to
// free a slot, since only the elapsed-quarantine sweep releases one.
func TestReclaimIsAllowedAtTheCap(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newFixture(t, handle.WithMaxHeldNames(3))
	f.seed(ownerA, "n0")

	// Two renames put the owner exactly at the cap: n0 and n1 held, n2 active.
	for i := 1; i <= 2; i++ {
		if _, err := f.svc.Rename(ctx, ownerA, fmt.Sprintf("n%d", i), "req"); err != nil {
			t.Fatalf("Rename %d: %v", i, err)
		}
	}
	held, err := f.store.Repos().Handles.ListByOwner(ctx, ownerA)
	if err != nil {
		t.Fatalf("ListByOwner: %v", err)
	}
	if len(held) != 3 {
		t.Fatalf("setup left %d claims, want 3 (the cap)", len(held))
	}

	// A fresh name is refused, which is what "at the cap" means here. Without
	// this the reclaim below could pass simply because the cap was not reached.
	if _, err := f.svc.Rename(ctx, ownerA, "n9", "req"); !errors.Is(err, handle.ErrTooManyNames) {
		t.Fatalf("fresh name at the cap = %v, want ErrTooManyNames", err)
	}

	got, err := f.svc.Rename(ctx, ownerA, "n0", "req-reclaim")
	if err != nil {
		t.Fatalf("reclaiming an own hold at the cap = %v, want success", err)
	}
	if got.Name != "n0" || got.State != domain.NameStateActive {
		t.Fatalf("reclaimed handle = %+v, want active n0", got)
	}
	if got.QuarantineUntil != nil {
		t.Errorf("reclaimed handle still carries a deadline: %v", got.QuarantineUntil)
	}
	if want := domain.AuditActionHandleReclaimed; !hasAction(f.auditor.actions(), want) {
		t.Errorf("actions = %v, want one %q", f.auditor.actions(), want)
	}

	// The premise of the exemption, asserted rather than assumed: the reclaim
	// reused the held row instead of adding one, so the owner is still at the
	// cap and not over it.
	after, err := f.store.Repos().Handles.ListByOwner(ctx, ownerA)
	if err != nil {
		t.Fatalf("ListByOwner: %v", err)
	}
	if len(after) != len(held) {
		t.Fatalf("reclaim changed the claim count: %d -> %d", len(held), len(after))
	}
	// And the exemption did not become a way through the cap: a fresh name is
	// still refused afterwards.
	if _, err := f.svc.Rename(ctx, ownerA, "n9", "req"); !errors.Is(err, handle.ErrTooManyNames) {
		t.Fatalf("fresh name after a reclaim = %v, want ErrTooManyNames", err)
	}
}

// TestAnotherOwnersHoldIsRefusedAtTheCap is the direction the cap exemption
// could have opened. The exemption keys off the caller's OWN held claims, so a
// quarantined name belonging to someone else must not qualify for it.
//
// The refusal surfaces as ErrTooManyNames rather than ErrNameTaken, because at
// the cap the exemption does not apply and the cap refuses first. That is the
// safe ordering and it leaks less: a caller at their limit cannot use this path
// to probe whether a name is held by another owner.
func TestAnotherOwnersHoldIsRefusedAtTheCap(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newFixture(t, handle.WithMaxHeldNames(3))
	f.seed(ownerA, "n0")
	// B's hold, belonging to nobody in A's list.
	bHold := f.seedHold(ownerB, "bees", fixedNow.Add(handle.DefaultQuarantineWindow))

	for i := 1; i <= 2; i++ {
		if _, err := f.svc.Rename(ctx, ownerA, fmt.Sprintf("n%d", i), "req"); err != nil {
			t.Fatalf("Rename %d: %v", i, err)
		}
	}

	if _, err := f.svc.Rename(ctx, ownerA, "bees", "req"); err == nil {
		t.Fatal("A took B's quarantined name at the cap, want a refusal")
	} else if !errors.Is(err, handle.ErrTooManyNames) {
		t.Fatalf("A renaming onto B's hold at the cap = %v, want ErrTooManyNames", err)
	}

	// B's hold must be untouched: same owner, same state, same deadline.
	still, err := f.byName("bees")
	if err != nil {
		t.Fatalf("B's hold vanished: %v", err)
	}
	if still.OwnerID != ownerB || still.State != domain.NameStateQuarantined {
		t.Errorf("B's hold = %+v, want quarantined and owned by B", still)
	}
	if still.QuarantineUntil == nil || !still.QuarantineUntil.Equal(*bHold.QuarantineUntil) {
		t.Errorf("B's deadline moved: %v, want %v", still.QuarantineUntil, bHold.QuarantineUntil)
	}
}

// TestRenameToOwnCurrentNameRefused keeps a no-op from being recorded as a
// move, and keeps the model free of a claim quarantined onto itself.
func TestRenameToOwnCurrentNameRefused(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.seed(ownerA, "alice")

	if _, err := f.svc.Rename(context.Background(), ownerA, "alice", "req-1"); !errors.Is(err, handle.ErrNameTaken) {
		t.Fatalf("renaming to the current name = %v, want ErrNameTaken", err)
	}
	if len(f.auditor.captured()) != 0 {
		t.Errorf("a refused no-op emitted %d audit records, want 0", len(f.auditor.captured()))
	}
}

// TestRenameWithoutAHandleIsNotFound: this service moves an existing name and
// does not mint a first one. An owner with none gets the uniform verdict.
func TestRenameWithoutAHandleIsNotFound(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	if _, err := f.svc.Rename(context.Background(), ownerA, "alice", "req-1"); !errors.Is(err, handle.ErrNotFound) {
		t.Fatalf("Rename with no active handle = %v, want ErrNotFound", err)
	}
}

// TestRenameRefusesBlockedNames proves the guard is consulted on the rename
// path. A name blocked at creation that a rename would accept is a bypass: an
// owner would register something innocuous and rename onto the reserved one.
func TestRenameRefusesBlockedNames(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.seed(ownerA, "alice")

	// "adm1n" is not the literal reserved word; it reaches the blocklist only
	// through the same skeleton fold, which is what makes it a real check of
	// the guard rather than of a string comparison.
	for _, name := range []string{"admin", "adm1n", "NotASlug"} {
		if _, err := f.svc.Rename(context.Background(), ownerA, name, "req-1"); err == nil {
			t.Errorf("Rename to %q succeeded, want a refusal", name)
		}
	}
	if _, err := f.byName("alice"); err != nil {
		t.Fatalf("a refused rename disturbed the existing handle: %v", err)
	}
}

// TestRenameRecordsBothNames pins what the audit record carries. A record that
// named only the destination would leave an incident review unable to say which
// public address stopped resolving — which is the address whose consumers are
// now failing closed and need to be told.
func TestRenameRecordsBothNames(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.seed(ownerA, "alice")

	if _, err := f.svc.Rename(context.Background(), ownerA, "alicia", "req-7"); err != nil {
		t.Fatalf("Rename: %v", err)
	}

	renames := recordsFor(replay(t, f.auditor.captured()), domain.AuditActionHandleRenamed)
	if len(renames) != 1 {
		t.Fatalf("emitted %d rename records, want 1", len(renames))
	}
	rec := renames[0]
	if rec.ActorID != string(ownerA) || rec.TargetType != domain.TargetTypeHandle {
		t.Errorf("actor/target = %q/%q, want %q/handle", rec.ActorID, rec.TargetType, ownerA)
	}
	wantDetail(t, rec, audit.DetailFrom, "alice")
	wantDetail(t, rec, audit.DetailTo, "alicia")
	wantDetail(t, rec, audit.DetailHandle, "alicia")
	wantDetail(t, rec, audit.DetailRequestID, "req-7")
}

// TestReleaseIsAudited: the moment a name becomes claimable by a stranger is
// the moment a review needs to place in time, so it is recorded like any other
// access-affecting change.
func TestReleaseIsAudited(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newFixture(t)
	f.seed(ownerA, "alice")

	if _, err := f.svc.Rename(ctx, ownerA, "alicia", "req-1"); err != nil {
		t.Fatalf("Rename: %v", err)
	}
	f.clock.advance(handle.DefaultQuarantineWindow + time.Second)
	if _, err := f.svc.ReleaseExpired(ctx, 10); err != nil {
		t.Fatalf("ReleaseExpired: %v", err)
	}

	released := recordsFor(replay(t, f.auditor.captured()), domain.AuditActionHandleReleased)
	if len(released) != 1 {
		t.Fatalf("actions = %v, want one handle.released", f.auditor.actions())
	}
	// The record must name the name that was freed, not the one that replaced
	// it: the freed name is the address whose next holder could be anyone.
	wantDetail(t, released[0], audit.DetailHandle, "alice")
	if released[0].ActorID != string(ownerA) {
		t.Errorf("released record actor = %q, want %q", released[0].ActorID, ownerA)
	}
}

// TestReleaseFailureLeavesTheNameClaimed: a release that cannot be recorded
// must not have happened silently. The failure direction matters — freeing a
// public name with no audit trail is the outcome worth refusing.
func TestReleaseFailureStopsTheSweep(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newFixture(t)
	f.seed(ownerA, "alice")

	if _, err := f.svc.Rename(ctx, ownerA, "alicia", "req-1"); err != nil {
		t.Fatalf("Rename: %v", err)
	}
	f.clock.advance(handle.DefaultQuarantineWindow + time.Second)

	f.auditor.mu.Lock()
	f.auditor.err = errors.New("audit sink down")
	f.auditor.mu.Unlock()

	if _, err := f.svc.ReleaseExpired(ctx, 10); err == nil {
		t.Fatal("ReleaseExpired with a failing auditor returned nil, want the error")
	}
}

// TestNewRequiresEveryCollaborator: a Service missing one of these does not
// half-work, it fails to build. A nil guard would let renames land on reserved
// names; a nil auditor would move public names leaving no trace.
func TestNewRequiresEveryCollaborator(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	for _, tc := range []struct {
		name  string
		build func() (*handle.Service, error)
	}{
		{name: "nil store", build: func() (*handle.Service, error) {
			return handle.New(nil, mustGuard(t), f.auditor)
		}},
		{name: "nil guard", build: func() (*handle.Service, error) {
			return handle.New(f.store, nil, f.auditor)
		}},
		{name: "nil auditor", build: func() (*handle.Service, error) {
			return handle.New(f.store, mustGuard(t), nil)
		}},
		{name: "nil option", build: func() (*handle.Service, error) {
			return handle.New(f.store, mustGuard(t), f.auditor, nil)
		}},
	} {
		if _, err := tc.build(); !errors.Is(err, handle.ErrMissingDependency) {
			t.Errorf("%s: New error = %v, want ErrMissingDependency", tc.name, err)
		}
	}
}

func hasAction(actions []domain.AuditAction, want domain.AuditAction) bool {
	for _, a := range actions {
		if a == want {
			return true
		}
	}
	return false
}

// TestReclaimChecksOwnershipNotOnlyState isolates the reclaim check from the
// index that usually backs it up.
//
// TestReclaimCannotBeUsedOnAnotherOwnersHold exercises the same refusal, but in
// that setup the hold's owner is also active under their new name, so
// ux_handles_owner_active would refuse a wrongful takeover even if the service
// never looked at whose hold it was. Deleting the ownership half of the check
// therefore leaves that test green — the database catches it — which makes the
// test evidence about the index rather than about the check.
//
// Here the hold's owner has no active claim, so the index has nothing to say
// and the service's own check is the only thing standing between another owner
// and a name that is not theirs. Removing the ownership comparison must break
// this.
func TestReclaimChecksOwnershipNotOnlyState(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newFixture(t)

	held := f.seedHold(ownerA, "alice", fixedNow.Add(handle.DefaultQuarantineWindow))
	f.seed(ownerB, "bob")

	if _, err := f.svc.Rename(ctx, ownerB, "alice", "req-1"); !errors.Is(err, handle.ErrNameTaken) {
		t.Fatalf("B taking A's hold = %v, want ErrNameTaken", err)
	}

	// A's claim must be untouched: same owner, still quarantined, same deadline.
	got, err := f.byName("alice")
	if err != nil {
		t.Fatalf("A's hold vanished: %v", err)
	}
	if got.OwnerID != ownerA {
		t.Errorf("hold changed hands to %q", got.OwnerID)
	}
	if got.State != domain.NameStateQuarantined {
		t.Errorf("hold state = %q, want quarantined", got.State)
	}
	if got.QuarantineUntil == nil || !got.QuarantineUntil.Equal(*held.QuarantineUntil) {
		t.Errorf("hold deadline moved to %v, want %v", got.QuarantineUntil, held.QuarantineUntil)
	}

	// And B must still hold its own name rather than having vacated it into a
	// rename that then failed.
	bob, err := f.byName("bob")
	if err != nil || bob.State != domain.NameStateActive {
		t.Fatalf("B lost its handle to a refused rename: %+v %v", bob, err)
	}
}

// TestOwnerCannotReclaimARetiredName is the other half of the reclaim check.
//
// NameStateRetired is the operator's never-release decision — the affordance
// ADR-0026 leaves open for permanently withdrawing a name, typically after
// abuse. The reclaim exception is scoped to QUARANTINED holds for exactly that
// reason: if it turned on ownership alone, the owner whose name was retired
// would be the one person able to take it back, which inverts the control.
func TestOwnerCannotReclaimARetiredName(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newFixture(t)

	f.seedRetired(ownerA, "banned")
	f.seed(ownerA, "alice")

	if _, err := f.svc.Rename(ctx, ownerA, "banned", "req-1"); !errors.Is(err, handle.ErrNameTaken) {
		t.Fatalf("reclaiming a retired name = %v, want ErrNameTaken", err)
	}

	// The retirement must be intact, and the caller must still hold the name
	// they started with rather than having vacated it into a failed rename.
	got, err := f.byName("banned")
	if err != nil {
		t.Fatalf("retired claim vanished: %v", err)
	}
	if got.State != domain.NameStateRetired {
		t.Errorf("retired claim state = %q, want retired", got.State)
	}
	if _, err := f.byName("alice"); err != nil {
		t.Fatalf("refused rename left the caller without a handle: %v", err)
	}
}

// TestRenameSurvivesANilActiveRow drives the rename against a repository that
// breaks the port contract by returning a nil row with a nil error.
//
// No adapter in this tree does that, and the test does not claim one might. It
// pins which of the two available readings of the violation the service takes:
// dereference the nil and take the process down, or refuse. The assertion that
// carries the weight is that the call RETURNS — the error it returns is
// secondary, and is checked only to confirm the refusal is the uniform one a
// caller with no active handle already gets.
func TestRenameSurvivesANilActiveRow(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	f.seed(ownerA, "alice")

	// The embedded repository is left nil: GetActiveByOwner is the first handle
	// read the rename makes, so nothing else should be reached before the guard
	// refuses. Anything else would panic here rather than pass quietly.
	svc := f.withNilRows(func(repository.HandleRepository) repository.HandleRepository {
		return nilRowRepo{nilActiveByOwner: true}
	})

	_, err := svc.Rename(context.Background(), ownerA, "alicia", "")
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("Rename with a nil active row = %v, want domain.ErrNotFound", err)
	}
}

// TestReclaimSurvivesANilNamedRow covers the sharper of the two sites: the
// reclaim gate, the check that decides who may take a quarantined name.
//
// Only GetByName is falsified; every other read and write goes to the real
// SQLite adapter, so the rename genuinely reaches the gate with the old name
// already quarantined rather than being turned away earlier by a fake.
//
// ErrNameTaken here is not evidence on its own — a real collision returns the
// same error, so this test would pass against a service that never looked at
// the row at all. What it proves is that the gate reaches a verdict instead of
// panicking, which is why the mutation that removes the nil test fails it.
func TestReclaimSurvivesANilNamedRow(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	f.seed(ownerA, "alice")

	svc := f.withNilRows(func(real repository.HandleRepository) repository.HandleRepository {
		return nilRowRepo{HandleRepository: real, nilByName: true}
	})

	_, err := svc.Rename(context.Background(), ownerA, "alicia", "")
	if !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("Rename with a nil named row = %v, want domain.ErrConflict", err)
	}

	// The refusal must not have half-applied the rename. A gate that bails out
	// after the old name was already parked would strand the owner with no
	// active handle at all, which is worse than the refusal it was avoiding.
	old, err := f.byName("alice")
	if err != nil {
		t.Fatalf("byName(alice) after refused rename: %v", err)
	}
	if old.State != domain.NameStateActive {
		t.Fatalf("alice state after refused rename = %q, want %q",
			old.State, domain.NameStateActive)
	}
}
