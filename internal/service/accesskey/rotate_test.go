package accesskey

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/audit"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/secrets"
)

// rotateWindow is the window the rotation tests configure. It is short and
// exact so the boundary assertions land on a specific instant rather than
// somewhere inside a range.
const rotateWindow = 2 * time.Hour

// withGraceWindow rebuilds the fixture's service with an explicit window, so a
// test asserts against a deadline it chose rather than the shipped default.
func (f *fixture) withGraceWindow(t *testing.T, d time.Duration) {
	t.Helper()

	svc, err := New(f.store, f.audit, testPepper,
		WithClock(func() time.Time { return f.now }),
		WithGraceWindow(d))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	f.svc = svc
}

// verifies asserts whether a token opens the set, through the REAL Verify path.
// The rotation tests go through Verify rather than reading the row's status
// because the row is not what refuses a lapsed credential — usable is, on every
// request — and a test that asserted on the stored status would keep passing if
// the refusal were removed.
func (f *fixture) verifies(t *testing.T, setID domain.KeySetID, ownerID domain.OwnerID, token secrets.Redacted) bool {
	t.Helper()

	_, err := f.svc.Verify(context.Background(), ownerID, setID, token)
	if err == nil {
		return true
	}
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Verify: unexpected error %v", err)
	}
	return false
}

// TestRotateLeavesBothCredentialsUsableInsideTheWindow is the transition itself:
// the promise a grace window makes is that a deployment does not break the
// instant its operator rotates.
func TestRotateLeavesBothCredentialsUsableInsideTheWindow(t *testing.T) {
	f := newFixture(t)
	f.withGraceWindow(t, rotateWindow)
	owner := f.seedOwner("alice")
	old, oldToken := f.mint(owner.OwnerID, owner.KeySetID, "ci")

	fresh, newToken, err := f.svc.Rotate(context.Background(), owner.OwnerID, old.ID, "req-2")
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if fresh.ID == old.ID {
		t.Fatal("Rotate reused the credential's id; the replacement must be a new credential")
	}
	if newToken.Reveal() == oldToken.Reveal() {
		t.Fatal("Rotate handed back the credential's own token")
	}
	if fresh.Name != old.Name {
		t.Errorf("replacement name = %q, want the inherited %q", fresh.Name, old.Name)
	}
	if fresh.Status != domain.AccessKeyStatusActive {
		t.Errorf("replacement status = %q, want active", fresh.Status)
	}

	// The new credential works at once: an owner who rotates has a credential
	// to deploy before the old one lapses, or the window buys them nothing.
	if !f.verifies(t, owner.KeySetID, owner.OwnerID, newToken) {
		t.Error("the replacement does not verify immediately after rotation")
	}
	// And the old one still works, which is the whole point.
	if !f.verifies(t, owner.KeySetID, owner.OwnerID, oldToken) {
		t.Error("the rotated credential stopped working immediately; the grace window bought nothing")
	}

	// The deadline is the configured window from the rotation, not a literal
	// and not the zero time.
	row, err := f.store.Repos().AccessKeys.Get(context.Background(), owner.OwnerID, old.ID)
	if err != nil {
		t.Fatalf("Get rotated key: %v", err)
	}
	if row.Status != domain.AccessKeyStatusGrace {
		t.Fatalf("rotated key status = %q, want grace", row.Status)
	}
	if row.GraceUntil == nil {
		t.Fatal("rotated key has no grace deadline; without one it is refused, but the window was promised")
	}
	if want := f.now.Add(rotateWindow); !row.GraceUntil.Equal(want) {
		t.Errorf("grace deadline = %v, want %v (now + the configured window)", row.GraceUntil, want)
	}
	if row.ReplacedByID == nil || *row.ReplacedByID != fresh.ID {
		t.Errorf("ReplacedByID = %v, want the replacement %q", row.ReplacedByID, fresh.ID)
	}
}

// TestRotatedCredentialIsRefusedAfterTheWindow is the half that makes rotation
// mean something. It runs through Verify, so what is asserted is the enforcement
// at time of use — no sweep involved.
func TestRotatedCredentialIsRefusedAfterTheWindow(t *testing.T) {
	f := newFixture(t)
	f.withGraceWindow(t, rotateWindow)
	owner := f.seedOwner("alice")
	old, oldToken := f.mint(owner.OwnerID, owner.KeySetID, "ci")

	_, newToken, err := f.svc.Rotate(context.Background(), owner.OwnerID, old.ID, "req-2")
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}

	// Exactly on the deadline the credential is still good: usable compares
	// with After, so the boundary instant is inside the window.
	f.now = f.now.Add(rotateWindow)
	if !f.verifies(t, owner.KeySetID, owner.OwnerID, oldToken) {
		t.Error("the credential was refused ON its deadline; the window is inclusive")
	}

	// One nanosecond past it, it is gone.
	f.now = f.now.Add(time.Nanosecond)
	if f.verifies(t, owner.KeySetID, owner.OwnerID, oldToken) {
		t.Fatal("the rotated credential still verifies past its grace window")
	}
	// The replacement is unaffected: expiry is the old credential's, not the
	// owner's.
	if !f.verifies(t, owner.KeySetID, owner.OwnerID, newToken) {
		t.Error("the replacement stopped working when the old window closed")
	}
}

// TestRotateIsAuditedUnderTheOwner pins the attribution. Unlike the expiry
// sweep, which is correctly ActorTypeSystem with no actor id, a rotation is
// something a principal asked for, and an accountability record that named the
// system for it would be recording the wrong actor.
func TestRotateIsAuditedUnderTheOwner(t *testing.T) {
	f := newFixture(t)
	f.withGraceWindow(t, rotateWindow)
	owner := f.seedOwner("alice")
	old, _ := f.mint(owner.OwnerID, owner.KeySetID, "ci")
	f.audit.events = nil

	fresh, _, err := f.svc.Rotate(context.Background(), owner.OwnerID, old.ID, "req-9")
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}

	var rotated, created *audit.Event
	for i := range f.audit.events {
		switch f.audit.events[i].Action {
		case domain.AuditActionAccessKeyRotated:
			rotated = &f.audit.events[i]
		case domain.AuditActionAccessKeyCreated:
			created = &f.audit.events[i]
		}
	}
	if rotated == nil {
		t.Fatal("no access_key.rotated record was emitted")
	}
	if created == nil {
		t.Fatal("no access_key.created record was emitted for the replacement")
	}

	if rotated.ActorType != domain.ActorTypeOwner {
		t.Errorf("rotation actor type = %q, want owner", rotated.ActorType)
	}
	if rotated.ActorID != string(owner.OwnerID) {
		t.Errorf("rotation actor id = %q, want the owner %q", rotated.ActorID, owner.OwnerID)
	}
	if rotated.TargetID != string(old.ID) {
		t.Errorf("rotation target = %q, want the rotated credential %q", rotated.TargetID, old.ID)
	}
	if created.TargetID != string(fresh.ID) {
		t.Errorf("creation target = %q, want the replacement %q", created.TargetID, fresh.ID)
	}
	// The details are asserted through a real emitter rather than off the
	// struct: Details keeps its pairs unexported on purpose, and replaying
	// means a value the audit screen would reject fails here instead of
	// passing because a test read around the screen.
	meta := replayMetadata(t, *rotated)
	// The record has to say which credential replaced which, or an incident
	// review cannot follow the chain.
	if got := meta[string(audit.DetailTo)]; got != string(fresh.ID) {
		t.Errorf("rotation detail 'to' = %q, want the replacement %q", got, fresh.ID)
	}
	if got := meta[string(audit.DetailFrom)]; got != string(old.ID) {
		t.Errorf("rotation detail 'from' = %q, want the rotated credential %q", got, old.ID)
	}
	// Neither the plaintext nor a digest may ever appear in a record. The
	// allowlist in the audit package makes a key named for a secret impossible;
	// this pins that no VALUE here is one either.
	for k, v := range meta {
		switch k {
		case string(audit.DetailFrom), string(audit.DetailTo),
			string(audit.DetailClientLabel), string(audit.DetailKeySetName), string(audit.DetailRequestID):
		default:
			t.Errorf("rotation record carries an unexpected detail %q=%q", k, v)
		}
	}
}

// auditSink captures the records a real emitter produces.
type auditSink struct{ records []*domain.AuditRecord }

func (s *auditSink) Append(_ context.Context, rec *domain.AuditRecord) error {
	s.records = append(s.records, rec)
	return nil
}

// replayMetadata pushes one captured event through a real audit.Emitter and
// returns the metadata the stored record carries.
func replayMetadata(t *testing.T, ev audit.Event) map[string]string {
	t.Helper()

	sink := &auditSink{}
	emitter, err := audit.NewEmitter(sink)
	if err != nil {
		t.Fatalf("audit.NewEmitter: %v", err)
	}
	if err := emitter.Emit(context.Background(), ev); err != nil {
		t.Fatalf("Emit %s: %v", ev.Action, err)
	}
	if len(sink.records) != 1 {
		t.Fatalf("replay produced %d records, want 1", len(sink.records))
	}
	return sink.records[0].Metadata
}

// TestRotateRefusesARevokedCredential is the resurrection refusal. A revoked
// credential returning to life as a grace row, through an ordinary management
// call that looks nothing like an un-revoke, is the same family of bug as the
// tombstoned key set this project already fixed.
func TestRotateRefusesARevokedCredential(t *testing.T) {
	f := newFixture(t)
	f.withGraceWindow(t, rotateWindow)
	owner := f.seedOwner("alice")
	old, oldToken := f.mint(owner.OwnerID, owner.KeySetID, "ci")

	if err := f.svc.Revoke(context.Background(), owner.OwnerID, old.ID, "req-2"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	k, token, err := f.svc.Rotate(context.Background(), owner.OwnerID, old.ID, "req-3")
	denied(t, "Rotate on a revoked credential", err)
	if k != nil || token.Reveal() != "" {
		t.Fatal("Rotate produced a replacement for a revoked credential")
	}
	// The refusal must not have been cosmetic: the row stays revoked and dead.
	row, err := f.store.Repos().AccessKeys.Get(context.Background(), owner.OwnerID, old.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if row.Status != domain.AccessKeyStatusRevoked {
		t.Errorf("status after a refused rotation = %q, want it to stay revoked", row.Status)
	}
	if f.verifies(t, owner.KeySetID, owner.OwnerID, oldToken) {
		t.Fatal("a revoked credential verifies again after a refused rotation")
	}
}

// TestRotateRefusesACredentialAlreadyInGrace is the decision that a window
// cannot be extended. Allowed, repeated rotation would walk the deadline
// forward indefinitely and the credential the owner retired would outlive the
// retirement for as long as anyone kept calling — and the caller need only hold
// the credential itself. MarkRotated does NOT refuse this (it excludes revoked
// rows only), so this refusal is the service's alone and nothing below it would
// catch a regression.
func TestRotateRefusesACredentialAlreadyInGrace(t *testing.T) {
	f := newFixture(t)
	f.withGraceWindow(t, rotateWindow)
	owner := f.seedOwner("alice")
	old, oldToken := f.mint(owner.OwnerID, owner.KeySetID, "ci")

	if _, _, err := f.svc.Rotate(context.Background(), owner.OwnerID, old.ID, "req-2"); err != nil {
		t.Fatalf("first Rotate: %v", err)
	}
	first, err := f.store.Repos().AccessKeys.Get(context.Background(), owner.OwnerID, old.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}

	// Time moves on, so a window that WAS extended would be visibly later.
	f.now = f.now.Add(time.Hour)
	k, token, err := f.svc.Rotate(context.Background(), owner.OwnerID, old.ID, "req-3")
	denied(t, "Rotate on a credential already in grace", err)
	if k != nil || token.Reveal() != "" {
		t.Fatal("Rotate produced a replacement for a credential already in grace")
	}

	after, err := f.store.Repos().AccessKeys.Get(context.Background(), owner.OwnerID, old.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !after.GraceUntil.Equal(*first.GraceUntil) {
		t.Fatalf("grace deadline moved from %v to %v; the window must not be extendable",
			first.GraceUntil, after.GraceUntil)
	}
	// And it still closes on the original schedule.
	f.now = first.GraceUntil.Add(time.Nanosecond)
	if f.verifies(t, owner.KeySetID, owner.OwnerID, oldToken) {
		t.Fatal("the credential outlived its original window after a refused re-rotation")
	}
}

// TestRotateIsAtomicWhenTheTransitionFails is the fail-open guard. The mint
// succeeds and MarkRotated fails, which is exactly the ordering that would
// otherwise leave the owner two live credentials with no deadline on either.
//
// The rollback asserted here is the real SQLite transaction's, not a fake's: the
// fault is injected into the transaction-bound repository, so Create genuinely
// wrote inside the transaction before the failure took it back.
func TestRotateIsAtomicWhenTheTransitionFails(t *testing.T) {
	f := newFixture(t)
	owner := f.seedOwner("alice")
	old, oldToken := f.mint(owner.OwnerID, owner.KeySetID, "ci")

	faulty := f.withFaultyKeys(t)
	boom := errors.New("transition failed")
	faulty.markRotatedErr = boom

	k, token, err := f.svc.Rotate(context.Background(), owner.OwnerID, old.ID, "req-2")
	if !errors.Is(err, boom) {
		t.Fatalf("Rotate = %v, want the transition failure", err)
	}
	if k != nil || token.Reveal() != "" {
		t.Fatal("Rotate handed back a credential whose rotation did not commit")
	}

	// The mint must NOT have survived. Anything else is the fail-open: a second
	// live credential nobody recorded and nothing will expire.
	keys, err := f.store.Repos().AccessKeys.ListByOwner(context.Background(), owner.OwnerID)
	if err != nil {
		t.Fatalf("ListByOwner: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("owner holds %d credentials after a failed rotation, want only the original", len(keys))
	}
	if keys[0].ID != old.ID {
		t.Fatalf("the surviving credential is %q, want the original %q", keys[0].ID, old.ID)
	}

	// The original is untouched: still active, no window, and still the owner's
	// working credential.
	if keys[0].Status != domain.AccessKeyStatusActive {
		t.Errorf("original status = %q, want it to stay active", keys[0].Status)
	}
	if keys[0].GraceUntil != nil {
		t.Errorf("original carries a grace deadline %v after a rolled-back rotation", keys[0].GraceUntil)
	}
	f.svc = newFixtureService(t, f)
	if !f.verifies(t, owner.KeySetID, owner.OwnerID, oldToken) {
		t.Error("the original credential stopped working after a rotation that did not commit")
	}
}

// newFixtureService rebuilds a service over the undecorated store, so an
// assertion made after a fault-injection test is not itself running through the
// injector.
func newFixtureService(t *testing.T, f *fixture) *Service {
	t.Helper()

	svc, err := New(f.store, f.audit, testPepper,
		WithClock(func() time.Time { return f.now }),
		WithGraceWindow(rotateWindow))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return svc
}

// TestRotateRefusesAcrossOwners keeps rotation inside the owner-scoped world
// every other method here lives in: a credential id is not a capability, and
// naming another owner's must be indistinguishable from naming one that was
// never created.
func TestRotateRefusesAcrossOwners(t *testing.T) {
	f := newFixture(t)
	f.withGraceWindow(t, rotateWindow)
	alice := f.seedOwner("alice")
	bob := f.seedOwner("bob")
	k, aliceToken := f.mint(alice.OwnerID, alice.KeySetID, "ci")

	got, token, err := f.svc.Rotate(context.Background(), bob.OwnerID, k.ID, "req-2")
	denied(t, "Rotate of another owner's credential", err)
	if got != nil || token.Reveal() != "" {
		t.Fatal("Rotate produced a replacement for another owner's credential")
	}
	if !f.verifies(t, alice.KeySetID, alice.OwnerID, aliceToken) {
		t.Error("a stranger's refused rotation disturbed the owner's credential")
	}

	// An id that never existed answers the same way, so the two are not
	// distinguishable.
	_, _, missing := f.svc.Rotate(context.Background(), bob.OwnerID, "ak-invented", "req-3")
	denied(t, "Rotate of an invented id", missing)
}

// TestRotateRefusesWhenTheKeySetIsNoLongerActive stops rotation being a way
// around Mint's refusal. Mint will not issue a credential for a quarantined or
// retired set, and rotation mints — a name out of service must not gain fresh
// credentials that would outlive its return.
func TestRotateRefusesWhenTheKeySetIsNoLongerActive(t *testing.T) {
	f := newFixture(t)
	f.withGraceWindow(t, rotateWindow)
	owner := f.seedOwner("alice")
	setID := f.seedSet(owner.OwnerID, "staging", domain.NameStateActive)
	k, _ := f.mint(owner.OwnerID, setID, "ci")

	f.exec(`UPDATE key_sets SET state = ? WHERE id = ?`,
		string(domain.NameStateQuarantined), string(setID))

	got, token, err := f.svc.Rotate(context.Background(), owner.OwnerID, k.ID, "req-2")
	denied(t, "Rotate into a quarantined key set", err)
	if got != nil || token.Reveal() != "" {
		t.Fatal("Rotate minted a credential for a set that is out of service")
	}
}

// TestRotateRejectsMissingArguments pins the two input guards, and the
// difference between them: an absent owner is invalid input the caller can fix,
// while an absent id collapses into the single negative verdict so a caller
// cannot learn which id shapes are well formed.
func TestRotateRejectsMissingArguments(t *testing.T) {
	f := newFixture(t)
	f.withGraceWindow(t, rotateWindow)

	if _, _, err := f.svc.Rotate(context.Background(), "", "ak-1", "req-1"); !errors.Is(err, domain.ErrInvalidInput) {
		t.Errorf("Rotate with no owner = %v, want ErrInvalidInput", err)
	}
	_, _, err := f.svc.Rotate(context.Background(), "owner-1", "", "req-1")
	denied(t, "Rotate with no id", err)
}

// TestRotateSurfacesAnAuditFailureAndWithholdsTheToken asserts a rotation that
// could not be recorded does not hand back a usable credential. The row is
// committed by then, so the token is the only thing left to withhold — and a
// caller that never receives it cannot use it.
func TestRotateSurfacesAnAuditFailureAndWithholdsTheToken(t *testing.T) {
	f := newFixture(t)
	f.withGraceWindow(t, rotateWindow)
	owner := f.seedOwner("alice")
	old, _ := f.mint(owner.OwnerID, owner.KeySetID, "ci")

	boom := errors.New("audit sink down")
	f.audit.err = boom

	k, token, err := f.svc.Rotate(context.Background(), owner.OwnerID, old.ID, "req-2")
	if !errors.Is(err, boom) {
		t.Fatalf("Rotate = %v, want the audit failure", err)
	}
	if k != nil || token.Reveal() != "" {
		t.Fatal("Rotate handed back a token for a rotation it could not record")
	}
}

// TestRotateRefusesARevokedCredentialWithoutRelyingOnTheAdapter is the test
// that attributes the refusal correctly, and it was added because its absence
// was caught by mutation: deleting the service's status guard entirely left
// TestRotateRefusesARevokedCredential still passing, because the SQLite
// adapter's MarkRotated excludes revoked rows in SQL and refused on the
// service's behalf.
//
// That is genuine defense in depth and it should stay. But a refusal only the
// storage layer performs is one a different adapter — a future Postgres
// predicate written slightly differently, a cache, an in-memory port — can lose
// without any test noticing, and what it would lose is a revoked credential
// coming back to life as a grace row. So the transition here is made
// permissive: MarkRotated reports success without enforcing anything, and the
// only thing left that can refuse is this package.
func TestRotateRefusesARevokedCredentialWithoutRelyingOnTheAdapter(t *testing.T) {
	f := newFixture(t)
	owner := f.seedOwner("alice")
	old, oldToken := f.mint(owner.OwnerID, owner.KeySetID, "ci")

	if err := f.svc.Revoke(context.Background(), owner.OwnerID, old.ID, "req-2"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	faulty := f.withFaultyKeys(t)
	faulty.markRotatedNoop = true

	k, token, err := f.svc.Rotate(context.Background(), owner.OwnerID, old.ID, "req-3")
	denied(t, "Rotate on a revoked credential with a permissive adapter", err)
	if k != nil || token.Reveal() != "" {
		t.Fatal("the service minted a replacement for a revoked credential; the refusal was the adapter's alone")
	}

	// Nothing was written: a replacement that committed would be a live
	// credential descended from a revoked one.
	keys, err := f.store.Repos().AccessKeys.ListByOwner(context.Background(), owner.OwnerID)
	if err != nil {
		t.Fatalf("ListByOwner: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("owner holds %d credentials, want only the revoked original", len(keys))
	}
	if keys[0].Status != domain.AccessKeyStatusRevoked {
		t.Errorf("status = %q, want it to stay revoked", keys[0].Status)
	}

	f.svc = newFixtureService(t, f)
	if f.verifies(t, owner.KeySetID, owner.OwnerID, oldToken) {
		t.Fatal("the revoked credential is live again")
	}
}
