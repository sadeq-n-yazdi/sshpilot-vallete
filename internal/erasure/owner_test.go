package erasure_test

import (
	"context"
	"strings"
	"testing"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/audit"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/erasure"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/repository"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/storage/sqlite"
)

// newOwnerEraser wires the traversal, the primitive and a real audit emitter
// over the store.
func newOwnerEraser(t *testing.T, s *sqlite.Store) *erasure.OwnerEraser {
	t.Helper()
	r := s.Repos()

	e, err := erasure.New(r.Audit, r.OwnerSalts)
	if err != nil {
		t.Fatalf("erasure.New: %v", err)
	}
	em, err := audit.NewEmitter(s.AuditAppender())
	if err != nil {
		t.Fatalf("audit.NewEmitter: %v", err)
	}
	oe, err := erasure.NewOwnerEraser(newGraph(t, r), e, em)
	if err != nil {
		t.Fatalf("NewOwnerEraser: %v", err)
	}
	return oe
}

// emitFor appends one audit record naming the given actor and target, standing
// in for the events the services write during normal operation.
func emitFor(t *testing.T, s *sqlite.Store, actor, target string, tt domain.TargetType) {
	t.Helper()
	em, err := audit.NewEmitter(s.AuditAppender())
	if err != nil {
		t.Fatalf("audit.NewEmitter: %v", err)
	}
	err = em.Emit(context.Background(), audit.Event{
		ActorType: domain.ActorTypeOwner, ActorID: actor,
		Action: domain.AuditActionDeviceRegistered, TargetType: tt, TargetID: target,
	})
	if err != nil {
		t.Fatalf("emit for %s/%s: %v", actor, target, err)
	}
}

// listAll returns every audit record currently stored.
func listAll(t *testing.T, s *sqlite.Store) []domain.AuditRecord {
	t.Helper()
	recs, _, err := s.Repos().Audit.List(context.Background(), repository.AuditQuery{}, repository.Page{Limit: 500})
	if err != nil {
		t.Fatalf("list audit records: %v", err)
	}
	return recs
}

// seedWithAudit seeds an owner and emits one audit record per collected
// identifier, so every table's identifier is present in the log and a table
// missed by the traversal leaves a live identifier behind.
func seedWithAudit(t *testing.T, s *sqlite.Store, ownerID, prefix string) seeded {
	t.Helper()
	rows := seedOwner(t, s, ownerID, prefix)
	for table, ids := range rows {
		for _, id := range ids {
			tt := domain.TargetTypeDevice
			if table == "owners" {
				tt = domain.TargetTypeOwner
			}
			emitFor(t, s, id, id, tt)
		}
	}
	return rows
}

// TestEraseOwnerTombstonesEveryTablesIdentifiers is the end-to-end statement of
// the guarantee: after erasure, no identifier from any owner-scoped table is
// still readable in the audit log.
func TestEraseOwnerTombstonesEveryTablesIdentifiers(t *testing.T) {
	t.Parallel()
	_, store := newStore(t)
	rows := seedWithAudit(t, store, "owner-a", "a")

	if _, err := newOwnerEraser(t, store).EraseOwner(context.Background(), "owner-a"); err != nil {
		t.Fatalf("EraseOwner: %v", err)
	}

	live := map[string]bool{}
	for _, rec := range listAll(t, store) {
		live[rec.ActorID] = true
		live[rec.TargetID] = true
	}
	for table, ids := range rows {
		for _, id := range ids {
			if live[id] {
				t.Errorf("identifier %q from table %s survives in the audit log after erasure", id, table)
			}
		}
	}
}

// TestEraseOwnerLeavesOtherOwnersUntouched asserts non-interference per table.
func TestEraseOwnerLeavesOtherOwnersUntouched(t *testing.T) {
	t.Parallel()
	_, store := newStore(t)
	seedWithAudit(t, store, "owner-a", "a")
	other := seedWithAudit(t, store, "owner-b", "b")

	if _, err := newOwnerEraser(t, store).EraseOwner(context.Background(), "owner-a"); err != nil {
		t.Fatalf("EraseOwner: %v", err)
	}

	live := map[string]bool{}
	for _, rec := range listAll(t, store) {
		live[rec.ActorID] = true
		live[rec.TargetID] = true
	}
	for table, ids := range other {
		for _, id := range ids {
			if !live[id] {
				t.Errorf("erasing owner-a destroyed %q from owner-b's %s: a cross-owner erasure", id, table)
			}
		}
	}
	// owner-b's salt is the other half of the guarantee: destroying it would
	// make owner-b's future erasure mint tombstones nothing can verify.
	if _, err := store.Repos().OwnerSalts.Get(context.Background(), "owner-b"); err != nil {
		t.Errorf("erasing owner-a destroyed owner-b's salt: %v", err)
	}
}

// TestEraseOwnerDestroysTheSalt covers the irreversibility itself: the key that
// makes a tombstone computable is gone.
func TestEraseOwnerDestroysTheSalt(t *testing.T) {
	t.Parallel()
	_, store := newStore(t)
	seedWithAudit(t, store, "owner-a", "a")
	ctx := context.Background()

	before, err := store.Repos().OwnerSalts.Get(ctx, "owner-a")
	if err != nil {
		t.Fatalf("salt before erasure: %v", err)
	}
	// While the salt exists the link is verifiable; that is the capability
	// erasure removes.
	tomb := erasure.Tombstone(before, "owner-a")
	if !erasure.Verify(before, "owner-a", tomb) {
		t.Fatal("tombstone does not verify under its own salt")
	}

	if _, eerr := newOwnerEraser(t, store).EraseOwner(ctx, "owner-a"); eerr != nil {
		t.Fatalf("EraseOwner: %v", eerr)
	}

	if _, gerr := store.Repos().OwnerSalts.Get(ctx, "owner-a"); gerr == nil {
		t.Fatal("the salt survived erasure: every tombstone remains reversible")
	}
	// A salt minted afresh cannot recompute the destroyed one's tombstones, so
	// the surviving records can no longer be linked to the identifier.
	fresh, err := store.Repos().OwnerSalts.Ensure(ctx, "owner-a")
	if err != nil {
		t.Fatalf("ensure fresh salt: %v", err)
	}
	if erasure.Verify(fresh, "owner-a", tomb) {
		t.Error("a fresh salt reproduced the destroyed salt's tombstone")
	}
}

// TestEraseOwnerIsIdempotent covers the re-run over a fully erased owner.
func TestEraseOwnerIsIdempotent(t *testing.T) {
	t.Parallel()
	_, store := newStore(t)
	rows := seedWithAudit(t, store, "owner-a", "a")
	oe := newOwnerEraser(t, store)
	ctx := context.Background()

	if _, err := oe.EraseOwner(ctx, "owner-a"); err != nil {
		t.Fatalf("first EraseOwner: %v", err)
	}
	first := listAll(t, store)

	if _, err := oe.EraseOwner(ctx, "owner-a"); err != nil {
		t.Fatalf("second EraseOwner: %v", err)
	}
	second := listAll(t, store)

	// The second pass adds its own erasure record and rewrites nothing else.
	if len(second) != len(first)+1 {
		t.Errorf("second pass left %d records, want %d", len(second), len(first)+1)
	}
	live := map[string]bool{}
	for _, rec := range second {
		live[rec.ActorID] = true
		live[rec.TargetID] = true
	}
	for table, ids := range rows {
		for _, id := range ids {
			if live[id] {
				t.Errorf("identifier %q from %s reappeared after a second pass", id, table)
			}
		}
	}
	if _, err := store.Repos().OwnerSalts.Get(ctx, "owner-a"); err == nil {
		t.Error("the second pass left a salt behind")
	}
}

// TestEraseOwnerCompletesAPartiallyErasedOwner covers the crash window in the
// middle of the pseudonymize pass: some identifiers tombstoned, salt alive.
func TestEraseOwnerCompletesAPartiallyErasedOwner(t *testing.T) {
	t.Parallel()
	_, store := newStore(t)
	rows := seedWithAudit(t, store, "owner-a", "a")
	ctx := context.Background()

	// Simulate the interrupted pass by rewriting one identifier under the live
	// salt and leaving the rest, which is exactly the state a crash produces.
	salt, err := store.Repos().OwnerSalts.Get(ctx, "owner-a")
	if err != nil {
		t.Fatalf("get salt: %v", err)
	}
	partial := "a-dev-active"
	if _, perr := store.Repos().Audit.Pseudonymize(ctx, []string{partial}, erasure.Tombstone(salt, partial)); perr != nil {
		t.Fatalf("partial pseudonymize: %v", perr)
	}

	if _, eerr := newOwnerEraser(t, store).EraseOwner(ctx, "owner-a"); eerr != nil {
		t.Fatalf("EraseOwner over a partially erased owner: %v", eerr)
	}

	live := map[string]bool{}
	for _, rec := range listAll(t, store) {
		live[rec.ActorID] = true
		live[rec.TargetID] = true
	}
	for table, ids := range rows {
		for _, id := range ids {
			if live[id] {
				t.Errorf("identifier %q from %s survived the completing pass", id, table)
			}
		}
	}
	if _, gerr := store.Repos().OwnerSalts.Get(ctx, "owner-a"); gerr == nil {
		t.Error("the completing pass did not destroy the salt")
	}
}

// TestEraseOwnerRecordsTheErasureWithoutRestatingIt covers the audit obligation
// and its constraint: the record must exist, and must not name what it erased.
func TestEraseOwnerRecordsTheErasureWithoutRestatingIt(t *testing.T) {
	t.Parallel()
	_, store := newStore(t)
	rows := seedWithAudit(t, store, "owner-a", "a")

	if _, err := newOwnerEraser(t, store).EraseOwner(context.Background(), "owner-a"); err != nil {
		t.Fatalf("EraseOwner: %v", err)
	}

	// One read, one slice. The earlier form ranged over listAll(t, store) and
	// then indexed a SECOND call to it, which is two separate queries: nothing
	// makes the row order of the second match the first, so the record examined
	// below need not have been the one the loop matched. A test that can assert
	// against a different record than it selected is a test that can pass while
	// the erasure record still names the owner.
	recs := listAll(t, store)
	var found *domain.AuditRecord
	for i := range recs {
		if recs[i].Action == domain.AuditActionOwnerErased {
			found = &recs[i]
			break
		}
	}
	if found == nil {
		t.Fatal("no owner.erased record: the erasure was unaccountable")
	}
	if !strings.HasPrefix(found.TargetID, "anon:") {
		t.Errorf("erasure record target %q is not a tombstone: the record names the owner it erased", found.TargetID)
	}
	if len(found.Metadata) != 0 {
		t.Errorf("erasure record carries metadata %v: it must not restate what was destroyed", found.Metadata)
	}
	// No identifier from any table may appear anywhere in the record.
	blob := found.ActorID + "|" + found.TargetID
	for k, v := range found.Metadata {
		blob += "|" + k + "=" + v
	}
	for table, ids := range rows {
		for _, id := range ids {
			if strings.Contains(blob, id) {
				t.Errorf("erasure record restates %q from %s", id, table)
			}
		}
	}
}

func TestNewOwnerEraserRequiresEveryPort(t *testing.T) {
	t.Parallel()
	_, store := newStore(t)
	r := store.Repos()
	e, err := erasure.New(r.Audit, r.OwnerSalts)
	if err != nil {
		t.Fatalf("erasure.New: %v", err)
	}
	em, err := audit.NewEmitter(store.AuditAppender())
	if err != nil {
		t.Fatalf("audit.NewEmitter: %v", err)
	}
	g := newGraph(t, r)

	if _, err := erasure.NewOwnerEraser(nil, e, em); err == nil {
		t.Error("NewOwnerEraser accepted a nil graph")
	}
	if _, err := erasure.NewOwnerEraser(g, nil, em); err == nil {
		t.Error("NewOwnerEraser accepted a nil eraser")
	}
	// An erasure with no audit emitter is the unaccountable destruction ADR-0024
	// forbids, so it must be impossible to construct.
	if _, err := erasure.NewOwnerEraser(g, e, nil); err == nil {
		t.Error("NewOwnerEraser accepted a nil audit emitter")
	}
}

func TestEraseOwnerRejectsEmptyOwner(t *testing.T) {
	t.Parallel()
	_, store := newStore(t)
	if _, err := newOwnerEraser(t, store).EraseOwner(context.Background(), ""); err == nil {
		t.Fatal("EraseOwner(\"\") succeeded, want an invalid-input error")
	}
}

// TestEraseOwnerLeavesListAdminRecordsStanding is the proof for gap #38: a
// reserved-list edit is NOT owner personal data and must survive an owner's
// erasure, even when the term it names coincides with that owner's handle.
//
// The brief framed these records as carrying owner handle strings in metadata
// that the traversal might miss. Reading the emit path shows otherwise: a
// listadmin record names an administrator as actor and the reserved TERM as
// target, with no metadata. It is an administrator's policy act about a word,
// not a fact about a person, and must outlive every owner for accountability
// (ADR-0024). This test seeds exactly such a record, with a term equal to the
// owner's own handle name, and asserts the erasure neither collects the term
// nor rewrites the record.
func TestEraseOwnerLeavesListAdminRecordsStanding(t *testing.T) {
	t.Parallel()
	_, store := newStore(t)
	ctx := context.Background()

	// Seed the owner and its own audit trail. seedOwner registers the handle
	// with name "aname"; the administrator below allowlists that very term, the
	// coincidence gap #38 is about.
	seedWithAudit(t, store, "owner-a", "a")
	const term = "aname"

	em, err := audit.NewEmitter(store.AuditAppender())
	if err != nil {
		t.Fatalf("audit.NewEmitter: %v", err)
	}
	if eerr := em.Emit(ctx, audit.Event{
		ActorType:  domain.ActorTypeAdministrator,
		ActorID:    "admin-1",
		Action:     domain.AuditActionAllowlistEntryAdded,
		TargetType: domain.TargetTypeAllowlistEntry,
		TargetID:   term,
	}); eerr != nil {
		t.Fatalf("emit listadmin record: %v", eerr)
	}

	// The term must not even be discovered by the traversal: it collects owner
	// row IDs, never name strings, so a handle's display name is never in scope.
	collected, err := newGraph(t, store.Repos()).Collect(ctx, "owner-a")
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	for _, id := range collected {
		if id == term {
			t.Fatalf("traversal collected the reserved term %q: a policy record would be erased with the owner", term)
		}
	}

	if _, err := newOwnerEraser(t, store).EraseOwner(ctx, "owner-a"); err != nil {
		t.Fatalf("EraseOwner: %v", err)
	}

	// The administrator's record survives, naming the administrator and the term
	// in the clear: erasing the owner did not reach it.
	var found *domain.AuditRecord
	for _, rec := range listAll(t, store) {
		if rec.Action == domain.AuditActionAllowlistEntryAdded {
			r := rec
			found = &r
			break
		}
	}
	if found == nil {
		t.Fatal("the listadmin record vanished: an administrator's policy act was destroyed by an owner erasure")
	}
	if found.ActorID != "admin-1" {
		t.Errorf("listadmin actor = %q, want admin-1 untouched: the administrator was tombstoned", found.ActorID)
	}
	if found.TargetID != term {
		t.Errorf("listadmin target = %q, want the term %q untouched", found.TargetID, term)
	}
}
