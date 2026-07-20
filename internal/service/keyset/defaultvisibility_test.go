package keyset_test

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/audit"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/service/keyset"
)

// These tests run against the real SQLite adapter for the reason harness_test.go
// gives, and two of the invariants below only exist there: the one-default rule
// is a partial unique index plus an ordered clear-then-set inside the
// repository, and the cross-owner verdict is an owner_id predicate in the query.
// A fake repository would satisfy both by construction and prove neither.

// invented is an identifier no set has, used to establish what a caller with no
// business here is supposed to see.
const invented = domain.KeySetID("INVENTEDIDENTIFIER00000000")

// auditSink collects the records a real audit.Emitter writes.
type auditSink struct{ records []*domain.AuditRecord }

func (s *auditSink) Append(_ context.Context, rec *domain.AuditRecord) error {
	s.records = append(s.records, rec)
	return nil
}

// replay pushes captured events through a real audit.Emitter and returns the
// records it produced. Details keeps its pairs unexported on purpose, so what a
// stored record ends up carrying is the only observable worth asserting on --
// and going through the real emitter means a detail the screen would reject is
// caught here rather than passing because a test read the struct directly.
func replay(t *testing.T, events []audit.Event) []*domain.AuditRecord {
	t.Helper()
	sink := &auditSink{}
	emitter, err := audit.NewEmitter(sink)
	if err != nil {
		t.Fatalf("audit.NewEmitter: %v", err)
	}
	for _, ev := range events {
		if err := emitter.Emit(context.Background(), ev); err != nil {
			t.Fatalf("Emit %s: %v", ev.Action, err)
		}
	}
	return sink.records
}

// recordsFor returns the records of one action, in the order they were emitted.
func recordsFor(records []*domain.AuditRecord, action domain.AuditAction) []*domain.AuditRecord {
	out := make([]*domain.AuditRecord, 0, len(records))
	for _, rec := range records {
		if rec.Action == action {
			out = append(out, rec)
		}
	}
	return out
}

func wantDetail(t *testing.T, rec *domain.AuditRecord, key audit.DetailKey, want string) {
	t.Helper()
	if got := rec.Metadata[string(key)]; got != want {
		t.Errorf("%s record: %s = %q, want %q", rec.Action, key, got, want)
	}
}

// defaultID returns the id of the owner's default set, or "" if there is none.
func (f *fixture) defaultID(owner domain.OwnerID) domain.KeySetID {
	f.t.Helper()
	set, err := f.store.Repos().KeySets.GetDefault(context.Background(), owner)
	if errors.Is(err, domain.ErrNotFound) {
		return ""
	}
	if err != nil {
		f.t.Fatalf("GetDefault(%s): %v", owner, err)
	}
	return set.ID
}

// countDefaults counts the owner's rows carrying the designation, reading every
// row rather than asking GetDefault.
//
// This is the assertion that actually tests the invariant. GetDefault selects
// with LIMIT-like semantics through a single-row scan, so it would return one
// answer just as happily with two rows designated; counting is what makes a
// second default visible.
func (f *fixture) countDefaults(owner domain.OwnerID) int {
	f.t.Helper()
	sets, err := f.store.Repos().KeySets.ListByOwner(context.Background(), owner)
	if err != nil {
		f.t.Fatalf("ListByOwner(%s): %v", owner, err)
	}
	n := 0
	for _, s := range sets {
		if s.IsDefault {
			n++
		}
	}
	return n
}

// tombstone renames a set and returns the id of the row left behind, which is a
// quarantined reserved name rather than an addressable set.
func (f *fixture) tombstone(owner domain.OwnerID, name, to string) domain.KeySetID {
	f.t.Helper()
	set := f.mustCreate(owner, name)
	if _, err := f.svc.Rename(context.Background(), owner, set.ID, to, ""); err != nil {
		f.t.Fatalf("Rename: %v", err)
	}
	return set.ID
}

// TestSetDefaultMovesTheDesignation is the base case: the designation lands on
// the named set and, crucially, leaves the previous holder without it.
func TestSetDefaultMovesTheDesignation(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newFixture(t)

	first := f.mustCreate(ownerA, "prod")
	second := f.mustCreate(ownerA, "staging")

	got, err := f.svc.SetDefault(ctx, ownerA, first.ID, "req-1")
	if err != nil {
		t.Fatalf("SetDefault: %v", err)
	}
	if !got.IsDefault {
		t.Error("the returned set is not marked default; the struct disagrees with the row")
	}
	if id := f.defaultID(ownerA); id != first.ID {
		t.Fatalf("default = %q, want %q", id, first.ID)
	}

	if _, err := f.svc.SetDefault(ctx, ownerA, second.ID, "req-2"); err != nil {
		t.Fatalf("SetDefault (move): %v", err)
	}
	if id := f.defaultID(ownerA); id != second.ID {
		t.Fatalf("default after move = %q, want %q", id, second.ID)
	}
	// The invariant, asserted by counting rather than by asking for one answer.
	if n := f.countDefaults(ownerA); n != 1 {
		t.Fatalf("owner holds %d default sets, want exactly 1", n)
	}
}

// TestSetDefaultIsIdempotent pins that re-designating the set that already holds
// the designation neither fails nor leaves the owner with none. The repository
// clears before it sets, so a clear that ran without its set landing would be
// visible here as zero defaults -- which makes bare GET /{handle} dangle.
func TestSetDefaultIsIdempotent(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newFixture(t)

	set := f.mustCreate(ownerA, "prod")
	for range 3 {
		if _, err := f.svc.SetDefault(ctx, ownerA, set.ID, ""); err != nil {
			t.Fatalf("SetDefault: %v", err)
		}
	}
	if n := f.countDefaults(ownerA); n != 1 {
		t.Fatalf("owner holds %d default sets after re-designating, want exactly 1", n)
	}
	if id := f.defaultID(ownerA); id != set.ID {
		t.Fatalf("default = %q, want %q", id, set.ID)
	}
}

// TestDesignatingANewDefaultFreesTheOldOne is the end-to-end sequence ADR-0016
// describes: the default cannot be deleted, and designating another is the way
// out. If the designation did not actually move, the first set would stay
// undeletable and an owner would have no path to removing it at all.
func TestDesignatingANewDefaultFreesTheOldOne(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newFixture(t)

	first := f.mustCreate(ownerA, "prod")
	second := f.mustCreate(ownerA, "staging")

	if _, err := f.svc.SetDefault(ctx, ownerA, first.ID, ""); err != nil {
		t.Fatalf("SetDefault: %v", err)
	}
	wantErr(t, f.svc.Delete(ctx, ownerA, first.ID, true, ""), keyset.ErrDefaultSet,
		"Delete while still the default")

	if _, err := f.svc.SetDefault(ctx, ownerA, second.ID, ""); err != nil {
		t.Fatalf("SetDefault (move): %v", err)
	}
	if err := f.svc.Delete(ctx, ownerA, first.ID, true, ""); err != nil {
		t.Fatalf("Delete after the designation moved: %v", err)
	}

	if got := f.names(ownerA); !slices.Equal(got, []string{"staging"}) {
		t.Fatalf("List = %v, want [staging]", got)
	}
	// And the owner is left with a default, not without one.
	if n := f.countDefaults(ownerA); n != 1 {
		t.Fatalf("owner holds %d default sets, want exactly 1", n)
	}
}

// TestSetVisibilityMovesBothDirections covers the toggle and, with it, the claim
// that neither direction is the quiet one.
func TestSetVisibilityMovesBothDirections(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newFixture(t)

	set := f.mustCreate(ownerA, "prod")
	if set.Visibility != domain.VisibilityProtected {
		t.Fatalf("created visibility = %q, want protected", set.Visibility)
	}

	pub, err := f.svc.SetVisibility(ctx, ownerA, set.ID, domain.VisibilityPublic, "req-1")
	if err != nil {
		t.Fatalf("SetVisibility(public): %v", err)
	}
	if pub.Visibility != domain.VisibilityPublic {
		t.Errorf("returned visibility = %q, want public", pub.Visibility)
	}
	if pub.ID != set.ID {
		t.Errorf("visibility change replaced the identifier: %q -> %q", set.ID, pub.ID)
	}
	f.requireStoredVisibility(ownerA, set.ID, domain.VisibilityPublic)

	prot, err := f.svc.SetVisibility(ctx, ownerA, set.ID, domain.VisibilityProtected, "req-2")
	if err != nil {
		t.Fatalf("SetVisibility(protected): %v", err)
	}
	if prot.Visibility != domain.VisibilityProtected {
		t.Errorf("returned visibility = %q, want protected", prot.Visibility)
	}
	f.requireStoredVisibility(ownerA, set.ID, domain.VisibilityProtected)

	// Both directions recorded, and recorded distinctly.
	recs := f.visibilityRecords()
	if len(recs) != 2 {
		t.Fatalf("visibility records = %d, want 2 (one per direction)", len(recs))
	}
}

// requireStoredVisibility reads the row back rather than trusting the returned
// struct. A method that set the field on the struct and never wrote it would
// pass every assertion made against its own return value.
func (f *fixture) requireStoredVisibility(owner domain.OwnerID, id domain.KeySetID, want domain.Visibility) {
	f.t.Helper()
	set, err := f.store.Repos().KeySets.Get(context.Background(), owner, id)
	if err != nil {
		f.t.Fatalf("Get(%s): %v", id, err)
	}
	if set.Visibility != want {
		f.t.Fatalf("stored visibility = %q, want %q", set.Visibility, want)
	}
}

// visibilityRecords returns the emitted visibility-change events.
func (f *fixture) visibilityRecords() []audit.Event {
	f.t.Helper()
	f.auditor.mu.Lock()
	defer f.auditor.mu.Unlock()
	var out []audit.Event
	for _, ev := range f.auditor.events {
		if ev.Action == domain.AuditActionKeySetVisibilityChanged {
			out = append(out, ev)
		}
	}
	return out
}

// TestUnknownVisibilityIsRefused is the fail-closed check. The zero value is
// what an absent or malformed field decodes to, so it must not be a visibility
// the service will persist -- otherwise a request that said nothing would move
// the set somewhere.
func TestUnknownVisibilityIsRefused(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newFixture(t)

	set := f.mustCreate(ownerA, "prod")
	if _, err := f.svc.SetVisibility(ctx, ownerA, set.ID, domain.VisibilityPublic, ""); err != nil {
		t.Fatalf("SetVisibility: %v", err)
	}

	for _, v := range []domain.Visibility{"", "PUBLIC", "private", "public ", "unlisted"} {
		_, err := f.svc.SetVisibility(ctx, ownerA, set.ID, v, "")
		wantErr(t, err, domain.ErrInvalidInput, "SetVisibility("+string(v)+")")
		// The stored value is unchanged: a refusal must not be a partial write.
		f.requireStoredVisibility(ownerA, set.ID, domain.VisibilityPublic)
	}
	if n := len(f.visibilityRecords()); n != 1 {
		t.Errorf("visibility records = %d, want 1; a refused change was recorded", n)
	}
}

// TestTombstonesAreNotAddressable is the invariant that lives entirely in the
// service. Neither repository method carries a state predicate -- SetDefault's
// UPDATE is scoped by id and owner_id only, and Update's is too -- so without
// live() the adapter would point bare GET /{handle} at a reserved name, or
// rewrite the visibility of a row nothing resolves through.
func TestTombstonesAreNotAddressable(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("default", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t)
		dead := f.tombstone(ownerA, "prod", "production")

		_, gone := f.svc.SetDefault(ctx, ownerA, dead, "")
		_, unknown := f.svc.SetDefault(ctx, ownerA, invented, "")
		requireIndistinguishable(t, gone, unknown)

		if n := f.countDefaults(ownerA); n != 0 {
			t.Fatalf("%d sets are designated default after a refused designation, want 0", n)
		}
	})

	t.Run("visibility", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t)
		dead := f.tombstone(ownerA, "prod", "production")

		_, gone := f.svc.SetVisibility(ctx, ownerA, dead, domain.VisibilityPublic, "")
		_, unknown := f.svc.SetVisibility(ctx, ownerA, invented, domain.VisibilityPublic, "")
		requireIndistinguishable(t, gone, unknown)

		f.requireStoredVisibility(ownerA, dead, domain.VisibilityProtected)
	})
}

// TestCrossOwnerDefaultAndVisibility repeats the isolation check for the two new
// operations: B acting on A's set must get the answer an invented identifier
// gets, and must leave A's state exactly as it found it.
func TestCrossOwnerDefaultAndVisibility(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("default", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t)
		set := f.mustCreate(ownerA, "prod")

		_, foreign := f.svc.SetDefault(ctx, ownerB, set.ID, "")
		_, unknown := f.svc.SetDefault(ctx, ownerB, invented, "")
		requireIndistinguishable(t, foreign, unknown)

		// Nothing was designated, for either owner. A cross-owner write that
		// landed would have made A's set the default -- and, because the clear
		// is owner-scoped, could also have cleared B's own.
		if n := f.countDefaults(ownerA); n != 0 {
			t.Errorf("A holds %d defaults after B's attempt, want 0", n)
		}
		if n := f.countDefaults(ownerB); n != 0 {
			t.Errorf("B holds %d defaults after its attempt, want 0", n)
		}
	})

	t.Run("default does not clear the target owner's own", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t)
		mine := f.mustCreate(ownerA, "prod")
		if _, err := f.svc.SetDefault(ctx, ownerA, mine.ID, ""); err != nil {
			t.Fatalf("SetDefault: %v", err)
		}

		// B aims at A's set. The repository's clear is owner-scoped, so even a
		// designation that somehow got past live() could not touch A's row --
		// but the refusal must come first, and A must keep its default.
		if _, err := f.svc.SetDefault(ctx, ownerB, mine.ID, ""); !errors.Is(err, keyset.ErrNotFound) {
			t.Fatalf("B designating A's set = %v, want ErrNotFound", err)
		}
		if id := f.defaultID(ownerA); id != mine.ID {
			t.Errorf("A's default = %q, want %q; B's attempt disturbed it", id, mine.ID)
		}
		if n := f.countDefaults(ownerB); n != 0 {
			t.Errorf("B holds %d defaults, want 0", n)
		}
	})

	t.Run("visibility", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t)
		set := f.mustCreate(ownerA, "prod")

		_, foreign := f.svc.SetVisibility(ctx, ownerB, set.ID, domain.VisibilityPublic, "")
		_, unknown := f.svc.SetVisibility(ctx, ownerB, invented, domain.VisibilityPublic, "")
		requireIndistinguishable(t, foreign, unknown)

		// The sharp end: a cross-owner visibility change that landed would
		// publish A's keys at A's URL on B's say-so.
		f.requireStoredVisibility(ownerA, set.ID, domain.VisibilityProtected)
	})
}

// TestDefaultAndVisibilityRefuseAnEmptyOwnerOrID covers the two arguments that
// must never be defaulted. An empty owner would act on a set belonging to
// nobody; an empty id names no set and collapses into the same verdict a wrong
// one gets, so a caller cannot learn which shapes are well formed.
func TestDefaultAndVisibilityRefuseAnEmptyOwnerOrID(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newFixture(t)

	_, err := f.svc.SetDefault(ctx, "", "some-id", "")
	wantErr(t, err, domain.ErrInvalidInput, "SetDefault with no owner")
	_, err = f.svc.SetVisibility(ctx, "", "some-id", domain.VisibilityPublic, "")
	wantErr(t, err, domain.ErrInvalidInput, "SetVisibility with no owner")

	_, err = f.svc.SetDefault(ctx, ownerA, "", "")
	wantErr(t, err, keyset.ErrNotFound, "SetDefault with no id")
	_, err = f.svc.SetVisibility(ctx, ownerA, "", domain.VisibilityPublic, "")
	wantErr(t, err, keyset.ErrNotFound, "SetVisibility with no id")
}

// TestDefaultAndVisibilityAreAudited holds the two operations to ADR-0007. Both
// are access-affecting -- one repoints the bare handle, the other changes who
// may resolve the set -- so a failure to record is returned to the caller and
// not swallowed.
func TestDefaultAndVisibilityAreAudited(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("records carry the before and after", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t)
		first := f.mustCreate(ownerA, "prod")
		second := f.mustCreate(ownerA, "staging")

		if _, err := f.svc.SetDefault(ctx, ownerA, first.ID, ""); err != nil {
			t.Fatalf("SetDefault: %v", err)
		}
		if _, err := f.svc.SetDefault(ctx, ownerA, second.ID, ""); err != nil {
			t.Fatalf("SetDefault (move): %v", err)
		}
		if _, err := f.svc.SetVisibility(ctx, ownerA, second.ID, domain.VisibilityPublic, ""); err != nil {
			t.Fatalf("SetVisibility: %v", err)
		}

		want := []domain.AuditAction{
			domain.AuditActionKeySetCreated,
			domain.AuditActionKeySetCreated,
			domain.AuditActionKeySetDefaultChanged,
			domain.AuditActionKeySetDefaultChanged,
			domain.AuditActionKeySetVisibilityChanged,
		}
		if got := f.auditor.actions(); !slices.Equal(got, want) {
			t.Fatalf("audit actions = %v, want %v", got, want)
		}

		// The action alone is not the record. What makes one readable in an
		// incident review is which set took the designation and which one gave
		// it up, and which direction a visibility moved, so the details are
		// asserted by value rather than merely counted.
		records := replay(t, f.auditor.captured())
		moves := recordsFor(records, domain.AuditActionKeySetDefaultChanged)
		wantDetail(t, moves[0], audit.DetailTo, "prod")
		if got, ok := moves[0].Metadata[string(audit.DetailFrom)]; ok {
			// The first designation has no predecessor to name, and the audit
			// screen refuses an empty value, so the key is omitted rather than
			// carrying something a reader could mistake for a set's name.
			t.Errorf("the first designation recorded from=%q; there was no previous default", got)
		}
		wantDetail(t, moves[1], audit.DetailFrom, "prod")
		wantDetail(t, moves[1], audit.DetailTo, "staging")

		vis := recordsFor(records, domain.AuditActionKeySetVisibilityChanged)[0]
		wantDetail(t, vis, audit.DetailFrom, string(domain.VisibilityProtected))
		wantDetail(t, vis, audit.DetailTo, string(domain.VisibilityPublic))
		wantDetail(t, vis, audit.DetailVisibility, string(domain.VisibilityPublic))
		wantDetail(t, vis, audit.DetailKeySetName, "staging")
	})

	t.Run("a failure to record is returned", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t)
		set := f.mustCreate(ownerA, "prod")
		sentinel := errors.New("audit sink down")
		f.auditor.fail(sentinel)

		if _, err := f.svc.SetDefault(ctx, ownerA, set.ID, ""); !errors.Is(err, sentinel) {
			t.Errorf("SetDefault with a failing auditor = %v, want the sink error", err)
		}
		if _, err := f.svc.SetVisibility(ctx, ownerA, set.ID, domain.VisibilityPublic, ""); !errors.Is(err, sentinel) {
			t.Errorf("SetVisibility with a failing auditor = %v, want the sink error", err)
		}
	})
}
