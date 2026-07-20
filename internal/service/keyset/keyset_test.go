package keyset_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/service/keyset"
)

func TestCreateListRenameDeleteRoundTrip(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newFixture(t)

	set := f.mustCreate(ownerA, "prod")
	if set.Name != "prod" {
		t.Errorf("created name = %q, want prod", set.Name)
	}
	// A new set is protected and not the default. Both are C4's decisions, and
	// a create that quietly made either one would publish keys the owner never
	// asked to publish.
	if set.Visibility != domain.VisibilityProtected {
		t.Errorf("created visibility = %q, want protected", set.Visibility)
	}
	if set.IsDefault {
		t.Error("a newly created set is the default; nothing asked for that")
	}
	if set.State != domain.NameStateActive {
		t.Errorf("created state = %q, want active", set.State)
	}

	if got := f.names(ownerA); !slices.Equal(got, []string{"prod"}) {
		t.Fatalf("List after create = %v, want [prod]", got)
	}

	renamed, err := f.svc.Rename(ctx, ownerA, set.ID, "production", "req-2")
	if err != nil {
		t.Fatalf("Rename: %v", err)
	}
	if renamed.Name != "production" {
		t.Errorf("renamed name = %q, want production", renamed.Name)
	}
	// The identifier changes: a row's name is immutable, so a rename is a new
	// row plus a tombstone. A client that kept the old id must re-read.
	if renamed.ID == set.ID {
		t.Error("rename reused the identifier; the row name is supposed to be immutable")
	}
	if got := f.names(ownerA); !slices.Equal(got, []string{"production"}) {
		t.Fatalf("List after rename = %v, want [production]", got)
	}

	if err := f.svc.Delete(ctx, ownerA, renamed.ID, false, "req-3"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if got := f.names(ownerA); len(got) != 0 {
		t.Fatalf("List after delete = %v, want empty", got)
	}

	want := []domain.AuditAction{
		domain.AuditActionKeySetCreated,
		domain.AuditActionKeySetRenamed,
		domain.AuditActionKeySetDeleted,
	}
	if got := f.auditor.actions(); !slices.Equal(got, want) {
		t.Errorf("audit actions = %v, want %v", got, want)
	}
}

// TestEmptyListReturnsNilSlice pins the repository's nil-collection convention
// at the service boundary. The transport is what turns nil into "[]"; if the
// service started returning an allocated empty slice, the two layers would
// disagree about which one owns that decision.
func TestEmptyListReturnsNilSlice(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	sets, err := f.svc.List(context.Background(), ownerA)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if sets != nil {
		t.Errorf("List = %#v, want a nil slice", sets)
	}
}

// TestListOmitsQuarantinedTombstones checks that a freed name is not presented
// as a set. It is not addressable, not publishable, and showing it would put a
// row in the owner's inventory that every other operation answers 404 for.
func TestListOmitsQuarantinedTombstones(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newFixture(t)

	set := f.mustCreate(ownerA, "prod")
	if _, err := f.svc.Rename(ctx, ownerA, set.ID, "production", ""); err != nil {
		t.Fatalf("Rename: %v", err)
	}

	if got := f.names(ownerA); !slices.Equal(got, []string{"production"}) {
		t.Errorf("List = %v, want only the live set", got)
	}
	// The tombstone is still in storage — that is what reserves the name.
	all, err := f.store.Repos().KeySets.ListByOwner(ctx, ownerA)
	if err != nil {
		t.Fatalf("ListByOwner: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("stored rows = %d, want 2 (the live set and its tombstone)", len(all))
	}
}

func TestNameValidation(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	// The boundaries are exercised at exactly 1 and exactly 64, and at 65,
	// because an off-by-one in the length rule is the failure this table
	// exists to catch.
	valid := []string{"a", "1", strings.Repeat("a", 64), "web-prod-01"}
	invalid := []string{
		"",                      // empty
		strings.Repeat("a", 65), // one over the bound
		"Prod",                  // uppercase
		"-lead",                 // leading hyphen
		"trail-",                // trailing hyphen
		"has space",             // charset
		"under_score",           // charset
		"dot.name",              // charset
		"emoji-\U0001F600",      // non-ASCII
		"tab\tname",             // control character
	}

	for _, name := range valid {
		f := newFixture(t)
		if _, err := f.svc.Create(ctx, ownerA, name, ""); err != nil {
			t.Errorf("Create(%q) = %v, want success", name, err)
		}
	}
	for _, name := range invalid {
		f := newFixture(t)
		_, err := f.svc.Create(ctx, ownerA, name, "")
		if !errors.Is(err, domain.ErrInvalidInput) {
			t.Errorf("Create(%q) error = %v, want ErrInvalidInput", name, err)
		}
	}
}

// TestBlockedNameIsRefused proves the reserved-identifier blocklist is actually
// reached from this code path, rather than merely being importable from it. It
// uses a name that passes every syntax rule, so only the blocklist can refuse
// it — and a confusable spelling too, so the refusal is the matcher's skeleton
// comparison rather than a literal string equality that a different spelling
// would slip past.
func TestBlockedNameIsRefused(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	for _, name := range []string{"admin", "adm1n", "ad-min"} {
		f := newFixture(t)
		_, err := f.svc.Create(ctx, ownerA, name, "")
		wantErr(t, err, domain.ErrBlockedName, "Create("+name+")")
	}
}

// TestRenameIsBlocklistCheckedToo closes the bypass a create-only check would
// leave: claim a permitted name, then rename onto a blocked one.
func TestRenameIsBlocklistCheckedToo(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newFixture(t)

	set := f.mustCreate(ownerA, "prod")
	_, err := f.svc.Rename(ctx, ownerA, set.ID, "admin", "")
	wantErr(t, err, domain.ErrBlockedName, "Rename onto a blocked name")

	// The original is untouched: a refused rename must not half-apply.
	if got := f.names(ownerA); !slices.Equal(got, []string{"prod"}) {
		t.Errorf("List after refused rename = %v, want [prod]", got)
	}
}

func TestDuplicateNameIsRefused(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newFixture(t)

	f.mustCreate(ownerA, "prod")
	_, err := f.svc.Create(ctx, ownerA, "prod", "")
	wantErr(t, err, keyset.ErrDuplicate, "Create a duplicate name")

	// A different owner may hold the same name: set names are unique per owner,
	// not globally. If this failed, one owner could deny a name to every other.
	if _, err := f.svc.Create(ctx, ownerB, "prod", ""); err != nil {
		t.Errorf("another owner cannot use the same name: %v", err)
	}
}

// TestQuarantinedNameStaysReserved is the mechanism behind ADR-0016's
// re-registration rule: a freed name must not be reclaimable while consumers
// may still be polling its URL.
func TestQuarantinedNameStaysReserved(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newFixture(t)

	set := f.mustCreate(ownerA, "prod")
	if _, err := f.svc.Rename(ctx, ownerA, set.ID, "production", ""); err != nil {
		t.Fatalf("Rename: %v", err)
	}

	_, err := f.svc.Create(ctx, ownerA, "prod", "")
	wantErr(t, err, keyset.ErrDuplicate, "re-creating a quarantined name")

	// The tombstone carries the window it is held for.
	all, err := f.store.Repos().KeySets.ListByOwner(ctx, ownerA)
	if err != nil {
		t.Fatalf("ListByOwner: %v", err)
	}
	for _, s := range all {
		if s.Name != "prod" {
			continue
		}
		if s.State != domain.NameStateQuarantined {
			t.Errorf("freed name state = %q, want quarantined", s.State)
		}
		if s.QuarantineUntil == nil || !s.QuarantineUntil.After(fixedNow) {
			t.Errorf("freed name QuarantineUntil = %v, want a future time", s.QuarantineUntil)
		}
	}
}

// TestMaxSetsPerOwnerCap uses a small configured cap rather than creating 100
// sets, so the test is fast; the boundary logic is the same either way. The
// default is asserted separately below so a change to it cannot pass unnoticed.
func TestMaxSetsPerOwnerCap(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newFixture(t, keyset.WithMaxSets(3))

	for _, name := range []string{"one", "two", "three"} {
		f.mustCreate(ownerA, name)
	}
	_, err := f.svc.Create(ctx, ownerA, "four", "")
	wantErr(t, err, keyset.ErrLimitExceeded, "Create past the cap")

	// The cap is per owner, not global: another owner is unaffected.
	if _, err := f.svc.Create(ctx, ownerB, "four", ""); err != nil {
		t.Errorf("another owner hit A's cap: %v", err)
	}

	// Freeing a slot lets a create through again, so the cap is a live count
	// and not a high-water mark.
	sets, err := f.svc.List(ctx, ownerA)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if err := f.svc.Delete(ctx, ownerA, sets[0].ID, false, ""); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := f.svc.Create(ctx, ownerA, "four", ""); err != nil {
		t.Errorf("Create after freeing a slot: %v", err)
	}
}

func TestDefaultMaxSetsIsOneHundred(t *testing.T) {
	t.Parallel()
	if keyset.DefaultMaxSets != 100 {
		t.Errorf("DefaultMaxSets = %d, want 100 (ADR-0016)", keyset.DefaultMaxSets)
	}
}

// TestCapCountsQuarantinedTombstones records the deliberate reading of the
// KeySetRepository contract: CountByOwner counts every row. Excluding
// tombstones would let an owner hold unboundedly many reserved names by
// renaming in a loop, which is the enumeration bloat the cap exists to stop.
func TestCapCountsQuarantinedTombstones(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newFixture(t, keyset.WithMaxSets(2))

	set := f.mustCreate(ownerA, "one")
	// Renaming turns one row into two: the live set and its tombstone.
	if _, err := f.svc.Rename(ctx, ownerA, set.ID, "uno", ""); err != nil {
		t.Fatalf("Rename: %v", err)
	}
	_, err := f.svc.Create(ctx, ownerA, "two", "")
	wantErr(t, err, keyset.ErrLimitExceeded, "Create with a tombstone occupying a slot")
}

// TestDefaultSetIsNotDeletable is the invariant that keeps bare GET /{handle}
// from dangling.
func TestDefaultSetIsNotDeletable(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newFixture(t)

	set := f.mustCreate(ownerA, "prod")
	f.makeDefault(ownerA, set.ID)

	// Confirmed or not, empty or not, the default is refused.
	for _, confirm := range []bool{false, true} {
		err := f.svc.Delete(ctx, ownerA, set.ID, confirm, "")
		wantErr(t, err, keyset.ErrDefaultSet, "Delete the default set")
	}
	if got := f.names(ownerA); !slices.Equal(got, []string{"prod"}) {
		t.Fatalf("the default set was deleted: List = %v", got)
	}

	// Nothing was deleted, so nothing may have been recorded as deleted.
	if slices.Contains(f.auditor.actions(), domain.AuditActionKeySetDeleted) {
		t.Error("a refused delete emitted a deletion record")
	}
}

// TestRenamingTheDefaultCarriesTheDesignation is the indirect route to the same
// dangle: quarantine the default's row without moving the designation and bare
// GET /{handle} resolves to a set that is no longer live.
func TestRenamingTheDefaultCarriesTheDesignation(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newFixture(t)

	set := f.mustCreate(ownerA, "prod")
	f.makeDefault(ownerA, set.ID)

	renamed, err := f.svc.Rename(ctx, ownerA, set.ID, "production", "")
	if err != nil {
		t.Fatalf("Rename: %v", err)
	}
	if !renamed.IsDefault {
		t.Error("the returned set is not the default; the designation was dropped")
	}

	got, err := f.store.Repos().KeySets.GetDefault(ctx, ownerA)
	if err != nil {
		t.Fatalf("GetDefault after renaming the default: %v", err)
	}
	if got.ID != renamed.ID {
		t.Errorf("default is %q, want the renamed set %q", got.ID, renamed.ID)
	}
	if got.State != domain.NameStateActive {
		t.Errorf("default state = %q, want active; the default must never be a tombstone", got.State)
	}
	// And it is still undeletable through its new identity.
	wantErr(t, f.svc.Delete(ctx, ownerA, renamed.ID, true, ""), keyset.ErrDefaultSet,
		"Delete the renamed default")
}

// TestRenameMovesMembership checks the composition does not silently empty a
// set. A rename that lost its members would publish an empty authorized_keys
// at the new URL, locking every server that polls it out.
func TestRenameMovesMembership(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newFixture(t)

	set := f.mustCreate(ownerA, "prod")
	f.addMember(ownerA, set.ID, "key-one")
	f.addMember(ownerA, set.ID, "key-two")

	renamed, err := f.svc.Rename(ctx, ownerA, set.ID, "production", "")
	if err != nil {
		t.Fatalf("Rename: %v", err)
	}

	members, err := f.store.Repos().KeySets.ListMembers(ctx, ownerA, renamed.ID)
	if err != nil {
		t.Fatalf("ListMembers: %v", err)
	}
	if len(members) != 2 {
		t.Fatalf("members after rename = %d, want 2", len(members))
	}
}

func TestNonEmptyDeleteRequiresConfirmation(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newFixture(t)

	set := f.mustCreate(ownerA, "prod")
	f.addMember(ownerA, set.ID, "key-one")

	err := f.svc.Delete(ctx, ownerA, set.ID, false, "")
	wantErr(t, err, keyset.ErrConfirmationRequired, "unconfirmed delete of a non-empty set")
	if got := f.names(ownerA); !slices.Equal(got, []string{"prod"}) {
		t.Fatalf("the set was deleted without confirmation: List = %v", got)
	}

	if err := f.svc.Delete(ctx, ownerA, set.ID, true, ""); err != nil {
		t.Fatalf("confirmed delete: %v", err)
	}
	if got := f.names(ownerA); len(got) != 0 {
		t.Fatalf("List after confirmed delete = %v, want empty", got)
	}

	// The keys themselves survive: they belong to their device and may belong
	// to other sets. Deleting a set must never delete key material.
	keys, err := f.store.Repos().PublicKeys.ListByOwner(ctx, ownerA)
	if err != nil {
		t.Fatalf("PublicKeys.ListByOwner: %v", err)
	}
	if len(keys) != 1 {
		t.Errorf("public keys after deleting their set = %d, want 1", len(keys))
	}
}

// TestEmptyDeleteNeedsNoConfirmation keeps the confirmation from becoming a
// blanket requirement: it is scoped to the case ADR-0016 names.
func TestEmptyDeleteNeedsNoConfirmation(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	set := f.mustCreate(ownerA, "prod")
	if err := f.svc.Delete(context.Background(), ownerA, set.ID, false, ""); err != nil {
		t.Fatalf("Delete an empty set without confirmation: %v", err)
	}
}

// TestCrossOwnerIsolation is the security test this package exists for.
//
// For every method, B addressing A's set must produce EXACTLY what B addressing
// an invented identifier produces. The assertion is deliberately on the pair
// being equal, not on either being 404: if a future change made both into some
// other answer, the property that matters — indistinguishability — would still
// hold, and if only one changed the test fails, which is the direction that
// matters.
func TestCrossOwnerIsolation(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	const invented = domain.KeySetID("INVENTEDIDENTIFIER00000000")

	t.Run("rename", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t)
		set := f.mustCreate(ownerA, "prod")

		_, foreign := f.svc.Rename(ctx, ownerB, set.ID, "stolen", "")
		_, unknown := f.svc.Rename(ctx, ownerB, invented, "stolen", "")
		requireIndistinguishable(t, foreign, unknown)

		// A's set is untouched, and the name B tried to take is not claimed.
		if got := f.names(ownerA); !slices.Equal(got, []string{"prod"}) {
			t.Errorf("A's sets after B's rename attempt = %v, want [prod]", got)
		}
		if got := f.names(ownerB); len(got) != 0 {
			t.Errorf("B gained a set from the attempt: %v", got)
		}
	})

	t.Run("delete", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t)
		set := f.mustCreate(ownerA, "prod")

		foreign := f.svc.Delete(ctx, ownerB, set.ID, true, "")
		unknown := f.svc.Delete(ctx, ownerB, invented, true, "")
		requireIndistinguishable(t, foreign, unknown)

		if got := f.names(ownerA); !slices.Equal(got, []string{"prod"}) {
			t.Errorf("A's sets after B's delete attempt = %v, want [prod]", got)
		}
	})

	// A's DEFAULT set is the sharpest case: for A it answers ErrDefaultSet, so
	// if the guard were reached before the owner check, B could learn which of
	// A's sets is the default by comparing the two refusals.
	t.Run("delete A's default", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t)
		set := f.mustCreate(ownerA, "prod")
		f.makeDefault(ownerA, set.ID)

		foreign := f.svc.Delete(ctx, ownerB, set.ID, true, "")
		unknown := f.svc.Delete(ctx, ownerB, invented, true, "")
		requireIndistinguishable(t, foreign, unknown)
		if errors.Is(foreign, keyset.ErrDefaultSet) {
			t.Error("B learned that A's set is A's default")
		}
	})

	// A's NON-EMPTY set is the same trap on the other refusal: an unconfirmed
	// delete of A's non-empty set must not tell B that it has members.
	t.Run("unconfirmed delete of A's non-empty set", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t)
		set := f.mustCreate(ownerA, "prod")
		f.addMember(ownerA, set.ID, "key-one")

		foreign := f.svc.Delete(ctx, ownerB, set.ID, false, "")
		unknown := f.svc.Delete(ctx, ownerB, invented, false, "")
		requireIndistinguishable(t, foreign, unknown)
		if errors.Is(foreign, keyset.ErrConfirmationRequired) {
			t.Error("B learned that A's set has members")
		}
	})

	t.Run("list", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t)
		f.mustCreate(ownerA, "prod")

		if got := f.names(ownerB); len(got) != 0 {
			t.Errorf("B's list contains A's sets: %v", got)
		}
	})

	// A tombstone is addressable by nobody, including its own owner. It is a
	// reserved name, not a set.
	t.Run("owner's own tombstone", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t)
		set := f.mustCreate(ownerA, "prod")
		if _, err := f.svc.Rename(ctx, ownerA, set.ID, "production", ""); err != nil {
			t.Fatalf("Rename: %v", err)
		}

		tombstone := f.svc.Delete(ctx, ownerA, set.ID, true, "")
		unknown := f.svc.Delete(ctx, ownerA, invented, true, "")
		requireIndistinguishable(t, tombstone, unknown)
	})
}

// requireIndistinguishable asserts two refusals are the same answer. Comparing
// the messages as well as the sentinel matters: a message that named the set,
// or that differed between "yours" and "no such thing", would be an oracle even
// with an identical sentinel.
func requireIndistinguishable(t *testing.T, foreign, unknown error) {
	t.Helper()
	if foreign == nil || unknown == nil {
		t.Fatalf("expected refusals, got foreign=%v unknown=%v", foreign, unknown)
	}
	if !errors.Is(foreign, keyset.ErrNotFound) {
		t.Errorf("another owner's set answered %v, want ErrNotFound", foreign)
	}
	if foreign.Error() != unknown.Error() {
		t.Errorf("another owner's set is distinguishable:\n  foreign = %q\n  unknown = %q",
			foreign.Error(), unknown.Error())
	}
}

// TestEmptyOwnerIsRefused covers the argument that must never be defaulted. An
// empty owner would produce a set belonging to nobody, reachable by any other
// request that also failed to carry one.
func TestEmptyOwnerIsRefused(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newFixture(t)

	_, err := f.svc.Create(ctx, "", "prod", "")
	wantErr(t, err, domain.ErrInvalidInput, "Create with no owner")
	_, err = f.svc.List(ctx, "")
	wantErr(t, err, domain.ErrInvalidInput, "List with no owner")
	_, err = f.svc.Rename(ctx, "", "some-id", "prod", "")
	wantErr(t, err, domain.ErrInvalidInput, "Rename with no owner")
	wantErr(t, f.svc.Delete(ctx, "", "some-id", true, ""), domain.ErrInvalidInput,
		"Delete with no owner")
}

// TestEmptyIDIsNotFound folds an empty identifier into the same verdict a wrong
// one gets, so a caller cannot learn which shapes are well formed.
func TestEmptyIDIsNotFound(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newFixture(t)

	_, err := f.svc.Rename(ctx, ownerA, "", "prod", "")
	wantErr(t, err, keyset.ErrNotFound, "Rename with an empty id")
	wantErr(t, f.svc.Delete(ctx, ownerA, "", true, ""), keyset.ErrNotFound,
		"Delete with an empty id")
}

// TestAuditFailureIsReturned pins that a change with no accountability trail is
// reported rather than swallowed. It is not a partial success: the caller is
// told, and the operator sees a failure rather than a silent gap in the log.
func TestAuditFailureIsReturned(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newFixture(t)

	f.auditor.fail(errors.New("audit sink down"))
	if _, err := f.svc.Create(ctx, ownerA, "prod", ""); err == nil {
		t.Error("Create succeeded although the change could not be recorded")
	}
}

func TestNewRefusesMissingDependencies(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	if _, err := keyset.New(nil, mustGuard(t), f.auditor); !errors.Is(err, keyset.ErrMissingDependency) {
		t.Errorf("New with no store: %v, want ErrMissingDependency", err)
	}
	if _, err := keyset.New(f.store, nil, f.auditor); !errors.Is(err, keyset.ErrMissingDependency) {
		t.Errorf("New with no guard: %v, want ErrMissingDependency", err)
	}
	if _, err := keyset.New(f.store, mustGuard(t), nil); !errors.Is(err, keyset.ErrMissingDependency) {
		t.Errorf("New with no auditor: %v, want ErrMissingDependency", err)
	}
	if _, err := keyset.New(f.store, mustGuard(t), f.auditor, nil); !errors.Is(err, keyset.ErrMissingDependency) {
		t.Errorf("New with a nil option: %v, want ErrMissingDependency", err)
	}
}

// TestDegenerateOptionsAreIgnored covers the direction that silently removes a
// control: a cap of zero refuses everything, a negative one is always under the
// limit, and a zero quarantine window frees a name immediately.
func TestDegenerateOptionsAreIgnored(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	for _, n := range []int{0, -1} {
		f := newFixture(t, keyset.WithMaxSets(n))
		if _, err := f.svc.Create(ctx, ownerA, "prod", ""); err != nil {
			t.Errorf("WithMaxSets(%d) broke Create: %v", n, err)
		}
	}
	for _, d := range []time.Duration{0, -time.Hour} {
		f := newFixture(t, keyset.WithQuarantineWindow(d))
		set := f.mustCreate(ownerA, "prod")
		if _, err := f.svc.Rename(ctx, ownerA, set.ID, "production", ""); err != nil {
			t.Fatalf("Rename: %v", err)
		}
		_, err := f.svc.Create(ctx, ownerA, "prod", "")
		wantErr(t, err, keyset.ErrDuplicate, "re-creating a freed name with a degenerate window")
	}
}

// TestDeleteWithUnrecordableDetailKeepsTheSet pins the ordering of the audit
// details against the write in Delete.
//
// The details must be built inside the transaction, before the row is removed,
// so that a value the audit screen refuses aborts the delete. Building them
// afterwards is the failure this test exists to catch: the row is already gone
// and committed, the caller gets an error, and the deletion is never audited --
// a set that vanished with no record of who removed it or what it was called.
//
// requestID is the value that makes this reachable. The set name was screened
// when the set was created, but requestID comes straight from the caller and
// reaches the audit screen for the first time on this path, so a caller can
// genuinely drive setDetails into refusing.
//
// Both halves are asserted. Checking only that an error came back would pass
// against the broken ordering, which also returns an error -- it just returns
// it after destroying the row.
func TestDeleteWithUnrecordableDetailKeepsTheSet(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newFixture(t)

	set := f.mustCreate(ownerA, "prod")

	// Longer than the audit package's per-value limit, so the screen refuses it
	// for a reason that does not depend on any character-class rule.
	unrecordable := strings.Repeat("r", 300)

	err := f.svc.Delete(ctx, ownerA, set.ID, false, unrecordable)
	wantErr(t, err, domain.ErrInvalidInput, "Delete with an unrecordable request id")

	// The assertion that matters: the transaction rolled back, so the set is
	// still there to be deleted properly once the caller sends a request id
	// that can be recorded.
	if got := f.names(ownerA); !slices.Contains(got, "prod") {
		t.Errorf("live sets = %v, want the set to survive a refused delete", got)
	}
	if _, err := f.store.Repos().KeySets.Get(ctx, ownerA, set.ID); err != nil {
		t.Errorf("Get after a refused delete: %v, want the row to still exist", err)
	}

	// Nothing was removed, so nothing may be recorded as removed.
	if got := f.auditor.actions(); slices.Contains(got, domain.AuditActionKeySetDeleted) {
		t.Errorf("audit actions = %v, want no delete recorded when nothing was deleted", got)
	}

	// The set is still deletable: the refusal cost the caller nothing but the
	// bad request id.
	if err := f.svc.Delete(ctx, ownerA, set.ID, false, "req-ok"); err != nil {
		t.Fatalf("Delete with a recordable request id: %v", err)
	}
}
