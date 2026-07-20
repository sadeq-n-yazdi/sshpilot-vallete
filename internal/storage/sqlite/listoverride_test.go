package sqlite

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/repository"
)

func newListOverrideRepo(t *testing.T) (*listOverrideRepo, *Store) {
	t.Helper()
	s := newStore(t)
	return &listOverrideRepo{e: s.db}, s
}

// testOverride builds a valid override with a fixed, distinguishable timestamp,
// so a round-trip assertion cannot pass by comparing two zero values.
func testOverride(kind domain.ListKind, skeleton, entry string, state domain.ListOverrideState) *domain.ListOverride {
	return &domain.ListOverride{
		List:      kind,
		Skeleton:  skeleton,
		Entry:     entry,
		State:     state,
		ActorID:   "adm-1",
		UpdatedAt: time.Date(2026, 7, 20, 9, 30, 0, 0, time.UTC),
	}
}

func TestListOverridePutAndListRoundTrips(t *testing.T) {
	t.Parallel()
	repo, _ := newListOverrideRepo(t)
	ctx := context.Background()

	want := testOverride(domain.ListKindAllowlist, "admin", "Admin", domain.ListOverridePresent)
	if err := repo.Put(ctx, want); err != nil {
		t.Fatalf("Put: %v", err)
	}

	got, err := repo.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("List returned %d overrides, want 1", len(got))
	}
	o := got[0]
	if o.List != want.List || o.Skeleton != want.Skeleton || o.Entry != want.Entry {
		t.Errorf("List[0] = %+v, want %+v", o, want)
	}
	if o.State != want.State || o.ActorID != want.ActorID {
		t.Errorf("state/actor = %q/%q, want %q/%q", o.State, o.ActorID, want.State, want.ActorID)
	}
	if !o.UpdatedAt.Equal(want.UpdatedAt) {
		t.Errorf("UpdatedAt = %v, want %v", o.UpdatedAt, want.UpdatedAt)
	}
}

// TestListOverrideRetainsRawSpellingOnATombstone pins that a removal keeps the
// word the administrator typed. A tombstone carrying only a skeleton would
// leave a reviewer unable to see what was removed, and a skeleton must never be
// displayed as the thing that was decided.
func TestListOverrideRetainsRawSpellingOnATombstone(t *testing.T) {
	t.Parallel()
	repo, _ := newListOverrideRepo(t)
	ctx := context.Background()

	tomb := testOverride(domain.ListKindAllowlist, "admin", "Admin", domain.ListOverrideRemoved)
	if err := repo.Put(ctx, tomb); err != nil {
		t.Fatalf("Put: %v", err)
	}

	got, err := repo.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 1 || got[0].State != domain.ListOverrideRemoved {
		t.Fatalf("List = %+v, want one removed override", got)
	}
	if got[0].Entry != "Admin" {
		t.Errorf("tombstone entry = %q, want the raw spelling %q", got[0].Entry, "Admin")
	}
}

// TestListOverridePutReplacesTheSameEntry pins the upsert. An entry that is
// added, removed, and added again must stay one row carrying its current state,
// so no reader of this table can ever see a stale decision.
func TestListOverridePutReplacesTheSameEntry(t *testing.T) {
	t.Parallel()
	repo, _ := newListOverrideRepo(t)
	ctx := context.Background()

	states := []domain.ListOverrideState{
		domain.ListOverridePresent,
		domain.ListOverrideRemoved,
		domain.ListOverridePresent,
	}
	for _, st := range states {
		if err := repo.Put(ctx, testOverride(domain.ListKindAllowlist, "admin", "Admin", st)); err != nil {
			t.Fatalf("Put(%s): %v", st, err)
		}
	}

	got, err := repo.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("List returned %d overrides, want 1 after three Puts of one entry", len(got))
	}
	if got[0].State != domain.ListOverridePresent {
		t.Errorf("state = %q, want the last decision %q", got[0].State, domain.ListOverridePresent)
	}
}

// TestListOverrideKindsAreIndependent pins that the two lists do not collide.
// The same skeleton may legitimately be allowlisted and blocklisted, and the
// primary key spans both columns so one cannot overwrite the other.
func TestListOverrideKindsAreIndependent(t *testing.T) {
	t.Parallel()
	repo, _ := newListOverrideRepo(t)
	ctx := context.Background()

	allow := testOverride(domain.ListKindAllowlist, "admin", "Admin", domain.ListOverridePresent)
	block := testOverride(domain.ListKindBlocklistTerm, "admin", "admin", domain.ListOverrideRemoved)
	for _, o := range []*domain.ListOverride{allow, block} {
		if err := repo.Put(ctx, o); err != nil {
			t.Fatalf("Put(%s): %v", o.List, err)
		}
	}

	got, err := repo.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("List returned %d overrides, want 2", len(got))
	}
	// Ordered by list then skeleton: "allowlist" sorts before "blocklist_term".
	if got[0].List != domain.ListKindAllowlist || got[1].List != domain.ListKindBlocklistTerm {
		t.Errorf("List order = %q, %q; want allowlist first", got[0].List, got[1].List)
	}
}

// TestListOverrideListIsOrdered pins the deterministic order replay depends on.
func TestListOverrideListIsOrdered(t *testing.T) {
	t.Parallel()
	repo, _ := newListOverrideRepo(t)
	ctx := context.Background()

	for _, sk := range []string{"zulu", "alfa", "mike"} {
		if err := repo.Put(ctx, testOverride(domain.ListKindAllowlist, sk, sk, domain.ListOverridePresent)); err != nil {
			t.Fatalf("Put(%s): %v", sk, err)
		}
	}

	got, err := repo.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	want := []string{"alfa", "mike", "zulu"}
	if len(got) != len(want) {
		t.Fatalf("List returned %d overrides, want %d", len(got), len(want))
	}
	for i, w := range want {
		if got[i].Skeleton != w {
			t.Errorf("List[%d].Skeleton = %q, want %q", i, got[i].Skeleton, w)
		}
	}
}

// TestListOverrideListEmptyIsNil pins the convention that an empty list is a
// nil slice rather than an allocated empty one.
func TestListOverrideListEmptyIsNil(t *testing.T) {
	t.Parallel()
	repo, _ := newListOverrideRepo(t)

	got, err := repo.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if got != nil {
		t.Errorf("List = %#v, want a nil slice", got)
	}
}

// TestListOverridePutRejectsMalformedInput pins that every field an override
// needs to be interpretable is required. A row missing one of these could not be
// replayed as policy, and the fail-open direction makes a silent accept
// unacceptable.
func TestListOverridePutRejectsMalformedInput(t *testing.T) {
	t.Parallel()
	repo, _ := newListOverrideRepo(t)
	ctx := context.Background()

	valid := func() *domain.ListOverride {
		return testOverride(domain.ListKindAllowlist, "admin", "Admin", domain.ListOverridePresent)
	}
	cases := map[string]func(*domain.ListOverride){
		"unknown list":  func(o *domain.ListOverride) { o.List = "denylist" },
		"empty list":    func(o *domain.ListOverride) { o.List = "" },
		"unknown state": func(o *domain.ListOverride) { o.State = "pending" },
		"empty state":   func(o *domain.ListOverride) { o.State = "" },
		"empty skarg":   func(o *domain.ListOverride) { o.Skeleton = "" },
		"empty entry":   func(o *domain.ListOverride) { o.Entry = "" },
		"empty actor":   func(o *domain.ListOverride) { o.ActorID = "" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			o := valid()
			mutate(o)
			err := repo.Put(ctx, o)
			if !errors.Is(err, domain.ErrInvalidInput) {
				t.Errorf("Put(%s) error = %v, want domain.ErrInvalidInput", name, err)
			}
		})
	}
}

func TestListOverridePutRejectsNil(t *testing.T) {
	t.Parallel()
	repo, _ := newListOverrideRepo(t)

	err := repo.Put(context.Background(), nil)
	if !errors.Is(err, domain.ErrInvalidInput) {
		t.Errorf("Put(nil) error = %v, want domain.ErrInvalidInput", err)
	}
}

// TestListOverrideReadRefusesAnUninterpretableRow pins the fail-closed read.
// The CHECK constraints stop the application writing such a row, so this writes
// one behind their back to reach the decode path -- the case where the table was
// modified out from under the service. Returning the row would let replay act on
// a value it cannot interpret, and for a tombstone that is the fail-open
// direction: a removal read as anything else lets the seed resurrect the entry.
func TestListOverrideReadRefusesAnUninterpretableRow(t *testing.T) {
	t.Parallel()

	cases := map[string]struct{ list, state string }{
		"unknown list":  {"denylist", string(domain.ListOverridePresent)},
		"unknown state": {string(domain.ListKindAllowlist), "pending"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			repo, s := newListOverrideRepo(t)
			ctx := context.Background()

			// PRAGMA ignore_check_constraints lets the test install the row the
			// application layer is designed to make unwritable.
			if _, err := s.db.ExecContext(ctx, `PRAGMA ignore_check_constraints = ON`); err != nil {
				t.Fatalf("disable check constraints: %v", err)
			}
			_, err := s.db.ExecContext(ctx,
				`INSERT INTO list_overrides (`+listOverrideColumns+`) VALUES (?, ?, ?, ?, ?, ?)`,
				tc.list, "admin", "Admin", tc.state, "adm-1", encTime(time.Now().UTC()))
			if err != nil {
				t.Fatalf("insert unconstrained row: %v", err)
			}

			if _, err := repo.List(ctx); !errors.Is(err, domain.ErrInvalidInput) {
				t.Errorf("List error = %v, want domain.ErrInvalidInput", err)
			}
		})
	}
}

// TestListOverrideRepoIsWiredIntoRepos pins that a Store hands out the adapter.
// A nil field here would be a service that silently could not persist anything.
func TestListOverrideRepoIsWiredIntoRepos(t *testing.T) {
	t.Parallel()
	s := newStore(t)

	var want repository.ListOverrideRepository
	if got := s.Repos().ListOverrides; got == want {
		t.Fatal("Repos().ListOverrides is nil, want the SQLite adapter")
	}
}
