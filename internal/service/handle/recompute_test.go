package handle_test

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/audit"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/blocklist"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/repository"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/service/handle"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/storage/sqlite"
)

// foldTimeLayout matches the SQLite adapter's fixed-width UTC layout, so a raw
// pre-migration row inserted here decodes exactly like one the adapter wrote.
const foldTimeLayout = "2006-01-02T15:04:05.000000000Z07:00"

// recomputeFix is a recompute pass's world: a migrated database whose *sql.DB is
// reachable (the pass's whole reason to exist is rows the adapter's Register
// would never have written, so the fixture writes them raw), the store, the
// Recomputer under test, and the auditor it emits to.
type recomputeFix struct {
	t       *testing.T
	db      *sql.DB
	store   repository.Store
	auditor *recordingAuditor
	rc      *handle.Recomputer
	now     time.Time
}

func newRecomputeFix(t *testing.T) *recomputeFix {
	t.Helper()

	db, err := sqlite.Open(sqlite.Options{Path: ":memory:"})
	if err != nil {
		t.Fatalf("sqlite.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	migrateUp(t, db)

	store := sqlite.NewStore(db)
	for _, id := range []domain.OwnerID{ownerA, ownerB} {
		if err := store.Repos().Owners.Create(context.Background(), &domain.Owner{
			ID: id, Status: domain.OwnerStatusActive,
			CreatedAt: fixedNow, UpdatedAt: fixedNow,
		}); err != nil {
			t.Fatalf("Owners.Create(%s): %v", id, err)
		}
	}

	auditor := &recordingAuditor{}
	now := fixedNow
	rc, err := handle.NewRecomputer(store, auditor, handle.WithRecomputeClock(func() time.Time { return now }))
	if err != nil {
		t.Fatalf("handle.NewRecomputer: %v", err)
	}
	return &recomputeFix{t: t, db: db, store: store, auditor: auditor, rc: rc, now: now}
}

// rawInsert writes a handle row directly, bypassing Register, so the fixture can
// stand up the exact pre-recompute shapes migration 0012 leaves: a RAW,
// unfolded name_fold at fold_version 0. It always writes an active row.
func (f *recomputeFix) rawInsert(id string, owner domain.OwnerID, name, nameFold string, ver int, created time.Time) {
	f.t.Helper()
	ts := created.UTC().Format(foldTimeLayout)
	_, err := f.db.ExecContext(context.Background(),
		`INSERT INTO handles
(id, owner_id, name, name_fold, fold_version, state, quarantine_until,
flagged_for_review, quarantine_on_release, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, 'active', NULL, 0, 0, ?, ?)`,
		id, string(owner), name, nameFold, ver, ts, ts)
	if err != nil {
		f.t.Fatalf("raw insert %q: %v", id, err)
	}
}

func (f *recomputeFix) foldOf(id string) (string, int) {
	f.t.Helper()
	var fold string
	var ver int
	if err := f.db.QueryRowContext(context.Background(),
		`SELECT name_fold, fold_version FROM handles WHERE id = ?`, id).Scan(&fold, &ver); err != nil {
		f.t.Fatalf("read fold for %q: %v", id, err)
	}
	return fold, ver
}

func (f *recomputeFix) get(owner domain.OwnerID, id string) *domain.Handle {
	f.t.Helper()
	h, err := f.store.Repos().Handles.Get(context.Background(), owner, domain.HandleID(id))
	if err != nil {
		f.t.Fatalf("Get(%s): %v", id, err)
	}
	return h
}

// TestRecomputeBackfilledRowBecomesSkeleton is the base case: a fold_version 0
// row with a raw, unfolded fold is rewritten to blocklist.Skeleton(name) at the
// current revision, and the exact name still resolves.
func TestRecomputeBackfilledRowBecomesSkeleton(t *testing.T) {
	f := newRecomputeFix(t)
	// "al-ice" folds to "alice" (the separator is dropped), so the raw backfill
	// "al-ice" is demonstrably wrong and the recompute has visible work to do.
	f.rawInsert("h-1", ownerA, "al-ice", "al-ice", 0, fixedNow)

	res, err := f.rc.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Recomputed != 1 || res.Quarantined != 0 {
		t.Fatalf("result = %+v, want 1 recomputed, 0 quarantined", res)
	}
	if fold, ver := f.foldOf("h-1"); fold != "alice" || ver != blocklist.TableVersion {
		t.Fatalf("fold = %q ver = %d, want alice/%d", fold, ver, blocklist.TableVersion)
	}
	// Resolution matches the exact name, untouched by the fold rewrite.
	if got, err := f.store.Repos().Handles.GetByName(context.Background(), "al-ice"); err != nil || got.State != domain.NameStateActive {
		t.Fatalf("GetByName(al-ice) = %+v, %v; want active", got, err)
	}
}

// TestRecomputeLeavesCurrentRowsUntouched proves the pass acts only on stale
// rows: a row already at the current revision keeps its fold, its version, and
// its updated_at.
func TestRecomputeLeavesCurrentRowsUntouched(t *testing.T) {
	f := newRecomputeFix(t)
	// A current row, registered the normal way (empty table, so the guard lets
	// it through), and a stale row alongside it.
	if err := f.store.Repos().Handles.Register(context.Background(), &domain.Handle{
		ID: "h-cur", OwnerID: ownerA, Name: "carol", State: domain.NameStateActive,
		CreatedAt: fixedNow, UpdatedAt: fixedNow,
	}); err != nil {
		t.Fatalf("Register current: %v", err)
	}
	before := f.get(ownerA, "h-cur").UpdatedAt
	f.rawInsert("h-1", ownerB, "al-ice", "al-ice", 0, fixedNow)

	if _, err := f.rc.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if fold, ver := f.foldOf("h-cur"); fold != "carol" || ver != blocklist.TableVersion {
		t.Fatalf("current row changed: fold=%q ver=%d", fold, ver)
	}
	if got := f.get(ownerA, "h-cur").UpdatedAt; !got.Equal(before) {
		t.Fatalf("current row updated_at moved from %v to %v", before, got)
	}
	// The stale row WAS recomputed, so the pass was not simply a no-op.
	if fold, _ := f.foldOf("h-1"); fold != "alice" {
		t.Fatalf("stale row fold = %q, want alice", fold)
	}
}

// TestRecomputeKeepsOldestQuarantinesNewer is the collision case: two
// pre-existing handles that fold to one skeleton. The oldest survives with the
// true skeleton; the newer is quarantined, flagged, and audited; the pass does
// not abort; the survivor still resolves.
func TestRecomputeKeepsOldestQuarantinesNewer(t *testing.T) {
	f := newRecomputeFix(t)
	// Both fold to "paypal"; the hyphen in "pay-pal" is a dropped separator.
	if blocklist.Skeleton("paypal") != blocklist.Skeleton("pay-pal") {
		t.Fatalf("fixture invalid: paypal and pay-pal do not fold together")
	}
	f.rawInsert("h-old", ownerA, "paypal", "paypal", 0, fixedNow)                      // survivor
	f.rawInsert("h-new", ownerB, "pay-pal", "pay-pal", 0, fixedNow.Add(1*time.Minute)) // look-alike

	res, err := f.rc.Run(context.Background())
	if err != nil {
		t.Fatalf("Run must not abort on a pre-existing collision: %v", err)
	}
	if res.Recomputed != 1 || res.Quarantined != 1 {
		t.Fatalf("result = %+v, want 1 recomputed, 1 quarantined", res)
	}

	// Oldest kept: active, true skeleton, still resolvable by exact name.
	if got := f.get(ownerA, "h-old"); got.State != domain.NameStateActive {
		t.Fatalf("survivor state = %q, want active", got.State)
	}
	if fold, ver := f.foldOf("h-old"); fold != "paypal" || ver != blocklist.TableVersion {
		t.Fatalf("survivor fold = %q ver = %d, want paypal/%d", fold, ver, blocklist.TableVersion)
	}
	if _, err := f.store.Repos().Handles.GetByName(context.Background(), "paypal"); err != nil {
		t.Fatalf("survivor no longer resolves: %v", err)
	}

	// Newer quarantined: held indefinitely, flagged, and NOT holding the shared
	// skeleton (its placeholder occupies no reachable fold slot).
	loser := f.get(ownerB, "h-new")
	if loser.State != domain.NameStateQuarantined || !loser.FlaggedForReview || loser.QuarantineUntil != nil {
		t.Fatalf("loser = %+v, want quarantined, flagged, no deadline", loser)
	}
	if fold, ver := f.foldOf("h-new"); fold == "paypal" || ver != blocklist.TableVersion {
		t.Fatalf("loser fold = %q ver = %d, want a non-paypal placeholder at %d", fold, ver, blocklist.TableVersion)
	}

	// A loud, correctly shaped audit record was emitted for the quarantine.
	quarantines := recordsFor(replay(t, f.auditor.captured()), domain.AuditActionHandleQuarantined)
	if len(quarantines) != 1 {
		t.Fatalf("got %d handle.quarantined records, want 1", len(quarantines))
	}
	rec := quarantines[0]
	if rec.TargetID != "h-new" {
		t.Errorf("audit TargetID = %q, want h-new", rec.TargetID)
	}
	wantDetail(t, rec, audit.DetailHandle, "pay-pal")
	wantDetail(t, rec, audit.DetailTo, "paypal")
	if rec.Metadata[string(audit.DetailReason)] == "" {
		t.Error("audit record carries no reason")
	}
}

// TestRecomputeEmptyIsNoop returns cleanly and writes nothing when no row is
// stale, without opening a transaction or emitting a record.
func TestRecomputeEmptyIsNoop(t *testing.T) {
	f := newRecomputeFix(t)
	res, err := f.rc.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Recomputed != 0 || res.Quarantined != 0 {
		t.Fatalf("result = %+v, want zero", res)
	}
	if got := len(f.auditor.captured()); got != 0 {
		t.Fatalf("emitted %d records on an empty pass, want 0", got)
	}
}

// TestRenameFailsClosedOnStaleFold proves the guard reaches the rename path too:
// a stale row present anywhere refuses a rename-to-a-new-name, because that path
// registers a fresh claim through the same guarded Register.
func TestRenameFailsClosedOnStaleFold(t *testing.T) {
	f := newFixture(t)
	seeded := f.seed(ownerA, "alice")
	// Knock the seeded row stale after the fact (Register itself would refuse to
	// write into a stale table).
	if err := f.store.Repos().Handles.SetFold(context.Background(), seeded.ID, "alice", 0, fixedNow); err != nil {
		t.Fatalf("SetFold stale: %v", err)
	}
	if _, err := f.svc.Rename(context.Background(), ownerA, "alicetwo", "req-1"); !errors.Is(err, domain.ErrFoldStale) {
		t.Fatalf("Rename with a stale row present = %v, want ErrFoldStale", err)
	}
}

// TestNewRecomputerRequiresDependencies refuses to build without a usable store
// and auditor, mirroring New: a Recomputer that starts and nil-panics mid-pass
// is worse than one that will not build.
func TestNewRecomputerRequiresDependencies(t *testing.T) {
	f := newFixture(t)
	cases := map[string]func() (*handle.Recomputer, error){
		"nil store":   func() (*handle.Recomputer, error) { return handle.NewRecomputer(nil, f.auditor) },
		"nil auditor": func() (*handle.Recomputer, error) { return handle.NewRecomputer(f.store, nil) },
		"nil handle repository": func() (*handle.Recomputer, error) {
			return handle.NewRecomputer(nilRowStore{
				inner: f.store,
				decor: func(repository.HandleRepository) repository.HandleRepository { return nil },
			}, f.auditor)
		},
		"nil audit repository": func() (*handle.Recomputer, error) {
			return handle.NewRecomputer(nilAuditStore{inner: f.store}, f.auditor)
		},
		"nil option": func() (*handle.Recomputer, error) {
			return handle.NewRecomputer(f.store, f.auditor, nil)
		},
	}
	for name, build := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := build(); !errors.Is(err, handle.ErrMissingDependency) {
				t.Fatalf("%s: err = %v, want ErrMissingDependency", name, err)
			}
		})
	}
}
