package handle_test

import (
	"context"
	"database/sql"
	"errors"
	"slices"
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

// passClock is later than fixedNow, so a write the recompute pass makes moves a
// row's updated_at off the fixedNow the fixture stamps — which is how a test
// tells "the pass touched this row again" from "it left it as a peer wrote it."
var passClock = fixedNow.Add(time.Hour)

// staleInjectRepo prepends fabricated stale rows to the AUTO-COMMIT (outer)
// ListStaleFolds only. It fakes the snapshot a replica holds after a peer has
// resolved rows the replica still believes are stale, so a test can prove the
// pass acts on the in-transaction re-read, not this outer snapshot.
type staleInjectRepo struct {
	repository.HandleRepository
	extra []domain.Handle
}

func (r staleInjectRepo) ListStaleFolds(ctx context.Context, ver int) ([]domain.Handle, error) {
	real, err := r.HandleRepository.ListStaleFolds(ctx, ver)
	if err != nil {
		return nil, err
	}
	return append(slices.Clone(r.extra), real...), nil
}

// outerStaleStore decorates ONLY the outer Repos().Handles.ListStaleFolds with
// injected extras; WithTx passes straight through to the real repositories. The
// asymmetry is the whole test: the pre-check sees a stale set a peer has since
// changed, and the transaction sees the truth. A store that decorated WithTx too
// would hide the very divergence the double-checked re-query closes (#110).
type outerStaleStore struct {
	inner repository.Store
	extra []domain.Handle
}

func (s outerStaleStore) Repos() repository.Repos {
	r := s.inner.Repos()
	r.Handles = staleInjectRepo{HandleRepository: r.Handles, extra: s.extra}
	return r
}

func (s outerStaleStore) WithTx(ctx context.Context, fn func(context.Context, repository.Repos) error) error {
	return s.inner.WithTx(ctx, fn)
}

// recomputerOverOuter builds a Recomputer whose outer pre-check reports extra as
// stale on top of the real database, clocked at passClock so any row it writes
// is visibly stamped later than the fixedNow the fixture used.
func (f *recomputeFix) recomputerOverOuter(extra ...domain.Handle) *handle.Recomputer {
	f.t.Helper()
	rc, err := handle.NewRecomputer(
		outerStaleStore{inner: f.store, extra: extra},
		f.auditor,
		handle.WithRecomputeClock(func() time.Time { return passClock }),
	)
	if err != nil {
		f.t.Fatalf("NewRecomputer over outerStaleStore: %v", err)
	}
	return rc
}

// TestRecomputeTrustsInTxSetNotOuterPhantom proves the pass never acts on a row
// the outer read reports but the transaction does not contain. The outer read
// carries a row with no database row behind it — the shape a peer leaves after
// resolving and removing a row past this instance's snapshot. On the pre-fix
// code the pass would SetFold that phantom and abort with ErrNotFound; trusting
// the in-transaction re-read, it never sees the phantom and completes.
func TestRecomputeTrustsInTxSetNotOuterPhantom(t *testing.T) {
	f := newRecomputeFix(t)
	// One genuinely stale row exists; "al-ice" folds to "alice".
	f.rawInsert("h-1", ownerA, "al-ice", "al-ice", 0, fixedNow)

	ghost := domain.Handle{ID: "ghost", OwnerID: ownerB, Name: "ghost", State: domain.NameStateActive}
	rc := f.recomputerOverOuter(ghost)

	res, err := rc.Run(context.Background())
	if err != nil {
		t.Fatalf("Run must not abort on a phantom outer row: %v", err)
	}
	if res.Recomputed != 1 || res.Quarantined != 0 {
		t.Fatalf("result = %+v, want 1 recomputed, 0 quarantined", res)
	}
	// The real stale row WAS recomputed: the pass did in-tx work, it did not just
	// short-circuit on an empty set.
	if fold, ver := f.foldOf("h-1"); fold != "alice" || ver != blocklist.TableVersion {
		t.Fatalf("real stale row not recomputed: fold=%q ver=%d", fold, ver)
	}
}

// TestRecomputeActsOnInTxSetNotOuterSnapshot is the double-checked case. A peer
// instance has already resolved a confusable pair: the survivor holds its true
// skeleton at the current revision and the look-alike is already quarantined and
// current, so NEITHER is stale in the database. This instance's outer pre-check
// still reports both as stale (its snapshot predates the peer's commit). The
// pass must re-read inside the transaction, find nothing stale, and do nothing —
// no re-quarantine of a row already held, no churn, no second audit record.
func TestRecomputeActsOnInTxSetNotOuterSnapshot(t *testing.T) {
	f := newRecomputeFix(t)
	if blocklist.Skeleton("paypal") != blocklist.Skeleton("pay-pal") {
		t.Fatalf("fixture invalid: paypal and pay-pal do not fold together")
	}
	f.rawInsert("h-old", ownerA, "paypal", "paypal", 0, fixedNow)
	f.rawInsert("h-new", ownerB, "pay-pal", "pay-pal", 0, fixedNow.Add(time.Minute))

	// Bring the database to the post-peer state directly: survivor current, loser
	// quarantined and current on its placeholder fold.
	ctx := context.Background()
	if err := f.store.Repos().Handles.SetFold(ctx, "h-old", "paypal", blocklist.TableVersion, fixedNow); err != nil {
		t.Fatalf("peer SetFold survivor: %v", err)
	}
	if err := f.store.Repos().Handles.SetFold(ctx, "h-new", "!h-new", blocklist.TableVersion, fixedNow); err != nil {
		t.Fatalf("peer SetFold loser placeholder: %v", err)
	}
	if err := f.store.Repos().Handles.QuarantineLookalike(ctx, "h-new", fixedNow); err != nil {
		t.Fatalf("peer QuarantineLookalike: %v", err)
	}
	loserBefore := f.get(ownerB, "h-new")
	survivorBefore := f.get(ownerA, "h-old")

	// The outer pre-check reports both rows as stale, as they looked before the
	// peer committed.
	staleOld := domain.Handle{ID: "h-old", OwnerID: ownerA, Name: "paypal", State: domain.NameStateActive, CreatedAt: fixedNow}
	staleNew := domain.Handle{ID: "h-new", OwnerID: ownerB, Name: "pay-pal", State: domain.NameStateActive, CreatedAt: fixedNow.Add(time.Minute)}
	rc := f.recomputerOverOuter(staleOld, staleNew)

	res, err := rc.Run(ctx)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	// The in-tx set is empty, so the pass is a clean no-op.
	if res.Recomputed != 0 || res.Quarantined != 0 {
		t.Fatalf("result = %+v, want zero — the peer already resolved the group", res)
	}
	// The already-quarantined loser is untouched: no second quarantine write moved
	// its updated_at to passClock.
	if got := f.get(ownerB, "h-new"); !got.UpdatedAt.Equal(loserBefore.UpdatedAt) {
		t.Fatalf("loser updated_at moved %v -> %v: the pass acted on a row already resolved", loserBefore.UpdatedAt, got.UpdatedAt)
	}
	// The survivor is likewise untouched.
	if got := f.get(ownerA, "h-old"); !got.UpdatedAt.Equal(survivorBefore.UpdatedAt) {
		t.Fatalf("survivor updated_at moved %v -> %v", survivorBefore.UpdatedAt, got.UpdatedAt)
	}
	// No second quarantine audit was emitted for a row a peer already held.
	if got := len(recordsFor(replay(t, f.auditor.captured()), domain.AuditActionHandleQuarantined)); got != 0 {
		t.Fatalf("emitted %d quarantine records on a no-op pass, want 0", got)
	}
}

// TestRecomputeIsIdempotentAcrossPasses runs two real passes over one confusable
// group — the shape two replicas produce when one follows the other. The first
// keeps the oldest and quarantines the newer; the second finds nothing stale and
// does nothing, so the survivor is never lost and the loser is quarantined
// exactly once.
func TestRecomputeIsIdempotentAcrossPasses(t *testing.T) {
	f := newRecomputeFix(t)
	if blocklist.Skeleton("paypal") != blocklist.Skeleton("pay-pal") {
		t.Fatalf("fixture invalid: paypal and pay-pal do not fold together")
	}
	f.rawInsert("h-old", ownerA, "paypal", "paypal", 0, fixedNow)
	f.rawInsert("h-new", ownerB, "pay-pal", "pay-pal", 0, fixedNow.Add(time.Minute))

	first, err := f.rc.Run(context.Background())
	if err != nil {
		t.Fatalf("first Run: %v", err)
	}
	if first.Recomputed != 1 || first.Quarantined != 1 {
		t.Fatalf("first pass = %+v, want 1 recomputed, 1 quarantined", first)
	}
	survivorBefore := f.get(ownerA, "h-old")

	second, err := f.rc.Run(context.Background())
	if err != nil {
		t.Fatalf("second Run: %v", err)
	}
	if second.Recomputed != 0 || second.Quarantined != 0 {
		t.Fatalf("second pass = %+v, want a clean no-op", second)
	}
	// The survivor is still the oldest, active, resolvable, and unchurned.
	survivorAfter := f.get(ownerA, "h-old")
	if survivorAfter.State != domain.NameStateActive || !survivorAfter.UpdatedAt.Equal(survivorBefore.UpdatedAt) {
		t.Fatalf("survivor changed on the second pass: %+v", survivorAfter)
	}
	if fold, ver := f.foldOf("h-old"); fold != "paypal" || ver != blocklist.TableVersion {
		t.Fatalf("survivor fold = %q ver = %d, want paypal/%d", fold, ver, blocklist.TableVersion)
	}
	if _, err := f.store.Repos().Handles.GetByName(context.Background(), "paypal"); err != nil {
		t.Fatalf("survivor no longer resolves: %v", err)
	}
	// Exactly one quarantine across both passes: no double-quarantine.
	if got := len(recordsFor(replay(t, f.auditor.captured()), domain.AuditActionHandleQuarantined)); got != 1 {
		t.Fatalf("total quarantine records = %d across two passes, want 1", got)
	}
}
