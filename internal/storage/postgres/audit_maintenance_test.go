package postgres

import (
	"context"
	"errors"
	"reflect"
	"strconv"
	"testing"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/repository"
)

// auditIDs returns the IDs of every record in the table, oldest first, so a
// test can assert exactly which rows survived an operation.
func auditIDs(t *testing.T, repo *auditRepo) []string {
	t.Helper()
	recs, _, err := repo.List(context.Background(), repository.AuditQuery{}, repository.Page{Limit: 1000})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	ids := make([]string, 0, len(recs))
	for i := len(recs) - 1; i >= 0; i-- {
		ids = append(ids, string(recs[i].ID))
	}
	return ids
}

// TestAuditPurgeCutoffBoundary pins the inclusive cutoff from both sides. The
// record exactly at the cutoff must go (the port says "at or before cutoff"),
// and the record one nanosecond after it must survive. The survival half is the
// security-critical direction: a reversed or widened comparison there silently
// destroys evidence.
//
// The one-nanosecond gap is also what makes this test an engine-parity check.
// It is only representable because occurred_at is nanosecond-precision text; on
// a microsecond-precision timestamptz the "after" record would compare equal to
// the cutoff and be purged, so this test would fail — which is exactly the
// alarm wanted if the column type is ever changed.
func TestAuditPurgeCutoffBoundary(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	sink, repo := auditSink(t, s)

	cutoff := testClock
	before := cutoff.Add(-time.Nanosecond)
	after := cutoff.Add(time.Nanosecond)

	for _, tc := range []struct {
		id string
		at time.Time
	}{
		{"aud-before", before},
		{"aud-at", cutoff},
		{"aud-after", after},
	} {
		if err := sink.Append(ctx, newAuditRecord(tc.id, "owner-a", "key-1", tc.at)); err != nil {
			t.Fatalf("Append %s: %v", tc.id, err)
		}
	}

	n, err := repo.PurgeOlderThan(ctx, cutoff, 100)
	if err != nil {
		t.Fatalf("PurgeOlderThan: %v", err)
	}
	if n != 2 {
		t.Errorf("deleted = %d, want 2 (strictly-before and at-cutoff)", n)
	}

	got := auditIDs(t, repo)
	want := []string{"aud-after"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("survivors = %v, want %v", got, want)
	}
}

// TestAuditPurgeNeverDeletesNewerThanCutoff is the anti-evidence-destruction
// test. Every record is newer than the cutoff, so a correct purge deletes
// nothing at all no matter how large the batch limit is.
func TestAuditPurgeNeverDeletesNewerThanCutoff(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	sink, repo := auditSink(t, s)

	cutoff := testClock
	for i := range 5 {
		id := "aud-recent-" + strconv.Itoa(i)
		at := cutoff.Add(time.Duration(i+1) * time.Hour)
		if err := sink.Append(ctx, newAuditRecord(id, "owner-a", "key-1", at)); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}

	n, err := repo.PurgeOlderThan(ctx, cutoff, 1000)
	if err != nil {
		t.Fatalf("PurgeOlderThan: %v", err)
	}
	if n != 0 {
		t.Errorf("deleted = %d, want 0: purge reached records newer than the cutoff", n)
	}
	if got := len(auditIDs(t, repo)); got != 5 {
		t.Errorf("surviving records = %d, want 5", got)
	}
}

// TestAuditPurgeRespectsBatchLimit proves one call deletes at most limit rows
// and that repeated calls drain the backlog oldest-first.
func TestAuditPurgeRespectsBatchLimit(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	sink, repo := auditSink(t, s)

	cutoff := testClock.Add(24 * time.Hour)
	for i := range 7 {
		id := "aud-" + strconv.Itoa(i)
		at := testClock.Add(time.Duration(i) * time.Minute)
		if err := sink.Append(ctx, newAuditRecord(id, "owner-a", "key-1", at)); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}

	n, err := repo.PurgeOlderThan(ctx, cutoff, 3)
	if err != nil {
		t.Fatalf("PurgeOlderThan: %v", err)
	}
	if n != 3 {
		t.Fatalf("first batch deleted = %d, want 3 (batch limit ignored)", n)
	}
	// Oldest-first: the three lowest timestamps went, the rest remain.
	want := []string{"aud-3", "aud-4", "aud-5", "aud-6"}
	if got := auditIDs(t, repo); !reflect.DeepEqual(got, want) {
		t.Fatalf("after first batch = %v, want %v", got, want)
	}

	// Drain: the final batch returns fewer than the limit, which is the
	// caller's signal that the backlog is exhausted.
	n, err = repo.PurgeOlderThan(ctx, cutoff, 3)
	if err != nil {
		t.Fatalf("PurgeOlderThan: %v", err)
	}
	if n != 3 {
		t.Fatalf("second batch deleted = %d, want 3", n)
	}
	n, err = repo.PurgeOlderThan(ctx, cutoff, 3)
	if err != nil {
		t.Fatalf("PurgeOlderThan: %v", err)
	}
	if n != 1 {
		t.Errorf("final batch deleted = %d, want 1", n)
	}
	if got := auditIDs(t, repo); len(got) != 0 {
		t.Errorf("after drain = %v, want empty", got)
	}
}

func TestAuditPurgeRejectsNonPositiveLimit(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	_, repo := auditSink(t, s)

	for _, limit := range []int{0, -1} {
		n, err := repo.PurgeOlderThan(ctx, testClock, limit)
		if !errors.Is(err, domain.ErrInvalidInput) {
			t.Errorf("limit %d: err = %v, want ErrInvalidInput", limit, err)
		}
		if n != 0 {
			t.Errorf("limit %d: deleted = %d, want 0", limit, n)
		}
	}
}

func TestAuditPurgeEmptyTableIsNotAnError(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	_, repo := auditSink(t, s)

	n, err := repo.PurgeOlderThan(context.Background(), testClock, 10)
	if err != nil {
		t.Fatalf("PurgeOlderThan: %v", err)
	}
	if n != 0 {
		t.Errorf("deleted = %d, want 0", n)
	}
}

// TestAuditPseudonymizeRewritesOnlyIdentity is the anti-forgery test: the
// action, timestamp, and both type columns must be byte-identical afterwards.
// Pseudonymization removes WHO an event was about; it must never be a route to
// changing WHAT happened or WHEN.
func TestAuditPseudonymizeRewritesOnlyIdentity(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	sink, repo := auditSink(t, s)

	rec := newAuditRecord("aud-1", "owner-a", "key-1", testClock)
	rec.Metadata = map[string]string{"fingerprint": "SHA256:abc"}
	if err := sink.Append(ctx, rec); err != nil {
		t.Fatalf("Append: %v", err)
	}

	n, err := repo.Pseudonymize(ctx, []string{"owner-a"}, "tomb-xyz")
	if err != nil {
		t.Fatalf("Pseudonymize: %v", err)
	}
	if n != 1 {
		t.Fatalf("rewritten = %d, want 1", n)
	}

	got, err := repo.Get(ctx, "aud-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.ActorID != "tomb-xyz" {
		t.Errorf("ActorID = %q, want the tombstone", got.ActorID)
	}
	if !got.Pseudonymized {
		t.Error("Pseudonymized = false, want true")
	}
	// The substance of the event is untouched.
	if got.Action != rec.Action {
		t.Errorf("Action = %q, want %q: pseudonymize altered the recorded action", got.Action, rec.Action)
	}
	if !got.OccurredAt.Equal(rec.OccurredAt) {
		t.Errorf("OccurredAt = %v, want %v: pseudonymize altered the timestamp", got.OccurredAt, rec.OccurredAt)
	}
	if got.ActorType != rec.ActorType || got.TargetType != rec.TargetType {
		t.Errorf("type columns changed: %v/%v", got.ActorType, got.TargetType)
	}
	// The target was not in the erasure set, so it must survive in the clear.
	if got.TargetID != "key-1" {
		t.Errorf("TargetID = %q, want key-1: a bystander identity was erased", got.TargetID)
	}
}

// TestAuditPseudonymizeLeavesMetadataUntouched pins the division of labor
// between the two erasure writes: Pseudonymize rewrites ONLY the identity
// columns, and metadata erasure is the separate ScrubMetadata method's job
// (exercised by TestAuditScrubMetadataTouchesOnlyMetadata).
//
// Keeping Pseudonymize to the two columns is what preserves its structural
// anti-forgery guarantee — it cannot reach any other column, metadata included.
// A change that added metadata rewriting to this UPDATE would both break that
// guarantee and, if made on one engine only, make the two disagree about what
// Pseudonymize does. The whole-record erasure that DOES scrub metadata runs the
// two methods together in the erasure service; here each is pinned in isolation
// so the boundary between them stays sharp on both engines.
func TestAuditPseudonymizeLeavesMetadataUntouched(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	sink, repo := auditSink(t, s)

	// Metadata that identifies the very subject being erased, on both the
	// actor and the target side.
	meta := map[string]string{
		"fingerprint": "SHA256:abc",
		"actor_email": "owner-a@example.com",
	}
	rec := newAuditRecord("aud-1", "owner-a", "key-1", testClock)
	rec.Metadata = meta
	if err := sink.Append(ctx, rec); err != nil {
		t.Fatalf("Append: %v", err)
	}

	if _, err := repo.Pseudonymize(ctx, []string{"owner-a", "key-1"}, "tomb-xyz"); err != nil {
		t.Fatalf("Pseudonymize: %v", err)
	}

	got, err := repo.Get(ctx, "aud-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	// Both identity columns were erased...
	if got.ActorID != "tomb-xyz" || got.TargetID != "tomb-xyz" {
		t.Fatalf("identity columns = %q/%q, want both tombstoned", got.ActorID, got.TargetID)
	}
	// ...and metadata was not, because scrubbing it is ScrubMetadata's job, not
	// this method's. This boundary must stay identical on both engines.
	if !reflect.DeepEqual(got.Metadata, meta) {
		t.Errorf("Metadata = %v, want %v unchanged: Pseudonymize must touch only the "+
			"identity columns; metadata erasure belongs to ScrubMetadata", got.Metadata, meta)
	}
}

// TestAuditPseudonymizeIsIdempotent runs the same erasure twice. The second run
// must match nothing and change nothing: the match is on the original IDs, which
// no longer exist, and the pseudonym is never derived from the column's current
// value, so there is no double-hashing and nothing is resurrected.
func TestAuditPseudonymizeIsIdempotent(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	sink, repo := auditSink(t, s)

	if err := sink.Append(ctx, newAuditRecord("aud-1", "owner-a", "key-1", testClock)); err != nil {
		t.Fatalf("Append: %v", err)
	}

	first, err := repo.Pseudonymize(ctx, []string{"owner-a"}, "tomb-xyz")
	if err != nil {
		t.Fatalf("first Pseudonymize: %v", err)
	}
	if first != 1 {
		t.Fatalf("first run rewritten = %d, want 1", first)
	}
	afterFirst, err := repo.Get(ctx, "aud-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}

	second, err := repo.Pseudonymize(ctx, []string{"owner-a"}, "tomb-xyz")
	if err != nil {
		t.Fatalf("second Pseudonymize: %v", err)
	}
	if second != 0 {
		t.Errorf("second run rewritten = %d, want 0: operation is not idempotent", second)
	}
	afterSecond, err := repo.Get(ctx, "aud-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if afterSecond.ActorID != afterFirst.ActorID {
		t.Errorf("ActorID drifted across runs: %q then %q (double-hashed?)",
			afterFirst.ActorID, afterSecond.ActorID)
	}
	if afterSecond.ActorID != "tomb-xyz" {
		t.Errorf("ActorID = %q, want the stable tombstone", afterSecond.ActorID)
	}
}

// TestAuditPseudonymizeIndependentSubjects proves the two identity columns are
// erased independently. One record names an administrator actor acting on an
// owner target; erasing the owner must not disturb the administrator, and a
// later erasure of the administrator must still work even though the row is
// already flagged pseudonymized.
//
// It is also the test that catches a misnumbered placeholder in
// pseudonymizeBatch. The statement binds the ID list four times, and the two
// CASE arms must each test the column they rewrite: if the numbering slipped so
// that the actor arm tested the target list (or the WHERE selected on one
// column while the CASE rewrote the other), the query would still run without
// error and would either erase the bystander here or leave the subject in the
// clear. Both outcomes fail this test; neither would raise a database error.
func TestAuditPseudonymizeIndependentSubjects(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	sink, repo := auditSink(t, s)

	rec := newAuditRecord("aud-1", "admin-a", "owner-b", testClock)
	rec.ActorType = domain.ActorTypeAdministrator
	rec.TargetType = domain.TargetTypeOwner
	if err := sink.Append(ctx, rec); err != nil {
		t.Fatalf("Append: %v", err)
	}

	if _, err := repo.Pseudonymize(ctx, []string{"owner-b"}, "tomb-owner"); err != nil {
		t.Fatalf("erase owner: %v", err)
	}
	got, err := repo.Get(ctx, "aud-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.ActorID != "admin-a" {
		t.Errorf("ActorID = %q, want admin-a: erasing the target hit the actor", got.ActorID)
	}
	if got.TargetID != "tomb-owner" {
		t.Errorf("TargetID = %q, want tomb-owner", got.TargetID)
	}

	// The row is already pseudonymized; the second subject must still be
	// erasable. A WHERE gated on pseudonymized = FALSE would fail here.
	n, err := repo.Pseudonymize(ctx, []string{"admin-a"}, "tomb-admin")
	if err != nil {
		t.Fatalf("erase admin: %v", err)
	}
	if n != 1 {
		t.Fatalf("rewritten = %d, want 1: flag gate locked out the second subject", n)
	}
	got, err = repo.Get(ctx, "aud-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.ActorID != "tomb-admin" || got.TargetID != "tomb-owner" {
		t.Errorf("after both erasures = %q/%q, want tomb-admin/tomb-owner", got.ActorID, got.TargetID)
	}
}

// TestAuditPseudonymizeSelectsOnlyNamedSubjects is the placeholder-numbering
// test for the erasure statement's WHERE clause.
//
// Several records with distinct actors and targets are seeded and only some are
// named in the erasure set. A correct statement rewrites exactly those; a
// statement whose four bound ID groups drifted out of alignment would either
// leave a named subject in the clear (erasure silently incomplete) or rewrite
// an unnamed one (a bystander erased). Asserting the exact partition, rather
// than only the returned count, is what distinguishes those cases: a swapped
// grouping can still report a plausible number of affected rows.
func TestAuditPseudonymizeSelectsOnlyNamedSubjects(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	sink, repo := auditSink(t, s)

	seed := []struct{ id, actor, target string }{
		{"aud-1", "owner-a", "key-1"}, // actor named
		{"aud-2", "owner-b", "key-2"}, // target named
		{"aud-3", "owner-c", "key-3"}, // neither named
		{"aud-4", "owner-a", "key-2"}, // both named
	}
	for i, sd := range seed {
		rec := newAuditRecord(sd.id, sd.actor, sd.target, testClock.Add(time.Duration(i)*time.Minute))
		if err := sink.Append(ctx, rec); err != nil {
			t.Fatalf("Append %s: %v", sd.id, err)
		}
	}

	n, err := repo.Pseudonymize(ctx, []string{"owner-a", "key-2"}, "tomb")
	if err != nil {
		t.Fatalf("Pseudonymize: %v", err)
	}
	if n != 3 {
		t.Errorf("rewritten = %d, want 3 (aud-1, aud-2, aud-4)", n)
	}

	want := map[string]struct{ actor, target string }{
		"aud-1": {"tomb", "key-1"},
		"aud-2": {"owner-b", "tomb"},
		"aud-3": {"owner-c", "key-3"},
		"aud-4": {"tomb", "tomb"},
	}
	for id, w := range want {
		got, gerr := repo.Get(ctx, domain.AuditRecordID(id))
		if gerr != nil {
			t.Fatalf("Get %s: %v", id, gerr)
		}
		if got.ActorID != w.actor || got.TargetID != w.target {
			t.Errorf("%s = %q/%q, want %q/%q: the erasure set selected the wrong rows or columns",
				id, got.ActorID, got.TargetID, w.actor, w.target)
		}
	}
	// The untouched record must not have been flagged either.
	got, err := repo.Get(ctx, "aud-3")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Pseudonymized {
		t.Error("aud-3 was flagged pseudonymized although neither of its subjects was named")
	}
}

func TestAuditPseudonymizeRejectsBadInput(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	sink, repo := auditSink(t, s)

	// A system-actor record with an empty actor ID: the bystander that an
	// empty ID in the erasure set would sweep in.
	rec := newAuditRecord("aud-sys", "", "key-1", testClock)
	rec.ActorType = domain.ActorTypeSystem
	if err := sink.Append(ctx, rec); err != nil {
		t.Fatalf("Append: %v", err)
	}

	if _, err := repo.Pseudonymize(ctx, []string{"owner-a"}, ""); !errors.Is(err, domain.ErrInvalidInput) {
		t.Errorf("empty pseudonym: err = %v, want ErrInvalidInput", err)
	}
	if _, err := repo.Pseudonymize(ctx, []string{"owner-a", ""}, "tomb"); !errors.Is(err, domain.ErrInvalidInput) {
		t.Errorf("empty id: err = %v, want ErrInvalidInput", err)
	}
	// The bystander was not touched by either rejected call.
	got, err := repo.Get(ctx, "aud-sys")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.ActorID != "" || got.Pseudonymized {
		t.Errorf("system record was modified by a rejected call: %+v", got)
	}
}

func TestAuditPseudonymizeEmptySetIsNoOp(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	sink, repo := auditSink(t, s)

	if err := sink.Append(ctx, newAuditRecord("aud-1", "owner-a", "key-1", testClock)); err != nil {
		t.Fatalf("Append: %v", err)
	}
	n, err := repo.Pseudonymize(ctx, nil, "tomb")
	if err != nil {
		t.Fatalf("Pseudonymize: %v", err)
	}
	if n != 0 {
		t.Errorf("rewritten = %d, want 0", n)
	}
	got, err := repo.Get(ctx, "aud-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.ActorID != "owner-a" || got.Pseudonymized {
		t.Errorf("empty set modified a record: %+v", got)
	}
}

// TestAuditPseudonymizeChunksLargeSets drives the input past
// maxPseudonymizeBatch so the multi-batch path runs. It also exercises the
// widest statement this adapter ever issues: a full batch binds 4*400+2 = 1602
// numbered parameters, so a numbering scheme that broke down at scale — or a
// batch size that exceeded the protocol's 65535-parameter ceiling — fails here.
func TestAuditPseudonymizeChunksLargeSets(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	sink, repo := auditSink(t, s)

	const n = maxPseudonymizeBatch + 25
	ids := make([]string, 0, n)
	for i := range n {
		id := "owner-" + strconv.Itoa(i)
		ids = append(ids, id)
		if err := sink.Append(ctx, newAuditRecord("aud-"+strconv.Itoa(i), id, "key-1", testClock)); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}

	got, err := repo.Pseudonymize(ctx, ids, "tomb")
	if err != nil {
		t.Fatalf("Pseudonymize: %v", err)
	}
	if got != int64(n) {
		t.Errorf("rewritten = %d, want %d: chunking dropped records", got, n)
	}
	recs, _, err := repo.List(ctx, repository.AuditQuery{ActorID: "tomb"}, repository.Page{Limit: 1000})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(recs) != n {
		t.Errorf("tombstoned records = %d, want %d", len(recs), n)
	}
}

// TestAuditRecordsForErasureMatchesActorOrTarget covers the read half of
// metadata crypto-erasure: a record is returned when either identity column is
// in the ID set, an unrelated record is not, and an empty set yields nothing.
// It mirrors the SQLite adapter's test so the two engines are proven identical.
func TestAuditRecordsForErasureMatchesActorOrTarget(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	sink, repo := auditSink(t, s)

	byActor := newAuditRecord("aud-actor", "owner-a", "key-1", testClock)
	byTarget := newAuditRecord("aud-target", "admin-9", "owner-a", testClock)
	byTarget.ActorType = domain.ActorTypeAdministrator
	byTarget.TargetType = domain.TargetTypeOwner
	unrelated := newAuditRecord("aud-other", "owner-b", "key-2", testClock)
	for _, rec := range []*domain.AuditRecord{byActor, byTarget, unrelated} {
		if err := sink.Append(ctx, rec); err != nil {
			t.Fatalf("Append %s: %v", rec.ID, err)
		}
	}

	got, err := repo.RecordsForErasure(ctx, []string{"owner-a"})
	if err != nil {
		t.Fatalf("RecordsForErasure: %v", err)
	}
	ids := map[string]bool{}
	for _, r := range got {
		ids[string(r.ID)] = true
	}
	if !ids["aud-actor"] || !ids["aud-target"] {
		t.Errorf("missing a matched record: got %v", ids)
	}
	if ids["aud-other"] {
		t.Error("an unrelated owner's record was returned")
	}
	if len(got) != 2 {
		t.Errorf("returned %d records, want 2", len(got))
	}

	empty, err := repo.RecordsForErasure(ctx, nil)
	if err != nil {
		t.Fatalf("RecordsForErasure(nil): %v", err)
	}
	if len(empty) != 0 {
		t.Errorf("empty id set returned %d records, want 0", len(empty))
	}
}

// TestAuditRecordsForErasureDedupsAcrossBatches pins that a record whose actor
// and target land in different batches is returned once, not once per batch. It
// mirrors the SQLite adapter's test: one more ID than a single batch can carry,
// the record's actor in the first batch and its target in the last, the exact
// case the read's seen set exists to fold.
func TestAuditRecordsForErasureDedupsAcrossBatches(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	sink, repo := auditSink(t, s)

	ids := make([]string, maxPseudonymizeBatch+1)
	for i := range ids {
		ids[i] = "id-" + strconv.Itoa(i)
	}
	// Actor in the first batch (ids[0]), target in the second (last id).
	rec := newAuditRecord("aud-split", ids[0], ids[len(ids)-1], testClock)
	if err := sink.Append(ctx, rec); err != nil {
		t.Fatalf("Append: %v", err)
	}

	got, err := repo.RecordsForErasure(ctx, ids)
	if err != nil {
		t.Fatalf("RecordsForErasure: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("returned %d records, want 1 (cross-batch duplicate not folded)", len(got))
	}
	if got[0].ID != "aud-split" {
		t.Errorf("returned %q, want aud-split", got[0].ID)
	}
}

// TestAuditScrubMetadataTouchesOnlyMetadata is the anti-forgery test for the
// write half: it replaces the metadata column and leaves every other column —
// action, timestamp, the type and identity columns, and the pseudonymized flag
// — byte-identical. Rewriting metadata must never become a route to doctoring
// what happened or when.
func TestAuditScrubMetadataTouchesOnlyMetadata(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	sink, repo := auditSink(t, s)

	rec := newAuditRecord("aud-1", "owner-a", "key-1", testClock)
	rec.Metadata = map[string]string{"handle": "acme", "algorithm": "ssh-ed25519"}
	if err := sink.Append(ctx, rec); err != nil {
		t.Fatalf("Append: %v", err)
	}

	newMeta := map[string]string{"handle": "anon:xyz", "algorithm": "ssh-ed25519"}
	n, err := repo.ScrubMetadata(ctx, []repository.AuditMetadataUpdate{{ID: "aud-1", Metadata: newMeta}})
	if err != nil {
		t.Fatalf("ScrubMetadata: %v", err)
	}
	if n != 1 {
		t.Fatalf("updated = %d, want 1", n)
	}

	got, err := repo.Get(ctx, "aud-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !reflect.DeepEqual(got.Metadata, newMeta) {
		t.Errorf("Metadata = %v, want %v", got.Metadata, newMeta)
	}
	if got.Action != rec.Action {
		t.Errorf("Action = %q, want %q: scrub altered the action", got.Action, rec.Action)
	}
	if !got.OccurredAt.Equal(rec.OccurredAt) {
		t.Errorf("OccurredAt changed: %v want %v", got.OccurredAt, rec.OccurredAt)
	}
	if got.ActorID != "owner-a" || got.TargetID != "key-1" {
		t.Errorf("identity columns changed: %q/%q", got.ActorID, got.TargetID)
	}
	if got.ActorType != rec.ActorType || got.TargetType != rec.TargetType {
		t.Errorf("type columns changed: %v/%v", got.ActorType, got.TargetType)
	}
	if got.Pseudonymized {
		t.Error("Pseudonymized flag was set by a metadata scrub: that flag belongs to the column pass")
	}
}

// TestAuditScrubMetadataSkipsUnknownAndRejectsEmpty covers the two edge cases: a
// record ID that names no row updates nothing (erasure tolerates a partially
// deleted owner), and an empty ID is refused rather than silently applied.
func TestAuditScrubMetadataSkipsUnknownAndRejectsEmpty(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	_, repo := auditSink(t, s)

	n, err := repo.ScrubMetadata(ctx, []repository.AuditMetadataUpdate{{ID: "missing", Metadata: map[string]string{"handle": "x"}}})
	if err != nil {
		t.Fatalf("ScrubMetadata(missing): %v", err)
	}
	if n != 0 {
		t.Errorf("updated = %d for a missing record, want 0", n)
	}

	if _, err := repo.ScrubMetadata(ctx, []repository.AuditMetadataUpdate{{ID: "", Metadata: nil}}); !errors.Is(err, domain.ErrInvalidInput) {
		t.Errorf("empty id err = %v, want ErrInvalidInput", err)
	}

	if n, err := repo.ScrubMetadata(ctx, nil); err != nil || n != 0 {
		t.Errorf("ScrubMetadata(nil) = %d, %v, want 0, nil", n, err)
	}
}
