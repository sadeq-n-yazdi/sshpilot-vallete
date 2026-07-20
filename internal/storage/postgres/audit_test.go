package postgres

import (
	"context"
	"errors"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/repository"
)

// newAuditRecord returns a fully populated audit record. The caller supplies the
// ID and timestamp, matching the port convention that repositories mint neither.
func newAuditRecord(id, actorID, targetID string, at time.Time) *domain.AuditRecord {
	return &domain.AuditRecord{
		ID:         domain.AuditRecordID(id),
		ActorType:  domain.ActorTypeOwner,
		ActorID:    actorID,
		Action:     domain.AuditActionKeyAdded,
		TargetType: domain.TargetTypePublicKey,
		TargetID:   targetID,
		OccurredAt: at,
	}
}

// auditSink returns the append-only sink together with the reading repo behind
// it, so a test can append through the narrow interface and verify through the
// reads.
func auditSink(t *testing.T, s *Store) (repository.AuditAppender, *auditRepo) {
	t.Helper()
	return s.AuditAppender(), &auditRepo{e: s.db}
}

func TestAuditAppendAndGet(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	sink, repo := auditSink(t, s)

	want := newAuditRecord("aud-1", "owner-a", "key-1", testClock)
	want.Metadata = map[string]string{"fingerprint": "SHA256:abc", "device": "laptop"}
	if err := sink.Append(ctx, want); err != nil {
		t.Fatalf("Append: %v", err)
	}

	got, err := repo.Get(ctx, "aud-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.ID != want.ID || got.ActorType != want.ActorType || got.ActorID != want.ActorID {
		t.Errorf("actor round-trip = %+v, want %+v", got, want)
	}
	if got.Action != want.Action || got.TargetType != want.TargetType || got.TargetID != want.TargetID {
		t.Errorf("action/target round-trip = %+v, want %+v", got, want)
	}
	if !got.OccurredAt.Equal(want.OccurredAt) {
		t.Errorf("OccurredAt = %v, want %v", got.OccurredAt, want.OccurredAt)
	}
	if !reflect.DeepEqual(got.Metadata, want.Metadata) {
		t.Errorf("Metadata = %v, want %v", got.Metadata, want.Metadata)
	}
	if got.Pseudonymized {
		t.Error("Pseudonymized = true, want false")
	}
}

// TestAuditOccurredAtRoundTripsExactly is the engine-parity pin on the time
// encoding, and it is the reason occurred_at is TEXT rather than timestamptz.
//
// A timestamptz column stores microseconds, so it would silently truncate the
// nanosecond component of every timestamp written through it. This test seeds
// values whose nanosecond digits are non-zero and asserts they come back
// bit-identical, which fails immediately if the column type or the encoder is
// ever changed to something lossy. The consequence of such a change would not
// be a visibly wrong timestamp — it would be PurgeOlderThan's retention
// boundary landing on a different row here than on SQLite, silently, for
// records within a microsecond of the cutoff.
func TestAuditOccurredAtRoundTripsExactly(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	sink, repo := auditSink(t, s)

	// Nanosecond components a microsecond-precision column cannot represent.
	instants := []time.Time{
		testClock.Add(1 * time.Nanosecond),
		testClock.Add(999 * time.Nanosecond),
		testClock.Add(123456789 * time.Nanosecond),
	}
	for i, at := range instants {
		id := domain.AuditRecordID("aud-ns-" + strconv.Itoa(i))
		if err := sink.Append(ctx, newAuditRecord(string(id), "owner-a", "key-1", at)); err != nil {
			t.Fatalf("Append: %v", err)
		}
		got, err := repo.Get(ctx, id)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if !got.OccurredAt.Equal(at) {
			t.Errorf("OccurredAt = %v, want %v: the stored timestamp is lossy", got.OccurredAt, at)
		}
		if got.OccurredAt.Nanosecond() != at.Nanosecond() {
			t.Errorf("nanoseconds = %d, want %d: sub-microsecond precision was truncated",
				got.OccurredAt.Nanosecond(), at.Nanosecond())
		}
	}
}

func TestAuditGetMissingReturnsNotFound(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	_, repo := auditSink(t, s)

	if _, err := repo.Get(context.Background(), "nope"); !errors.Is(err, domain.ErrNotFound) {
		t.Errorf("Get missing = %v, want ErrNotFound", err)
	}
}

func TestAuditAppendNilRecordRejected(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	sink, _ := auditSink(t, s)

	if err := sink.Append(context.Background(), nil); !errors.Is(err, domain.ErrInvalidInput) {
		t.Errorf("Append(nil) = %v, want ErrInvalidInput", err)
	}
}

func TestAuditAppendDuplicateIDConflicts(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	sink, _ := auditSink(t, s)

	rec := newAuditRecord("aud-dup", "owner-a", "key-1", testClock)
	if err := sink.Append(ctx, rec); err != nil {
		t.Fatalf("first Append: %v", err)
	}
	if err := sink.Append(ctx, rec); !errors.Is(err, domain.ErrConflict) {
		t.Errorf("duplicate Append = %v, want ErrConflict", err)
	}
}

// TestAuditAppendCannotOverwriteExisting is the append-only property at the
// storage level: re-appending under an existing ID must be refused outright
// rather than replacing the stored row. If the INSERT ever became an upsert,
// history could be rewritten silently through the one write this type exposes.
func TestAuditAppendCannotOverwriteExisting(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	sink, repo := auditSink(t, s)

	original := newAuditRecord("aud-fixed", "owner-a", "key-1", testClock)
	if err := sink.Append(ctx, original); err != nil {
		t.Fatalf("Append: %v", err)
	}

	// Same ID, different content: an attacker rewriting what happened.
	tampered := newAuditRecord("aud-fixed", "owner-evil", "key-99", testClock.Add(time.Hour))
	tampered.Action = domain.AuditActionKeyRevoked
	if err := sink.Append(ctx, tampered); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("overwrite attempt = %v, want ErrConflict", err)
	}

	got, err := repo.Get(ctx, "aud-fixed")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.ActorID != "owner-a" || got.Action != domain.AuditActionKeyAdded || got.TargetID != "key-1" {
		t.Errorf("record was mutated by a failed re-append: %+v", got)
	}
	if !got.OccurredAt.Equal(testClock) {
		t.Errorf("OccurredAt = %v, want the original %v", got.OccurredAt, testClock)
	}
}

// TestAuditRepoExposesNoMutatingMethods is the test that fails if a delete or
// update capability is ever added to the audit adapter or its append-only port.
//
// It reflects over the method sets rather than asserting on behavior, because
// the property under test is the *absence* of a capability: no behavioral test
// can observe a method that does not exist. Adding a Delete, Purge, Update, or
// similar method to auditRepo or to repository.AuditAppender fails this test,
// which forces that change to be a deliberate, reviewed edit here rather than a
// quiet expansion of what the sink can do.
//
// The ADR-0024 maintenance operations — PurgeOlderThan and Pseudonymize — are
// implemented here deliberately, so they are in the allowed set below. That is
// the whole mechanism: widening this list is a visible, reviewed edit, and
// anything NOT on it still fails. A general Delete or Update, which could
// rewrite the substance of a record rather than only its subject, remains
// forbidden.
func TestAuditRepoExposesNoMutatingMethods(t *testing.T) {
	t.Parallel()

	// The full surface this adapter implements. Append/Get/List are the
	// append-and-read core; the other two are the bounded ADR-0024 maintenance
	// capabilities, each of which can only remove an aged row or overwrite the
	// two identity columns.
	allowed := map[string]bool{
		"Append": true, "Get": true, "List": true,
		"PurgeOlderThan": true, "Pseudonymize": true,
	}

	repoType := reflect.TypeOf(&auditRepo{})
	for i := range repoType.NumMethod() {
		name := repoType.Method(i).Name
		if !allowed[name] {
			t.Errorf("auditRepo exposes unexpected method %q: the audit log is append-and-read only; "+
				"deletion and rewriting are ADR-0024 maintenance capabilities that must be added deliberately", name)
		}
	}

	// The narrow port handed to request-path services must stay insert-only.
	appenderType := reflect.TypeOf((*repository.AuditAppender)(nil)).Elem()
	if n := appenderType.NumMethod(); n != 1 || appenderType.Method(0).Name != "Append" {
		t.Errorf("repository.AuditAppender must expose exactly Append, got %d methods", n)
	}

	// auditRepo satisfies the full AuditRepository; maintenance jobs receive it
	// through Repos.Audit.
	fullType := reflect.TypeOf((*repository.AuditRepository)(nil)).Elem()
	if !repoType.Implements(fullType) {
		t.Error("auditRepo must implement repository.AuditRepository")
	}

	// The value handed to request-path code must NOT. auditAppenderOnly is the
	// wrapper that keeps the sink narrow at the type level, so it must carry
	// exactly one method — adding a second here would reopen the type-assertion
	// escalation route that TestAuditAppenderIsInsertOnlyAtTheTypeLevel guards.
	sinkType := reflect.TypeOf(auditAppenderOnly{})
	if n := sinkType.NumMethod(); n != 1 || sinkType.Method(0).Name != "Append" {
		t.Errorf("auditAppenderOnly must expose exactly Append, got %d methods", n)
	}
	if sinkType.Implements(fullType) {
		t.Error("auditAppenderOnly implements repository.AuditRepository: the request-path " +
			"sink can be widened back to the purge and rewrite powers")
	}
}

func TestAuditListNewestFirst(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	sink, repo := auditSink(t, s)

	for i, id := range []string{"aud-1", "aud-2", "aud-3"} {
		rec := newAuditRecord(id, "owner-a", "key-1", testClock.Add(time.Duration(i)*time.Minute))
		if err := sink.Append(ctx, rec); err != nil {
			t.Fatalf("Append %s: %v", id, err)
		}
	}

	got, next, err := repo.List(ctx, repository.AuditQuery{}, repository.Page{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if next != "" {
		t.Errorf("next cursor = %q, want empty (single page)", next)
	}
	wantOrder := []string{"aud-3", "aud-2", "aud-1"}
	if len(got) != len(wantOrder) {
		t.Fatalf("List returned %d records, want %d", len(got), len(wantOrder))
	}
	for i, want := range wantOrder {
		if string(got[i].ID) != want {
			t.Errorf("record %d = %q, want %q (newest first)", i, got[i].ID, want)
		}
	}
}

func TestAuditListEmptyReturnsNilSlice(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	_, repo := auditSink(t, s)

	got, next, err := repo.List(context.Background(), repository.AuditQuery{}, repository.Page{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if got != nil {
		t.Errorf("List on empty log = %v, want nil slice", got)
	}
	if next != "" {
		t.Errorf("next cursor = %q, want empty", next)
	}
}

// TestAuditListFilters exercises every optional predicate. On this engine the
// table doubles as the placeholder-numbering test: each filter shifts where the
// LIMIT parameter lands, so a query whose numbering did not track the argument
// order would bind the row limit against a filter value (or vice versa) and
// return the wrong rows for some subset of these cases rather than erroring.
func TestAuditListFilters(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	sink, repo := auditSink(t, s)

	base := newAuditRecord("aud-a", "owner-a", "key-1", testClock)
	other := newAuditRecord("aud-b", "owner-b", "key-2", testClock.Add(time.Minute))
	other.ActorType = domain.ActorTypeAdministrator
	other.Action = domain.AuditActionDeviceRevoked
	other.TargetType = domain.TargetTypeDevice
	for _, rec := range []*domain.AuditRecord{base, other} {
		if err := sink.Append(ctx, rec); err != nil {
			t.Fatalf("Append %s: %v", rec.ID, err)
		}
	}

	from := testClock.Add(30 * time.Second)
	to := testClock.Add(30 * time.Second)
	tests := []struct {
		name  string
		query repository.AuditQuery
		want  string
	}{
		{"by actor type", repository.AuditQuery{ActorType: domain.ActorTypeAdministrator}, "aud-b"},
		{"by actor id", repository.AuditQuery{ActorID: "owner-a"}, "aud-a"},
		{"by action", repository.AuditQuery{Action: domain.AuditActionKeyAdded}, "aud-a"},
		{"by target type", repository.AuditQuery{TargetType: domain.TargetTypeDevice}, "aud-b"},
		{"by target id", repository.AuditQuery{TargetID: "key-1"}, "aud-a"},
		{"from bound", repository.AuditQuery{From: &from}, "aud-b"},
		{"to bound", repository.AuditQuery{To: &to}, "aud-a"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, _, err := repo.List(ctx, tc.query, repository.Page{})
			if err != nil {
				t.Fatalf("List: %v", err)
			}
			if len(got) != 1 || string(got[0].ID) != tc.want {
				t.Errorf("List = %v, want exactly [%s]", ids(got), tc.want)
			}
		})
	}
}

// TestAuditListAllFiltersTogether is the placeholder-numbering test proper. It
// sets every optional predicate at once plus a cursor, so the statement carries
// the maximum number of bind parameters this query can produce and the LIMIT
// lands at $11. If any placeholder were numbered by hand, or the numbering
// drifted from the argument order, this is the shape that breaks.
func TestAuditListAllFiltersTogether(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	sink, repo := auditSink(t, s)

	for i, id := range []string{"aud-1", "aud-2", "aud-3"} {
		rec := newAuditRecord(id, "owner-a", "key-1", testClock.Add(time.Duration(i)*time.Minute))
		if err := sink.Append(ctx, rec); err != nil {
			t.Fatalf("Append %s: %v", id, err)
		}
	}

	from := testClock.Add(-time.Hour)
	to := testClock.Add(time.Hour)
	q := repository.AuditQuery{
		ActorType:  domain.ActorTypeOwner,
		ActorID:    "owner-a",
		Action:     domain.AuditActionKeyAdded,
		TargetType: domain.TargetTypePublicKey,
		TargetID:   "key-1",
		From:       &from,
		To:         &to,
	}

	// Without a cursor first: all three match.
	got, _, err := repo.List(ctx, q, repository.Page{Limit: 10})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if want := []string{"aud-3", "aud-2", "aud-1"}; !reflect.DeepEqual(ids(got), want) {
		t.Fatalf("List with every filter = %v, want %v", ids(got), want)
	}

	// Now with a cursor as well, which adds three more parameters ahead of the
	// LIMIT. Starting after the newest record must yield exactly the older two.
	cursor := encAuditCursor(got[0].OccurredAt, got[0].ID)
	got, _, err = repo.List(ctx, q, repository.Page{Limit: 10, Cursor: cursor})
	if err != nil {
		t.Fatalf("List with cursor: %v", err)
	}
	if want := []string{"aud-2", "aud-1"}; !reflect.DeepEqual(ids(got), want) {
		t.Errorf("List with every filter and a cursor = %v, want %v", ids(got), want)
	}
}

// TestAuditListBoundsAreInclusive pins the port's documented "From and To bound
// OccurredAt inclusively" against an off-by-one in the comparison operators.
func TestAuditListBoundsAreInclusive(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	sink, repo := auditSink(t, s)

	if err := sink.Append(ctx, newAuditRecord("aud-1", "owner-a", "key-1", testClock)); err != nil {
		t.Fatalf("Append: %v", err)
	}

	at := testClock
	got, _, err := repo.List(ctx, repository.AuditQuery{From: &at, To: &at}, repository.Page{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 1 {
		t.Errorf("List with From == To == the record's timestamp returned %d records, want 1", len(got))
	}
}

// TestAuditListPaginates walks every page and asserts the full sequence is
// returned exactly once, in order. Records deliberately share a timestamp so
// that a cursor keyed on occurred_at alone would skip or repeat rows.
func TestAuditListPaginates(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	sink, repo := auditSink(t, s)

	// aud-1..aud-5, all at the same instant: the id is what makes the keyset total.
	want := []string{"aud-5", "aud-4", "aud-3", "aud-2", "aud-1"}
	for _, id := range want {
		if err := sink.Append(ctx, newAuditRecord(id, "owner-a", "key-1", testClock)); err != nil {
			t.Fatalf("Append %s: %v", id, err)
		}
	}

	var seen []string
	cursor := ""
	for range len(want) + 1 {
		page, next, err := repo.List(ctx, repository.AuditQuery{}, repository.Page{Limit: 2, Cursor: cursor})
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		seen = append(seen, ids(page)...)
		if next == "" {
			break
		}
		cursor = next
	}
	if !reflect.DeepEqual(seen, want) {
		t.Errorf("paginated sequence = %v, want %v", seen, want)
	}
}

func TestAuditListRejectsMalformedCursor(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	_, repo := auditSink(t, s)

	for _, cursor := range []string{"short", strings.Repeat("x", encodedTimeWidth+4)} {
		_, _, err := repo.List(context.Background(), repository.AuditQuery{},
			repository.Page{Cursor: cursor})
		if !errors.Is(err, domain.ErrInvalidInput) {
			t.Errorf("List with cursor %q = %v, want ErrInvalidInput", cursor, err)
		}
	}
}

// TestAuditCursorWidthMatchesEncTime pins encodedTimeWidth to the real encoder,
// so a change to timeLayout cannot silently split cursors at the wrong offset.
func TestAuditCursorWidthMatchesEncTime(t *testing.T) {
	t.Parallel()
	if got := len(encTime(testClock)); got != encodedTimeWidth {
		t.Errorf("len(encTime(...)) = %d, want encodedTimeWidth = %d", got, encodedTimeWidth)
	}
}

func TestAuditCursorRoundTrips(t *testing.T) {
	t.Parallel()

	cursor := encAuditCursor(testClock, "aud-1")
	at, id, err := decAuditCursor(cursor)
	if err != nil {
		t.Fatalf("decAuditCursor: %v", err)
	}
	if at != encTime(testClock) {
		t.Errorf("timestamp part = %q, want %q", at, encTime(testClock))
	}
	if id != "aud-1" {
		t.Errorf("id part = %q, want %q", id, "aud-1")
	}
}

// TestAuditMetadataRoundTrip covers the nil/empty/populated encodings, including
// the convention that an absent map stays nil rather than becoming an empty map.
func TestAuditMetadataRoundTrip(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	sink, repo := auditSink(t, s)

	tests := []struct {
		name string
		in   map[string]string
		want map[string]string
	}{
		{"nil", nil, nil},
		{"empty", map[string]string{}, nil},
		{"populated", map[string]string{"a": "1", "b": "2"}, map[string]string{"a": "1", "b": "2"}},
		{"unicode value", map[string]string{"name": "café ☕"}, map[string]string{"name": "café ☕"}},
	}
	for i, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := newAuditRecord("aud-meta-"+tc.name, "owner-a", "key-1",
				testClock.Add(time.Duration(i)*time.Second))
			rec.Metadata = tc.in
			if err := sink.Append(ctx, rec); err != nil {
				t.Fatalf("Append: %v", err)
			}
			got, err := repo.Get(ctx, rec.ID)
			if err != nil {
				t.Fatalf("Get: %v", err)
			}
			if !reflect.DeepEqual(got.Metadata, tc.want) {
				t.Errorf("Metadata = %#v, want %#v", got.Metadata, tc.want)
			}
		})
	}
}

func TestAuditDecMetadataRejectsCorruptJSON(t *testing.T) {
	t.Parallel()
	if _, err := decAuditMetadata(`{"a":`); err == nil {
		t.Error("decAuditMetadata on truncated JSON = nil error, want failure")
	}
}

// TestAuditPseudonymizedFlagRoundTrips exercises the BOOLEAN column, which is
// the one column whose type differs from the SQLite adapter's (INTEGER 0/1).
func TestAuditPseudonymizedFlagRoundTrips(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	sink, repo := auditSink(t, s)

	rec := newAuditRecord("aud-p", "pseudo-xyz", "key-1", testClock)
	rec.Pseudonymized = true
	if err := sink.Append(ctx, rec); err != nil {
		t.Fatalf("Append: %v", err)
	}
	got, err := repo.Get(ctx, "aud-p")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !got.Pseudonymized {
		t.Error("Pseudonymized = false, want true")
	}
}

// TestAuditAppenderIsInsertOnlyAtTheTypeLevel asserts the value handed to
// request-path code cannot be widened back to the reading repo by a type
// assertion the compiler would not catch.
func TestAuditAppenderIsInsertOnlyAtTheTypeLevel(t *testing.T) {
	t.Parallel()
	s := newStore(t)

	sink := s.AuditAppender()
	if _, ok := sink.(interface {
		Delete(context.Context, domain.AuditRecordID) error
	}); ok {
		t.Error("the audit sink can be asserted to a Delete capability")
	}
	if _, ok := sink.(repository.AuditRepository); ok {
		t.Error("the audit sink can be asserted back to the full AuditRepository, " +
			"handing request-path code the purge and pseudonymize powers")
	}
}

// TestAuditRecordsAreNotOwnerScoped documents, as an executable note, that the
// audit log is deliberately cross-owner: records for different owners live in
// one log and a reader of the log sees all of them. There is therefore no
// cross-owner isolation property to test at this layer — confidentiality comes
// from who is handed the reading repo at all, not from a per-row owner filter.
// See ADR-0007/ADR-0024 and the auditRepo doc comment.
func TestAuditRecordsAreNotOwnerScoped(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	sink, repo := auditSink(t, s)

	if err := sink.Append(ctx, newAuditRecord("aud-a", "owner-a", "key-1", testClock)); err != nil {
		t.Fatalf("Append: %v", err)
	}
	if err := sink.Append(ctx, newAuditRecord("aud-b", "owner-b", "key-2", testClock.Add(time.Minute))); err != nil {
		t.Fatalf("Append: %v", err)
	}

	// domain.AuditRecord has no OwnerID field to scope on; confirm that stays true.
	if _, ok := reflect.TypeOf(domain.AuditRecord{}).FieldByName("OwnerID"); ok {
		t.Error("domain.AuditRecord gained an OwnerID field: the audit log is a cross-owner " +
			"system record whose rows must outlive the owners they name (ADR-0024)")
	}

	all, _, err := repo.List(ctx, repository.AuditQuery{}, repository.Page{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(all) != 2 {
		t.Errorf("List returned %d records, want both owners' records in one log", len(all))
	}

	// Narrowing to one actor is a query filter, not an authorization boundary.
	mine, _, err := repo.List(ctx, repository.AuditQuery{ActorID: "owner-a"}, repository.Page{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(mine) != 1 || mine[0].ActorID != "owner-a" {
		t.Errorf("List filtered by actor = %v, want exactly owner-a's record", ids(mine))
	}
}

// ids extracts record IDs for readable failure messages.
func ids(records []domain.AuditRecord) []string {
	if len(records) == 0 {
		return nil
	}
	out := make([]string, len(records))
	for i, r := range records {
		out[i] = string(r.ID)
	}
	return out
}
