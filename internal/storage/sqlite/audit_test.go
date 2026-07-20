package sqlite

import (
	"context"
	"database/sql"
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
// now implemented here deliberately, so they are in the allowed set below. That
// is the whole mechanism: widening this list is a visible, reviewed edit, and
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

	// auditRepo now satisfies the full AuditRepository; maintenance jobs receive
	// it through Repos.Audit.
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

// insertRawAudit writes an audit row straight through the handle, bypassing the
// adapter's encoders, so the decode paths can be exercised against values the
// adapter itself would never produce.
func insertRawAudit(t *testing.T, s *Store, id, occurredAt, metadata string) {
	t.Helper()
	const q = `INSERT INTO audit_records
(id, actor_type, actor_id, action, target_type, target_id, occurred_at, metadata, pseudonymized)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
	if _, err := s.db.ExecContext(context.Background(), q,
		id, string(domain.ActorTypeOwner), "owner-a", string(domain.AuditActionKeyAdded),
		string(domain.TargetTypePublicKey), "key-1", occurredAt, metadata, 0); err != nil {
		t.Fatalf("insert raw audit row %q: %v", id, err)
	}
}

// TestAuditGetRejectsCorruptRow covers both decode branches in scanAuditRecord:
// an unparseable timestamp and unparseable metadata JSON.
func TestAuditGetRejectsCorruptRow(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	_, repo := auditSink(t, s)

	insertRawAudit(t, s, "aud-bad-time", "not-a-timestamp", "{}")
	insertRawAudit(t, s, "aud-bad-meta", encTime(testClock), `{"a":`)

	for _, id := range []string{"aud-bad-time", "aud-bad-meta"} {
		if _, err := repo.Get(ctx, domain.AuditRecordID(id)); err == nil {
			t.Errorf("Get(%q) on a corrupt row = nil error, want a decode failure", id)
		}
	}
}

// TestAuditListRejectsCorruptRow drives the same decode failure through the
// iterating path in collectAuditRecords rather than the single-row path.
func TestAuditListRejectsCorruptRow(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	_, repo := auditSink(t, s)

	insertRawAudit(t, s, "aud-bad-time", "not-a-timestamp", "{}")

	if _, _, err := repo.List(context.Background(), repository.AuditQuery{}, repository.Page{}); err == nil {
		t.Error("List over a corrupt row = nil error, want a decode failure")
	}
}

// TestAuditNullMetadataDecodesToNil covers the JSON-null metadata branch: a
// literal "null" unmarshals to a nil map and must surface as nil, not as an
// empty map, matching the nil-collection convention.
func TestAuditNullMetadataDecodesToNil(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	_, repo := auditSink(t, s)

	insertRawAudit(t, s, "aud-null-meta", encTime(testClock), "null")

	got, err := repo.Get(context.Background(), "aud-null-meta")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Metadata != nil {
		t.Errorf("Metadata = %#v, want nil", got.Metadata)
	}
}

func TestAuditEmptyMetadataColumnDecodesToNil(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	_, repo := auditSink(t, s)

	insertRawAudit(t, s, "aud-empty-meta", encTime(testClock), "")

	got, err := repo.Get(context.Background(), "aud-empty-meta")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Metadata != nil {
		t.Errorf("Metadata = %#v, want nil", got.Metadata)
	}
}

// TestAuditQueryErrorsAreMapped covers the query-failure branches by driving
// both reads with an already-canceled context.
func TestAuditQueryErrorsAreMapped(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	sink, repo := auditSink(t, s)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, _, err := repo.List(ctx, repository.AuditQuery{}, repository.Page{}); err == nil {
		t.Error("List with a canceled context = nil error, want failure")
	}
	if _, err := repo.Get(ctx, "aud-1"); err == nil {
		t.Error("Get with a canceled context = nil error, want failure")
	}
	if err := sink.Append(ctx, newAuditRecord("aud-1", "owner-a", "key-1", testClock)); err == nil {
		t.Error("Append with a canceled context = nil error, want failure")
	}
}

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
	// Metadata survives verbatim. That cuts both ways, and the seeded record
	// says so deliberately: the surviving "fingerprint" names a specific key,
	// and therefore its owner, after the actor id has been tombstoned. Erasure
	// covers the identifier columns only. See the limits section in the
	// internal/erasure package doc; this assertion is the pin on the current
	// behavior, not an endorsement of it.
	if !reflect.DeepEqual(got.Metadata, rec.Metadata) {
		t.Errorf("Metadata = %v, want %v", got.Metadata, rec.Metadata)
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
	// erasable. A WHERE gated on pseudonymized = 0 would fail here.
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
// maxPseudonymizeBatch so the multi-batch path runs and the per-statement bound
// variable ceiling is respected.
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

// errResult is a sql.Result whose RowsAffected fails. The SQLite driver always
// reports a row count successfully, so this stub is the only way to exercise
// the RowsAffected error branches, which must surface the failure rather than
// silently report zero rows purged or rewritten.
type errResult struct{ err error }

func (r errResult) LastInsertId() (int64, error) { return 0, r.err }
func (r errResult) RowsAffected() (int64, error) { return 0, r.err }

// countErrExecer runs statements against a real execer but replaces every Exec
// result with one whose RowsAffected fails.
type countErrExecer struct {
	execer
	err error
}

func (e countErrExecer) ExecContext(ctx context.Context, q string, args ...any) (sql.Result, error) {
	if _, err := e.execer.ExecContext(ctx, q, args...); err != nil {
		return nil, err
	}
	return errResult{err: e.err}, nil
}

// closedStore returns a store whose database has been closed, so every
// statement issued through it fails at the driver.
func closedStore(t *testing.T) *Store {
	t.Helper()
	s := newStore(t)
	if err := s.db.Close(); err != nil {
		t.Fatalf("close db: %v", err)
	}
	return s
}

func TestAuditPurgeSurfacesExecError(t *testing.T) {
	t.Parallel()
	repo := &auditRepo{e: closedStore(t).db}

	n, err := repo.PurgeOlderThan(context.Background(), testClock, 10)
	if err == nil {
		t.Fatal("PurgeOlderThan on a closed db = nil error, want error")
	}
	if n != 0 {
		t.Errorf("deleted = %d, want 0 on error", n)
	}
}

func TestAuditPurgeSurfacesRowsAffectedError(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	sentinel := errors.New("rows affected failed")
	repo := &auditRepo{e: countErrExecer{execer: s.db, err: sentinel}}

	n, err := repo.PurgeOlderThan(context.Background(), testClock, 10)
	if !errors.Is(err, sentinel) {
		t.Errorf("err = %v, want the RowsAffected failure", err)
	}
	if n != 0 {
		t.Errorf("deleted = %d, want 0 on error", n)
	}
}

func TestAuditPseudonymizeSurfacesExecError(t *testing.T) {
	t.Parallel()
	repo := &auditRepo{e: closedStore(t).db}

	n, err := repo.Pseudonymize(context.Background(), []string{"owner-a"}, "tomb")
	if err == nil {
		t.Fatal("Pseudonymize on a closed db = nil error, want error")
	}
	if n != 0 {
		t.Errorf("rewritten = %d, want 0 on error", n)
	}
}

// TestAuditPseudonymizeBatchSurfacesErrors drives the batch helper directly.
// withLocalTx only accepts a real *sql.DB or *sql.Tx, so a stub execer cannot
// reach the helper through Pseudonymize; calling it here is what exercises its
// two failure branches.
func TestAuditPseudonymizeBatchSurfacesErrors(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	sentinel := errors.New("rows affected failed")

	t.Run("rows affected", func(t *testing.T) {
		t.Parallel()
		s := newStore(t)
		n, err := pseudonymizeBatch(ctx, countErrExecer{execer: s.db, err: sentinel}, []string{"owner-a"}, "tomb")
		if !errors.Is(err, sentinel) {
			t.Errorf("err = %v, want the RowsAffected failure", err)
		}
		if n != 0 {
			t.Errorf("rewritten = %d, want 0 on error", n)
		}
	})

	t.Run("exec", func(t *testing.T) {
		t.Parallel()
		n, err := pseudonymizeBatch(ctx, closedStore(t).db, []string{"owner-a"}, "tomb")
		if err == nil {
			t.Fatal("pseudonymizeBatch on a closed db = nil error, want error")
		}
		if n != 0 {
			t.Errorf("rewritten = %d, want 0 on error", n)
		}
	})
}

// TestAuditPseudonymizeAbortsTransactionOnBatchError covers the failure inside
// the transaction: the tx begins successfully and the UPDATE then fails, so the
// error must propagate out and the transaction must roll back rather than
// leaving a half-erased set behind.
func TestAuditPseudonymizeAbortsTransactionOnBatchError(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	if _, err := s.db.ExecContext(ctx, `DROP TABLE audit_records`); err != nil {
		t.Fatalf("drop table: %v", err)
	}
	repo := &auditRepo{e: s.db}

	n, err := repo.Pseudonymize(ctx, []string{"owner-a"}, "tomb")
	if err == nil {
		t.Fatal("Pseudonymize against a missing table = nil error, want error")
	}
	if n != 0 {
		t.Errorf("rewritten = %d, want 0 on error", n)
	}
}
