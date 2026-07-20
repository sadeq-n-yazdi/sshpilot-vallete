package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/repository"
)

// auditColumns is the fixed column list shared by every audit SELECT so the
// scan order in scanAuditRecord stays in lockstep with the queries.
const auditColumns = `id, actor_type, actor_id, action, target_type, target_id, occurred_at, metadata, pseudonymized`

// auditRepo is the SQLite audit log adapter.
//
// It implements the append-and-read surface (Append, Get, List) plus exactly
// two ADR-0024 system-maintenance operations: PurgeOlderThan for retention and
// Pseudonymize for crypto-erasure. There is deliberately no general Update and
// no general Delete, and their absence is the security property. The two
// maintenance methods are narrow by construction rather than by convention:
// PurgeOlderThan can only remove a whole row that is already older than a
// caller-supplied cutoff, and Pseudonymize can only overwrite the two identity
// columns. Neither can alter the substance of a surviving record — its action,
// its timestamp, or its actor/target kinds — so neither can be turned into a
// tool for forging or doctoring history. See the per-method notes for why.
//
// Unlike every other repository in this package, auditRepo is not owner-scoped.
// The audit log is a cross-owner system record: its actors may be an
// administrator or the system itself and its targets are polymorphic, so
// domain.AuditRecord carries no OwnerID to filter on. This is scoping by
// design, not a missing predicate — see the UNSCOPED notes on List and Get.
type auditRepo struct {
	e execer
}

// Compile-time assertions that auditRepo satisfies both the insert-only
// appender and the full maintenance port.
//
// Both are asserted deliberately. The AuditAppender assertion is the load
// bearing one for the request path: Store.AuditAppender hands out this type
// behind that narrow interface, so a service that emits events cannot reach
// Get, List, PurgeOlderThan, or Pseudonymize even though the concrete type has
// them. Capability is restricted by the interface a caller is given, not by
// what the adapter can do.
var (
	_ repository.AuditAppender   = (*auditRepo)(nil)
	_ repository.AuditRepository = (*auditRepo)(nil)
)

// Append inserts a fully populated audit record exactly as given. Per the
// repository convention the caller supplies the ID and OccurredAt; this method
// mints neither. A duplicate primary key maps to domain.ErrConflict.
//
// This is the only write this type can perform.
func (r *auditRepo) Append(ctx context.Context, rec *domain.AuditRecord) error {
	// A nil entity is a caller programming error, not a storage fault; reject it
	// as invalid input rather than dereferencing it into a panic.
	if rec == nil {
		return fmt.Errorf("%s: nil audit record: %w", errPrefix, domain.ErrInvalidInput)
	}

	const q = `INSERT INTO audit_records
(id, actor_type, actor_id, action, target_type, target_id, occurred_at, metadata, pseudonymized)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
	_, err := r.e.ExecContext(ctx, q,
		string(rec.ID),
		string(rec.ActorType),
		rec.ActorID,
		string(rec.Action),
		string(rec.TargetType),
		rec.TargetID,
		encTime(rec.OccurredAt),
		encAuditMetadata(rec.Metadata),
		encBool(rec.Pseudonymized),
	)
	return mapError(err)
}

// Get returns the audit record with the given ID, or domain.ErrNotFound if none
// exists.
//
// UNSCOPED: audit records carry no owner. The log is a cross-owner system
// record, so there is no ownerID to filter by; access is restricted by giving
// request-path services the insert-only AuditAppender instead of this type.
func (r *auditRepo) Get(ctx context.Context, id domain.AuditRecordID) (*domain.AuditRecord, error) {
	q := `SELECT ` + auditColumns + ` FROM audit_records WHERE id = ?`
	return scanAuditRecord(r.e.QueryRowContext(ctx, q, string(id)))
}

// List returns a newest-first page of records matching q, together with the
// next-page cursor ("" when there are no further pages).
//
// Ordering and pagination are over the composite (occurred_at, id) descending.
// occurred_at alone is not unique — two events can share a timestamp — so a
// cursor over it alone could skip or repeat rows at a page boundary; appending
// the unique id makes the keyset total and the pagination exact.
//
// UNSCOPED: as for Get, the audit log has no owner column to scope by.
func (r *auditRepo) List(ctx context.Context, q repository.AuditQuery, page repository.Page) ([]domain.AuditRecord, string, error) {
	limit := page.Limit
	if limit <= 0 {
		limit = defaultPageLimit
	}

	where, args, err := auditWhere(q, page.Cursor)
	if err != nil {
		return nil, "", err
	}

	// Fetch one extra row to detect whether a further page exists without a
	// second round trip.
	query := `SELECT ` + auditColumns + ` FROM audit_records` + where +
		` ORDER BY occurred_at DESC, id DESC LIMIT ?`
	args = append(args, limit+1)

	rows, err := r.e.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, "", mapError(err)
	}
	records, err := collectAuditRecords(rows)
	if err != nil {
		return nil, "", err
	}

	next := ""
	if len(records) > limit {
		last := records[limit-1]
		next = encAuditCursor(last.OccurredAt, last.ID)
		records = records[:limit]
	}
	return records, next, nil
}

// auditWhere builds the WHERE clause and bound arguments for a listing. Zero
// valued query fields are omitted, so an empty query and an empty cursor yield
// no clause at all. Every value is bound as a parameter; no caller-supplied
// text is ever concatenated into the SQL.
func auditWhere(q repository.AuditQuery, cursor string) (string, []any, error) {
	var (
		clauses []string
		args    []any
	)
	add := func(clause string, value any) {
		clauses = append(clauses, clause)
		args = append(args, value)
	}

	if q.ActorType != "" {
		add(`actor_type = ?`, string(q.ActorType))
	}
	if q.ActorID != "" {
		add(`actor_id = ?`, q.ActorID)
	}
	if q.Action != "" {
		add(`action = ?`, string(q.Action))
	}
	if q.TargetType != "" {
		add(`target_type = ?`, string(q.TargetType))
	}
	if q.TargetID != "" {
		add(`target_id = ?`, q.TargetID)
	}
	// From and To bound OccurredAt inclusively. Because encTime is fixed-width
	// UTC text, a lexical comparison in SQL is a chronological one.
	if q.From != nil {
		add(`occurred_at >= ?`, encTime(*q.From))
	}
	if q.To != nil {
		add(`occurred_at <= ?`, encTime(*q.To))
	}

	if cursor != "" {
		at, id, err := decAuditCursor(cursor)
		if err != nil {
			return "", nil, err
		}
		// Strictly older than the cursor row under (occurred_at, id) DESC.
		clauses = append(clauses, `(occurred_at < ? OR (occurred_at = ? AND id < ?))`)
		args = append(args, at, at, id)
	}

	if len(clauses) == 0 {
		return "", nil, nil
	}
	return ` WHERE ` + strings.Join(clauses, ` AND `), args, nil
}

// encodedTimeWidth is the exact character width of an encTime result. encTime
// forces UTC, so the zone always renders as the single character "Z" and every
// encoded timestamp has this same fixed width. auditCursorWidthMatchesEncTime
// in the tests pins this constant to the real encoder.
const encodedTimeWidth = 30

// encAuditCursor encodes a keyset cursor as the fixed-width encoded timestamp
// followed by the record ID. The timestamp's width is constant, so the two
// parts split unambiguously without a separator that an ID might contain.
func encAuditCursor(occurredAt time.Time, id domain.AuditRecordID) string {
	return encTime(occurredAt) + string(id)
}

// decAuditCursor splits a cursor back into its encoded timestamp and record ID.
// A cursor that is too short or whose timestamp does not parse is caller error
// and maps to domain.ErrInvalidInput; the malformed value is not echoed back.
func decAuditCursor(cursor string) (string, string, error) {
	if len(cursor) <= encodedTimeWidth {
		return "", "", fmt.Errorf("%s: malformed audit cursor: %w", errPrefix, domain.ErrInvalidInput)
	}
	at, id := cursor[:encodedTimeWidth], cursor[encodedTimeWidth:]
	if _, err := decTime(at); err != nil {
		return "", "", fmt.Errorf("%s: malformed audit cursor: %w", errPrefix, domain.ErrInvalidInput)
	}
	return at, id, nil
}

// encAuditMetadata encodes the metadata map as a JSON object for the metadata
// column. A nil or empty map encodes as "{}" rather than SQL NULL, so readers
// never have to distinguish "no metadata" from "null metadata".
// encoding/json sorts object keys, so the encoding is deterministic.
//
// It returns no error because it cannot fail: json.Marshal of a
// map[string]string has no unsupported type, no cycle, and no non-finite float
// to reject, and invalid UTF-8 in a value is replaced rather than refused. An
// error return here would be unreachable code masquerading as a handled
// failure, which is worse than none.
func encAuditMetadata(m map[string]string) string {
	if len(m) == 0 {
		return "{}"
	}
	b, err := json.Marshal(m)
	if err != nil {
		panic("sqlite: unreachable: map[string]string failed to marshal: " + err.Error())
	}
	return string(b)
}

// decAuditMetadata decodes the metadata column. "{}" and an empty column both
// yield a nil map, matching the convention that absent collections are nil.
func decAuditMetadata(s string) (map[string]string, error) {
	if s == "" || s == "{}" {
		return nil, nil
	}
	var m map[string]string
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		return nil, fmt.Errorf("%s: decode audit metadata: %w", errPrefix, err)
	}
	if len(m) == 0 {
		return nil, nil
	}
	return m, nil
}

// collectAuditRecords drains rows into a slice, mapping any iteration error
// through mapError and always closing the cursor. An empty result yields a nil
// slice, per the repository convention.
func collectAuditRecords(rows *sql.Rows) ([]domain.AuditRecord, error) {
	defer func() { _ = rows.Close() }()

	var records []domain.AuditRecord
	for rows.Next() {
		rec, err := scanAuditRecord(rows)
		if err != nil {
			return nil, err
		}
		records = append(records, *rec)
	}
	if err := rows.Err(); err != nil {
		return nil, mapError(err)
	}
	return records, nil
}

// scanAuditRecord decodes one audit row in auditColumns order. A sql.ErrNoRows
// from a *sql.Row read maps to domain.ErrNotFound via mapError.
func scanAuditRecord(s rowScanner) (*domain.AuditRecord, error) {
	var (
		rec           domain.AuditRecord
		actorType     string
		action        string
		targetType    string
		occurredAt    string
		metadata      string
		pseudonymized int
	)
	if err := s.Scan(&rec.ID, &actorType, &rec.ActorID, &action, &targetType,
		&rec.TargetID, &occurredAt, &metadata, &pseudonymized); err != nil {
		return nil, mapError(err)
	}
	rec.ActorType = domain.ActorType(actorType)
	rec.Action = domain.AuditAction(action)
	rec.TargetType = domain.TargetType(targetType)
	rec.Pseudonymized = pseudonymized != 0

	var err error
	if rec.OccurredAt, err = decTime(occurredAt); err != nil {
		return nil, err
	}
	if rec.Metadata, err = decAuditMetadata(metadata); err != nil {
		return nil, err
	}
	return &rec, nil
}

// maxPseudonymizeBatch bounds how many IDs are bound into a single UPDATE.
// Each ID is bound twice (once against actor_id, once against target_id), so a
// batch of this size stays well inside SQLite's default limit of 32766 bound
// variables per statement. Callers pass whole owner ID sets without having to
// know that limit.
const maxPseudonymizeBatch = 400

// PurgeOlderThan deletes up to limit records whose occurred_at is at or before
// cutoff and returns the number deleted.
//
// The cutoff is INCLUSIVE, matching the port contract ("at or before cutoff").
// A record whose timestamp is even one nanosecond after cutoff is out of scope
// and survives. This direction is the one that matters: an off-by-one that
// deleted newer records would silently destroy evidence, so the comparison is
// pinned by boundary tests on both sides of the cutoff.
//
// Deletion is bounded by limit so that purging a large backlog runs as a
// sequence of short transactions rather than one long one that holds a write
// lock over the whole table. The returned count is how the caller drives that
// loop: a count equal to limit means the batch was filled and more may remain,
// a smaller count means the backlog is drained. This method performs exactly
// one batch and never loops internally, so the caller keeps control of pacing
// and cancellation.
//
// Rows are selected oldest-first so repeated batches make monotonic progress
// from the back of the log rather than nibbling at an arbitrary middle.
//
// Zero rows deleted is a normal outcome (nothing was old enough), not an error,
// so this method deliberately does not use requireAffected.
//
// UNSCOPED: retention is a system-maintenance sweep across all records; the
// audit log carries no owner column to scope by.
func (r *auditRepo) PurgeOlderThan(ctx context.Context, cutoff time.Time, limit int) (int64, error) {
	// A non-positive limit has no safe interpretation. Treating it as
	// "unbounded" would turn a caller's zero value into a full-table delete,
	// which is precisely the accident this API's batching exists to prevent, so
	// it is rejected as invalid input instead.
	if limit <= 0 {
		return 0, fmt.Errorf("%s: purge limit must be positive: %w", errPrefix, domain.ErrInvalidInput)
	}

	// DELETE ... LIMIT is not available: it requires a SQLite build flag this
	// driver does not set, and PostgreSQL has no such form at all. The
	// portable equivalent is to delete the rows named by a bounded subquery,
	// which is also what makes the oldest-first ordering explicit.
	const q = `DELETE FROM audit_records WHERE id IN (
	SELECT id FROM audit_records WHERE occurred_at <= ? ORDER BY occurred_at, id LIMIT ?
)`
	res, err := r.e.ExecContext(ctx, q, encTime(cutoff), limit)
	if err != nil {
		return 0, mapError(err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, mapError(err)
	}
	return n, nil
}

// Pseudonymize replaces every occurrence of the given IDs in the actor_id and
// target_id columns with pseudonym, marks the affected rows pseudonymized, and
// returns the number of rows rewritten.
//
// # What this can and cannot touch
//
// The UPDATE sets exactly three columns: actor_id, target_id, and the
// pseudonymized flag. It cannot reach action, occurred_at, actor_type, or
// target_type. That is the anti-forgery property stated on the type: this
// method removes WHO an event was about while leaving WHAT happened and WHEN
// byte-identical, so a surviving record still proves the event. There is no
// input to this method that alters the substance of history.
//
// # Idempotence
//
// The match is on the ORIGINAL IDs, and the new value is a constant supplied by
// the caller. A second run with the same arguments matches nothing, because
// those IDs no longer appear in the table, and returns 0. The pseudonym is
// never derived from the column's current value, so there is no way for a
// repeated run to double-hash a tombstone or to resurrect a prior value.
//
// The WHERE clause is deliberately NOT gated on pseudonymized = 0. A single
// record can name two different subjects — an administrator actor acting on an
// owner target, for instance — and each subject's erasure must be able to
// rewrite its own column independently. A flag gate would let the first
// erasure lock out the second, leaving a real identity standing in a row that
// already claims to be pseudonymized.
//
// UNSCOPED: as for PurgeOlderThan, records are identified by their polymorphic
// IDs, not by an owner scope.
func (r *auditRepo) Pseudonymize(ctx context.Context, ids []string, pseudonym string) (int64, error) {
	// An empty pseudonym is refused: it is not a tombstone, it would erase the
	// identity without leaving anything that links the record to the erasure,
	// and a later run could match "" and sweep in unrelated rows.
	if pseudonym == "" {
		return 0, fmt.Errorf("%s: empty pseudonym: %w", errPrefix, domain.ErrInvalidInput)
	}
	// An empty ID in the input is refused rather than skipped. actor_id is a
	// plain NOT NULL string that may legitimately be empty for a system actor,
	// so binding "" would match every such record and rewrite identities that
	// were never in scope for this erasure. Failing loudly beats silently
	// over-erasing.
	for _, id := range ids {
		if id == "" {
			return 0, fmt.Errorf("%s: empty id in pseudonymize set: %w", errPrefix, domain.ErrInvalidInput)
		}
	}
	if len(ids) == 0 {
		return 0, nil
	}

	// All batches commit together: a partial erasure that left some of an
	// owner's IDs in the clear would be a silent privacy failure, so the whole
	// set is atomic.
	var total int64
	err := withLocalTx(ctx, r.e, func(e execer) error {
		for start := 0; start < len(ids); start += maxPseudonymizeBatch {
			end := min(start+maxPseudonymizeBatch, len(ids))
			n, err := pseudonymizeBatch(ctx, e, ids[start:end], pseudonym)
			if err != nil {
				return err
			}
			total += n
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return total, nil
}

// pseudonymizeBatch rewrites one bounded chunk of IDs. Every ID is bound as a
// parameter; only the placeholder count is built from the input length, so no
// caller-supplied text is ever concatenated into the SQL.
func pseudonymizeBatch(ctx context.Context, e execer, ids []string, pseudonym string) (int64, error) {
	placeholders := strings.TrimSuffix(strings.Repeat("?, ", len(ids)), ", ")

	// CASE-per-column so that a row matched on only one of the two columns has
	// only that column rewritten. A blanket assignment of both columns would
	// erase a bystander identity that happens to share a record with the
	// subject being erased.
	q := `UPDATE audit_records SET
	actor_id = CASE WHEN actor_id IN (` + placeholders + `) THEN ? ELSE actor_id END,
	target_id = CASE WHEN target_id IN (` + placeholders + `) THEN ? ELSE target_id END,
	pseudonymized = 1
WHERE actor_id IN (` + placeholders + `) OR target_id IN (` + placeholders + `)`

	args := make([]any, 0, 4*len(ids)+2)
	bind := func() {
		for _, id := range ids {
			args = append(args, id)
		}
	}
	bind()
	args = append(args, pseudonym)
	bind()
	args = append(args, pseudonym)
	bind()
	bind()

	res, err := e.ExecContext(ctx, q, args...)
	if err != nil {
		return 0, mapError(err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, mapError(err)
	}
	return n, nil
}

// auditAppenderOnly is the wrapper that makes the request-path sink insert-only
// at the TYPE level, not merely at the interface level.
//
// Returning *auditRepo directly as a repository.AuditAppender would be unsafe
// once that type gained PurgeOlderThan and Pseudonymize: any holder of the
// narrow interface could recover the full capability with a single unchecked
// type assertion —
//
//	if full, ok := appender.(repository.AuditRepository); ok { full.PurgeOlderThan(...) }
//
// — which the compiler cannot flag, because a type assertion to a wider
// interface is legal on any interface value. Restricting capability by handing
// out a narrow interface only works when the dynamic value behind it is also
// narrow. This struct embeds nothing and forwards exactly one method, so the
// assertion above fails: the purge and rewrite powers are not reachable from
// the sink at all.
type auditAppenderOnly struct {
	r *auditRepo
}

// Compile-time assertion that the wrapper satisfies the insert-only port.
var _ repository.AuditAppender = auditAppenderOnly{}

// Append forwards to the underlying adapter. It is the only method on this
// type, and that is the point.
func (a auditAppenderOnly) Append(ctx context.Context, rec *domain.AuditRecord) error {
	return a.r.Append(ctx, rec)
}
