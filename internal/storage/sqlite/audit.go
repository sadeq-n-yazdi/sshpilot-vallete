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
// It implements exactly the append-and-read surface: Append, Get, and List.
// There is deliberately no Update and no Delete method here, and their absence
// is the security property, not an oversight or an unfinished stub. An attacker
// who reaches this type cannot quietly rewrite or erase history through it,
// because the capability to do so does not exist on the type. Controlled
// deletion (retention purge) and controlled rewriting (pseudonymization for
// crypto-erasure) are specified by ADR-0024 as deliberate, separately reviewed
// system-maintenance capabilities; they are declared on
// repository.AuditRepository and are added to this type by that later work, so
// that granting those powers is an explicit, reviewable act.
//
// Unlike every other repository in this package, auditRepo is not owner-scoped.
// The audit log is a cross-owner system record: its actors may be an
// administrator or the system itself and its targets are polymorphic, so
// domain.AuditRecord carries no OwnerID to filter on. This is scoping by
// design, not a missing predicate — see the UNSCOPED notes on List and Get.
type auditRepo struct {
	e execer
}

// Compile-time assertion that auditRepo satisfies the insert-only appender.
//
// It is deliberately NOT asserted against repository.AuditRepository: that
// interface also declares PurgeOlderThan and Pseudonymize, and asserting it
// here would force this type to grow a delete and a rewrite path as a side
// effect of a compile check. Request-path services take an AuditAppender, which
// by construction cannot read, rewrite, or delete audit content.
var _ repository.AuditAppender = (*auditRepo)(nil)

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
