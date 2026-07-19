package repository

import (
	"context"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
)

// AuditAppender is the insert-only view of the audit log. Request-path services
// should be constructed with this narrow interface so that, by construction,
// they cannot read, mutate, or delete audit content (ADR-0007, ADR-0024).
type AuditAppender interface {
	// Append inserts a new audit record. It is the only write operation on the
	// audit log; there is no update or delete of audit content anywhere in this
	// package.
	Append(ctx context.Context, r *domain.AuditRecord) error
}

// AuditQuery filters an audit listing. Zero-valued fields are ignored, so an
// empty query matches all records. From and To bound OccurredAt inclusively
// when non-nil.
type AuditQuery struct {
	ActorType  domain.ActorType
	ActorID    string
	Action     domain.AuditAction
	TargetType domain.TargetType
	TargetID   string
	From, To   *time.Time
}

// AuditRepository is the full audit log port: the insert-only AuditAppender
// plus read and maintenance operations. Audit records carry no OwnerID; the log
// is a cross-owner system record and is therefore unscoped by design, not by
// exception. Only maintenance jobs should receive this interface; request-path
// services get the narrow AuditAppender.
//
// There is deliberately no Update or Delete of audit content: the append-only
// property cannot be violated through this package. PurgeOlderThan removes whole
// aged records for retention, and Pseudonymize rewrites actor/target IDs for
// crypto-erasure, but neither can alter the recorded action of a surviving row.
type AuditRepository interface {
	AuditAppender

	// Get returns the audit record with the given ID, or domain.ErrNotFound if
	// none exists.
	Get(ctx context.Context, id domain.AuditRecordID) (*domain.AuditRecord, error)

	// List returns a newest-first page of records matching the query, together
	// with the next-page cursor ("" when there are no further pages).
	List(ctx context.Context, q AuditQuery, page Page) ([]domain.AuditRecord, string, error)

	// PurgeOlderThan deletes up to limit records whose OccurredAt is at or
	// before cutoff, and returns the number deleted.
	//
	// UNSCOPED: retention purge is a system-maintenance sweep across all
	// records and is not acting on behalf of any single owner.
	PurgeOlderThan(ctx context.Context, cutoff time.Time, limit int) (int64, error)

	// Pseudonymize replaces the matching actor/target IDs with pseudonym and
	// returns the number of records rewritten. The service gathers an owner's
	// polymorphic actor and target IDs before deletion, computes a salted-hash
	// pseudonym, then destroys the salt, achieving crypto-erasure while
	// preserving the audit trail.
	//
	// UNSCOPED: pseudonymization is a system-maintenance operation over records
	// identified by their polymorphic IDs, not by an owner scope.
	Pseudonymize(ctx context.Context, ids []string, pseudonym string) (int64, error)
}
