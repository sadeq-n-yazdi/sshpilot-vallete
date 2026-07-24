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

	// RecordsForErasure returns every audit record whose actor_id or target_id
	// is one of ids, with all columns populated. It is the read half of
	// metadata crypto-erasure: Pseudonymize erases the identity columns, but a
	// record's metadata can itself carry identifying values (a fingerprint, a
	// handle, a device name), and rewriting those to salted-hash tombstones
	// requires reading each record's current metadata because the tombstone is
	// an HMAC computed in the service, not in SQL. An empty ids yields no
	// records. It MUST be called before Pseudonymize rewrites the columns,
	// while ids still match, or the record set comes back empty.
	//
	// UNSCOPED: as for Pseudonymize, records are identified by their
	// polymorphic IDs, not by an owner scope.
	RecordsForErasure(ctx context.Context, ids []string) ([]domain.AuditRecord, error)

	// ScrubMetadata overwrites the metadata of each named record with the
	// supplied map, touching no other column, and returns the number of records
	// updated. It is the write half of metadata crypto-erasure (ADR-0024): the
	// erasure service computes each record's new metadata — identifying detail
	// values rewritten to tombstones, structural details preserved byte for
	// byte — and this persists them.
	//
	// Unlike Pseudonymize, which structurally cannot alter anything but the two
	// identity columns, this method writes a caller-supplied map, so which keys
	// are preserved and which are rewritten is the erasure service's
	// responsibility, pinned by its tests, not a property enforced here. What
	// this method does guarantee is the other half of the anti-forgery
	// property: it writes only the metadata column and never action,
	// occurred_at, the type columns, the identity columns, or the pseudonymized
	// flag, so it can no more forge WHAT happened or WHEN than Pseudonymize can.
	//
	// A record ID that names no row is skipped, not an error: erasure tolerates
	// a partially deleted owner, so a record that has since been purged simply
	// contributes nothing.
	//
	// UNSCOPED: records are identified by their IDs, not by an owner scope.
	ScrubMetadata(ctx context.Context, updates []AuditMetadataUpdate) (int64, error)
}

// AuditMetadataUpdate names one record and the metadata to store on it, the
// unit ScrubMetadata applies. It is a value type rather than a bare map so the
// record ID and its new metadata travel together and cannot be transposed.
type AuditMetadataUpdate struct {
	ID       domain.AuditRecordID
	Metadata map[string]string
}
