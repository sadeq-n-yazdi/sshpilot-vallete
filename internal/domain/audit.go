package domain

import "time"

// AuditRecordID is the opaque, non-guessable identifier for an AuditRecord.
type AuditRecordID string

// ActorType identifies the kind of actor that performed an audited action.
type ActorType string

// Actor types.
const (
	ActorTypeOwner         ActorType = "owner"
	ActorTypeAdministrator ActorType = "administrator"
	ActorTypeSystem        ActorType = "system"
)

// IsValid reports whether t is a known ActorType.
func (t ActorType) IsValid() bool {
	switch t {
	case ActorTypeOwner, ActorTypeAdministrator, ActorTypeSystem:
		return true
	default:
		return false
	}
}

// TargetType identifies the kind of entity an audited action affected.
type TargetType string

// Target types.
const (
	TargetTypeOwner             TargetType = "owner"
	TargetTypeHandle            TargetType = "handle"
	TargetTypeDevice            TargetType = "device"
	TargetTypePublicKey         TargetType = "public_key"
	TargetTypeKeySet            TargetType = "key_set"
	TargetTypeAccessKey         TargetType = "access_key"
	TargetTypeRefreshCredential TargetType = "refresh_credential"
	TargetTypeBlocklistEntry    TargetType = "blocklist_entry"
	TargetTypeAllowlistEntry    TargetType = "allowlist_entry"
	// TargetTypeAuditLog is the audit log itself, as the target of the
	// system-maintenance operations that act on it as a whole -- retention
	// purging and crypto-erasure pseudonymization. It names a singleton, not a
	// row: no audited action ever targets an individual audit record.
	TargetTypeAuditLog TargetType = "audit_log"
)

// AuditLogTargetID is the fixed TargetID used with TargetTypeAuditLog. The
// audit log is a singleton, so maintenance records identify it by a constant
// rather than by a row ID, which would wrongly suggest a single record was
// affected.
const AuditLogTargetID = "audit_log"

// IsValid reports whether t is a known TargetType.
func (t TargetType) IsValid() bool {
	switch t {
	case TargetTypeOwner, TargetTypeHandle, TargetTypeDevice, TargetTypePublicKey,
		TargetTypeKeySet, TargetTypeAccessKey, TargetTypeRefreshCredential,
		TargetTypeBlocklistEntry, TargetTypeAllowlistEntry, TargetTypeAuditLog:
		return true
	default:
		return false
	}
}

// AuditAction names an audited action. The consts below are a representative
// starter set, not an exhaustive enumeration.
type AuditAction string

// Representative audit actions.
const (
	AuditActionOwnerCreated AuditAction = "owner.created"
	AuditActionOwnerDeleted AuditAction = "owner.deleted"

	AuditActionHandleRegistered AuditAction = "handle.registered"
	AuditActionHandleRenamed    AuditAction = "handle.renamed"
	// AuditActionHandleReclaimed records an owner taking back a name they had
	// renamed away from, before its quarantine elapsed.
	AuditActionHandleReclaimed AuditAction = "handle.reclaimed"
	// AuditActionHandleReleased records a quarantine ending and the name
	// returning to the pool. It is the moment a name becomes claimable by
	// someone else, so it is the record an incident review needs to place a
	// change of ownership in time.
	AuditActionHandleReleased AuditAction = "handle.released"

	AuditActionDeviceRegistered AuditAction = "device.registered"
	AuditActionDeviceRevoked    AuditAction = "device.revoked"

	AuditActionKeyAdded   AuditAction = "key.added"
	AuditActionKeyRevoked AuditAction = "key.revoked"

	AuditActionKeySetCreated           AuditAction = "key_set.created"
	AuditActionKeySetRenamed           AuditAction = "key_set.renamed"
	AuditActionKeySetDeleted           AuditAction = "key_set.deleted"
	AuditActionKeySetDefaultChanged    AuditAction = "key_set.default_changed"
	AuditActionKeySetVisibilityChanged AuditAction = "key_set.visibility_changed"
	AuditActionKeySetMemberAdded       AuditAction = "key_set.member_added"
	AuditActionKeySetMemberRemoved     AuditAction = "key_set.member_removed"

	AuditActionAccessKeyCreated AuditAction = "access_key.created"
	AuditActionAccessKeyRotated AuditAction = "access_key.rotated"
	AuditActionAccessKeyRevoked AuditAction = "access_key.revoked"

	AuditActionCredentialIssued        AuditAction = "credential.issued"
	AuditActionCredentialRotated       AuditAction = "credential.rotated"
	AuditActionCredentialRevoked       AuditAction = "credential.revoked"
	AuditActionCredentialReuseDetected AuditAction = "credential.reuse_detected"

	AuditActionBlocklistEntryAdded   AuditAction = "blocklist.entry_added"
	AuditActionBlocklistEntryRemoved AuditAction = "blocklist.entry_removed"

	AuditActionAllowlistEntryAdded   AuditAction = "allowlist.entry_added"
	AuditActionAllowlistEntryRemoved AuditAction = "allowlist.entry_removed"

	AuditActionAuditPseudonymized AuditAction = "audit.pseudonymized"
	// AuditActionAuditPurged records a retention pass that removed aged records.
	// Deleting audit history is itself an access-affecting administrative event,
	// so it is recorded like any other.
	AuditActionAuditPurged AuditAction = "audit.purged"
	// AuditActionOwnerErased records that an owner's identity was crypto-erased
	// from the audit log: their identifiers replaced with tombstones and their
	// salt destroyed. The record proves the erasure happened without naming its
	// subject — the target ID is written as the owner ID and is tombstoned by
	// the same pass, so the record survives the erasure it describes rather than
	// defeating it.
	AuditActionOwnerErased AuditAction = "owner.erased"
)

// AuditRecord is an append-only record of an audited action. ActorID and
// TargetID are plain strings because they are polymorphic across entity types
// and must survive pseudonymization.
type AuditRecord struct {
	ID            AuditRecordID
	ActorType     ActorType
	ActorID       string
	Action        AuditAction
	TargetType    TargetType
	TargetID      string
	OccurredAt    time.Time
	Metadata      map[string]string
	Pseudonymized bool
}
