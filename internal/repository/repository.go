// Package repository defines the persistence-port interfaces for
// sshpilot-vallet. It declares only interfaces and small value types; it holds
// no implementations. SQLite and Postgres adapters live in other packages and
// must behave identically against these contracts (ADR-0011).
//
// # Conventions
//
// Every method takes a context.Context as its first argument.
//
// Errors map to the sentinels in package domain and are tested with errors.Is,
// never by == or message text. Implementations translate storage failures into
// these sentinels:
//
//   - domain.ErrNotFound covers BOTH a missing row AND a row owned by another
//     owner. The two are never distinguished: doing so would leak the existence
//     of another owner's data across the owner boundary.
//   - domain.ErrConflict signals a uniqueness or state clash (for example a
//     duplicate name claim or fingerprint).
//
// Repositories never return domain.ErrQuarantined, domain.ErrBlockedName, or
// domain.ErrLimitExceeded: those are service-layer verdicts, not storage facts.
//
// Repositories do NOT generate identifiers, timestamps, or hashes, and do NOT
// normalize names. The service supplies fully populated entities and
// already-normalized names; repositories persist and compare exactly what they
// are given. This keeps the SQLite and Postgres behaviors identical (ADR-0011).
//
// Single-entity reads return *domain.T; lists return []domain.T. Mutators are
// intent-named (Revoke, SetDefault, MarkRotated) rather than a generic Update,
// except HandleRepository and KeySetRepository, which expose a real Update for
// their mutable fields.
//
// Time-dependent queries take an explicit now time.Time; implementations hold
// no clock, so callers pass the current time.
//
// # Owner-scoping (ADR-0004)
//
// Every method that touches owner-owned data takes an explicit
// ownerID domain.OwnerID (typically the second argument), and implementations
// MUST filter by it. The only deliberately unscoped methods are marked with an
// inline "// UNSCOPED:" comment and a justification; there are no others.
package repository

import "context"

// Page requests a bounded slice of a paginated list. Cursor is an opaque token
// returned by a previous call; an empty Cursor starts from the beginning.
// Pagination is cursor-based only (no offset). Only AuditRepository.List and
// OwnerRepository.List paginate; all other lists are owner-bounded and return
// plain slices.
type Page struct {
	// Limit is the maximum number of items to return. A non-positive Limit
	// lets the implementation apply its default page size.
	Limit int
	// Cursor is the opaque continuation token; "" starts from the beginning.
	Cursor string
}

// Repos is the set of all entity repositories. It is a plain struct so that
// tests and fakes can fill only the fields they exercise; production code
// obtains a fully populated Repos from a Store.
type Repos struct {
	Owners             OwnerRepository
	Handles            HandleRepository
	Devices            DeviceRepository
	PublicKeys         PublicKeyRepository
	KeySets            KeySetRepository
	AccessKeys         AccessKeyRepository
	RefreshCredentials RefreshCredentialRepository
	DevicePairings     DevicePairingRepository
	LinkedIdentities   LinkedIdentityRepository
	Audit              AuditRepository
	Admins             AdministratorRepository
	ListOverrides      ListOverrideRepository
	OwnerSalts         OwnerSaltRepository
}

// Store is the unit-of-work root. It hands out repositories for direct
// auto-commit use and runs multi-entity work atomically inside a transaction.
type Store interface {
	// Repos returns repositories whose operations each auto-commit.
	Repos() Repos

	// WithTx runs fn inside a single transaction, passing transaction-bound
	// repositories. It also passes fn a context derived from (or equal to) the
	// one that scopes the transaction, so fn can detect that it is already
	// inside a WithTx and honor cancellation: implementations MUST propagate
	// cancellation of that context into the transaction. The transaction commits
	// when fn returns nil and rolls back when fn returns an error or panics (the
	// panic is re-raised after rollback). It composes multi-entity invariants
	// atomically on both engines (Postgres transactions; SQLite BEGIN IMMEDIATE
	// with serialized writers); the interface promises atomicity, not identical
	// engine semantics. Phase 1 has no savepoints, so a nested WithTx MUST return
	// an error rather than attempt to nest.
	WithTx(ctx context.Context, fn func(ctx context.Context, r Repos) error) error
}
