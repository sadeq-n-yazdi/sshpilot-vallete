package erasure

import (
	"context"
	"fmt"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/audit"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
)

// OwnerEraser erases one owner end to end: it walks the owner's graph, rewrites
// every identifier it finds into a tombstone, and destroys the salt those
// tombstones were minted under.
//
// It is the composition Graph and Eraser were each written to be half of.
// Neither is usable alone for a real erasure — Graph discovers identifiers but
// destroys nothing, Eraser destroys but discovers nothing — and joining them is
// where the ordering and the audit obligation actually live.
//
// # Why the API takes exactly one owner
//
// Erasure is irreversible, so the design goal is not to validate a dangerous
// request but to leave no way to phrase one. EraseOwner accepts a single
// domain.OwnerID: there is no slice, no filter, no predicate and no "erase all"
// variant, so an over-broad erasure cannot be expressed as an argument at all.
// Erasing a thousand owners requires a thousand deliberate calls, each naming
// its subject. That follows the retention work, where the unsafe state was made
// inexpressible rather than merely rejected.
//
// # Ordering
//
//	collect -> record -> pseudonymize -> destroy salt
//
// Every step before the last is retryable, and the last one is the only
// irreversible act. The order is chosen so that a crash always lands in the
// retryable region:
//
//   - Collect must run first because it reads the owner's rows. Any step that
//     removed them would blind a later retry: identifiers that no longer exist
//     in any table cannot be rediscovered, and the records naming them would
//     stay identifiable forever. This is why the traversal reads and never
//     deletes, and why an account-deletion path must run this erasure BEFORE it
//     removes an owner's rows, never after.
//   - The audit record is written before the pseudonymize pass, not after. It
//     names the owner as its target, so the very pass it precedes rewrites its
//     target ID into a tombstone. Written after the salt was destroyed it would
//     be the one row naming the erased owner in plaintext, with no key left to
//     ever tombstone it — the record would defeat the erasure it documents.
//   - The salt is destroyed last, because destroying it first would strand every
//     not-yet-rewritten record: minting their tombstones needs the key that is
//     already gone.
//
// # Crash windows that remain
//
// These are not eliminated, and pretending otherwise would be the more dangerous
// error. Each is stated with what a retry does about it:
//
//  1. Crash during collection, or before the audit record commits. Nothing has
//     changed. A retry starts over. No exposure.
//  2. Crash part-way through the pseudonymize pass. Some identifiers are
//     tombstoned, the rest are not, and the salt is alive. A retry re-collects
//     (the rows were never deleted) and finishes. Tombstone is a pure function
//     of salt and identifier, so already-rewritten records are matched by
//     nothing on the second pass and are neither altered again nor counted
//     twice; the returned count is per-pass progress, not a cumulative total.
//  3. THE REAL EXPOSURE WINDOW: crash after the last identifier is rewritten but
//     before Destroy commits. Every record is tombstoned and the salt still
//     exists, so anyone holding the salt and a candidate identifier can still
//     confirm the link — the erasure is complete in appearance and reversible in
//     fact. It closes only when a retry reaches Destroy. An erasure that reports
//     an error must therefore be re-run; treating a failed erasure as finished
//     leaves this window open indefinitely. Narrowing it further requires the
//     rewrite and the destroy to share one transaction, which the audit port
//     does not currently offer across repositories.
//  4. Re-running a fully erased owner. Ensure mints a fresh salt for an owner
//     that no longer has one, the pass matches no records because they are
//     already tombstoned, and Destroy removes the new salt. Converges, changes
//     nothing, and leaves no stray secret. The new salt cannot verify the old
//     tombstones, which is exactly the intended consequence of erasure.
//
// # What survives, and why
//
// The audit records themselves survive, structurally intact: which action
// happened, when, and against what kind of target. That is the whole point of
// crypto-erasure over deletion — accountability without the person (ADR-0024).
// The owner's rows in the owner-scoped tables also survive this operation; it
// erases identity from the audit log and is not an account-deletion routine.
//
// # Limit inherited from the primitive
//
// This rewrites identifier columns only. Audit metadata may still carry
// identifying values — fingerprint, handle, device_name, key_set_name,
// client_label are all allowlisted — and destroying the salt does nothing about
// them. That gap is documented on the package and remains out of scope here; do
// not read this type as providing erasure over a whole audit record.
type OwnerEraser struct {
	graph   *Graph
	eraser  *Eraser
	emitter *audit.Emitter
}

// NewOwnerEraser returns an OwnerEraser over the traversal, the erasure
// primitive and the audit emitter. All three are required.
//
// The emitter is required, unlike the retention scheduler's optional one. ADR
// 0024 makes erasure a controlled, audited operation, and an erasure that
// silently skipped its record because a port was nil would be exactly the
// unaccountable destruction the ADR forbids. Wiring it wrong fails here, at
// construction, rather than at the first irreversible call.
func NewOwnerEraser(graph *Graph, eraser *Eraser, emitter *audit.Emitter) (*OwnerEraser, error) {
	if graph == nil || eraser == nil || emitter == nil {
		return nil, fmt.Errorf("erasure: graph, eraser and audit emitter are all required: %w", domain.ErrInvalidInput)
	}
	return &OwnerEraser{graph: graph, eraser: eraser, emitter: emitter}, nil
}

// EraseOwner erases the named owner's identity from the audit log and destroys
// their salt, returning the number of identity fields rewritten by this pass.
//
// It is idempotent. A second call over a partially erased owner completes the
// work rather than failing, and a call over a fully erased owner is a no-op that
// still returns without error. The count is per-pass progress and does not
// accumulate across runs; a converging second pass legitimately returns zero.
//
// The whole operation is scoped to the single owner named. Nothing it calls can
// reach another owner's rows: the traversal's ports accept only an owner ID, and
// the identifiers handed to the primitive are only those the traversal returned.
func (o *OwnerEraser) EraseOwner(ctx context.Context, ownerID domain.OwnerID) (int64, error) {
	if ownerID == "" {
		return 0, fmt.Errorf("erasure: empty owner id: %w", domain.ErrInvalidInput)
	}

	ids, err := o.graph.Collect(ctx, ownerID)
	if err != nil {
		return 0, fmt.Errorf("erasure: collect owner graph: %w", err)
	}

	if rerr := o.record(ctx, ownerID); rerr != nil {
		// Fail closed, destroying nothing. Unlike the retention purge — which
		// records after a deletion that has already committed and so can only
		// log its failure — nothing irreversible has happened yet here. An
		// unrecorded erasure is exactly what the ADR forbids, and at this point
		// it is still entirely avoidable by not proceeding.
		return 0, rerr
	}

	// The primitive performs the rewrite and the destroy in that order; see the
	// ordering note above for why the salt goes last.
	rewritten, err := o.eraser.EraseOwner(ctx, string(ownerID), ids)
	if err != nil {
		return rewritten, err
	}
	return rewritten, nil
}

// record writes the audit record for the erasure.
//
// It carries no details. A count of the identifiers found would leak the shape
// of the owner's account — how many devices and keys they had — and listing them
// would restate in plaintext precisely what the next step destroys, so the
// record says that an erasure occurred and nothing about its content. The target
// is the owner ID, which the pass that follows rewrites into a tombstone; the
// surviving record therefore proves an erasure happened without naming who it
// happened to.
//
// The actor is the system. No owner principal survives the operation to be
// attributed, and the erasure is a controlled system-level act in the same sense
// the retention purge is.
func (o *OwnerEraser) record(ctx context.Context, ownerID domain.OwnerID) error {
	err := o.emitter.Emit(ctx, audit.Event{
		ActorType:  domain.ActorTypeSystem,
		Action:     domain.AuditActionOwnerErased,
		TargetType: domain.TargetTypeOwner,
		TargetID:   string(ownerID),
	})
	if err != nil {
		return fmt.Errorf("erasure: record owner erasure: %w", err)
	}
	return nil
}
