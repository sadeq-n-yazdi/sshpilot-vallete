// Package erasure implements audit crypto-erasure: making an owner's identity
// in the append-only audit log permanently unrecoverable without deleting the
// records that prove what happened (ADR-0024).
//
// # The problem
//
// Two requirements pull in opposite directions. An owner must be able to have
// their identity removed, and an audit log must not be rewritable. Deleting the
// records satisfies the first and destroys the second: the evidence that a key
// was revoked, or that an administrator acted, vanishes with the subject.
// Blanking the identifiers is barely better — the trail survives but every
// erased subject collapses into the same empty value, so a reader can no longer
// tell whether two events involved one subject or two.
//
// # The resolution
//
// Replace each of the owner's identifiers with a tombstone
//
//	tombstone = HMAC-SHA256(key = per-owner salt, message = identifier)
//
// and then DESTROY THE SALT. Before destruction the mapping is verifiable but
// not invertible: an operator holding a candidate identifier can recompute the
// tombstone and confirm it, which is what allows a final check before erasure,
// but nobody can run the function backwards. After destruction even that check
// is gone, because the key it needs no longer exists anywhere. The records
// remain, distinct from one another and internally consistent, naming a subject
// nobody can name.
//
// HMAC rather than a plain hash of salt||identifier is deliberate. Identifiers
// are drawn from a small, guessable space, so an unsalted or naively
// concatenated digest invites both dictionary attacks and length-extension
// games. HMAC is a keyed construction whose security rests on the key, which is
// precisely the thing this design destroys.
//
// # Why destroying the salt is enough
//
// The salt is 256 bits of cryptographic randomness held in exactly one place,
// its row in owner_erasure_salts. Recovering an identifier from a tombstone
// without it means either inverting SHA-256 or searching a 2^256 keyspace.
// So the irreversibility does not rest on the identifiers being unguessable, or
// on the records being unreadable — an attacker may hold the complete record
// and the complete tombstone and still learn nothing. It rests only on the salt
// being gone.
//
// The honest caveat: DELETE removes the row logically, and the bytes may remain
// in reclaimable database pages or a write-ahead log until the engine compacts
// them. Erasure is complete against every reader that goes through the
// database; excluding a forensic reader of the raw files additionally needs a
// VACUUM or full-disk encryption. That is a storage-level concern, called out
// here so it is a known and accepted boundary rather than an unexamined one.
//
// # Ordering
//
// Pseudonymize first, then destroy the salt, both inside one transaction. The
// order matters because the two failure directions are not equally bad. If the
// process dies with the salt still present and the records not yet rewritten,
// nothing is lost and the erasure can simply be retried. If it dies with the
// salt destroyed and the records still naming the real subject, those records
// can never be erased — the key needed to mint their tombstones is gone. The
// safe direction is the one that stays retryable.
//
// # Limit: erasure covers the identifier columns, NOT record metadata
//
// Pseudonymize rewrites actor_id and target_id. It does NOT touch a record's
// metadata, and the metadata allowlist in internal/audit admits keys that can
// carry an owner's identity: fingerprint, handle, device_name, key_set_name and
// client_label. A fingerprint is not a secret, but it names a specific key and
// therefore its owner.
//
// So the irreversibility argument above holds for the identifier columns only.
// A record whose metadata carries an identifying detail still identifies its
// subject after erasure, and destroying the salt does nothing about it. Do not
// read this package as providing erasure over a whole audit record until that
// is addressed.
//
// Closing it means deciding, per allowlisted key, whether the value is erasable
// (rewrite it), droppable (remove it) or genuinely non-identifying (keep it) —
// a policy question about the audit vocabulary, not a storage detail, which is
// why it is not settled here. Like the traversal below, it is NOT ASSIGNED to
// any planned task.
//
// # Scope: this package is a primitive, and its caller does not exist yet
//
// EraseOwner takes the identifiers to erase as an argument. It does NOT
// discover them. Erasing a real owner end to end additionally requires walking
// that owner's graph — handles, devices, public keys, key sets — to gather
// every polymorphic actor and target ID that owner's records may carry, and
// passing the complete set here.
//
// That traversal is NOT IMPLEMENTED and is NOT ASSIGNED to any planned task.
// It is a genuinely different concern: it spans several repositories, must
// tolerate partially deleted owners, and gets an owner's erasure wrong in a
// silent way if it misses an identifier — a missed ID means a real identity
// left standing in the log while the flow reports success. It is called out
// here rather than left implicit so that the gap is discovered by reading this
// package, not by trusting it.
package erasure

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/repository"
)

// tombstonePrefix marks a value in the audit log as a pseudonym rather than a
// real identifier. It makes the substitution legible to a human reading the
// log and, because real identifiers never begin with it, keeps a tombstone from
// being mistaken for an ID that could itself be looked up.
const tombstonePrefix = "anon:"

// Eraser performs audit crypto-erasure. It holds the two ports it needs and no
// state of its own, so it is safe for concurrent use by multiple goroutines
// when the repositories it wraps are.
type Eraser struct {
	audit repository.AuditRepository
	salts repository.OwnerSaltRepository
}

// New returns an Eraser over the audit log and the salt store. Both are
// required; a nil port would fail at the first call with a nil dereference
// rather than a clear error, so it is rejected here.
func New(audit repository.AuditRepository, salts repository.OwnerSaltRepository) (*Eraser, error) {
	if audit == nil || salts == nil {
		return nil, fmt.Errorf("erasure: audit and salt repositories are required: %w", domain.ErrInvalidInput)
	}
	return &Eraser{audit: audit, salts: salts}, nil
}

// Tombstone computes the pseudonym for one identifier under a salt.
//
// It is a pure function of its inputs, which is what makes the result stable:
// the same identifier under the same salt always yields the same tombstone, so
// an owner's records rewritten in separate batches still agree, and re-running
// an erasure is a no-op rather than a second, different substitution.
func Tombstone(salt []byte, id string) string {
	mac := hmac.New(sha256.New, salt)
	// Write on hash.Hash never returns an error, per its documented contract.
	_, _ = mac.Write([]byte(id))
	return tombstonePrefix + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// Verify reports whether id is the identifier behind tombstone under salt.
//
// This is the capability that erasure removes. While the salt exists an
// operator can still answer "was this owner the actor in that event?"; once
// Destroy has run, the salt argument cannot be supplied by anyone and the
// question becomes unanswerable. The comparison is constant-time so that
// repeatedly probing candidate identifiers cannot be sped up by timing.
func Verify(salt []byte, id, tombstone string) bool {
	return hmac.Equal([]byte(Tombstone(salt, id)), []byte(tombstone))
}

// EraseOwner replaces every occurrence of the given identifiers in the audit
// log with tombstones and then destroys the owner's salt, returning the number
// of identity fields rewritten.
//
// The count is fields, not records: each identifier is erased in its own pass,
// so a record naming one of these identifiers as both actor and target counts
// twice. It is a progress figure, not a record census.
//
// After it returns, the audit trail still records what happened and when, and
// no one — including the operator who ran this — can recover which owner it
// happened to.
//
// The identifiers must be the complete set for this owner; see the package
// doc's note on the unimplemented traversal that would gather them.
//
// Passing no identifiers still destroys the salt. An owner with no audit
// records is a legitimate case, and leaving a live salt behind for them would
// be a stray secret with nothing to protect.
func (e *Eraser) EraseOwner(ctx context.Context, ownerID string, ids []string) (int64, error) {
	if ownerID == "" {
		return 0, fmt.Errorf("erasure: empty owner id: %w", domain.ErrInvalidInput)
	}

	salt, err := e.salts.Ensure(ctx, ownerID)
	if err != nil {
		return 0, fmt.Errorf("erasure: load salt: %w", err)
	}

	// Each identifier gets its own tombstone, so distinct subjects stay
	// distinguishable in the surviving log. A single shared pseudonym would
	// merge an owner's device and key references into one value and destroy the
	// structure of the trail along with the identity.
	var rewritten int64
	for _, id := range ids {
		n, perr := e.audit.Pseudonymize(ctx, []string{id}, Tombstone(salt, id))
		if perr != nil {
			// Fail before destroying the salt. The records not yet rewritten
			// are still erasable on a retry precisely because the salt survives
			// this path.
			return rewritten, fmt.Errorf("erasure: pseudonymize: %w", perr)
		}
		rewritten += n
	}

	// The irreversible step, last.
	if derr := e.salts.Destroy(ctx, ownerID); derr != nil {
		return rewritten, fmt.Errorf("erasure: destroy salt: %w", derr)
	}
	return rewritten, nil
}
