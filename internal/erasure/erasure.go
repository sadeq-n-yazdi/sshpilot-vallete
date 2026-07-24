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
// # Erasure covers the whole record: identifier columns AND record metadata
//
// Pseudonymize rewrites actor_id and target_id, but a record's metadata can
// itself carry an owner's identity: the internal/audit allowlist admits
// fingerprint, handle, device_name, key_set_name and client_label, and the
// from/to pair carries the old and new names in a rename. A fingerprint is not
// a secret, but it names a specific key and therefore its owner. Tombstoning
// the columns alone would leave that owner nameable in the metadata.
//
// EraseOwner closes this. It rewrites every identifying detail value to a
// tombstone under the SAME per-owner salt used for the columns, so the whole
// record — both identity columns and metadata — is erased and the
// irreversibility argument above holds over all of it. The classification of
// which detail keys are identifying (erasable) and which are structural (kept
// byte-for-byte) is owned by internal/audit.IsErasableDetail and settled in
// ADR-0024; equal values across records collapse to equal tombstones, so event
// counts and lineage stay consistent, and the structural keys — algorithm,
// visibility, scope, reason, result, request_id, count — are preserved so a
// scrubbed record still proves what happened.
//
// A metadata value that already has a tombstone's exact shape is left alone, so
// a re-run scrubs nothing twice; see isTombstone for why the shape, not a bare
// prefix, is the test.
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
	"strings"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/audit"
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

// isTombstone reports whether s has the exact shape Tombstone produces: the
// prefix followed by the base64url encoding of a 32-byte HMAC-SHA256 digest.
//
// The metadata scrub uses this to leave an already-tombstoned value untouched,
// which is what makes a re-run idempotent. A bare prefix test would not do,
// because unlike a minted identifier a metadata value is user-supplied and can
// legitimately begin with the prefix: a device literally named "anon:bot"
// would be mistaken for an already-erased value and left standing in the clear.
// Requiring the full shape — a valid base64url body decoding to exactly the
// digest length — means only a real tombstone is skipped. The residual is a
// value a user deliberately crafts to the full 48-character tombstone shape to
// dodge its own scrub, which is self-defeating and left un-guarded here.
func isTombstone(s string) bool {
	rest, ok := strings.CutPrefix(s, tombstonePrefix)
	if !ok {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(rest)
	return err == nil && len(raw) == sha256.Size
}

// scrubDetails returns metadata with every identifying detail value rewritten
// to a tombstone under salt, and whether anything changed. Structural values
// (see audit.IsErasableDetail) and values already in tombstone shape are left
// exactly as they are, and an empty value is nothing to erase. The input map is
// never mutated; a fresh copy is made only when a rewrite is actually needed,
// so the common no-metadata and all-structural cases allocate nothing.
func scrubDetails(meta map[string]string, salt []byte) (map[string]string, bool) {
	var out map[string]string
	for k, v := range meta {
		if v == "" || isTombstone(v) || !audit.IsErasableDetail(audit.DetailKey(k)) {
			continue
		}
		if out == nil {
			out = make(map[string]string, len(meta))
			for mk, mv := range meta {
				out[mk] = mv
			}
		}
		out[k] = Tombstone(salt, v)
	}
	if out == nil {
		return meta, false
	}
	return out, true
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

	// Scrub identifying metadata BEFORE the column pass. RecordsForErasure finds
	// the owner's records by their identifiers in actor_id/target_id, which the
	// column pass is about to overwrite; run it after and the records no longer
	// match. Nothing here is irreversible — the salt is still alive — so a
	// failure returns for a retry, having destroyed nothing.
	if serr := e.scrubMetadata(ctx, ids, salt); serr != nil {
		return 0, fmt.Errorf("erasure: scrub metadata: %w", serr)
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

// scrubMetadata rewrites the identifying detail values in the owner's records
// to tombstones under salt. It reads the records the owner's identifiers name,
// computes each one's scrubbed metadata, and persists only those that changed.
//
// The count is not surfaced through EraseOwner's return, which stays a count of
// identity-column fields; the metadata pass is a distinct rewrite whose progress
// is not comparable to a per-identifier field count, and conflating the two
// would make the returned figure mean two different things at once.
func (e *Eraser) scrubMetadata(ctx context.Context, ids []string, salt []byte) error {
	recs, err := e.audit.RecordsForErasure(ctx, ids)
	if err != nil {
		return err
	}
	var updates []repository.AuditMetadataUpdate
	for i := range recs {
		newMeta, changed := scrubDetails(recs[i].Metadata, salt)
		if changed {
			updates = append(updates, repository.AuditMetadataUpdate{ID: recs[i].ID, Metadata: newMeta})
		}
	}
	if len(updates) == 0 {
		return nil
	}
	_, err = e.audit.ScrubMetadata(ctx, updates)
	return err
}
