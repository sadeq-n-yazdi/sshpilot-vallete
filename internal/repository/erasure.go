package repository

import "context"

// OwnerSaltRepository stores the per-owner secret that makes audit
// crypto-erasure work (ADR-0024).
//
// The salt is the key under which an owner's identifiers are turned into
// audit-log tombstones. While the salt exists the tombstone is verifiable: an
// operator holding a candidate identifier can recompute the tombstone and
// confirm or refute it. Once the salt is destroyed nobody can perform that
// computation, so the tombstone becomes irreversible and the surviving audit
// records name a subject that can no longer be recovered.
//
// Destroy is therefore not a cleanup operation but the erasure itself, and it
// is the one method on this port whose effect is irreversible by design.
type OwnerSaltRepository interface {
	// Ensure returns the owner's salt, generating and storing a fresh random
	// one if none exists yet. It is idempotent: repeated calls for the same
	// owner return the same salt, so tombstones minted at different times for
	// one owner agree.
	//
	// Ensure must never return a salt for an owner whose salt has been
	// destroyed and then silently mint a new one in a way that appears to be
	// the original; a new salt produces different tombstones, which is correct
	// (the old ones stay unrecoverable) but means the old records can no longer
	// be linked to the new ones. That is the intended consequence of erasure.
	Ensure(ctx context.Context, ownerID string) ([]byte, error)

	// Get returns the owner's salt, or domain.ErrNotFound if the owner has no
	// salt — either because none was ever created or because it was destroyed.
	// The two cases are deliberately indistinguishable: reporting "this salt
	// was destroyed" separately from "there was never a salt" would leak that
	// the owner once existed, which is precisely what erasure removes.
	Get(ctx context.Context, ownerID string) ([]byte, error)

	// Destroy removes the owner's salt, making every tombstone minted under it
	// permanently irreversible. It is idempotent and reports no error when
	// there is nothing to destroy, so a retried erasure converges rather than
	// failing on its second attempt.
	//
	// The removal is logical: the row is gone as far as any reader of the
	// database is concerned, but the bytes may linger in reclaimable pages
	// until the engine compacts them. Excluding a forensic reader of the raw
	// files additionally requires storage-level measures (a VACUUM, or full
	// disk encryption).
	Destroy(ctx context.Context, ownerID string) error
}
