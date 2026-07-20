package repository

import (
	"context"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
)

// HandleRepository persists Handle rows. A handle row is a name-claim: an old
// name that was quarantined remains an ordinary row with
// State == domain.NameStateQuarantined, so a name is considered taken while any
// row (active or quarantined, under any owner) holds it.
type HandleRepository interface {
	// Register persists a new handle name-claim. It returns domain.ErrConflict
	// if any row, under any owner, currently holds the same normalized Name in
	// an active or quarantined state, if the name is a look-alike of a live
	// claim, or if the owner already holds an active claim.
	//
	// The look-alike fold is derived from h.Name by the implementation, and is
	// deliberately not a field on domain.Handle. This is a considered exception
	// to the rule that repositories compute nothing: an ID, a timestamp, or a
	// hash is an independent value the caller owns, but the fold is only
	// meaningful as a pure function of the name in its own row. Left to the
	// caller it becomes settable, and a caller supplying a fold that disagrees
	// with the name registers a look-alike the unique index never sees. A
	// control that can be switched off by the code it is meant to constrain is
	// not a control, so the value is produced where the row is written.
	Register(ctx context.Context, h *domain.Handle) error

	// GetByName returns the handle row that holds the given normalized name in
	// any state, or domain.ErrNotFound if the name is unclaimed.
	//
	// UNSCOPED: handle-name resolution is public; any caller may look up which
	// handle owns a name, so this method is deliberately not owner-scoped.
	GetByName(ctx context.Context, normalized string) (*domain.Handle, error)

	// Get returns the owner's handle with the given ID, or domain.ErrNotFound
	// if it does not exist or belongs to another owner.
	Get(ctx context.Context, ownerID domain.OwnerID, id domain.HandleID) (*domain.Handle, error)

	// GetActiveByOwner returns the owner's single active handle, or
	// domain.ErrNotFound if the owner has none.
	GetActiveByOwner(ctx context.Context, ownerID domain.OwnerID) (*domain.Handle, error)

	// ListByOwner returns all of the owner's handle rows, including quarantined
	// and retired name-claims.
	ListByOwner(ctx context.Context, ownerID domain.OwnerID) ([]domain.Handle, error)

	// Update persists changes to the mutable fields of a handle, scoped by
	// h.OwnerID and h.ID. Only State, QuarantineUntil, FlaggedForReview,
	// QuarantineOnRelease, and UpdatedAt are mutable; Name is immutable per row
	// and an implementation should reject a Name change with
	// domain.ErrImmutable. It returns domain.ErrNotFound if the row does not
	// exist or belongs to another owner.
	Update(ctx context.Context, h *domain.Handle) error

	// ListExpiredQuarantine returns up to limit quarantined handle rows whose
	// QuarantineUntil is at or before now, for the release sweep.
	//
	// UNSCOPED: this is a system-maintenance sweep across all owners; the
	// quarantine-release job is not acting on behalf of any single owner.
	ListExpiredQuarantine(ctx context.Context, now time.Time, limit int) ([]domain.Handle, error)

	// Release deletes a quarantined name-claim whose hold has elapsed, returning
	// the name to the pool. The row is removed rather than moved to a terminal
	// state because uniqueness is unconditional: while any row holds the name,
	// the name is taken, so a surviving row would reserve it forever.
	// NameStateRetired is not that terminal state — it is the operator's
	// never-release decision, which Release must leave alone.
	//
	// now is re-checked in the same statement that deletes, so a claim the owner
	// reclaimed, or an operator retired, between the sweep's read and this call
	// is not deleted out from under them. It returns domain.ErrNotFound when no
	// row matched, which is the benign outcome of exactly that race.
	//
	// UNSCOPED: the release sweep is system maintenance across all owners, and
	// the elapsed hold — not a caller's identity — is what authorizes the delete.
	Release(ctx context.Context, id domain.HandleID, now time.Time) error
}
