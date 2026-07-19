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
	// an active or quarantined state.
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
}
