package handle

import (
	"context"
	"fmt"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/audit"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/blocklist"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/repository"
)

// FoldRecomputeResult reports what one recompute pass did, for the startup log.
type FoldRecomputeResult struct {
	// Recomputed counts rows brought to their true skeleton at the current table
	// revision — the survivor of each confusable group and every ungrouped row.
	Recomputed int
	// Quarantined counts the newer look-alikes a pre-existing collision forced
	// into the quarantined hold for review.
	Quarantined int
}

// Recomputer brings the stored look-alike folds current after a
// blocklist.TableVersion bump (ADR-0030).
//
// It is a SYSTEM-maintenance pass, distinct from the owner-driven lifecycle the
// rest of this package implements: it is not owner-scoped, it takes no name from
// a caller, and it is meant to run once at startup, after migrations and before
// the listener binds. Recompute rewrites name_fold = blocklist.Skeleton(name),
// fold_version = blocklist.TableVersion for every stale row, and — because the
// unique fold index that migration 0012 added can surface a pair of handles
// registered before it that fold to one skeleton — keeps the OLDEST of each such
// pair and quarantines the newer look-alike(s), auditing each loudly.
//
// It is immutable after construction and safe for concurrent use if its
// collaborators are, though nothing runs it concurrently.
type Recomputer struct {
	store   repository.Store
	auditor Auditor
	now     func() time.Time
}

// RecomputeOption customizes a Recomputer.
type RecomputeOption func(*Recomputer)

// WithRecomputeClock overrides the clock used to stamp updated_at on rewritten
// rows. A nil value is ignored. It exists for tests, which need deterministic
// timestamps; it is not a security control.
func WithRecomputeClock(now func() time.Time) RecomputeOption {
	return func(rc *Recomputer) {
		if now != nil {
			rc.now = now
		}
	}
}

// NewRecomputer builds a Recomputer.
//
// Both collaborators are required, and the store must carry a usable handle and
// audit repository, for the same reasons New checks them: the pass reaches rows
// through store.Repos().Handles and records each quarantine through the
// transaction-bound r.Audit, so a store assembled with either left nil would
// satisfy every non-nil check and then nil-panic in the middle of the pass.
func NewRecomputer(store repository.Store, auditor Auditor, opts ...RecomputeOption) (*Recomputer, error) {
	if store == nil {
		return nil, fmt.Errorf("%w: store", ErrMissingDependency)
	}
	if auditor == nil {
		return nil, fmt.Errorf("%w: auditor", ErrMissingDependency)
	}
	if store.Repos().Handles == nil {
		return nil, fmt.Errorf("%w: handle repository", ErrMissingDependency)
	}
	if store.Repos().Audit == nil {
		return nil, fmt.Errorf("%w: audit repository", ErrMissingDependency)
	}
	rc := &Recomputer{store: store, auditor: auditor, now: time.Now}
	for i, opt := range opts {
		if opt == nil {
			return nil, fmt.Errorf("%w: nil option at index %d", ErrMissingDependency, i)
		}
		opt(rc)
	}
	return rc, nil
}

// Run recomputes every stale fold in one transaction and reports what it did.
//
// The whole pass is one transaction because a partial recompute is not a valid
// state: a crash between two rows would leave some folds current and some stale,
// and the create/rename guard would keep blocking anyway. All-or-nothing means a
// crash rolls back to fully-stale, the guard keeps refusing, and the next boot
// retries — a fold held stale a little longer, never a fold silently half-fixed.
//
// A pre-existing collision is resolved in Go, never by letting the unique index
// discover it: a not-yet-processed row's RAW backfilled fold can equal another
// row's TRUE skeleton mid-pass, so the index would refuse the wrong (older) row.
// Phase 0 first clears every stale row's fold to a unique, non-collidable
// placeholder; phase 1 then writes true skeletons into an empty namespace, so
// the index is only ever a backstop.
func (rc *Recomputer) Run(ctx context.Context) (FoldRecomputeResult, error) {
	var res FoldRecomputeResult
	version := blocklist.TableVersion

	stale, err := rc.store.Repos().Handles.ListStaleFolds(ctx, version)
	if err != nil {
		return res, fmt.Errorf("handle: list stale folds: %w", err)
	}
	if len(stale) == 0 {
		// Nothing to do. Return before opening a transaction so the common
		// already-current boot does no write at all.
		return res, nil
	}
	now := rc.now().UTC()

	// Group stale rows by true skeleton. stale is ordered oldest-first
	// (created_at ASC, id ASC) by the port, so the first index in each group is
	// the survivor and the rest are newer look-alikes. order preserves first-seen
	// skeleton order so the pass — and its audit records — are deterministic.
	order := make([]string, 0, len(stale))
	groups := make(map[string][]int, len(stale))
	for i := range stale {
		sk := blocklist.Skeleton(stale[i].Name)
		if _, seen := groups[sk]; !seen {
			order = append(order, sk)
		}
		groups[sk] = append(groups[sk], i)
	}

	if err := rc.store.WithTx(ctx, func(ctx context.Context, r repository.Repos) error {
		res = FoldRecomputeResult{}
		// Phase 0: empty the skeleton namespace of raw squatters.
		for i := range stale {
			if err := r.Handles.SetFold(ctx, stale[i].ID, foldPlaceholder(stale[i].ID), version, now); err != nil {
				return err
			}
		}
		// Phase 1: survivors take their true skeleton; losers are quarantined.
		for _, sk := range order {
			idxs := groups[sk]
			survivor := stale[idxs[0]]
			if err := r.Handles.SetFold(ctx, survivor.ID, sk, version, now); err != nil {
				return err
			}
			res.Recomputed++
			for _, li := range idxs[1:] {
				loser := stale[li]
				if err := r.Handles.QuarantineLookalike(ctx, loser.ID, now); err != nil {
					return err
				}
				// Recorded on the transaction-bound r.Audit so the quarantine and
				// its record commit as one unit: a name a human reads as another's
				// must never be held with no trace of why.
				if err := rc.emitQuarantine(ctx, r.Audit, loser, survivor.Name); err != nil {
					return err
				}
				res.Quarantined++
			}
		}
		return nil
	}); err != nil {
		return FoldRecomputeResult{}, fmt.Errorf("handle: recompute folds: %w", err)
	}
	return res, nil
}

// emitQuarantine records one look-alike quarantine. The system is the actor: no
// owner asked for this, the pass did. Both names are public handle slugs, so
// neither is a secret; naming the survivor is what tells an incident review which
// two names collided.
func (rc *Recomputer) emitQuarantine(
	ctx context.Context,
	sink repository.AuditAppender,
	loser domain.Handle,
	survivorName string,
) error {
	d := audit.Details{}.
		Set(audit.DetailHandle, loser.Name).
		Set(audit.DetailTo, survivorName).
		Set(audit.DetailReason, "quarantined as a look-alike of an existing handle")
	if err := d.Err(); err != nil {
		// The rejected value is not quoted back; this error is destined for a log
		// and has no reason to carry content it does not need.
		return fmt.Errorf("handle: quarantine cannot be recorded: %w", domain.ErrInvalidInput)
	}
	return rc.auditor.EmitTo(ctx, sink, audit.Event{
		ActorType:  domain.ActorTypeSystem,
		Action:     domain.AuditActionHandleQuarantined,
		TargetType: domain.TargetTypeHandle,
		TargetID:   string(loser.ID),
		Details:    d,
	})
}

// foldPlaceholder returns a name_fold value that no blocklist.Skeleton output
// can equal — a skeleton is lowercase alphanumerics and never contains '!' — and
// that is unique per row because handle ids are unique. Storing it therefore
// occupies no reachable fold slot and collides with nothing, which is exactly
// what phase 0 needs and what a quarantined look-alike keeps.
func foldPlaceholder(id domain.HandleID) string {
	return "!" + string(id)
}
