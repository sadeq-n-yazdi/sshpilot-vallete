package main

import (
	"context"
	"fmt"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/audit"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/repository"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/service/handle"
)

// runFoldRecompute brings the stored handle look-alike folds current after a
// blocklist table bump, keeping the oldest of any pre-existing confusable pair
// and quarantining the newer (ADR-0030).
//
// It is the single wiring site shared by normal server startup and the
// bootstrap subcommand, so the two can never drift. Both run it AFTER migrations
// and BEFORE they build anything that accepts a handle create or rename: the
// adapter's fail-closed guard refuses those while any fold is stale, and this
// pass is what lifts that refusal. A failure here is a startup failure, which is
// the point — a live server must never serve against stale look-alike folds.
//
// The audit records the pass emits commit on the transaction-bound sink inside
// the Recomputer, so the emitter built here supplies only the collaborator
// interface; its own auto-commit sink is never used by the pass.
func runFoldRecompute(ctx context.Context, store repository.Store, appender repository.AuditAppender) (handle.FoldRecomputeResult, error) {
	emitter, err := audit.NewEmitter(appender)
	if err != nil {
		return handle.FoldRecomputeResult{}, fmt.Errorf("build audit emitter for fold recompute: %w", err)
	}
	rc, err := handle.NewRecomputer(store, emitter)
	if err != nil {
		return handle.FoldRecomputeResult{}, fmt.Errorf("build fold recomputer: %w", err)
	}
	res, err := rc.Run(ctx)
	if err != nil {
		return handle.FoldRecomputeResult{}, fmt.Errorf("recompute handle folds: %w", err)
	}
	return res, nil
}
