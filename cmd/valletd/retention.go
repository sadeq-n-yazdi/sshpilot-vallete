package main

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/config"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/erasure"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/repository"
)

// newRetentionScheduler builds the audit retention purge from config.
//
// It returns (nil, nil) when purging is disabled, which is the one case the
// caller must handle rather than treat as a failure. Everything else is
// fail-closed: an out-of-range window, batch, or ceiling returns an error and
// the process exits instead of starting with a silently corrected policy. A
// retention window is the difference between keeping a year of evidence and
// keeping none, so "the operator wrote something we could not use, so we picked
// a number" is not an acceptable startup outcome.
//
// The two ports are deliberately different types. The purge needs the full
// repository.AuditRepository because PurgeOlderThan lives there; the recorder
// gets the insert-only repository.AuditAppender, so the code that writes the
// "we deleted N records" entry cannot itself delete anything.
func newRetentionScheduler(
	cfg *config.Config,
	logger *slog.Logger,
	auditRepo repository.AuditRepository,
	sink repository.AuditAppender,
) (*erasure.Scheduler, error) {
	r := cfg.Retention

	// Disabled is expressed only here, on the schedule. There is deliberately
	// no value of audit_retention that means "purge everything" -- config
	// validation rejects a non-positive window outright -- so the reversible
	// setting (keep too much) carries the off switch and the irreversible one
	// (keep nothing) cannot be expressed at all.
	if r.AuditPurgeInterval.Std() == 0 {
		logger.Warn("audit retention purging is DISABLED (retention.audit_purge_interval is 0); audit records will accumulate without bound",
			slog.Duration("configured_retention", r.AuditRetention.Std()))
		return nil, nil
	}

	purger, err := erasure.NewPurger(auditRepo,
		erasure.WithRetention(r.AuditRetention.Std()),
		erasure.WithBatchSize(r.AuditPurgeBatch),
		erasure.WithMaxPerRun(int64(r.AuditPurgeMaxPerRun)),
	)
	if err != nil {
		return nil, fmt.Errorf("audit retention purge: %w", err)
	}

	sched, err := erasure.NewScheduler(purger, r.AuditPurgeInterval.Std(), logger,
		erasure.WithAuditSink(sink))
	if err != nil {
		return nil, fmt.Errorf("audit retention purge: %w", err)
	}
	return sched, nil
}

// startRetention runs sched until ctx is canceled and returns a join function.
//
// The join is not optional bookkeeping. A purge holds a write transaction; if
// the process exited while one was in flight, the drain would race the database
// handle being closed. Joining means the last thing the purge does always
// happens before the datastore goes away.
//
// A nil scheduler (purging disabled) yields a join that returns immediately, so
// the caller has no branch to forget.
func startRetention(ctx context.Context, sched *erasure.Scheduler) func() {
	if sched == nil {
		return func() {}
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		sched.Run(ctx)
	}()
	return wg.Wait
}
