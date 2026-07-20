package main

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/audit"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/config"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/nameguard"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/repository"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/service/handle"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/sweep"
)

// handleQuarantineSweep is the job name used in logs and in the runner's
// duplicate check. It is a constant so an operator's alert on it does not
// depend on a string literal in two places staying the same.
const handleQuarantineSweep = "handle_quarantine_release"

// newSweepRunner builds the periodic maintenance runner from config.
//
// It returns (nil, nil) when every sweep is disabled, which is the one case the
// caller must handle rather than treat as a failure. Everything else is
// fail-closed: a misconfigured cadence or batch returns an error and the
// process exits instead of serving with a sweep silently switched off.
//
// # What is and is not swept here today
//
// Only the handle quarantine release is registered, because it is the only
// sweep in the tree that exists as a service operation. The other expiry
// primitives -- the key-set quarantine list, the access-key grace list, and the
// pairing and refresh-credential expiry deletes -- are repository methods with
// no service consumer at all, so there is nothing to schedule yet. They are not
// unwired jobs; they are jobs that have not been written.
//
// That gap is worth stating plainly because the directions differ. This sweep
// fails CLOSED: if it never runs, a vacated handle stays held by its previous
// owner and nobody else can claim it, which is inconvenient and safe. The
// access-key grace sweep would fail OPEN -- a rotated credential stays usable
// past the window it was supposed to lapse in -- so when that service operation
// lands it needs a job here and, unlike this one, no off switch.
func newSweepRunner(
	cfg *config.Config,
	logger *slog.Logger,
	store repository.Store,
	sink repository.AuditAppender,
) (*sweep.Runner, error) {
	r := cfg.Retention

	if r.HandleQuarantineSweepInterval.Std() == 0 {
		logger.Warn("handle quarantine release sweep is DISABLED (retention.handle_quarantine_sweep_interval is 0); vacated handles will stay reserved indefinitely",
			slog.Duration("quarantine_window", r.HandleQuarantine.Std()))
		return nil, nil
	}

	svc, err := newHandleSweepService(cfg, store, sink)
	if err != nil {
		return nil, fmt.Errorf("handle quarantine release sweep: %w", err)
	}

	runner, err := sweep.NewRunner(logger)
	if err != nil {
		return nil, fmt.Errorf("maintenance sweeps: %w", err)
	}

	// Batch is read from config here rather than passed as 0 and left to the
	// repository, whose ListExpiredQuarantine coerces a non-positive limit to
	// its page-size default instead of rejecting it. Config validation already
	// requires >= 1, so this is a positive number the operator chose; relying
	// on the coercion would mean the effective bound was set by a storage
	// constant nobody configured.
	batch := r.HandleQuarantineSweepBatch

	// Concurrent instances are safe on this sweep. Two servers sweeping the
	// same datastore both list rows whose quarantine_until has already passed,
	// and the release itself is a DELETE that re-checks the state and the same
	// deadline, so the loser of a race deletes nothing and its
	// domain.ErrNotFound is treated as "already released" rather than an error.
	// Neither instance can release a hold the owner reclaimed in between.
	err = runner.AddJob(sweep.Job{
		Name:     handleQuarantineSweep,
		Interval: r.HandleQuarantineSweepInterval.Std(),
		Run: func(ctx context.Context) error {
			// The released count is deliberately dropped rather than logged
			// here: the service emits an audit record per released name, which
			// is the durable account, and a per-pass count in the log would add
			// nothing an operator could act on.
			_, err := svc.ReleaseExpired(ctx, batch)
			return err
		},
	})
	if err != nil {
		return nil, fmt.Errorf("maintenance sweeps: %w", err)
	}
	return runner, nil
}

// newHandleSweepService builds the handle service used by the release sweep.
//
// # Why constructing this here does not pre-empt the deferred blocklist choice
//
// handle.New requires a *nameguard.Guard and refuses a nil one, so the sweep
// cannot be built without naming a source for the reserved-identifier
// blocklist -- a deployment decision main deliberately does not make for the
// request-serving services (see the SEAM notes in run).
//
// It is not made here either, because the sweep never consults the guard.
// ReleaseExpired lists quarantines past their deadline and deletes them; the
// guard is reached only from Rename and Reclaim, which take a caller-supplied
// name. The blocklist source therefore cannot change what this sweep does to a
// single row, and nameguard.Default is used as the guard that must exist rather
// than as a choice about policy.
//
// The instance returned is for the sweep and must NOT be reused for request
// serving. A handler built on it would be enforcing the curated defaults with
// no operator extra or allow list applied, which is precisely the decision the
// SEAM defers -- and it would be enforcing it invisibly, because nothing on the
// request path would look wrong.
func newHandleSweepService(
	cfg *config.Config,
	store repository.Store,
	sink repository.AuditAppender,
) (*handle.Service, error) {
	guard, err := nameguard.Default()
	if err != nil {
		return nil, fmt.Errorf("name guard: %w", err)
	}

	// The insert-only appender, not the full audit repository. The sweep's job
	// is to write a record for every name it frees; a recorder holding the full
	// port could also delete records, and the code that accounts for a release
	// has no business being able to erase the account of one.
	emitter, err := audit.NewEmitter(sink)
	if err != nil {
		return nil, fmt.Errorf("audit sink: %w", err)
	}

	return handle.New(store, guard, emitter,
		handle.WithQuarantineWindow(cfg.Retention.HandleQuarantine.Std()))
}

// startSweeps runs the maintenance sweeps until ctx is canceled and returns a
// join function.
//
// A nil runner (every sweep disabled) yields a join that returns immediately,
// so the caller has no branch to forget. The join is not optional bookkeeping:
// a release holds a write transaction, and a process that exited without
// joining would race the database handle being closed.
func startSweeps(ctx context.Context, runner *sweep.Runner) func() {
	if runner == nil {
		return func() {}
	}
	return runner.Start(ctx)
}
