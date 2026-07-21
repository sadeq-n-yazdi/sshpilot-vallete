package main

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/audit"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/config"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/nameguard"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/repository"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/secrets"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/service/accesskey"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/service/handle"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/sweep"
)

// handleQuarantineSweep is the job name used in logs and in the runner's
// duplicate check. It is a constant so an operator's alert on it does not
// depend on a string literal in two places staying the same.
const handleQuarantineSweep = "handle_quarantine_release"

// accessKeyGraceSweep is the job name for the access key grace-expiry sweep,
// a constant for the same reason.
const accessKeyGraceSweep = "access_key_grace_expiry"

// newSweepRunner builds the periodic maintenance runner from config.
//
// It returns (nil, nil) when every sweep is disabled, which is the one case the
// caller must handle rather than treat as a failure. Everything else is
// fail-closed: a misconfigured cadence or batch returns an error and the
// process exits instead of serving with a sweep silently switched off.
//
// # What is and is not swept here today
//
// Two jobs are registered: the handle quarantine release and the access key
// grace expiry. The remaining expiry primitives -- the key-set quarantine list
// and the pairing and refresh-credential expiry deletes -- are repository
// methods with no service consumer at all, so there is nothing to schedule for
// them yet. They are not unwired jobs; they are jobs that have not been written.
//
// # Both jobs fail CLOSED, which is why both may be switched off
//
// An earlier version of this comment claimed the access key grace sweep fails
// OPEN -- that a rotated credential stays usable past its window if the sweep
// stops -- and concluded it would need to be mandatory. That is wrong, and the
// correction is recorded here rather than quietly deleted because the earlier
// claim was the stated reason no off switch was to be offered.
//
// accesskey.Service.Verify evaluates the grace deadline against the clock on
// EVERY request, through usable. A credential past its window is refused with
// no sweep in the picture at all, so a sweep that is late, disabled, or has
// never run cannot lengthen anybody's access by a moment. What it does is move
// the dead row to the revoked status, so the stored state stops advertising a
// window that closed and the audit trail records when the rotation completed.
//
// The handle sweep fails closed for a different reason: if it never runs, a
// vacated name stays held by its previous owner rather than being handed to a
// stranger. Both are therefore safe to disable and both take an interval of 0
// as the off switch. What would NOT be safe is moving either deadline
// comparison out of the request path onto its sweep.
func newSweepRunner(
	cfg *config.Config,
	logger *slog.Logger,
	store repository.Store,
	sink repository.AuditAppender,
	pepper secrets.Redacted,
) (*sweep.Runner, error) {
	runner, err := sweep.NewRunner(logger)
	if err != nil {
		return nil, fmt.Errorf("maintenance sweeps: %w", err)
	}

	added := 0
	for _, register := range []func(*config.Config, *slog.Logger, repository.Store, repository.AuditAppender, secrets.Redacted, *sweep.Runner) (bool, error){
		addHandleQuarantineSweep,
		addAccessKeyGraceSweep,
	} {
		ok, err := register(cfg, logger, store, sink, pepper, runner)
		if err != nil {
			return nil, err
		}
		if ok {
			added++
		}
	}
	// Nothing registered means every sweep is disabled. Returning a runner with
	// no jobs would work -- Start on an empty Runner is a no-op -- but returning
	// nil keeps the one signal the caller already handles, and keeps the
	// disabled case distinguishable from a runner whose jobs went missing.
	if added == 0 {
		return nil, nil
	}
	return runner, nil
}

// addHandleQuarantineSweep registers the quarantine release job, reporting
// whether it was enabled.
func addHandleQuarantineSweep(
	cfg *config.Config,
	logger *slog.Logger,
	store repository.Store,
	sink repository.AuditAppender,
	_ secrets.Redacted,
	runner *sweep.Runner,
) (bool, error) {
	r := cfg.Retention

	if r.HandleQuarantineSweepInterval.Std() == 0 {
		logger.Warn("handle quarantine release sweep is DISABLED (retention.handle_quarantine_sweep_interval is 0); vacated handles will stay reserved indefinitely",
			slog.Duration("quarantine_window", r.HandleQuarantine.Std()))
		return false, nil
	}

	svc, err := newHandleSweepService(cfg, store, sink)
	if err != nil {
		return false, fmt.Errorf("handle quarantine release sweep: %w", err)
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
		return false, fmt.Errorf("maintenance sweeps: %w", err)
	}
	return true, nil
}

// addAccessKeyGraceSweep registers the grace-expiry job, reporting whether it
// was enabled.
//
// The disabled warning is deliberately milder than the handle sweep's. Off is
// the shipped default here and it costs no access guarantee -- see
// newSweepRunner on why Verify, not this job, is what refuses a lapsed
// credential -- so an operator running stock config should not be told every
// startup that something is wrong.
func addAccessKeyGraceSweep(
	cfg *config.Config,
	logger *slog.Logger,
	store repository.Store,
	sink repository.AuditAppender,
	pepper secrets.Redacted,
	runner *sweep.Runner,
) (bool, error) {
	r := cfg.Retention

	if r.AccessKeyGraceSweepInterval.Std() == 0 {
		logger.Info("access key grace expiry sweep is disabled (retention.access_key_grace_sweep_interval is 0); lapsed rotation grace windows keep their grace status, and are still refused at verification")
		return false, nil
	}

	svc, err := newAccessKeySweepService(store, sink, pepper)
	if err != nil {
		return false, fmt.Errorf("access key grace expiry sweep: %w", err)
	}

	// As above, an explicit operator-chosen bound. Here it is not merely
	// preferable to passing 0: ListExpiredGrace REJECTS a non-positive limit as
	// invalid input rather than coercing it, so a 0 would fail every pass. The
	// two families of sweep primitive in this tree disagree on that, which is
	// exactly why neither caller relies on the repository's reading of a zero.
	batch := r.AccessKeyGraceSweepBatch

	// Concurrent instances are safe but not perfectly clean, and the difference
	// is stated rather than glossed. The repository's Revoke is keyed on id and
	// owner and does not re-check the grace state, so if two instances list the
	// same row before either writes, both writes land and TWO revocation records
	// are emitted for one credential. revoked_at is written with COALESCE and
	// keeps the first instant, so the credential's fate is identical either way
	// -- the cost is a duplicate audit line, not a wrong outcome. See
	// accesskey.Service.ExpireGrace for the full accounting.
	err = runner.AddJob(sweep.Job{
		Name:     accessKeyGraceSweep,
		Interval: r.AccessKeyGraceSweepInterval.Std(),
		Run: func(ctx context.Context) error {
			// The count is dropped for the same reason as above: the audit
			// record per retired credential is the durable account.
			_, err := svc.ExpireGrace(ctx, batch)
			return err
		},
	})
	if err != nil {
		return false, fmt.Errorf("maintenance sweeps: %w", err)
	}
	return true, nil
}

// newAccessKeySweepService builds the access key service used by the grace
// sweep.
//
// # Why this needs a real pepper
//
// accesskey.New refuses a pepper shorter than accesskey.MinPepperLen, and that
// refusal is the reason cmd/valletd could not construct this service until now:
// nothing in config named a pepper and nothing at startup resolved one. The
// sweep itself never hashes anything -- ExpireGrace lists and revokes -- so it
// would have been possible to satisfy the constructor with a throwaway value.
//
// That is emphatically not done, and the temptation is worth naming. The very
// same type verifies bearer tokens. A service built over a pepper nobody chose
// would compare digests under the wrong key, and the only thing standing
// between that instance and the request path is that no caller reaches for it
// today. This is the trap newHandleSweepService avoids differently: a
// nameguard default is a policy choice the sweep provably never consults, while
// a fabricated pepper is key material that changes what verification means.
//
// So the pepper is a real, operator-configured, startup-resolved secret, and
// config requires one whenever this sweep is enabled. The instance returned is
// consequently a correctly-keyed service and is safe to reuse for verification
// when the publish verifier wiring lands.
func newAccessKeySweepService(
	store repository.Store,
	sink repository.AuditAppender,
	pepper secrets.Redacted,
) (*accesskey.Service, error) {
	// The insert-only appender, not the full audit repository, for the same
	// reason as the handle sweep: the code that accounts for a retirement has no
	// business being able to erase the account of one.
	emitter, err := audit.NewEmitter(sink)
	if err != nil {
		return nil, fmt.Errorf("audit sink: %w", err)
	}

	repos := store.Repos()
	// Reveal at the point of use and nowhere else. accesskey.New copies the
	// bytes, so this slice is not retained; the value traveled here as a
	// secrets.Redacted so that any log line touching it on the way printed a
	// marker.
	return accesskey.New(repos.AccessKeys, repos.KeySets, emitter, []byte(pepper.Reveal()))
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
