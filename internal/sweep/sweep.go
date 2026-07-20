// Package sweep runs the server's periodic maintenance jobs.
//
// # Why this exists separately from erasure.Scheduler
//
// erasure.Scheduler is the audit-retention purge and only that: it is typed on
// *erasure.Purger, reads the purger's cutoff and batch to log the policy, and
// writes an AuditActionAuditPurged record through an insert-only sink. Those
// are not incidental details that a type parameter would abstract away -- they
// are the invariants that make destroying audit evidence accountable. Widening
// that type into a general job runner would mean editing the one scheduler in
// the tree that is already correct, under test, and on the irreversible path,
// in order to schedule jobs that are not audit deletions at all.
//
// So this package is a sibling, not a replacement. It borrows the shape that
// erasure.Scheduler established -- one pass immediately, passes run inline so
// they cannot overlap, every pass panic-guarded, shutdown by context -- and
// applies it to jobs described by a function. The retention purge keeps its own
// scheduler and is untouched by anything here.
//
// # What a sweep may be
//
// A job registered here runs with no owner context and no request behind it, so
// its query must select strictly by deadline and state and never by anything a
// request could steer. It must also be bounded: a sweep that reads "all expired
// rows" is a sweep that can spend an unbounded amount of time and memory the
// first time a deployment falls behind. Both properties live in the job's own
// code -- this package cannot check them -- but they are the conditions under
// which registering a job here is safe.
//
// # Concurrent instances
//
// Two servers running against one datastore both sweep, and that is expected
// rather than guarded against. It is safe for a job whose writes are idempotent
// and conditioned on the same deadline the read used: the loser of a race finds
// the row already gone and moves on. A job that is not idempotent must not be
// registered here without its own coordination, and each caller states which it
// is at the registration site.
package sweep

import (
	"context"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"runtime/debug"
	"sync"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
)

// DefaultJitter is the fraction of an interval by which each wait is randomly
// extended when no option overrides it.
//
// Jitter is one-sided on purpose: a wait is only ever lengthened, never
// shortened, so no amount of randomness can make a sweep run more often than
// the operator configured. Its job is to break up the alignment that otherwise
// happens by construction -- instances started together by one deploy tick
// together forever after, so every sweep in the fleet hits the database in the
// same instant.
const DefaultJitter = 0.1

// Job is one periodic maintenance sweep.
type Job struct {
	// Name identifies the job in logs. It is not derived from the function
	// because a stack-derived name changes when the code is refactored, and
	// an operator's alert should not.
	Name string

	// Interval is the wait between passes. It must be positive: see AddJob for
	// why "disabled" is not expressible here.
	Interval time.Duration

	// Run performs one pass. It must honor ctx and return promptly when it is
	// canceled, and it must bound its own batch size.
	Run func(ctx context.Context) error
}

// Runner owns a set of jobs and the goroutines that drive them.
type Runner struct {
	logger *slog.Logger
	jitter float64
	jobs   []Job

	// onPass is a test hook invoked after every completed pass, including a
	// failed or panicking one. It is unexported: production behavior must not
	// depend on a callback a caller could install to observe sweep outcomes.
	onPass func(name string, err error)
}

// Option configures a Runner.
type Option func(*Runner)

// WithJitter overrides the fraction by which each wait is randomly extended.
// A negative fraction is rejected by NewRunner rather than clamped, because
// negative jitter would shorten the wait -- the one direction that turns a
// spreading measure into a way of sweeping more often than configured.
func WithJitter(f float64) Option {
	return func(r *Runner) { r.jitter = f }
}

// withPassHook installs the test observation hook.
func withPassHook(fn func(name string, err error)) Option {
	return func(r *Runner) { r.onPass = fn }
}

// NewRunner returns an empty Runner. Jobs are added with AddJob.
func NewRunner(logger *slog.Logger, opts ...Option) (*Runner, error) {
	if logger == nil {
		return nil, fmt.Errorf("sweep: logger is required: %w", domain.ErrInvalidInput)
	}
	r := &Runner{logger: logger, jitter: DefaultJitter}
	for i, opt := range opts {
		// A nil option is rejected rather than skipped, so a Runner cannot be
		// left looking configured when it is not.
		if opt == nil {
			return nil, fmt.Errorf("sweep: nil option at index %d: %w", i, domain.ErrInvalidInput)
		}
		opt(r)
	}
	if r.jitter < 0 {
		return nil, fmt.Errorf("sweep: jitter must not be negative: %w", domain.ErrInvalidInput)
	}
	return r, nil
}

// AddJob registers j.
//
// Every field is required and a non-positive interval is an error, not a way to
// disable the job. Whether a sweep runs at all is a decision that belongs to
// the caller's configuration, made visibly there; a Runner that silently
// dropped a job would be indistinguishable from one that swept, which is the
// exact failure this package exists to close.
//
// Duplicate names are refused so that two jobs cannot report under one name in
// the logs, which would make a sweep that stopped invisible behind one that
// did not.
func (r *Runner) AddJob(j Job) error {
	if j.Name == "" {
		return fmt.Errorf("sweep: job name is required: %w", domain.ErrInvalidInput)
	}
	if j.Interval <= 0 {
		return fmt.Errorf("sweep: job %q interval must be positive: %w", j.Name, domain.ErrInvalidInput)
	}
	if j.Run == nil {
		return fmt.Errorf("sweep: job %q has no work function: %w", j.Name, domain.ErrInvalidInput)
	}
	for _, existing := range r.jobs {
		if existing.Name == j.Name {
			return fmt.Errorf("sweep: job %q is already registered: %w", j.Name, domain.ErrInvalidInput)
		}
	}
	r.jobs = append(r.jobs, j)
	return nil
}

// Start launches every registered job and returns a function that joins them.
//
// Each job gets its own goroutine, which is what keeps the jobs independent:
// one sweep that blocks on a slow query delays only itself, and one that panics
// takes down neither its siblings nor the process (see runGuarded). Passes
// within a single job are serialized by its loop, so a job can never overlap
// itself no matter how long a pass takes.
//
// The returned join must be called before the datastore is closed. A sweep may
// be mid-transaction when shutdown begins, and a process that exited without
// joining would race the database handle out from under it. Joining a Runner
// with no jobs returns immediately, so a caller has no branch to forget.
func (r *Runner) Start(ctx context.Context) func() {
	var wg sync.WaitGroup
	for _, j := range r.jobs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.runJob(ctx, j)
		}()
	}
	return wg.Wait
}

// runJob drives one job until ctx is canceled.
func (r *Runner) runJob(ctx context.Context, j Job) {
	r.logger.Info("maintenance sweep started",
		slog.String("sweep", j.Name),
		slog.Duration("interval", j.Interval),
	)

	// One pass immediately, before the first wait. Deferring to the first tick
	// would make the sweep depend on the process outliving its interval, and
	// deploys, autoscaling and node replacement routinely restart a service
	// more often than that -- so the sweep would be silently off in exactly the
	// environments that churn most.
	//
	// Guarded on ctx so a Runner started already-canceled does no work: an
	// immediate shutdown must not be able to trigger a pass on its way out.
	if ctx.Err() == nil {
		r.pass(ctx, j)
	}

	timer := time.NewTimer(r.wait(j.Interval))
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			r.logger.Info("maintenance sweep stopped", slog.String("sweep", j.Name))
			return
		case <-timer.C:
			// Inline, deliberately: spawning a goroutine per tick is what would
			// let two passes of the same job overlap. The next wait is computed
			// after the pass returns, so a slow pass delays the next one rather
			// than queueing ticks that replay in a burst afterwards.
			r.pass(ctx, j)
			timer.Reset(r.wait(j.Interval))
		}
	}
}

// wait returns the interval extended by up to jitter of itself.
func (r *Runner) wait(interval time.Duration) time.Duration {
	if r.jitter == 0 {
		return interval
	}
	//nolint:gosec // G404: this randomness spreads load across instances; it is
	// not a secret and nothing security-relevant depends on it being
	// unpredictable.
	return interval + time.Duration(rand.Float64()*r.jitter*float64(interval))
}

// pass runs one pass and reports it. It never returns an error and never
// propagates a panic: the caller is a loop that must survive both.
func (r *Runner) pass(ctx context.Context, j Job) {
	err := r.runGuarded(ctx, j)

	switch {
	case err == nil:
		// Debug, not info: an idle pass is the steady state, and logging one
		// per interval per job would bury everything else.
		r.logger.Debug("maintenance sweep completed", slog.String("sweep", j.Name))
	case ctx.Err() != nil:
		// Shutdown interrupted the pass. Not an operational fault: whatever the
		// job committed stands, and the next process start sweeps the rest.
		r.logger.Info("maintenance sweep interrupted by shutdown", slog.String("sweep", j.Name))
	default:
		// Logged at error and dropped. The next pass retries; a transient
		// storage fault must not be able to end a sweep for the life of the
		// process.
		r.logger.Error("maintenance sweep failed",
			slog.String("sweep", j.Name),
			slog.String("error", err.Error()),
		)
	}

	if r.onPass != nil {
		r.onPass(j.Name, err)
	}
}

// runGuarded runs one pass with a panic recovered into an error.
//
// The recovery is in its own function so the deferred recover runs before pass
// inspects the result, and so a panic cannot skip the reporting below it. A
// panicking sweep that killed its goroutine would leave the process running
// with that maintenance silently switched off -- indistinguishable from a
// healthy service, which is the worst outcome available.
//
// The stack is captured because that outcome is exactly when it is needed. The
// recovered value alone names what went wrong ("nil pointer dereference") but
// not where, and the frames are gone the moment this function returns: the job
// runs on its own goroutine, on a timer, with no request to correlate against,
// so an operator reading the log later has no other route back to the fault.
//
// It goes into the error rather than a separate log field deliberately. The
// logging package is a default-deny allowlist and "stack" is not on it, so a
// slog.String("stack", ...) would render "[REDACTED]" -- the stack would be
// captured and then thrown away. Allowlisting it is a change to that package,
// which this branch does not own, and the runner is handed the single
// process-wide logger, so the widening would apply everywhere rather than to
// sweeps. Folding it into the error reaches the already-allowlisted "error"
// key, and every secret this codebase puts in an error string redacts itself
// from the inside, so nothing is smuggled past the policy by doing so.
//
// The cost is a multi-line error string, paid only on a pass that panicked.
func (r *Runner) runGuarded(ctx context.Context, j Job) (err error) {
	defer func() {
		if rec := recover(); rec != nil {
			// Taken inside the deferred call, while the panicking frames are
			// still on the stack.
			err = fmt.Errorf("sweep: job %q panicked: %v\n%s", j.Name, rec, debug.Stack())
		}
	}()
	return j.Run(ctx)
}
