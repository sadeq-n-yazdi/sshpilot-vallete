package erasure

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/audit"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/repository"
)

// Scheduler runs a Purger on a fixed cadence for the lifetime of the process.
//
// # Why the loop is shaped this way
//
// Every property below is structural rather than checked, because a retention
// job is the kind of background work whose failures are silent: nobody notices
// that purging stopped until the disk fills or a regulator asks.
//
//   - No overlapping passes. A pass runs inline in the select loop, never in a
//     goroutine spawned per tick, so two passes cannot exist at once no matter
//     how long one takes. time.Ticker's channel is buffered to one and drops
//     ticks that arrive while the receiver is busy, so a slow pass causes ticks
//     to be skipped rather than queued up and replayed in a burst afterwards.
//   - Failure never stops purging. A pass that returns an error is logged and
//     the loop continues to the next tick. A pass that panics is recovered, so
//     a fault in the storage layer cannot kill the goroutine and leave the
//     process running with retention silently switched off -- the worst outcome
//     available, because it looks exactly like a healthy service.
//   - Prompt shutdown. Run returns on context cancellation, and PurgeOnce
//     honors the same context between batches, so a SIGTERM mid-pass stops at
//     the next transaction boundary instead of holding the process open.
type Scheduler struct {
	purger   *Purger
	interval time.Duration
	logger   *slog.Logger
	// sink is the audit appender, and sinkSet records that WithAuditSink was
	// applied. The flag is needed because a nil appender is a nil interface,
	// indistinguishable from "no option given" by a nil check alone -- and the
	// difference matters: no option means "deliberately unaudited", while
	// WithAuditSink(nil) is a wiring mistake that must fail construction rather
	// than yield a Scheduler that looks audited and silently is not.
	sink    repository.AuditAppender
	sinkSet bool
	emitter *audit.Emitter

	// onPass is a test hook invoked after every completed pass, including
	// failed ones. It is unexported: production behavior must not depend on a
	// callback a caller could install to observe or alter purge outcomes.
	onPass func(deleted int64, err error)
}

// auditRecordTimeout bounds the write of a pass's audit record. It runs on a
// context detached from shutdown, so it needs its own deadline or a wedged
// database could hold the process open past its drain window.
const auditRecordTimeout = 5 * time.Second

// SchedulerOption configures a Scheduler.
type SchedulerOption func(*Scheduler)

// WithAuditSink records each retention pass in the audit log through the
// insert-only appender.
//
// The narrow port is the point. Deleting audit history is an access-affecting
// administrative event and belongs in the log, but a recorder holding the full
// repository.AuditRepository could itself purge, so the sink is handed the
// interface that can only append. That also bounds the recursion: the record a
// pass writes is stamped now, the cutoff is strictly in the past (retention is
// validated positive), so a pass can never delete its own record, and passes
// that delete nothing write nothing (see recordPass) -- a job that exists to
// shrink the log cannot grow it on every idle tick.
func WithAuditSink(sink repository.AuditAppender) SchedulerOption {
	return func(s *Scheduler) { s.sink, s.sinkSet = sink, true }
}

// withPassHook installs the test observation hook.
func withPassHook(fn func(deleted int64, err error)) SchedulerOption {
	return func(s *Scheduler) { s.onPass = fn }
}

// NewScheduler returns a Scheduler that runs p every interval.
//
// A non-positive interval is rejected rather than silently treated as
// "disabled": whether purging runs at all is a decision the caller must make
// explicitly, and config validation makes it upstream. Constructing a Scheduler
// that never purges would be indistinguishable from one that does until the
// audit table grew without bound.
func NewScheduler(p *Purger, interval time.Duration, logger *slog.Logger, opts ...SchedulerOption) (*Scheduler, error) {
	if p == nil {
		return nil, fmt.Errorf("erasure: purger is required: %w", domain.ErrInvalidInput)
	}
	if interval <= 0 {
		return nil, fmt.Errorf("erasure: purge interval must be positive: %w", domain.ErrInvalidInput)
	}
	if logger == nil {
		return nil, fmt.Errorf("erasure: logger is required: %w", domain.ErrInvalidInput)
	}
	s := &Scheduler{purger: p, interval: interval, logger: logger}
	for _, opt := range opts {
		if opt == nil {
			return nil, fmt.Errorf("erasure: nil scheduler option: %w", domain.ErrInvalidInput)
		}
		opt(s)
	}
	if s.sinkSet {
		// Built here rather than in the option so the failure is returned to
		// the caller. An option that swallowed this would produce a Scheduler
		// that looks audited and is not, which is worse than one that is
		// visibly unaudited.
		e, err := audit.NewEmitter(s.sink)
		if err != nil {
			return nil, fmt.Errorf("erasure: audit sink: %w", err)
		}
		s.emitter = e
	}
	if s.emitter == nil && s.onPass == nil {
		// Not an error: auditing the purge is optional, and a deployment may
		// legitimately run without it. Recorded here only so the branch is a
		// deliberate one.
		s.logger.Debug("audit retention purge will not be recorded in the audit log")
	}
	return s, nil
}

// Run purges on the configured cadence until ctx is canceled, then returns.
//
// It blocks, so callers run it in their own goroutine and join it during
// shutdown. It returns no error because there is no failure it could report
// that should stop the process: every per-pass failure is logged and retried.
func (s *Scheduler) Run(ctx context.Context) {
	// The resolved policy is logged once at startup, with the cutoff a pass
	// would use right now. An operator who mistyped the window sees what it
	// will actually delete before it deletes anything, rather than inferring it
	// from a row count afterwards.
	s.logger.Info("audit retention purge started",
		slog.Duration("interval", s.interval),
		slog.Duration("retention", s.purger.retention),
		slog.Time("first_cutoff", s.purger.Cutoff().UTC()),
		slog.Int("batch", s.purger.batch),
		slog.Int64("max_per_run", s.purger.maxPerRun),
	)

	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	// One pass immediately, before waiting for the first tick.
	//
	// Waiting for a tick makes purging depend on the process outliving the
	// interval, and with the 24h default it very often does not: deploys,
	// autoscaling and node replacement restart a service daily or oftener, so
	// the tick is never reached and retention is silently off precisely in the
	// environments that churn most. Nothing surfaces that -- the startup log
	// above still announces the policy -- which is the failure mode this whole
	// scheduler is shaped to avoid.
	//
	// Guarded on ctx so a Run that starts already-canceled destroys nothing:
	// shutdown must not be able to trigger a deletion on its way out.
	if ctx.Err() == nil {
		s.pass(ctx)
	}

	for {
		select {
		case <-ctx.Done():
			s.logger.Info("audit retention purge stopped")
			return
		case <-ticker.C:
			// Inline, deliberately. Spawning a goroutine here is what would
			// allow two passes to overlap.
			s.pass(ctx)
		}
	}
}

// pass runs one purge and reports it. It never returns an error and never
// propagates a panic: the caller is a loop that must survive both.
func (s *Scheduler) pass(ctx context.Context) {
	deleted, err := s.runGuarded(ctx)

	switch {
	case err == nil:
		s.report(ctx, deleted)
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		// Shutdown interrupted the pass. Whatever it managed to delete is still
		// worth recording; the interruption itself is not an operational fault.
		s.logger.Info("audit retention purge interrupted by shutdown",
			slog.Int64("records_deleted", deleted))
		s.report(ctx, deleted)
	default:
		// Logged at error, with the partial count, and then dropped. The next
		// tick retries; a transient storage fault must not be able to end
		// purging for the life of the process.
		s.logger.Error("audit retention purge failed",
			slog.String("error", err.Error()),
			slog.Int64("records_deleted", deleted))
		if deleted > 0 {
			// A failed pass can still have destroyed records: PurgeOnce
			// deletes in batches and each batch commits its own transaction,
			// so a fault on batch five does not roll back batches one to four.
			// Logging the partial count and stopping there would leave those
			// rows permanently gone with no audit entry -- the one outcome
			// this record exists to prevent, and inconsistent with the
			// shutdown branch above, which records its partial count for
			// exactly this reason. ctx is normally still live on a storage
			// fault, and recordPass detaches it with WithoutCancel anyway, so
			// passing it here is safe even if it is not.
			s.report(ctx, deleted)
		}
	}

	if s.onPass != nil {
		s.onPass(deleted, err)
	}
}

// runGuarded runs one PurgeOnce with a panic recovered into an error.
//
// The recovery is in its own function so that the deferred recover runs before
// pass inspects the result, and so a panic cannot skip the reporting below it.
func (s *Scheduler) runGuarded(ctx context.Context) (deleted int64, err error) {
	defer func() {
		if r := recover(); r != nil {
			// The panic value is included because a purge never reads record
			// content -- it issues a bounded DELETE and receives a row count --
			// so nothing auditable can be in it, and an operator debugging a
			// storage-layer fault needs to see it.
			err = fmt.Errorf("erasure: purge panicked: %v", r)
		}
	}()
	return s.purger.PurgeOnce(ctx)
}

// report logs a successful pass and, when a sink is configured, records it.
func (s *Scheduler) report(ctx context.Context, deleted int64) {
	cutoff := s.purger.Cutoff().UTC()

	if deleted == 0 {
		// Debug, not info: an idle pass is the steady state once a deployment
		// has caught up, and logging it at info every interval would bury the
		// passes that actually removed something.
		s.logger.Debug("audit retention purge removed nothing", slog.Time("cutoff", cutoff))
		return
	}

	// Info, not debug: this is a destructive, irreversible action and an
	// operator must be able to see it in default log output. The count and the
	// cutoff say what was removed; no record content is logged, because the
	// purge never read any.
	s.logger.Info("audit retention purge removed records",
		slog.Int64("records_deleted", deleted),
		slog.Time("cutoff", cutoff))

	s.recordPass(ctx, cutoff, deleted)
}

// recordPass writes the audit record for a pass that deleted something.
//
// A pass that deleted nothing is not recorded. The purpose of the record is
// accountability for destroyed evidence, and an idle pass destroyed none; a
// record per idle tick would make the retention job the single largest producer
// of audit rows, which is the opposite of what it is for.
func (s *Scheduler) recordPass(ctx context.Context, cutoff time.Time, deleted int64) {
	if s.emitter == nil {
		return
	}

	// Detached from the caller's context, with its own bound. The pass may be
	// finishing because of a shutdown, and the deletion has already committed;
	// writing the record on a canceled context would guarantee losing exactly
	// the accountability entry for the destruction that just happened.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), auditRecordTimeout)
	defer cancel()

	// Recorded as the system actor: no principal requested this, and it is
	// deliberately not attributable to any owner. Retention is a property of
	// record age, not of ownership -- see the note on Purger.
	err := s.emitter.Emit(ctx, audit.Event{
		ActorType:  domain.ActorTypeSystem,
		Action:     domain.AuditActionAuditPurged,
		TargetType: domain.TargetTypeAuditLog,
		TargetID:   domain.AuditLogTargetID,
		Details: audit.Details{}.
			Set(audit.DetailCount, strconv.FormatInt(deleted, 10)).
			Set(audit.DetailTo, cutoff.Format(time.RFC3339)),
	})
	if err != nil {
		// Logged, never fatal, and never retried. The deletion has already
		// committed, so failing the pass here would not undo it; all that is
		// left is to make the gap in the record loud.
		s.logger.Error("audit retention purge could not be recorded in the audit log",
			slog.String("error", err.Error()),
			slog.Int64("records_deleted", deleted),
			slog.Time("cutoff", cutoff))
	}
}
