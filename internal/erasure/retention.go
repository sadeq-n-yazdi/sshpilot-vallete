package erasure

import (
	"context"
	"fmt"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/repository"
)

// DefaultRetention is the fallback audit retention window. It exists only as
// the zero-value fallback for a Purger built without one; the real value comes
// from config (Retention.AuditRetention, which defaults to the same 365 days).
// Deployments must be able to lengthen it for a compliance regime or shorten it
// for a data-minimisation one, so it is never hardcoded at a call site.
const DefaultRetention = 365 * 24 * time.Hour

// DefaultPurgeBatch is the fallback number of records removed per transaction.
// A purge of a long backlog is split into batches so each transaction is short:
// one unbounded DELETE over a large table holds a write lock for its whole
// duration, which on SQLite stalls every writer in the process.
const DefaultPurgeBatch = 500

// DefaultMaxPerRun is the fallback ceiling on how many records a single pass
// removes. Batching alone bounds each transaction but not the pass: against a
// years-old backlog the loop would keep finding full batches and run for as
// long as the backlog lasts, holding a writer busy throughout. The ceiling
// converts that into graceful degradation — the backlog drains over successive
// passes instead of one pass monopolising the database.
//
// It is also the only thing that guarantees termination when every batch comes
// back exactly full, which is what a repository that ignores the cutoff, or one
// racing an active writer, would produce.
const DefaultMaxPerRun = 100_000

// Purger deletes audit records that have aged past the retention window.
//
// It removes whole records once they are old enough. That is a different
// operation from crypto-erasure, which removes a subject's identity from
// records that remain: retention answers "this is older than we keep things",
// erasure answers "this subject asked to be forgotten". Neither can alter what
// a surviving record says happened.
// OWNER-AGNOSTIC BY DESIGN: a Purger takes no owner and offers no way to
// supply one. Retention is a system-wide policy about the age of records, not
// an operation any owner performs or can scope, and repository.AuditRepository
// reflects that — audit records carry no OwnerID at all, so there is nothing
// here to filter by even if a caller wanted to. The control that keeps this off
// owner-facing paths is the interface a caller is handed: request-path services
// are constructed with the insert-only repository.AuditAppender, which does not
// declare PurgeOlderThan, so no HTTP handler can reach a purge. Only the
// process-level retention job is given the full AuditRepository.
type Purger struct {
	audit     repository.AuditRepository
	retention time.Duration
	batch     int
	maxPerRun int64
	now       func() time.Time
}

// Option configures a Purger.
type Option func(*Purger)

// WithRetention sets the retention window: records older than this are purged.
func WithRetention(d time.Duration) Option {
	return func(p *Purger) { p.retention = d }
}

// WithBatchSize sets how many records a single transaction removes.
func WithBatchSize(n int) Option {
	return func(p *Purger) { p.batch = n }
}

// WithMaxPerRun caps how many records one PurgeOnce may remove in total.
func WithMaxPerRun(n int64) Option {
	return func(p *Purger) { p.maxPerRun = n }
}

// withClock overrides the clock. It is unexported because only tests need a
// clock that is not the wall clock; production must not be able to move the
// cutoff, since a caller who controls "now" controls which records are old
// enough to delete.
func withClock(fn func() time.Time) Option {
	return func(p *Purger) { p.now = fn }
}

// NewPurger returns a Purger over the audit log. A non-positive retention or
// batch size is rejected rather than defaulted: a zero retention would set the
// cutoff at the present moment and purge the entire log, and silently repairing
// a caller's mistake there would hide exactly the misconfiguration that
// destroys the most evidence.
func NewPurger(audit repository.AuditRepository, opts ...Option) (*Purger, error) {
	if audit == nil {
		return nil, fmt.Errorf("erasure: audit repository is required: %w", domain.ErrInvalidInput)
	}
	p := &Purger{
		audit:     audit,
		retention: DefaultRetention,
		batch:     DefaultPurgeBatch,
		maxPerRun: DefaultMaxPerRun,
		now:       time.Now,
	}
	for _, opt := range opts {
		opt(p)
	}
	if p.retention <= 0 {
		return nil, fmt.Errorf("erasure: retention must be positive: %w", domain.ErrInvalidInput)
	}
	if p.batch <= 0 {
		return nil, fmt.Errorf("erasure: batch size must be positive: %w", domain.ErrInvalidInput)
	}
	// Rejected rather than defaulted for the same reason as the others, and with
	// one extra consequence: the ceiling is what makes PurgeOnce terminate when
	// every batch comes back full, so a non-positive one would not merely be
	// misconfigured, it would permit an unbounded loop.
	if p.maxPerRun <= 0 {
		return nil, fmt.Errorf("erasure: max per run must be positive: %w", domain.ErrInvalidInput)
	}
	return p, nil
}

// Cutoff returns the timestamp at or before which records are eligible for
// purging. It is exported so an operator can see what a run would target
// before running it.
func (p *Purger) Cutoff() time.Time {
	return p.now().Add(-p.retention)
}

// PurgeOnce runs batches until the backlog older than the cutoff is drained,
// returning the total number of records deleted.
//
// The cutoff is computed once, at the start, and reused for every batch. A
// cutoff recomputed per batch would drift forward as the run proceeds, so a
// long purge would end up deleting records that were still within the retention
// window when it began — the window would silently shrink under load.
//
// The loop has two independent exits, and needs both:
//
//   - A short batch means the adapter found fewer eligible records than the
//     batch could hold, so the backlog is exhausted. This is the normal exit.
//   - The maxPerRun ceiling stops a pass that keeps finding full batches. This
//     is the only exit in the pathological case where every call returns exactly
//     the limit, so relying on the short batch alone would allow a loop with no
//     termination condition at all.
//
// Context cancellation is honored between batches, so a shutdown stops the purge
// at a transaction boundary rather than mid-sweep.
func (p *Purger) PurgeOnce(ctx context.Context) (int64, error) {
	cutoff := p.Cutoff()

	var total int64
	for total < p.maxPerRun {
		if err := ctx.Err(); err != nil {
			return total, err
		}
		// The final batch is trimmed to whatever headroom is left so a pass
		// stops at the ceiling instead of overshooting it by up to a batch.
		limit := p.batch
		if remaining := p.maxPerRun - total; remaining < int64(limit) {
			limit = int(remaining)
		}

		n, err := p.audit.PurgeOlderThan(ctx, cutoff, limit)
		total += n
		if err != nil {
			return total, fmt.Errorf("erasure: purge: %w", err)
		}
		if n < int64(limit) {
			return total, nil
		}
	}
	// The ceiling was reached with eligible records still behind it. That is a
	// deliberate, non-error outcome: the remainder is left for the next pass.
	return total, nil
}
