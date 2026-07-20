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

// Purger deletes audit records that have aged past the retention window.
//
// It removes whole records once they are old enough. That is a different
// operation from crypto-erasure, which removes a subject's identity from
// records that remain: retention answers "this is older than we keep things",
// erasure answers "this subject asked to be forgotten". Neither can alter what
// a surviving record says happened.
type Purger struct {
	audit     repository.AuditRepository
	retention time.Duration
	batch     int
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
// The loop ends when a batch comes back short, which is the adapter's signal
// that nothing older remains. Context cancellation is honored between batches,
// so a shutdown stops the purge at a transaction boundary rather than mid-sweep.
func (p *Purger) PurgeOnce(ctx context.Context) (int64, error) {
	cutoff := p.Cutoff()

	var total int64
	for {
		if err := ctx.Err(); err != nil {
			return total, err
		}
		n, err := p.audit.PurgeOlderThan(ctx, cutoff, p.batch)
		total += n
		if err != nil {
			return total, fmt.Errorf("erasure: purge: %w", err)
		}
		// A short batch means the adapter found fewer eligible records than the
		// batch could hold, so the backlog is exhausted.
		if n < int64(p.batch) {
			return total, nil
		}
	}
}
