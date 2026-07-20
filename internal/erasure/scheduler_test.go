package erasure

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/repository"
)

// testLogger discards output; these tests assert behavior, not log text.
func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// newTestScheduler builds a Purger and Scheduler over repo, with a pass hook
// that feeds outcomes to the returned channel.
func newTestScheduler(t *testing.T, repo repository.AuditRepository, interval time.Duration, opts ...Option) (*Scheduler, <-chan passResult) {
	t.Helper()
	p, err := NewPurger(repo, opts...)
	if err != nil {
		t.Fatalf("NewPurger: %v", err)
	}
	results := make(chan passResult, 64)
	s, err := NewScheduler(p, interval, testLogger(), withPassHook(func(deleted int64, err error) {
		select {
		case results <- passResult{deleted: deleted, err: err}:
		default:
		}
	}))
	if err != nil {
		t.Fatalf("NewScheduler: %v", err)
	}
	return s, results
}

type passResult struct {
	deleted int64
	err     error
}

// runInBackground starts s.Run and returns a function that cancels it and waits
// for Run to return, failing if it does not return promptly.
func runInBackground(t *testing.T, s *Scheduler) (context.Context, func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.Run(ctx)
	}()
	return ctx, func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("Run did not return after cancellation")
		}
	}
}

// TestSchedulerCancellationStopsLoopPromptly checks that a canceled context
// both ends the loop and reaches the in-flight purge, so a SIGTERM during a
// pass does not hold the process open for the rest of the backlog.
func TestSchedulerCancellationStopsLoopPromptly(t *testing.T) {
	t.Parallel()

	entered := make(chan struct{}, 1)
	repo := &scriptedAudit{hook: func(ctx context.Context, _ time.Time, limit int) (int64, error) {
		select {
		case entered <- struct{}{}:
		default:
		}
		// Block until the purge's own context is canceled. If cancellation
		// were not plumbed through, this would block forever and the test
		// would time out rather than pass.
		<-ctx.Done()
		return 0, ctx.Err()
	}}

	p, err := NewPurger(repo, WithBatchSize(1), WithMaxPerRun(1000))
	if err != nil {
		t.Fatalf("NewPurger: %v", err)
	}
	s, err := NewScheduler(p, time.Millisecond, testLogger())
	if err != nil {
		t.Fatalf("NewScheduler: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	returned := make(chan struct{})
	go func() {
		defer close(returned)
		s.Run(ctx)
	}()

	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		cancel()
		t.Fatal("scheduler never started a pass")
	}

	start := time.Now()
	cancel()
	select {
	case <-returned:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return within 5s of cancellation; a purge mid-loop must not delay shutdown")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("Run took %v to return after cancellation, want prompt", elapsed)
	}
}

// TestSchedulerPurgesImmediatelyOnStart is the "a daily restart still purges"
// proof.
//
// The interval is an hour, so no tick can fire during the test: if the loop
// only purged on ticks, nothing would ever reach the repository and this would
// time out. That is the real deployment shape -- a 24h interval in a service
// that restarts on every deploy -- where waiting for the first tick means
// retention never runs at all.
func TestSchedulerPurgesImmediatelyOnStart(t *testing.T) {
	t.Parallel()

	purged := make(chan struct{}, 1)
	repo := &scriptedAudit{hook: func(context.Context, time.Time, int) (int64, error) {
		select {
		case purged <- struct{}{}:
		default:
		}
		return 0, nil
	}}
	s, results := newTestScheduler(t, repo, time.Hour, WithBatchSize(1), WithMaxPerRun(10))
	_, stop := runInBackground(t, s)
	defer stop()

	select {
	case <-purged:
	case <-time.After(5 * time.Second):
		t.Fatal("no purge reached the repository before the first tick; a process shorter-lived than the interval would never purge")
	}
	if got := awaitPass(t, results); got.err != nil {
		t.Fatalf("startup pass err = %v, want nil", got.err)
	}
}

// TestSchedulerCancellationBeforeFirstTickReturns covers shutdown arriving
// before the loop has done anything, and pins that it purges nothing on the
// way out: a Run handed an already-canceled context must destroy no records.
//
// The assertion is on the pass hook rather than on the repository, and that is
// deliberate. PurgeOnce checks the context before its first batch, so a pass
// started on a dead context never reaches the repository either way -- only the
// completed-pass hook distinguishes "no pass was started" from "a pass ran and
// found the context dead".
func TestSchedulerCancellationBeforeFirstTickReturns(t *testing.T) {
	t.Parallel()

	repo := &scriptedAudit{hook: func(context.Context, time.Time, int) (int64, error) {
		t.Error("no pass should reach the repository: the context is canceled before Run starts")
		return 0, nil
	}}
	s, results := newTestScheduler(t, repo, time.Hour, WithBatchSize(1), WithMaxPerRun(10))

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	returned := make(chan struct{})
	go func() {
		defer close(returned)
		s.Run(ctx)
	}()
	select {
	case <-returned:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return when handed an already-canceled context")
	}

	// onPass fires synchronously inside Run, so by the time Run has returned
	// any pass that ran has already reported.
	select {
	case got := <-results:
		t.Fatalf("a pass ran (deleted=%d err=%v) on an already-canceled context; shutdown must not trigger a purge", got.deleted, got.err)
	default:
	}
}

// TestSchedulerSurvivesPurgeError is the "an error must not kill the loop"
// proof. The first pass fails; the test then waits for a *later* pass to
// succeed, which can only happen if the loop kept running.
func TestSchedulerSurvivesPurgeError(t *testing.T) {
	t.Parallel()

	sentinel := errors.New("storage exploded")
	var calls atomic.Int64
	repo := &scriptedAudit{hook: func(context.Context, time.Time, int) (int64, error) {
		if calls.Add(1) == 1 {
			return 0, sentinel
		}
		return 0, nil
	}}

	s, results := newTestScheduler(t, repo, time.Millisecond, WithBatchSize(5), WithMaxPerRun(50))
	_, stop := runInBackground(t, s)
	defer stop()

	first := awaitPass(t, results)
	if !errors.Is(first.err, sentinel) {
		t.Fatalf("first pass err = %v, want the injected error", first.err)
	}
	second := awaitPass(t, results)
	if second.err != nil {
		t.Fatalf("second pass err = %v, want nil; the loop must retry after a failure", second.err)
	}
}

// TestSchedulerSurvivesPurgePanic checks a panic in the storage layer cannot
// escape the pass. A dead goroutine here would leave the process healthy-looking
// with retention silently switched off, so the test insists a later pass runs.
func TestSchedulerSurvivesPurgePanic(t *testing.T) {
	t.Parallel()

	var calls atomic.Int64
	repo := &scriptedAudit{hook: func(context.Context, time.Time, int) (int64, error) {
		if calls.Add(1) == 1 {
			panic("boom")
		}
		return 0, nil
	}}

	s, results := newTestScheduler(t, repo, time.Millisecond, WithBatchSize(5), WithMaxPerRun(50))
	_, stop := runInBackground(t, s)
	defer stop()

	first := awaitPass(t, results)
	if first.err == nil {
		t.Fatal("panicking pass reported no error; the panic must be recovered into one, not swallowed")
	}
	second := awaitPass(t, results)
	if second.err != nil {
		t.Fatalf("second pass err = %v, want nil; a panic must not end the loop", second.err)
	}
}

// TestSchedulerDoesNotOverlapPasses is the no-concurrent-pass proof.
//
// The repository holds every call for well over the tick interval and counts
// how many calls are in flight at once. Ticks therefore pile up behind the
// running pass; if the scheduler spawned a goroutine per tick, or otherwise
// allowed a second pass to start, the concurrency counter would exceed one.
func TestSchedulerDoesNotOverlapPasses(t *testing.T) {
	t.Parallel()

	var inFlight atomic.Int64
	var maxInFlight atomic.Int64
	repo := &scriptedAudit{hook: func(context.Context, time.Time, int) (int64, error) {
		n := inFlight.Add(1)
		for {
			old := maxInFlight.Load()
			if n <= old || maxInFlight.CompareAndSwap(old, n) {
				break
			}
		}
		// Far longer than the tick interval, so several ticks fire during it.
		time.Sleep(60 * time.Millisecond)
		inFlight.Add(-1)
		return 0, nil
	}}

	s, results := newTestScheduler(t, repo, time.Millisecond, WithBatchSize(5), WithMaxPerRun(50))
	_, stop := runInBackground(t, s)
	defer stop()

	// Let several passes complete, each outlasting many ticks.
	for i := 0; i < 3; i++ {
		awaitPass(t, results)
	}
	stop()

	if got := maxInFlight.Load(); got > 1 {
		t.Errorf("maximum concurrent purge calls = %d, want 1; ticks arriving during a pass must be skipped, not stacked", got)
	}
	if inFlight.Load() != 0 {
		t.Errorf("%d purge calls still in flight after shutdown", inFlight.Load())
	}
}

// TestNewSchedulerRejectsInvalidInput pins the fail-closed construction: a
// scheduler that cannot purge must not be constructible in a state that merely
// looks configured.
func TestNewSchedulerRejectsInvalidInput(t *testing.T) {
	t.Parallel()

	p, err := NewPurger(&scriptedAudit{})
	if err != nil {
		t.Fatalf("NewPurger: %v", err)
	}

	tests := []struct {
		name     string
		purger   *Purger
		interval time.Duration
		logger   *slog.Logger
		opts     []SchedulerOption
	}{
		{"nil purger", nil, time.Minute, testLogger(), nil},
		{"zero interval", p, 0, testLogger(), nil},
		{"negative interval", p, -time.Second, testLogger(), nil},
		{"nil logger", p, time.Minute, nil, nil},
		{"nil option", p, time.Minute, testLogger(), []SchedulerOption{nil}},
		{"nil audit sink", p, time.Minute, testLogger(), []SchedulerOption{WithAuditSink(nil)}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s, err := NewScheduler(tc.purger, tc.interval, tc.logger, tc.opts...)
			if !errors.Is(err, domain.ErrInvalidInput) {
				t.Fatalf("error = %v, want ErrInvalidInput", err)
			}
			if s != nil {
				t.Error("a rejected configuration must not yield a Scheduler")
			}
		})
	}
}

// recordingSink captures appended audit records.
type recordingSink struct {
	mu      sync.Mutex
	records []domain.AuditRecord
	err     error
}

func (r *recordingSink) Append(_ context.Context, rec *domain.AuditRecord) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.err != nil {
		return r.err
	}
	r.records = append(r.records, *rec)
	return nil
}

func (r *recordingSink) snapshot() []domain.AuditRecord {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]domain.AuditRecord(nil), r.records...)
}

// TestSchedulerAuditsAPassThatDeleted checks the destroyed-evidence record: a
// pass that removed rows is itself recorded, with the count and cutoff and no
// record content.
func TestSchedulerAuditsAPassThatDeleted(t *testing.T) {
	t.Parallel()

	var served atomic.Bool
	repo := &scriptedAudit{hook: func(context.Context, time.Time, int) (int64, error) {
		if served.CompareAndSwap(false, true) {
			return 3, nil // short batch: the pass finishes having deleted 3
		}
		return 0, nil
	}}
	sink := &recordingSink{}

	p, err := NewPurger(repo, WithBatchSize(10), WithMaxPerRun(100), withClock(staticClock(testNow)))
	if err != nil {
		t.Fatalf("NewPurger: %v", err)
	}
	passes := make(chan passResult, 8)
	s, err := NewScheduler(p, time.Millisecond, testLogger(),
		WithAuditSink(sink),
		withPassHook(func(d int64, err error) {
			select {
			case passes <- passResult{d, err}:
			default:
			}
		}))
	if err != nil {
		t.Fatalf("NewScheduler: %v", err)
	}
	_, stop := runInBackground(t, s)
	defer stop()

	// Wait for the deleting pass and one idle pass after it.
	awaitPass(t, passes)
	awaitPass(t, passes)
	stop()

	recs := sink.snapshot()
	if len(recs) != 1 {
		t.Fatalf("appended %d audit records, want exactly 1 (only the pass that deleted something is recorded)", len(recs))
	}
	rec := recs[0]
	if rec.Action != domain.AuditActionAuditPurged {
		t.Errorf("action = %q, want %q", rec.Action, domain.AuditActionAuditPurged)
	}
	if rec.ActorType != domain.ActorTypeSystem {
		t.Errorf("actor type = %q, want system; a retention pass has no principal behind it", rec.ActorType)
	}
	if rec.ActorID != "" {
		t.Errorf("actor id = %q, want empty; the pass is owner-agnostic and must not be attributed to anyone", rec.ActorID)
	}
	if rec.TargetType != domain.TargetTypeAuditLog {
		t.Errorf("target type = %q, want %q", rec.TargetType, domain.TargetTypeAuditLog)
	}
	if got := rec.Metadata["count"]; got != "3" {
		t.Errorf("count detail = %q, want \"3\"", got)
	}
	wantCutoff := testNow.Add(-DefaultRetention).UTC().Format(time.RFC3339)
	if got := rec.Metadata["to"]; got != wantCutoff {
		t.Errorf("cutoff detail = %q, want %q", got, wantCutoff)
	}
}

// TestSchedulerAuditRecordCannotBePurgedByItsOwnPass is the anti-recursion
// proof. The record a pass writes is stamped now; the cutoff is now minus a
// strictly positive window, so the record is necessarily newer than the cutoff
// and outside the set any pass would delete.
func TestSchedulerAuditRecordCannotBePurgedByItsOwnPass(t *testing.T) {
	t.Parallel()

	p, err := NewPurger(&scriptedAudit{}, withClock(staticClock(testNow)))
	if err != nil {
		t.Fatalf("NewPurger: %v", err)
	}
	cutoff := p.Cutoff()
	if !cutoff.Before(testNow) {
		t.Fatalf("cutoff %v is not strictly before now %v; a record written during a pass would be eligible for that pass to delete", cutoff, testNow)
	}
}

// TestSchedulerSurvivesAuditRecordFailure checks that failing to record the
// pass neither fails the pass nor stops the loop. The deletion has already
// committed, so there is nothing to roll back.
func TestSchedulerSurvivesAuditRecordFailure(t *testing.T) {
	t.Parallel()

	repo := &scriptedAudit{hook: func(context.Context, time.Time, int) (int64, error) {
		return 2, nil
	}}
	sink := &recordingSink{err: errors.New("sink down")}

	p, err := NewPurger(repo, WithBatchSize(10), WithMaxPerRun(100))
	if err != nil {
		t.Fatalf("NewPurger: %v", err)
	}
	passes := make(chan passResult, 8)
	s, err := NewScheduler(p, time.Millisecond, testLogger(),
		WithAuditSink(sink),
		withPassHook(func(d int64, err error) {
			select {
			case passes <- passResult{d, err}:
			default:
			}
		}))
	if err != nil {
		t.Fatalf("NewScheduler: %v", err)
	}
	_, stop := runInBackground(t, s)
	defer stop()

	for i := 0; i < 2; i++ {
		got := awaitPass(t, passes)
		if got.err != nil {
			t.Fatalf("pass %d err = %v, want nil; an unrecordable purge must not fail the pass", i, got.err)
		}
		if got.deleted != 2 {
			t.Fatalf("pass %d deleted = %d, want 2", i, got.deleted)
		}
	}
}

// awaitPass waits for the next completed pass, failing the test on timeout.
func awaitPass(t *testing.T, ch <-chan passResult) passResult {
	t.Helper()
	select {
	case r := <-ch:
		return r
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for a purge pass")
		return passResult{}
	}
}
