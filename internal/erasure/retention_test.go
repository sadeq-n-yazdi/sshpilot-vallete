package erasure

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/repository"
)

// purgeCall records one PurgeOlderThan invocation so a test can assert the
// cutoff and the batch size the Purger actually asked for.
type purgeCall struct {
	cutoff time.Time
	limit  int
}

// fakePurgeAudit serves a fixed backlog in batches, exactly as the real
// adapter does: at most limit records at a time, never any newer than cutoff.
type fakePurgeAudit struct {
	repository.AuditRepository

	// times holds the OccurredAt of every record still in the log.
	times []time.Time
	calls []purgeCall
	err   error
}

func (f *fakePurgeAudit) PurgeOlderThan(_ context.Context, cutoff time.Time, limit int) (int64, error) {
	f.calls = append(f.calls, purgeCall{cutoff: cutoff, limit: limit})
	if f.err != nil {
		return 0, f.err
	}
	var kept []time.Time
	var deleted int64
	for _, at := range f.times {
		// Inclusive cutoff, bounded by the batch limit — the contract the
		// Purger is written against.
		if deleted < int64(limit) && !at.After(cutoff) {
			deleted++
			continue
		}
		kept = append(kept, at)
	}
	f.times = kept
	return deleted, nil
}

var testNow = time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

func TestPurgerCutoffUsesRetentionWindow(t *testing.T) {
	t.Parallel()
	p, err := NewPurger(&fakePurgeAudit{},
		WithRetention(30*24*time.Hour), withClock(staticClock(testNow)))
	if err != nil {
		t.Fatalf("NewPurger: %v", err)
	}

	want := testNow.Add(-30 * 24 * time.Hour)
	if got := p.Cutoff(); !got.Equal(want) {
		t.Errorf("Cutoff = %v, want %v", got, want)
	}
}

// TestPurgerDeletesOnlyAgedRecords is the evidence-preservation test at the
// service level: with a mix of records straddling the window, only those at or
// beyond it may go.
func TestPurgerDeletesOnlyAgedRecords(t *testing.T) {
	t.Parallel()
	retention := 30 * 24 * time.Hour
	cutoff := testNow.Add(-retention)

	audit := &fakePurgeAudit{times: []time.Time{
		cutoff.Add(-time.Hour),      // old, goes
		cutoff,                      // exactly at the cutoff, goes (inclusive)
		cutoff.Add(time.Nanosecond), // one nanosecond inside the window, stays
		testNow,                     // brand new, stays
	}}
	p, err := NewPurger(audit, WithRetention(retention), WithBatchSize(10),
		withClock(staticClock(testNow)))
	if err != nil {
		t.Fatalf("NewPurger: %v", err)
	}

	n, err := p.PurgeOnce(context.Background())
	if err != nil {
		t.Fatalf("PurgeOnce: %v", err)
	}
	if n != 2 {
		t.Errorf("deleted = %d, want 2", n)
	}
	if len(audit.times) != 2 {
		t.Fatalf("survivors = %d, want 2", len(audit.times))
	}
	for _, at := range audit.times {
		if !at.After(cutoff) {
			t.Errorf("record at %v survived but is not newer than the cutoff %v", at, cutoff)
		}
	}
}

// TestPurgerLoopsInBatches proves the Purger drives the adapter's batching
// rather than asking for the whole backlog at once, and that it stops when a
// short batch signals exhaustion.
func TestPurgerLoopsInBatches(t *testing.T) {
	t.Parallel()
	old := testNow.Add(-400 * 24 * time.Hour)
	audit := &fakePurgeAudit{}
	for range 7 {
		audit.times = append(audit.times, old)
	}
	p, err := NewPurger(audit, WithRetention(DefaultRetention), WithBatchSize(3),
		withClock(staticClock(testNow)))
	if err != nil {
		t.Fatalf("NewPurger: %v", err)
	}

	n, err := p.PurgeOnce(context.Background())
	if err != nil {
		t.Fatalf("PurgeOnce: %v", err)
	}
	if n != 7 {
		t.Errorf("deleted = %d, want 7", n)
	}
	// 3 + 3 + 1: the short final batch ends the loop.
	if len(audit.calls) != 3 {
		t.Fatalf("batches = %d, want 3", len(audit.calls))
	}
	for i, c := range audit.calls {
		if c.limit != 3 {
			t.Errorf("batch %d asked for limit %d, want 3", i, c.limit)
		}
	}
}

// TestPurgerCutoffIsStableAcrossBatches pins that the cutoff is computed once.
// A cutoff recomputed per batch would drift forward during a long run, silently
// shrinking the retention window and deleting records that were still inside it
// when the run began.
func TestPurgerCutoffIsStableAcrossBatches(t *testing.T) {
	t.Parallel()
	old := testNow.Add(-400 * 24 * time.Hour)
	audit := &fakePurgeAudit{}
	for range 5 {
		audit.times = append(audit.times, old)
	}

	// A clock that advances a day on every reading. If the cutoff were taken
	// per batch, the later batches would use a much later cutoff.
	tick := testNow
	moving := func() time.Time {
		tick = tick.Add(24 * time.Hour)
		return tick
	}
	p, err := NewPurger(audit, WithRetention(DefaultRetention), WithBatchSize(2),
		withClock(moving))
	if err != nil {
		t.Fatalf("NewPurger: %v", err)
	}
	if _, err := p.PurgeOnce(context.Background()); err != nil {
		t.Fatalf("PurgeOnce: %v", err)
	}

	if len(audit.calls) < 2 {
		t.Fatalf("batches = %d, want at least 2", len(audit.calls))
	}
	for i, c := range audit.calls {
		if !c.cutoff.Equal(audit.calls[0].cutoff) {
			t.Errorf("batch %d cutoff = %v, want the run's original %v: the window drifted",
				i, c.cutoff, audit.calls[0].cutoff)
		}
	}
}

func TestPurgerHonorsContextCancellation(t *testing.T) {
	t.Parallel()
	old := testNow.Add(-400 * 24 * time.Hour)
	audit := &fakePurgeAudit{}
	for range 10 {
		audit.times = append(audit.times, old)
	}
	p, err := NewPurger(audit, WithBatchSize(2), withClock(staticClock(testNow)))
	if err != nil {
		t.Fatalf("NewPurger: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := p.PurgeOnce(ctx); !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
	if len(audit.calls) != 0 {
		t.Errorf("purge ran %d batches after cancellation, want 0", len(audit.calls))
	}
}

func TestPurgerSurfacesAdapterError(t *testing.T) {
	t.Parallel()
	sentinel := errors.New("purge failed")
	audit := &fakePurgeAudit{err: sentinel}
	p, err := NewPurger(audit, withClock(staticClock(testNow)))
	if err != nil {
		t.Fatalf("NewPurger: %v", err)
	}

	if _, err := p.PurgeOnce(context.Background()); !errors.Is(err, sentinel) {
		t.Errorf("err = %v, want the adapter failure", err)
	}
}

// TestNewPurgerRejectsUnsafeConfig: a zero retention puts the cutoff at the
// present moment and would purge the entire log, so it must be refused rather
// than quietly defaulted.
func TestNewPurgerRejectsUnsafeConfig(t *testing.T) {
	t.Parallel()

	if _, err := NewPurger(nil); !errors.Is(err, domain.ErrInvalidInput) {
		t.Errorf("NewPurger(nil) = %v, want ErrInvalidInput", err)
	}
	for _, d := range []time.Duration{0, -time.Hour} {
		if _, err := NewPurger(&fakePurgeAudit{}, WithRetention(d)); !errors.Is(err, domain.ErrInvalidInput) {
			t.Errorf("retention %v = %v, want ErrInvalidInput", d, err)
		}
	}
	for _, n := range []int{0, -1} {
		if _, err := NewPurger(&fakePurgeAudit{}, WithBatchSize(n)); !errors.Is(err, domain.ErrInvalidInput) {
			t.Errorf("batch %d = %v, want ErrInvalidInput", n, err)
		}
	}
}

func TestNewPurgerDefaults(t *testing.T) {
	t.Parallel()
	p, err := NewPurger(&fakePurgeAudit{})
	if err != nil {
		t.Fatalf("NewPurger: %v", err)
	}
	if p.retention != DefaultRetention {
		t.Errorf("retention = %v, want %v", p.retention, DefaultRetention)
	}
	if p.batch != DefaultPurgeBatch {
		t.Errorf("batch = %d, want %d", p.batch, DefaultPurgeBatch)
	}
	// The default window must match the configured default, or a Purger built
	// without options would disagree with one built from config.
	if DefaultRetention != 365*24*time.Hour {
		t.Errorf("DefaultRetention = %v, want 365 days", DefaultRetention)
	}
}

// scriptedAudit is a purge repository whose behavior each test dictates. The
// hook is called with the requested limit and returns the rows deleted and any
// error, so a test can express "always return a full batch", "fail", or "block
// until released" without a bespoke fake for each.
type scriptedAudit struct {
	repository.AuditRepository

	mu    sync.Mutex
	calls int

	// hook is invoked for every PurgeOlderThan call. It must be safe for
	// concurrent use; several tests rely on that to detect overlap.
	hook func(ctx context.Context, cutoff time.Time, limit int) (int64, error)
}

func (s *scriptedAudit) PurgeOlderThan(ctx context.Context, cutoff time.Time, limit int) (int64, error) {
	s.mu.Lock()
	s.calls++
	s.mu.Unlock()
	return s.hook(ctx, cutoff, limit)
}

func (s *scriptedAudit) callCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

// TestPurgeOnceTerminatesWhenEveryBatchIsFull is the termination proof.
//
// It asserts the mechanism, not the artifact. The repository here always
// reports exactly the requested limit deleted and never runs out, which is what
// a repository that ignored the cutoff, or one racing a writer, would look
// like. The short-batch exit can therefore never fire, so the maxPerRun ceiling
// is the only thing that can stop the loop; if it is removed, this test hangs
// rather than failing, so it runs under its own deadline.
func TestPurgeOnceTerminatesWhenEveryBatchIsFull(t *testing.T) {
	t.Parallel()

	repo := &scriptedAudit{hook: func(_ context.Context, _ time.Time, limit int) (int64, error) {
		// Always a full batch: the backlog is inexhaustible.
		return int64(limit), nil
	}}
	p, err := NewPurger(repo, WithBatchSize(10), WithMaxPerRun(95))
	if err != nil {
		t.Fatalf("NewPurger: %v", err)
	}

	type outcome struct {
		n   int64
		err error
	}
	done := make(chan outcome, 1)
	go func() {
		n, err := p.PurgeOnce(context.Background())
		done <- outcome{n, err}
	}()

	select {
	case got := <-done:
		if got.err != nil {
			t.Fatalf("PurgeOnce: %v", got.err)
		}
		// Exactly the ceiling, not a batch-rounded overshoot: the final batch
		// is trimmed to the remaining headroom.
		if got.n != 95 {
			t.Errorf("deleted = %d, want exactly the 95 ceiling (an overshoot means the final batch was not trimmed)", got.n)
		}
		if repo.callCount() != 10 {
			t.Errorf("PurgeOlderThan called %d times, want 10 (nine full batches of 10 plus a trimmed batch of 5)", repo.callCount())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("PurgeOnce did not terminate with a repository that always returns a full batch; the per-run ceiling is the only exit in this case and it is not stopping the loop")
	}
}

// TestPurgeOnceTrimsFinalBatchToCeiling checks the ceiling is honored exactly
// rather than approximately, so a pass cannot delete more than an operator
// authorized for one run.
func TestPurgeOnceTrimsFinalBatchToCeiling(t *testing.T) {
	t.Parallel()

	var limits []int
	repo := &scriptedAudit{hook: func(_ context.Context, _ time.Time, limit int) (int64, error) {
		limits = append(limits, limit)
		return int64(limit), nil
	}}
	p, err := NewPurger(repo, WithBatchSize(100), WithMaxPerRun(250))
	if err != nil {
		t.Fatalf("NewPurger: %v", err)
	}
	n, err := p.PurgeOnce(context.Background())
	if err != nil {
		t.Fatalf("PurgeOnce: %v", err)
	}
	if n != 250 {
		t.Errorf("deleted = %d, want 250", n)
	}
	want := []int{100, 100, 50}
	if len(limits) != len(want) {
		t.Fatalf("limits = %v, want %v", limits, want)
	}
	for i := range want {
		if limits[i] != want[i] {
			t.Fatalf("limits = %v, want %v", limits, want)
		}
	}
}

// TestNewPurgerRejectsNonPositiveMaxPerRun pins that the ceiling cannot be
// disabled by configuration. A zero ceiling would remove the only guaranteed
// exit from the batch loop.
func TestNewPurgerRejectsNonPositiveMaxPerRun(t *testing.T) {
	t.Parallel()
	for _, n := range []int64{0, -1} {
		if _, err := NewPurger(&scriptedAudit{}, WithMaxPerRun(n)); !errors.Is(err, domain.ErrInvalidInput) {
			t.Errorf("NewPurger(WithMaxPerRun(%d)) error = %v, want ErrInvalidInput", n, err)
		}
	}
}
