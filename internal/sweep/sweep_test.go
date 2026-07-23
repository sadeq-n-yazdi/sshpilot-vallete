package sweep

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// newTestRunner builds a Runner with jitter off, so a test that waits on a
// number of passes is not waiting on a random extension of every interval.
func newTestRunner(t *testing.T, opts ...Option) *Runner {
	t.Helper()
	r, err := NewRunner(discardLogger(), append([]Option{WithJitter(0)}, opts...)...)
	if err != nil {
		t.Fatalf("NewRunner: %v", err)
	}
	return r
}

// joinWithin cancels ctx and fails unless join returns inside d. Shutdown that
// hangs is a production fault, not a slow test, so it must fail rather than
// block the suite until the package timeout.
func joinWithin(t *testing.T, cancel context.CancelFunc, join func(), d time.Duration) {
	t.Helper()
	cancel()
	done := make(chan struct{})
	go func() { defer close(done); join() }()
	select {
	case <-done:
	case <-time.After(d):
		t.Fatal("the sweep goroutines were not joined after cancellation; shutdown would hang")
	}
}

func TestRunnerRunsRegisteredJobRepeatedly(t *testing.T) {
	t.Parallel()

	passes := make(chan struct{}, 16)
	r := newTestRunner(t)
	if err := r.AddJob(Job{
		Name:     "counter",
		Interval: time.Millisecond,
		Run: func(context.Context) error {
			select {
			case passes <- struct{}{}:
			default:
			}
			return nil
		},
	}); err != nil {
		t.Fatalf("AddJob: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	join := r.Start(ctx)

	for i := range 3 {
		select {
		case <-passes:
		case <-time.After(10 * time.Second):
			cancel()
			join()
			t.Fatalf("only %d passes ran; the job is not being scheduled", i)
		}
	}
	joinWithin(t, cancel, join, 5*time.Second)
}

// TestRunnerSurvivesAPanickingJob is the isolation property: a sweep that
// panics must take down neither its siblings nor the process. Without the
// recover in runGuarded, the panicking goroutine unwinds and kills the whole
// process, so the sibling's pass count stops -- and this test fails.
func TestRunnerSurvivesAPanickingJob(t *testing.T) {
	t.Parallel()

	var panicked, healthy atomic.Int64
	progress := make(chan struct{}, 32)

	r := newTestRunner(t)
	if err := r.AddJob(Job{
		Name:     "panics",
		Interval: time.Millisecond,
		Run: func(context.Context) error {
			panicked.Add(1)
			panic("storage layer exploded")
		},
	}); err != nil {
		t.Fatalf("AddJob(panics): %v", err)
	}
	if err := r.AddJob(Job{
		Name:     "healthy",
		Interval: time.Millisecond,
		Run: func(context.Context) error {
			healthy.Add(1)
			select {
			case progress <- struct{}{}:
			default:
			}
			return nil
		},
	}); err != nil {
		t.Fatalf("AddJob(healthy): %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	join := r.Start(ctx)

	// The sibling must keep making progress after the panicking job has
	// panicked at least twice: once proves the recover caught it, twice proves
	// the panicking job's own loop survived and is still being scheduled.
	deadline := time.After(10 * time.Second)
	for healthy.Load() < 3 || panicked.Load() < 2 {
		select {
		case <-progress:
		case <-deadline:
			cancel()
			join()
			t.Fatalf("stalled: panicking job ran %d times, healthy sibling %d",
				panicked.Load(), healthy.Load())
		}
	}
	joinWithin(t, cancel, join, 5*time.Second)
}

// TestRunnerReportsAPanicAsAnError pins that the recovered panic reaches the
// reporting path as an error rather than being swallowed, so an operator sees
// it in the log.
func TestRunnerReportsAPanicAsAnError(t *testing.T) {
	t.Parallel()

	errs := make(chan error, 4)
	r := newTestRunner(t, withPassHook(func(_ string, err error) {
		select {
		case errs <- err:
		default:
		}
	}))
	if err := r.AddJob(Job{
		Name:     "panics",
		Interval: time.Hour,
		Run:      func(context.Context) error { panic("boom") },
	}); err != nil {
		t.Fatalf("AddJob: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	join := r.Start(ctx)

	select {
	case err := <-errs:
		if err == nil {
			t.Fatal("a panicking pass reported a nil error; the fault would be invisible")
		}
		if !strings.Contains(err.Error(), "panicked") || !strings.Contains(err.Error(), "boom") {
			t.Errorf("panic error = %q, want it to name the job and carry the panic value", err)
		}
		// The stack is the half an operator cannot reconstruct later: the job
		// runs on its own goroutine on a timer, so "nil pointer dereference"
		// with no frames names the fault without locating it. Asserting on a
		// frame proves the capture happened while the panicking frames were
		// still live, rather than after they had unwound.
		if !strings.Contains(err.Error(), "runGuarded") ||
			!strings.Contains(err.Error(), "sweep_test.go") {
			t.Errorf("panic error = %q, want it to carry the stack of the panicking pass", err)
		}
	case <-time.After(10 * time.Second):
		cancel()
		join()
		t.Fatal("no pass was reported")
	}
	joinWithin(t, cancel, join, 5*time.Second)
}

// TestRunnerKeepsSweepingAfterAFailedPass pins that an error is logged and
// retried rather than ending the job for the life of the process.
func TestRunnerKeepsSweepingAfterAFailedPass(t *testing.T) {
	t.Parallel()

	var calls atomic.Int64
	passes := make(chan struct{}, 16)
	r := newTestRunner(t)
	if err := r.AddJob(Job{
		Name:     "flaky",
		Interval: time.Millisecond,
		Run: func(context.Context) error {
			n := calls.Add(1)
			select {
			case passes <- struct{}{}:
			default:
			}
			if n == 1 {
				return errors.New("transient storage fault")
			}
			return nil
		},
	}); err != nil {
		t.Fatalf("AddJob: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	join := r.Start(ctx)

	for i := range 3 {
		select {
		case <-passes:
		case <-time.After(10 * time.Second):
			cancel()
			join()
			t.Fatalf("sweeping stopped after %d passes; a failed pass must be retried", i)
		}
	}
	joinWithin(t, cancel, join, 5*time.Second)
}

// TestRunnerDoesNotPassWhenStartedCanceled pins that shutdown cannot trigger a
// sweep on its way out: a Runner started with an already-canceled context does
// no work at all.
func TestRunnerDoesNotPassWhenStartedCanceled(t *testing.T) {
	t.Parallel()

	// The failure this pins is a scheduling race: once the immediate pass is
	// skipped, the run loop selects between ctx.Done() and a ready timer, and
	// when both are ready select chooses between them at random. A one-tick
	// interval makes the timer ready before the loop reaches its select, so
	// both branches are ready on every iteration -- turning a rare race into a
	// near-certain one. Without the context re-check in the timer branch a
	// removed guard then surfaces within a handful of the iterations below; a
	// single run could step over it.
	const iterations = 500
	for i := 0; i < iterations; i++ {
		var calls atomic.Int64
		r := newTestRunner(t)
		if err := r.AddJob(Job{
			Name:     "counter",
			Interval: time.Nanosecond,
			Run: func(context.Context) error {
				calls.Add(1)
				return nil
			},
		}); err != nil {
			t.Fatalf("AddJob: %v", err)
		}

		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		join := r.Start(ctx)
		join()

		if got := calls.Load(); got != 0 {
			t.Fatalf("iteration %d: an already-canceled Runner ran %d passes, want 0", i, got)
		}
	}
}

// TestRunnerJoinsPromptlyOnShutdown pins that a sweep in flight does not hold
// the process open past its drain window: the job returns as soon as its
// context is canceled and the join follows.
func TestRunnerJoinsPromptlyOnShutdown(t *testing.T) {
	t.Parallel()

	started := make(chan struct{}, 1)
	r := newTestRunner(t)
	if err := r.AddJob(Job{
		Name:     "blocks-until-canceled",
		Interval: time.Millisecond,
		Run: func(ctx context.Context) error {
			select {
			case started <- struct{}{}:
			default:
			}
			<-ctx.Done()
			return ctx.Err()
		},
	}); err != nil {
		t.Fatalf("AddJob: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	join := r.Start(ctx)

	select {
	case <-started:
	case <-time.After(10 * time.Second):
		cancel()
		join()
		t.Fatal("the job never started")
	}
	joinWithin(t, cancel, join, 5*time.Second)
}

func TestRunnerWithNoJobsJoinsImmediately(t *testing.T) {
	t.Parallel()

	r := newTestRunner(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r.Start(ctx)()
}

func TestNewRunnerRejectsBadConstruction(t *testing.T) {
	t.Parallel()

	if _, err := NewRunner(nil); !errors.Is(err, domain.ErrInvalidInput) {
		t.Errorf("NewRunner(nil logger) = %v, want ErrInvalidInput", err)
	}
	if _, err := NewRunner(discardLogger(), nil); !errors.Is(err, domain.ErrInvalidInput) {
		t.Errorf("NewRunner with a nil option = %v, want ErrInvalidInput", err)
	}
	// Negative jitter would shorten the wait, which is the one direction that
	// makes a sweep run more often than the operator configured.
	if _, err := NewRunner(discardLogger(), WithJitter(-0.1)); !errors.Is(err, domain.ErrInvalidInput) {
		t.Errorf("NewRunner with negative jitter = %v, want ErrInvalidInput", err)
	}
}

func TestAddJobRejectsIncompleteJobs(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		job  Job
	}{
		{"no name", Job{Interval: time.Second, Run: func(context.Context) error { return nil }}},
		{"zero interval", Job{Name: "j", Run: func(context.Context) error { return nil }}},
		{"negative interval", Job{Name: "j", Interval: -time.Second, Run: func(context.Context) error { return nil }}},
		{"no work function", Job{Name: "j", Interval: time.Second}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := newTestRunner(t)
			if err := r.AddJob(tc.job); !errors.Is(err, domain.ErrInvalidInput) {
				t.Errorf("AddJob(%s) = %v, want ErrInvalidInput", tc.name, err)
			}
		})
	}
}

func TestAddJobRejectsADuplicateName(t *testing.T) {
	t.Parallel()

	r := newTestRunner(t)
	j := Job{Name: "dup", Interval: time.Second, Run: func(context.Context) error { return nil }}
	if err := r.AddJob(j); err != nil {
		t.Fatalf("first AddJob: %v", err)
	}
	if err := r.AddJob(j); !errors.Is(err, domain.ErrInvalidInput) {
		t.Errorf("duplicate AddJob = %v, want ErrInvalidInput", err)
	}
}

// TestWaitOnlyEverExtendsTheInterval pins the one-sided jitter: randomness may
// spread instances apart but must never make a sweep run more often than
// configured.
func TestWaitOnlyEverExtendsTheInterval(t *testing.T) {
	t.Parallel()

	const interval = time.Second
	r, err := NewRunner(discardLogger(), WithJitter(0.5))
	if err != nil {
		t.Fatalf("NewRunner: %v", err)
	}
	sawExtension := false
	for range 200 {
		got := r.wait(interval)
		if got < interval {
			t.Fatalf("wait = %v, shorter than the %v interval", got, interval)
		}
		if got > interval+time.Duration(0.5*float64(interval)) {
			t.Fatalf("wait = %v, beyond the 50%% jitter bound", got)
		}
		if got > interval {
			sawExtension = true
		}
	}
	if !sawExtension {
		t.Error("jitter never extended the interval; instances would stay aligned")
	}
}
