package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/config"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/repository"
)

// stubAudit is a full audit port that records every purge request. Only
// PurgeOlderThan and Append are exercised here; the rest of the interface is
// embedded and would panic if the wiring reached for it, which is itself a
// useful assertion.
type stubAudit struct {
	repository.AuditRepository

	calls   atomic.Int64
	cutoffs chan time.Time
}

func newStubAudit() *stubAudit {
	return &stubAudit{cutoffs: make(chan time.Time, 64)}
}

func (s *stubAudit) PurgeOlderThan(_ context.Context, cutoff time.Time, _ int) (int64, error) {
	s.calls.Add(1)
	select {
	case s.cutoffs <- cutoff:
	default:
	}
	return 0, nil
}

func (s *stubAudit) Append(context.Context, *domain.AuditRecord) error { return nil }

func testCfg() *config.Config {
	c := config.Default()
	return &c
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// TestRetentionSchedulerIsWiredAndRuns is the regression test for the gap this
// change closes: the purge machinery existed and nothing ever called it.
//
// It asserts the mechanism -- that starting the scheduler built from default
// config actually reaches PurgeOlderThan -- rather than that some object was
// constructed. A future change that builds a scheduler and forgets to run it
// fails here.
func TestRetentionSchedulerIsWiredAndRuns(t *testing.T) {
	t.Parallel()

	cfg := testCfg()
	cfg.Retention.AuditPurgeInterval = config.Duration(time.Millisecond)

	repo := newStubAudit()
	sched, err := newRetentionScheduler(cfg, discardLogger(), repo, repo)
	if err != nil {
		t.Fatalf("newRetentionScheduler: %v", err)
	}
	if sched == nil {
		t.Fatal("scheduler is nil with a positive interval; purging would never run")
	}

	ctx, cancel := context.WithCancel(context.Background())
	join := startRetention(ctx, sched)

	select {
	case cutoff := <-repo.cutoffs:
		// And the cutoff must be the configured window behind now, not now.
		age := time.Since(cutoff)
		if age < 300*24*time.Hour {
			t.Errorf("cutoff is only %v old; with the 365d default window it must be about a year back, not near the present", age)
		}
	case <-time.After(10 * time.Second):
		cancel()
		join()
		t.Fatal("the retention purge never ran; the scheduler is not wired to anything")
	}

	cancel()
	joined := make(chan struct{})
	go func() { defer close(joined); join() }()
	select {
	case <-joined:
	case <-time.After(5 * time.Second):
		t.Fatal("the retention goroutine was not joined after cancellation")
	}
}

// TestRetentionDisabledByZeroInterval pins the off switch: a zero interval
// yields no scheduler and no purge, and startRetention still returns a usable
// join so no caller has a branch to forget.
func TestRetentionDisabledByZeroInterval(t *testing.T) {
	t.Parallel()

	cfg := testCfg()
	cfg.Retention.AuditPurgeInterval = 0

	repo := newStubAudit()
	sched, err := newRetentionScheduler(cfg, discardLogger(), repo, repo)
	if err != nil {
		t.Fatalf("newRetentionScheduler: %v", err)
	}
	if sched != nil {
		t.Fatal("a zero interval must disable purging entirely")
	}

	ctx, cancel := context.WithCancel(context.Background())
	join := startRetention(ctx, sched)
	time.Sleep(50 * time.Millisecond)
	cancel()
	join()

	if n := repo.calls.Load(); n != 0 {
		t.Errorf("purge ran %d times while disabled, want 0", n)
	}
}

// TestRetentionDisabledIsWarnedAboutLoudly checks the disabled path is visible
// in default log output. Purging silently switched off is the failure mode that
// looks exactly like a healthy service.
func TestRetentionDisabledIsWarnedAboutLoudly(t *testing.T) {
	t.Parallel()

	var buf strings.Builder
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))

	cfg := testCfg()
	cfg.Retention.AuditPurgeInterval = 0
	repo := newStubAudit()
	if _, err := newRetentionScheduler(cfg, logger, repo, repo); err != nil {
		t.Fatalf("newRetentionScheduler: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "level=WARN") {
		t.Errorf("disabled purging was not logged at WARN or above; an operator would not see it.\ngot: %s", out)
	}
	if !strings.Contains(out, "DISABLED") {
		t.Errorf("disabled purging log does not say so plainly.\ngot: %s", out)
	}
}

// TestRetentionInvalidConfigFailsStartup is the fail-closed proof.
//
// Each case is a setting that config validation would normally have caught;
// they are applied directly to prove the second gate holds too, so a
// misconfiguration cannot reach a running purge by any route. In particular a
// non-positive retention window must be an error and must never be silently
// replaced with a default, because the "helpful" fallback here is the one that
// deletes the audit log.
func TestRetentionInvalidConfigFailsStartup(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		mut  func(*config.Config)
	}{
		{"zero retention window", func(c *config.Config) { c.Retention.AuditRetention = 0 }},
		{"negative retention window", func(c *config.Config) {
			c.Retention.AuditRetention = config.Duration(-24 * time.Hour)
		}},
		{"zero batch", func(c *config.Config) { c.Retention.AuditPurgeBatch = 0 }},
		{"negative batch", func(c *config.Config) { c.Retention.AuditPurgeBatch = -5 }},
		{"zero ceiling", func(c *config.Config) { c.Retention.AuditPurgeMaxPerRun = 0 }},
		{"negative ceiling", func(c *config.Config) { c.Retention.AuditPurgeMaxPerRun = -1 }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := testCfg()
			cfg.Retention.AuditPurgeInterval = config.Duration(time.Hour)
			tc.mut(cfg)

			repo := newStubAudit()
			sched, err := newRetentionScheduler(cfg, discardLogger(), repo, repo)
			if err == nil {
				t.Fatal("invalid retention config was accepted; startup must fail closed rather than substitute a default")
			}
			if !errors.Is(err, domain.ErrInvalidInput) {
				t.Errorf("error = %v, want ErrInvalidInput", err)
			}
			if sched != nil {
				t.Error("a rejected config must not yield a runnable scheduler")
			}
			// And nothing may have been purged on the way to the error.
			if n := repo.calls.Load(); n != 0 {
				t.Errorf("purge ran %d times during a failed startup, want 0", n)
			}
		})
	}
}

// TestZeroRetentionWindowNeverPurgesEverything is the single most consequential
// assertion in this package.
//
// It goes through every layer that could accept a zero window -- config
// validation and the scheduler constructor -- and requires both to refuse. The
// purge is then confirmed never to have run, so there is no route by which a
// zero window becomes a cutoff at the present moment and deletes the entire
// audit log.
func TestZeroRetentionWindowNeverPurgesEverything(t *testing.T) {
	t.Parallel()

	for _, window := range []config.Duration{0, config.Duration(-time.Second), config.Duration(-365 * 24 * time.Hour)} {
		cfg := testCfg()
		cfg.Server.Environment = "development"
		cfg.TLS.Mode = "self_signed"
		cfg.Retention.AuditRetention = window

		if err := cfg.Validate(); err == nil {
			t.Errorf("config validation accepted audit_retention=%v; it must be rejected", time.Duration(window))
		}

		repo := newStubAudit()
		sched, err := newRetentionScheduler(cfg, discardLogger(), repo, repo)
		if err == nil {
			t.Errorf("scheduler construction accepted audit_retention=%v", time.Duration(window))
		}
		if sched != nil {
			t.Errorf("audit_retention=%v produced a runnable scheduler", time.Duration(window))
		}
		if n := repo.calls.Load(); n != 0 {
			t.Errorf("audit_retention=%v caused %d purge calls; a non-positive window must never delete anything", time.Duration(window), n)
		}
	}
}

// TestDefaultConfigProducesARunningPurge guards the shipped defaults end to
// end: with nothing overridden, valletd must purge. A default that disabled
// purging would restore the exact defect this change removes -- a documented
// 365-day retention policy that never runs.
func TestDefaultConfigProducesARunningPurge(t *testing.T) {
	t.Parallel()

	cfg := testCfg()
	repo := newStubAudit()
	sched, err := newRetentionScheduler(cfg, discardLogger(), repo, repo)
	if err != nil {
		t.Fatalf("default config must build a scheduler: %v", err)
	}
	if sched == nil {
		t.Fatal("default config disabled the retention purge; retention would be documented and never enforced")
	}
}

// TestRetentionJoinBlocksUntilContextCanceled is why serve's shutdown ordering
// matters, stated as a property rather than a comment.
//
// The join returned by startRetention completes only after the context is
// canceled. Deferred calls run last-registered-first, so joining before
// canceling would block forever -- on every exit path that never reaches
// serve's explicit stop(), most importantly the one where the listener fails on
// its own and the process most needs to exit and say why. This test pins the
// dependency that makes that ordering load-bearing: if join ever stopped
// waiting on cancellation, the first assertion here would fail and the ordering
// comment in serve would have quietly become wrong.
func TestRetentionJoinBlocksUntilContextCanceled(t *testing.T) {
	t.Parallel()

	cfg := testCfg()
	cfg.Retention.AuditPurgeInterval = config.Duration(time.Millisecond)
	repo := newStubAudit()
	sched, err := newRetentionScheduler(cfg, discardLogger(), repo, repo)
	if err != nil {
		t.Fatalf("newRetentionScheduler: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	join := startRetention(ctx, sched)

	joined := make(chan struct{})
	go func() { defer close(joined); join() }()

	// Still live: the join must not have returned.
	select {
	case <-joined:
		cancel()
		t.Fatal("join returned while the context was still live; it is not actually waiting for the purge goroutine")
	case <-time.After(100 * time.Millisecond):
	}

	cancel()
	select {
	case <-joined:
	case <-time.After(5 * time.Second):
		t.Fatal("join did not return after cancellation; serve would hang on shutdown")
	}
}
