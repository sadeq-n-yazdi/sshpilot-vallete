package main

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/config"
)

// syncBuffer is a writer safe for concurrent use. The logger is written from
// the goroutine running the server and read from the test goroutine polling
// for a line, so an unguarded bytes.Buffer would be a data race under -race.
type syncBuffer struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// TestRunStartsTheRetentionPurge is the end-to-end guard on the call site.
//
// Every other test in this package exercises newRetentionScheduler and
// startRetention directly, which proves the machinery works but not that
// anything calls it -- exactly the "asserts the artifact, not the mechanism"
// shape that lets a regression through. A change that stopped building the
// scheduler in run, or stopped passing it to serve, would leave the whole
// suite green while the retention policy silently stopped being enforced. That
// is the precise defect this change exists to remove, so it gets a test that
// drives the real entry point.
//
// The assertion is the line Scheduler.Run emits on entry, before its first
// tick. That is deliberate: it proves the chain run -> serve -> startRetention
// -> Run without depending on a tick landing, a purge deleting anything, or
// shutdown completing, none of which this test is about and all of which would
// make it timing-sensitive.
func TestRunStartsTheRetentionPurge(t *testing.T) {
	// Not parallel: this test signals its own process.
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "vallet.yaml")
	cfg := "" +
		"server:\n" +
		"  environment: development\n" +
		"  listen_addr: 127.0.0.1:0\n" +
		"tls:\n" +
		"  mode: self_signed\n" +
		"database:\n" +
		"  driver: sqlite\n" +
		"  sqlite:\n" +
		"    path: " + filepath.Join(dir, "vallet.db") + "\n" +
		"telemetry:\n" +
		"  log:\n" +
		"    level: info\n" +
		"    format: text\n" +
		"retention:\n" +
		"  audit_purge_interval: 1ms\n"
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	var logs syncBuffer
	done := make(chan error, 1)
	go func() { done <- run([]string{"-config", cfgPath}, &logs, &logs) }()

	const started = "audit retention purge started"
	deadline := time.After(30 * time.Second)
	for !strings.Contains(logs.String(), started) {
		select {
		case err := <-done:
			t.Fatalf("valletd exited before starting the retention purge: %v\nlogs:\n%s", err, logs.String())
		case <-deadline:
			t.Fatalf("the retention purge never started; run does not wire it up.\nlogs:\n%s", logs.String())
		case <-time.After(10 * time.Millisecond):
		}
	}

	// Only now signal. serve registers its handler before Run logs the line we
	// just saw, so by this point the process is guaranteed to catch SIGTERM
	// rather than die on the default disposition.
	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatalf("signal self: %v", err)
	}
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatalf("valletd did not shut down after SIGTERM.\nlogs:\n%s", logs.String())
	}
}

// TestNewLoggerFailsClosedOnBadLevel pins that startup refuses an unusable log
// level instead of quietly choosing one.
//
// The check is duplicated here on purpose. internal/config also rejects it, but
// this path must not depend on any caller having remembered to call Validate
// first: a second entry point added later that skips validation would otherwise
// reintroduce the silent default.
func TestNewLoggerFailsClosedOnBadLevel(t *testing.T) {
	t.Parallel()

	for _, level := range []string{"warning", "trace", ""} {
		cfg := config.Default()
		cfg.Telemetry.Log.Level = level

		logger, err := newLogger(&cfg, &bytes.Buffer{})
		if err == nil {
			t.Errorf("level %q accepted at startup; must fail closed", level)
		}
		if logger != nil {
			t.Errorf("level %q returned a logger alongside an error", level)
		}
	}
}

func TestNewLoggerFailsClosedOnBadFormat(t *testing.T) {
	t.Parallel()

	cfg := config.Default()
	cfg.Telemetry.Log.Format = "logfmt"

	if _, err := newLogger(&cfg, &bytes.Buffer{}); err == nil {
		t.Error("unknown log format accepted at startup; must fail closed")
	} else if !strings.Contains(err.Error(), "telemetry.log") {
		t.Errorf("error must name the config field, got: %v", err)
	}
}

// TestNewLoggerRedactsByDefault pins that the logger the process actually runs
// with is the redacting one, built from stock defaults. This is the end-to-end
// guarantee: a leak here would not be caught by any unit test of the handler.
func TestNewLoggerRedactsByDefault(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	cfg := config.Default()

	logger, err := newLogger(&cfg, &buf)
	if err != nil {
		t.Fatalf("newLogger: %v", err)
	}

	logger.Info("startup",
		slog.String("authorization", "Bearer eyJhbGciOiJIUzI1NiJ9.secret"),
		slog.String("dsn", "postgres://vallet:hunter2@db.internal/vallet"),
		slog.String("handle", "alice"),
	)

	out := buf.String()
	for _, secret := range []string{"eyJhbGciOiJIUzI1NiJ9.secret", "hunter2"} {
		if strings.Contains(out, secret) {
			t.Errorf("the process logger leaked %q: %s", secret, out)
		}
	}
	if !strings.Contains(out, "alice") {
		t.Errorf("the process logger redacted a public handle: %s", out)
	}
	if !strings.HasPrefix(out, "{") {
		t.Errorf("default format must be JSON (ADR-0025), got: %s", out)
	}
}

// TestWarnUnimplementedOnboardingModeConsumesTheMode proves run() actually reads
// onboarding.mode (ADR-0033): "open" produces a visible warning that the mode is
// not implemented, and every other value -- "invite", the default, included --
// stays silent. Without this, the one stated "consume onboarding.mode"
// requirement would have no test and a refactor could silently drop the branch.
func TestWarnUnimplementedOnboardingModeConsumesTheMode(t *testing.T) {
	for _, tc := range []struct {
		name     string
		mode     string
		wantWarn bool
	}{
		{"open warns", "open", true},
		{"invite is quiet", "invite", false},
		{"empty is quiet", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var logs syncBuffer
			logger := slog.New(slog.NewJSONHandler(&logs, nil))
			cfg := config.Default()
			cfg.Onboarding.Mode = tc.mode

			warnUnimplementedOnboardingMode(&cfg, logger)

			out := logs.String()
			warned := strings.Contains(out, "onboarding.mode") && strings.Contains(out, "not implemented")
			if warned != tc.wantWarn {
				t.Fatalf("mode %q: warned = %v, want %v; log = %q", tc.mode, warned, tc.wantWarn, out)
			}
		})
	}
}
