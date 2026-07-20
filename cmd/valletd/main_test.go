package main

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
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
