package main

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/config"
)

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
