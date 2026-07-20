package logging

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

// TestParseLevelAcceptsKnownNames pins the accepted vocabulary and that parsing
// is tolerant of the surrounding whitespace and case an operator's YAML may
// carry -- tolerance in *spelling* is fine; tolerance in *meaning* is not.
func TestParseLevelAcceptsKnownNames(t *testing.T) {
	t.Parallel()

	cases := map[string]slog.Level{
		"debug":   slog.LevelDebug,
		"info":    slog.LevelInfo,
		"warn":    slog.LevelWarn,
		"error":   slog.LevelError,
		"INFO":    slog.LevelInfo,
		"  warn ": slog.LevelWarn,
	}

	for name, want := range cases {
		got, err := ParseLevel(name)
		if err != nil {
			t.Errorf("ParseLevel(%q) returned error: %v", name, err)
			continue
		}
		if got != want {
			t.Errorf("ParseLevel(%q) = %v, want %v", name, got, want)
		}
	}
}

// TestParseLevelFailsClosedOnUnknown is the fail-closed pin.
//
// "warning" and "trace" are the two an operator actually types, and both are
// wrong in the dangerous direction: silently defaulting would give them a more
// verbose stream than they asked for, shipped wherever logs go, while they
// believe the level they wrote is in force. The value must be rejected, and the
// error must name the accepted set so the fix is obvious.
func TestParseLevelFailsClosedOnUnknown(t *testing.T) {
	t.Parallel()

	for _, name := range []string{"warning", "trace", "verbose", "", "DEBUG1", "0"} {
		got, err := ParseLevel(name)
		if err == nil {
			t.Errorf("ParseLevel(%q) = %v with no error; an unknown level must fail closed", name, got)
			continue
		}
		if !strings.Contains(err.Error(), "debug, error, info, warn") {
			t.Errorf("ParseLevel(%q) error must list the accepted levels, got: %v", name, err)
		}
	}
}

func TestValidateFormat(t *testing.T) {
	t.Parallel()

	for _, name := range []string{"json", "text", "JSON", " text "} {
		if err := ValidateFormat(name); err != nil {
			t.Errorf("ValidateFormat(%q) = %v, want nil", name, err)
		}
	}
	for _, name := range []string{"logfmt", "yaml", "", "console"} {
		if err := ValidateFormat(name); err == nil {
			t.Errorf("ValidateFormat(%q) = nil; an unknown format must fail closed", name)
		}
	}
}

func TestLevelsAndFormatsAreSorted(t *testing.T) {
	t.Parallel()

	if got := strings.Join(Levels(), ","); got != "debug,error,info,warn" {
		t.Errorf("Levels() = %q", got)
	}
	if got := strings.Join(Formats(), ","); got != "json,text" {
		t.Errorf("Formats() = %q", got)
	}
}

// TestNewProducesRedactingJSONLogger pins the wiring that matters: New's
// logger must be the redacting one, not the bare encoder.
func TestNewProducesRedactingJSONLogger(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger, err := New(&buf, "info", "json")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	logger.Info("op", slog.String("access_key", "ak_secret"), slog.String("handle", "alice"))
	out := buf.String()

	if !strings.HasPrefix(out, "{") {
		t.Errorf("json format must produce JSON, got: %s", out)
	}
	if strings.Contains(out, "ak_secret") {
		t.Errorf("New returned a logger that does not redact: %s", out)
	}
	if !strings.Contains(out, "alice") {
		t.Errorf("New's logger dropped an allowlisted value: %s", out)
	}
}

// TestNewTextFormatAlsoRedacts pins that the text encoder is not a way around
// the filter: redaction runs before the encoder, so the choice cannot weaken it.
func TestNewTextFormatAlsoRedacts(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger, err := New(&buf, "info", "text")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	logger.Info("op", slog.String("access_key", "ak_secret"))
	out := buf.String()

	if strings.HasPrefix(out, "{") {
		t.Errorf("text format must not produce JSON, got: %s", out)
	}
	if strings.Contains(out, "ak_secret") {
		t.Errorf("text handler bypassed redaction: %s", out)
	}
}

func TestNewHonoursLevel(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger, err := New(&buf, "warn", "json")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	logger.Info("suppressed")
	logger.Warn("emitted")

	out := buf.String()
	if strings.Contains(out, "suppressed") {
		t.Errorf("info record emitted at warn level: %s", out)
	}
	if !strings.Contains(out, "emitted") {
		t.Errorf("warn record missing: %s", out)
	}
}

// TestNewRejectsBadConfigWithoutReturningALogger pins that there is no
// unfiltered fallback to accidentally use: on error, New returns nil.
func TestNewRejectsBadConfigWithoutReturningALogger(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct{ level, format string }{
		{"warning", "json"},
		{"info", "logfmt"},
	} {
		logger, err := New(&bytes.Buffer{}, tc.level, tc.format)
		if err == nil {
			t.Errorf("New(%q, %q) = nil error; must fail closed", tc.level, tc.format)
		}
		if logger != nil {
			t.Errorf("New(%q, %q) returned a logger alongside an error", tc.level, tc.format)
		}
	}
}

func TestNewExtraAllowedKeysReachTheHandler(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger, err := New(&buf, "info", "json", "migration_step")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	logger.Info("op", slog.String("migration_step", "0007"))
	if !strings.Contains(buf.String(), "0007") {
		t.Errorf("extra allowed key did not reach the handler: %s", buf.String())
	}
}
