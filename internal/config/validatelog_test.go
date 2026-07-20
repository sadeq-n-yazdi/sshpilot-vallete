package config

import (
	"strings"
	"testing"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/logging"
)

// TestValidateRejectsBadLogLevel pins that an unusable log level is a startup
// failure.
//
// This is a regression pin as much as a feature test. validateTelemetry
// previously checked only the OTLP endpoints, while cmd/valletd's level parser
// carried a comment asserting that "config validation already rejects bad
// levels" and defaulted to info when it did not. The two halves each assumed
// the other was enforcing it, so every misspelled level ran at a volume the
// operator had not asked for, silently.
func TestValidateRejectsBadLogLevel(t *testing.T) {
	t.Parallel()

	for _, level := range []string{"warning", "trace", "verbose", "", "INFO2"} {
		c := validConfig()
		c.Telemetry.Log.Level = level

		err := c.Validate()
		if err == nil {
			t.Errorf("log level %q accepted; an unusable level must fail closed", level)
			continue
		}
		if !strings.Contains(err.Error(), "telemetry.log.level") {
			t.Errorf("log level %q: error must name the field, got: %v", level, err)
		}
		if !strings.Contains(err.Error(), "debug, error, info, warn") {
			t.Errorf("log level %q: error must list the accepted levels, got: %v", level, err)
		}
	}
}

func TestValidateRejectsBadLogFormat(t *testing.T) {
	t.Parallel()

	for _, format := range []string{"logfmt", "console", "", "yaml"} {
		c := validConfig()
		c.Telemetry.Log.Format = format

		err := c.Validate()
		if err == nil {
			t.Errorf("log format %q accepted; must fail closed", format)
			continue
		}
		if !strings.Contains(err.Error(), "telemetry.log.format") {
			t.Errorf("log format %q: error must name the field, got: %v", format, err)
		}
	}
}

func TestValidateAcceptsEveryDocumentedLogLevelAndFormat(t *testing.T) {
	t.Parallel()

	for _, level := range []string{"debug", "info", "warn", "error"} {
		for _, format := range []string{"json", "text"} {
			c := validConfig()
			c.Telemetry.Log.Level = level
			c.Telemetry.Log.Format = format
			if err := c.Validate(); err != nil {
				t.Errorf("level %q format %q should be valid, got: %v", level, format, err)
			}
		}
	}
}

// TestDefaultLogConfigIsValid pins that the shipped defaults survive their own
// validator, so an operator who configures no telemetry at all still starts.
func TestDefaultLogConfigIsValid(t *testing.T) {
	t.Parallel()

	d := Default()
	if _, err := logging.ParseLevel(d.Telemetry.Log.Level); err != nil {
		t.Errorf("default log level %q is not parseable: %v", d.Telemetry.Log.Level, err)
	}
	if d.Telemetry.Log.Format != "json" {
		t.Errorf("default log format = %q, want json (ADR-0025)", d.Telemetry.Log.Format)
	}
}
