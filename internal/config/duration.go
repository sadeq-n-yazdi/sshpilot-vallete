package config

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Duration is a time.Duration that marshals to and from a human-readable string
// understood by time.ParseDuration, extended with a "d" (day = 24h) suffix so
// that operationally meaningful values such as "30d", "90d", and "365d" can be
// written directly. It implements yaml.Unmarshaler, yaml.Marshaler, and
// encoding.TextUnmarshaler so it works from both config files and environment
// variables.
type Duration time.Duration

// Std returns the value as a standard time.Duration.
func (d Duration) Std() time.Duration { return time.Duration(d) }

// String renders the duration using time.Duration's own formatting.
func (d Duration) String() string { return time.Duration(d).String() }

// parseDuration accepts any input time.ParseDuration accepts, plus a bare "Nd"
// day form (integer or decimal number of days), e.g. "30d" or "1.5d".
func parseDuration(s string) (Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("config: empty duration")
	}
	if rest, ok := strings.CutSuffix(s, "d"); ok {
		// Only treat a trailing "d" as days when the remainder is a plain
		// number; otherwise fall through to ParseDuration (which has no "d"
		// unit and will report a clear error).
		if n, err := strconv.ParseFloat(rest, 64); err == nil {
			return Duration(time.Duration(n * float64(24*time.Hour))), nil
		}
	}
	parsed, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("config: invalid duration %q: %w", s, err)
	}
	return Duration(parsed), nil
}

// UnmarshalYAML implements yaml.Unmarshaler.
func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	var s string
	if err := value.Decode(&s); err != nil {
		return fmt.Errorf("config: duration must be a string: %w", err)
	}
	parsed, err := parseDuration(s)
	if err != nil {
		return err
	}
	*d = parsed
	return nil
}

// UnmarshalText implements encoding.TextUnmarshaler (used by env binding).
func (d *Duration) UnmarshalText(text []byte) error {
	parsed, err := parseDuration(string(text))
	if err != nil {
		return err
	}
	*d = parsed
	return nil
}

// MarshalYAML implements yaml.Marshaler, emitting a re-parseable Go duration
// string (day forms round-trip as hours, e.g. "30d" -> "720h0m0s").
func (d Duration) MarshalYAML() (any, error) {
	return time.Duration(d).String(), nil
}
