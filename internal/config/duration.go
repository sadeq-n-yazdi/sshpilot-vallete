package config

import (
	"fmt"
	"math"
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
//
// Two bounds are enforced here rather than in Validate, because by the time a
// Duration reaches Validate the damage is already done and is undetectable:
//
//   - Range. The day form multiplies a float64 by 24h worth of nanoseconds.
//     Converting an out-of-range float64 to time.Duration (an int64 of
//     nanoseconds) is undefined in Go and in practice wraps: "999999999999d"
//     yields -2562047h47m16.854775808s. A wrapped value is indistinguishable
//     from a legitimately negative one downstream, so the only correct place to
//     reject it is before the conversion happens.
//   - Sign. No configuration field has a meaningful negative duration; a
//     negative window means "already expired" or "never expires" depending on
//     which consumer reads it, and either reading is a silent security failure.
//     Rejecting at parse time closes that for present and future fields alike.
//     Per-field validators keep their own >0 checks, which additionally decide
//     whether zero (a legitimate "disabled" value for some fields) is allowed.
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
			return daysToDuration(s, n)
		}
	}
	parsed, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("config: invalid duration %q: %w", s, err)
	}
	if parsed < 0 {
		return 0, fmt.Errorf("config: negative duration %q not allowed", s)
	}
	return Duration(parsed), nil
}

// daysToDuration converts a number of days to a Duration, rejecting inputs that
// are not finite or that do not fit in a time.Duration. s is the original text,
// used only for the error message.
func daysToDuration(s string, days float64) (Duration, error) {
	if math.IsNaN(days) || math.IsInf(days, 0) {
		return 0, fmt.Errorf("config: invalid duration %q: not a finite number of days", s)
	}
	if days < 0 {
		return 0, fmt.Errorf("config: negative duration %q not allowed", s)
	}
	nanos := days * float64(24*time.Hour)
	// float64 cannot represent math.MaxInt64 exactly (it rounds up to 2^63), so
	// compare with >= to keep the conversion strictly in range.
	if nanos >= float64(math.MaxInt64) {
		return 0, fmt.Errorf("config: duration %q out of range (maximum is about 106751 days)", s)
	}
	return Duration(time.Duration(nanos)), nil
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
