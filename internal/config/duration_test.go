package config

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func TestParseDuration(t *testing.T) {
	tests := []struct {
		in      string
		want    time.Duration
		wantErr bool
	}{
		{"15m", 15 * time.Minute, false},
		{"1h30m", 90 * time.Minute, false},
		{"90s", 90 * time.Second, false},
		{"30d", 30 * 24 * time.Hour, false},
		{"90d", 90 * 24 * time.Hour, false},
		{"365d", 365 * 24 * time.Hour, false},
		{"1.5d", 36 * time.Hour, false},
		{"  10s  ", 10 * time.Second, false},
		{"0s", 0, false},
		{"0d", 0, false},
		{"", 0, true},
		{"d", 0, true},
		{"abc", 0, true},
		{"10x", 0, true},
		// Negative durations are rejected at parse time on both paths: no field
		// has a meaningful negative value, and downstream consumers would read
		// one as either "already expired" or "never expires".
		{"-5s", 0, true},
		{"-1d", 0, true},
		{"-1.5d", 0, true},
		// Day-form values that do not fit in a time.Duration must be rejected
		// rather than wrapped. See TestParseDurationDayOverflowWraps for proof
		// that these inputs wrap to a negative value when unguarded.
		{"999999999999d", 0, true},
		{"1e30d", 0, true},
		{"Infd", 0, true},
		{"-Infd", 0, true},
		{"NaNd", 0, true},
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			got, err := parseDuration(tc.in)
			if (err != nil) != tc.wantErr {
				t.Fatalf("parseDuration(%q) err = %v, wantErr %v", tc.in, err, tc.wantErr)
			}
			if err == nil && got.Std() != tc.want {
				t.Errorf("parseDuration(%q) = %v, want %v", tc.in, got.Std(), tc.want)
			}
		})
	}
}

// TestParseDurationDayOverflowWraps proves the inputs used in the overflow
// cases above are genuinely dangerous: performed unguarded, the multiplication
// this parser does wraps to a NEGATIVE duration rather than a large one. That
// is why the bound lives in parseDuration and cannot be deferred to Validate,
// which would see only an ordinary negative int64.
func TestParseDurationDayOverflowWraps(t *testing.T) {
	for _, in := range []string{"999999999999", "1e30"} {
		days, err := strconv.ParseFloat(in, 64)
		if err != nil {
			t.Fatalf("ParseFloat(%q): %v", in, err)
		}
		unguarded := time.Duration(days * float64(24*time.Hour)) //nolint:gosec // deliberate demonstration of the wrap this guard prevents
		if unguarded >= 0 {
			t.Fatalf("%qd: expected the unguarded conversion to wrap negative, got %v", in, unguarded)
		}
		if _, err := parseDuration(in + "d"); err == nil {
			t.Errorf("parseDuration(%qd) = nil error, want rejection", in)
		}
	}
}

// TestParseDurationDayBoundary pins the accept/reject edge of the day form.
// time.Duration holds math.MaxInt64 nanoseconds, i.e. just under 106752 days.
func TestParseDurationDayBoundary(t *testing.T) {
	const maxWholeDays = 106751 // floor(math.MaxInt64 / 24h)

	got, err := parseDuration(strconv.Itoa(maxWholeDays) + "d")
	if err != nil {
		t.Fatalf("parseDuration(%dd) should be accepted, got %v", maxWholeDays, err)
	}
	if got.Std() <= 0 {
		t.Errorf("parseDuration(%dd) = %v, want a positive duration", maxWholeDays, got.Std())
	}

	if _, err := parseDuration(strconv.Itoa(maxWholeDays+1) + "d"); err == nil {
		t.Errorf("parseDuration(%dd) = nil error, want out-of-range rejection", maxWholeDays+1)
	}
}

// TestParseDurationErrorsNameTheInput checks the parse errors stay diagnosable:
// they quote the offending duration text, which is operator-written config, not
// a secret value.
func TestParseDurationErrorsNameTheInput(t *testing.T) {
	for _, in := range []string{"-5s", "999999999999d", "10x"} {
		_, err := parseDuration(in)
		if err == nil {
			t.Fatalf("parseDuration(%q) = nil error", in)
		}
		if !strings.Contains(err.Error(), in) {
			t.Errorf("parseDuration(%q) error %q does not quote the input", in, err)
		}
	}
}

func TestDurationYAMLRoundTrip(t *testing.T) {
	type wrap struct {
		D Duration `yaml:"d"`
	}
	var w wrap
	if err := yaml.Unmarshal([]byte("d: 30d\n"), &w); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if w.D.Std() != 30*24*time.Hour {
		t.Fatalf("got %v", w.D.Std())
	}
	out, err := yaml.Marshal(w)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// Day form re-serializes as hours and must re-parse to the same value.
	var back wrap
	if err := yaml.Unmarshal(out, &back); err != nil {
		t.Fatalf("re-unmarshal %q: %v", out, err)
	}
	if back.D != w.D {
		t.Errorf("round trip changed value: %v -> %v", w.D, back.D)
	}
}

// TestDurationUnmarshalYAMLNonString covers the node-type guard: a duration
// written as a yaml sequence or mapping must be a decode error, not a zero
// value silently accepted.
func TestDurationUnmarshalYAMLNonString(t *testing.T) {
	type wrap struct {
		D Duration `yaml:"d"`
	}
	for _, doc := range []string{"d: [1, 2]\n", "d: {a: b}\n"} {
		var w wrap
		if err := yaml.Unmarshal([]byte(doc), &w); err == nil {
			t.Errorf("yaml.Unmarshal(%q) = nil error, want a type error", doc)
		}
	}
}

func TestDurationUnmarshalText(t *testing.T) {
	var d Duration
	if err := d.UnmarshalText([]byte("90d")); err != nil {
		t.Fatalf("UnmarshalText: %v", err)
	}
	if d.Std() != 90*24*time.Hour {
		t.Errorf("got %v", d.Std())
	}
	if err := d.UnmarshalText([]byte("nope")); err == nil {
		t.Error("expected error")
	}
}

func TestDurationString(t *testing.T) {
	if got := Duration(90 * time.Minute).String(); got != "1h30m0s" {
		t.Errorf("String() = %q", got)
	}
}
