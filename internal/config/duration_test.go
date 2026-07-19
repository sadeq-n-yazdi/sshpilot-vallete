package config

import (
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
		{"", 0, true},
		{"d", 0, true},
		{"abc", 0, true},
		{"10x", 0, true},
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
	// Day form re-serialises as hours and must re-parse to the same value.
	var back wrap
	if err := yaml.Unmarshal(out, &back); err != nil {
		t.Fatalf("re-unmarshal %q: %v", out, err)
	}
	if back.D != w.D {
		t.Errorf("round trip changed value: %v -> %v", w.D, back.D)
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
