package config

import (
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

// leaf is one non-struct field of Config, keyed by the environment variable
// name derived from its yaml path.
type leaf struct {
	typ reflect.Type
	val string // current value, formatted for comparison
}

// collectLeaves walks a Config value and records every non-struct leaf field by
// its derived environment variable name. Reflection is TEST ONLY; it mirrors
// the naming rule in env.go, the same way env_convention_test.go does.
func collectLeaves(v reflect.Value, prefix []string, out map[string]leaf) {
	typ := v.Type()
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		name := strings.Split(f.Tag.Get("yaml"), ",")[0]
		path := append(append([]string{}, prefix...), name)
		if f.Type.Kind() == reflect.Struct {
			collectLeaves(v.Field(i), path, out)
			continue
		}
		env := envPrefix + strings.ToUpper(strings.Join(path, "_"))
		out[env] = leaf{typ: f.Type, val: fmt.Sprintf("%v", v.Field(i).Interface())}
	}
}

// probeValue returns a raw environment value for a field that is guaranteed to
// differ from cur, so that applying it produces an observable change.
func probeValue(t *testing.T, typ reflect.Type, cur string) string {
	t.Helper()
	switch {
	case typ == reflect.TypeOf(Duration(0)):
		return "7h"
	case typ.Kind() == reflect.Bool:
		b, err := strconv.ParseBool(cur)
		if err != nil {
			t.Fatalf("bool field has non-bool default %q", cur)
		}
		return strconv.FormatBool(!b)
	case typ.Kind() == reflect.Int:
		return "37"
	case typ.Kind() == reflect.Float64:
		// A ratio field: differs from every default and stays in [0,1], so the
		// probed config remains one Validate would accept.
		return "0.25"
	case typ.Kind() == reflect.Slice:
		return "alpha,beta"
	default: // string and secrets.Ref
		return "env:PROBE"
	}
}

// TestEnvBindingsWriteTheirOwnField applies each binding in isolation and
// asserts it changes exactly the field its name refers to. The convention test
// next door proves the table's NAMES match the struct; it cannot catch a
// selector closure that names one field and writes another, which is a
// copy-paste away in a table of this shape and would silently route an
// operator's value (including a secret reference) into the wrong setting.
func TestEnvBindingsWriteTheirOwnField(t *testing.T) {
	base := Default()
	baseLeaves := map[string]leaf{}
	collectLeaves(reflect.ValueOf(base), nil, baseLeaves)

	for _, b := range bindings() {
		t.Run(b.name, func(t *testing.T) {
			want, ok := baseLeaves[b.name]
			if !ok {
				t.Fatalf("binding %s has no matching struct leaf", b.name)
			}
			raw := probeValue(t, want.typ, want.val)

			cfg := Default()
			err := applyEnv(&cfg, func(name string) (string, bool) {
				if name == b.name {
					return raw, true
				}
				return "", false
			})
			if err != nil {
				t.Fatalf("applyEnv(%s=%q): %v", b.name, raw, err)
			}

			got := map[string]leaf{}
			collectLeaves(reflect.ValueOf(cfg), nil, got)

			var changed []string
			for name, after := range got {
				if after.val != baseLeaves[name].val {
					changed = append(changed, name)
				}
			}
			if len(changed) != 1 || changed[0] != b.name {
				t.Fatalf("setting %s=%q changed %v, want exactly [%s]", b.name, raw, changed, b.name)
			}
		})
	}
}

// TestApplyEnvParseFailures checks that a malformed value is reported against
// its own variable and that every problem in one pass is reported, rather than
// the first aborting the rest.
func TestApplyEnvParseFailures(t *testing.T) {
	tests := []struct {
		name string
		env  map[string]string
		want []string
	}{
		{
			"bad bool",
			map[string]string{"VALLET_RATE_LIMIT_ENABLED": "yes-please"},
			[]string{"VALLET_RATE_LIMIT_ENABLED"},
		},
		{
			"bad int",
			map[string]string{"VALLET_RETENTION_MAX_SETS_PER_OWNER": "many"},
			[]string{"VALLET_RETENTION_MAX_SETS_PER_OWNER"},
		},
		{
			"bad duration",
			map[string]string{"VALLET_AUTH_ACCESS_TOKEN_TTL": "10x"},
			[]string{"VALLET_AUTH_ACCESS_TOKEN_TTL"},
		},
		{
			"negative duration",
			map[string]string{"VALLET_RETENTION_AUDIT_RETENTION": "-30d"},
			[]string{"VALLET_RETENTION_AUDIT_RETENTION"},
		},
		{
			"overflowing day duration",
			map[string]string{"VALLET_RETENTION_AUDIT_RETENTION": "999999999999d"},
			[]string{"VALLET_RETENTION_AUDIT_RETENTION"},
		},
		{
			"all problems reported together",
			map[string]string{
				"VALLET_RATE_LIMIT_ENABLED":           "maybe",
				"VALLET_RETENTION_MAX_SETS_PER_OWNER": "lots",
				"VALLET_AUTH_ACCESS_TOKEN_TTL":        "soon",
			},
			[]string{
				"VALLET_RATE_LIMIT_ENABLED",
				"VALLET_RETENTION_MAX_SETS_PER_OWNER",
				"VALLET_AUTH_ACCESS_TOKEN_TTL",
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Default()
			err := applyEnv(&cfg, func(name string) (string, bool) {
				v, ok := tc.env[name]
				return v, ok
			})
			if err == nil {
				t.Fatalf("expected an error for %v", tc.env)
			}
			for _, want := range tc.want {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q does not name %s", err, want)
				}
			}
		})
	}
}

// TestApplyEnvValueConversions pins the parsing behavior of the typed setters
// that is not obvious from the table: list splitting and the day duration form.
func TestApplyEnvValueConversions(t *testing.T) {
	cfg := Default()
	env := map[string]string{
		"VALLET_SERVER_TRUSTED_PROXIES":    " 10.0.0.1 , , 192.168.0.0/16 ",
		"VALLET_TLS_SANS":                  "",
		"VALLET_RETENTION_AUDIT_RETENTION": "365d",
		"VALLET_AUTH_ACCESS_TOKEN_TTL":     "30m",
	}
	if err := applyEnv(&cfg, func(name string) (string, bool) {
		v, ok := env[name]
		return v, ok
	}); err != nil {
		t.Fatalf("applyEnv: %v", err)
	}

	wantProxies := []string{"10.0.0.1", "192.168.0.0/16"}
	if !reflect.DeepEqual(cfg.Server.TrustedProxies, wantProxies) {
		t.Errorf("TrustedProxies = %v, want %v", cfg.Server.TrustedProxies, wantProxies)
	}
	// An all-empty list yields an empty, non-nil slice: the operator explicitly
	// cleared the value rather than leaving the default in place.
	if cfg.TLS.SANs == nil || len(cfg.TLS.SANs) != 0 {
		t.Errorf("SANs = %#v, want an empty non-nil slice", cfg.TLS.SANs)
	}
	if got, want := cfg.Retention.AuditRetention.Std(), 365*24*time.Hour; got != want {
		t.Errorf("AuditRetention = %v, want %v", got, want)
	}
	if got, want := cfg.Auth.AccessTokenTTL.Std(), 30*time.Minute; got != want {
		t.Errorf("AccessTokenTTL = %v, want %v", got, want)
	}
}

// TestApplyEnvUnsetLeavesDefaults confirms an empty environment is a no-op:
// precedence is env > file > defaults, and an unset variable must not overwrite
// a value that the file or the defaults already established.
func TestApplyEnvUnsetLeavesDefaults(t *testing.T) {
	cfg := Default()
	if err := applyEnv(&cfg, func(string) (string, bool) { return "", false }); err != nil {
		t.Fatalf("applyEnv: %v", err)
	}
	if !reflect.DeepEqual(cfg, Default()) {
		t.Error("applying an empty environment changed the config")
	}
}
