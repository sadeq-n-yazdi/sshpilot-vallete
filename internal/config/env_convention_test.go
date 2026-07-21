package config

import (
	"reflect"
	"sort"
	"strings"
	"testing"
)

// deriveEnvNames walks the Config struct (reflection is used in TEST ONLY) and
// derives the expected environment variable name for every non-struct leaf
// field from its yaml path. The rule mirrors env.go: recurse only into structs;
// every other field (string, bool, int, []string, Duration=int64, Ref=string)
// is a leaf whose name is VALLET_ + upper-snake of the joined yaml tag path.
func deriveEnvNames(t *testing.T, typ reflect.Type, prefix []string, out map[string]bool) {
	t.Helper()
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		tag := f.Tag.Get("yaml")
		if tag == "" || tag == "-" {
			t.Fatalf("field %s.%s has no yaml tag", typ.Name(), f.Name)
		}
		name := strings.Split(tag, ",")[0]
		path := append(append([]string{}, prefix...), name)
		if f.Type.Kind() == reflect.Struct {
			deriveEnvNames(t, f.Type, path, out)
			continue
		}
		if f.Type.Kind() == reflect.Map {
			// A map keyed by operator-chosen names (tls.acme.dns.credentials_refs)
			// has no single flat VALLET_* variable, so it is configured through
			// YAML rather than the env layer and is intentionally not a binding.
			continue
		}
		out[envPrefix+strings.ToUpper(strings.Join(path, "_"))] = true
	}
}

func TestEnvBindingConvention(t *testing.T) {
	expected := map[string]bool{}
	deriveEnvNames(t, reflect.TypeOf(Config{}), nil, expected)

	actual := map[string]bool{}
	for _, b := range bindings() {
		if actual[b.name] {
			t.Errorf("duplicate binding for %s", b.name)
		}
		actual[b.name] = true
	}

	for name := range expected {
		if !actual[name] {
			t.Errorf("missing env binding for %s (add it to bindings())", name)
		}
	}
	for name := range actual {
		if !expected[name] {
			t.Errorf("binding %s has no matching struct field (stale entry)", name)
		}
	}

	if t.Failed() {
		var e, a []string
		for n := range expected {
			e = append(e, n)
		}
		for n := range actual {
			a = append(a, n)
		}
		sort.Strings(e)
		sort.Strings(a)
		t.Logf("expected (%d): %s", len(e), strings.Join(e, "\n  "))
		t.Logf("actual   (%d): %s", len(a), strings.Join(a, "\n  "))
	}
}
