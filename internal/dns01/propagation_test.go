package dns01

import (
	"slices"
	"sort"
	"testing"
)

// TestChallengeRecordName pins the record name, including the wildcard case.
//
// RFC 8555 §8.4 puts the challenge for "*.example.com" at the same name as the
// challenge for "example.com". Leaving the asterisk in would publish a record
// at a name no CA ever queries, so the propagation wait would time out on a
// record nothing was looking for — a wildcard deployment that never issues.
func TestChallengeRecordName(t *testing.T) {
	t.Parallel()

	for identifier, want := range map[string]string{
		"vallet.example.com":  "_acme-challenge.vallet.example.com",
		"*.example.com":       "_acme-challenge.example.com",
		"example.com":         "_acme-challenge.example.com",
		"*.deep.example.com":  "_acme-challenge.deep.example.com",
		"a.b.c.d.example.com": "_acme-challenge.a.b.c.d.example.com",
	} {
		if got := ChallengeRecordName(identifier); got != want {
			t.Errorf("ChallengeRecordName(%q) = %q, want %q", identifier, got, want)
		}
	}
}

// TestIntersectRequiresEveryNameserver pins the propagation rule that makes the
// gate meaningful: a value counts only when EVERY authoritative nameserver
// serves it.
//
// A union would let one fast nameserver satisfy the gate while the CA queries a
// slower sibling that does not have the record, which produces an invalid
// authorization — and on Let's Encrypt a run of invalid authorizations is
// itself rate limited.
func TestIntersectRequiresEveryNameserver(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		answers [][]string
		want    []string
	}{
		{"all agree", [][]string{{"v"}, {"v"}, {"v"}}, []string{"v"}},
		{"one lagging server excludes the value", [][]string{{"v"}, {"v"}, {}}, nil},
		{"a stale value on one server is excluded", [][]string{{"v", "old"}, {"v"}}, []string{"v"}},
		{"disjoint answers leave nothing", [][]string{{"a"}, {"b"}}, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var current map[string]bool
			for _, answer := range tt.answers {
				current = intersect(current, answer)
			}

			got := make([]string, 0, len(current))
			for v := range current {
				got = append(got, v)
			}
			sort.Strings(got)
			if !slices.Equal(got, tt.want) {
				t.Errorf("intersected values = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestAuthoritativeLookupFailsClosedOnAnUnresolvableZone proves the lookup
// reports an error rather than an empty success for a name with no
// authoritative nameserver.
//
// The distinction matters: the solver treats a lookup ERROR as "not yet" and
// keeps polling to its bounded deadline, then fails. What it must never see is
// a successful lookup that happens to contain nothing, which would be
// indistinguishable from a record that is present but empty.
func TestAuthoritativeLookupFailsClosedOnAnUnresolvableZone(t *testing.T) {
	t.Parallel()

	// ".invalid" is reserved by RFC 2606 and is guaranteed never to resolve, so
	// this reaches no network service that could answer.
	_, err := NewAuthoritativeTXTLookup()(t.Context(), "_acme-challenge.vallet.invalid")
	if err == nil {
		t.Error("lookup of a name with no authoritative nameserver returned no error; " +
			"an empty success would be read as a propagated-but-empty record")
	}
}
