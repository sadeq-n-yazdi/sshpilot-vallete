package dns01

import (
	"context"
	"errors"
	"slices"
	"sort"
	"testing"
	"time"
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

// fakeAt builds a per-address TXT query whose answers -- and whose failures --
// are fixed by the test. An address absent from the map is unreachable.
func fakeAt(answers map[string][]string) func(ctx context.Context, server, name string) ([]string, error) {
	return func(_ context.Context, server, _ string) ([]string, error) {
		values, ok := answers[server]
		if !ok {
			return nil, errors.New("no route to host")
		}
		return values, nil
	}
}

// TestUnreachableAddressDoesNotBlockAReachableNameserver is the dual-stack case.
//
// A nameserver with both an A and a AAAA record, on a host with no IPv6 route,
// has one address this process can never reach. Treating each ADDRESS as an
// authority that must answer made that permanent: the result was empty on every
// poll, the bounded wait always expired, and no certificate could ever be
// issued on an IPv4-only host -- with nothing misconfigured to find.
func TestUnreachableAddressDoesNotBlockAReachableNameserver(t *testing.T) {
	t.Parallel()

	servers := [][]string{{"192.0.2.1:53", "[2001:db8::1]:53"}}
	got, err := commonTXT(context.Background(), servers, "_acme-challenge.example.com",
		fakeAt(map[string][]string{"192.0.2.1:53": {"token"}}))
	if err != nil {
		t.Fatalf("commonTXT: %v", err)
	}
	if !slices.Equal(got, []string{"token"}) {
		t.Fatalf("commonTXT = %v, want [token]: an unreachable address blocked a nameserver that answered", got)
	}
}

// TestAddressesOfOneNameserverMustAgree keeps the strictness where it is
// observable. Skipping unreachable addresses must not become "one yes is
// enough": two addresses of a nameserver that both answer, differing because
// they are anycast instances converging at different rates, still means the
// zone has not settled.
func TestAddressesOfOneNameserverMustAgree(t *testing.T) {
	t.Parallel()

	servers := [][]string{{"192.0.2.1:53", "192.0.2.2:53"}}
	got, err := commonTXT(context.Background(), servers, "_acme-challenge.example.com",
		fakeAt(map[string][]string{
			"192.0.2.1:53": {"token"},
			"192.0.2.2:53": {"stale"},
		}))
	if err != nil {
		t.Fatalf("commonTXT: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("commonTXT = %v, want empty: two answering addresses disagreed and it reported propagated", got)
	}
}

// TestNameserverWithNoReachableAddressIsNotPropagated holds the fail-closed
// rule at the level it now applies to. An authority observed at no address is
// unobserved, and an unobserved authority is never "assume yes" -- the CA may
// be the one that asks it.
func TestNameserverWithNoReachableAddressIsNotPropagated(t *testing.T) {
	t.Parallel()

	servers := [][]string{{"192.0.2.1:53"}, {"192.0.2.9:53", "[2001:db8::9]:53"}}
	got, err := commonTXT(context.Background(), servers, "_acme-challenge.example.com",
		fakeAt(map[string][]string{"192.0.2.1:53": {"token"}}))
	if err != nil {
		t.Fatalf("commonTXT: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("commonTXT = %v, want empty: a nameserver nothing could reach was counted as serving the value", got)
	}
}

// TestEveryNameserverMustServeTheValue is the property the gate exists for,
// asserted through the grouped shape: one authority still missing the record
// means not propagated, however many others have it.
func TestEveryNameserverMustServeTheValue(t *testing.T) {
	t.Parallel()

	servers := [][]string{{"192.0.2.1:53"}, {"192.0.2.2:53"}}
	got, err := commonTXT(context.Background(), servers, "_acme-challenge.example.com",
		fakeAt(map[string][]string{
			"192.0.2.1:53": {"token"},
			"192.0.2.2:53": {},
		}))
	if err != nil {
		t.Fatalf("commonTXT: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("commonTXT = %v, want empty: a nameserver without the record was counted as propagated", got)
	}
}

// TestAuthoritativeServersFailsFastOnACanceledContext pins that a canceled wait
// reports the cancellation rather than walking the whole domain tree issuing
// lookups that cannot succeed.
//
// The two assertions are independent and both matter. The ERROR assertion is
// the user-visible half: without the check the walk exhausts and reports "no
// authoritative nameserver found", a DNS-shaped error for what is really a
// shutdown or a deadline. The TIMING half is what proves it stopped early
// rather than merely relabeling the failure at the end.
func TestAuthoritativeServersFailsFastOnACanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	// A deep name: with no early exit the walk would issue one lookup per label
	// up to maxZoneLabels before giving up.
	const deep = "_acme-challenge.a.b.c.d.e.f.g.h.example.invalid"

	start := time.Now()
	got, err := authoritativeServers(ctx, deep)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatalf("authoritativeServers succeeded on a canceled context, returning %v", got)
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("error = %v, want it to report context.Canceled rather than a DNS fault", err)
	}
	if got != nil {
		t.Errorf("servers = %v, want nil alongside the error", got)
	}
	// A canceled resolver returns immediately, so a fast-failing walk finishes
	// far inside this bound while a full walk of the labels above would not.
	if elapsed > 2*time.Second {
		t.Errorf("walk took %v; it did not stop at the first canceled lookup", elapsed)
	}
}
