package httpserver

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// newIPRequest builds a request with a given peer and X-Forwarded-For lines.
func newIPRequest(remoteAddr string, xff ...string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/alice", nil)
	r.RemoteAddr = remoteAddr
	for _, v := range xff {
		r.Header.Add(forwardedForHeader, v)
	}
	return r
}

// TestClientIPSpoofing is THE test for this file. An attacker who can steer the
// rate-limit key gets an unbounded number of buckets, which is not a weakened
// limit but a complete bypass.
//
// The two halves are the same request differing only in who sent it: from an
// untrusted peer the forwarded header must change nothing, and from a
// configured proxy it must be honored. A single-sided test would pass against
// an implementation that trusted the header unconditionally.
func TestClientIPSpoofing(t *testing.T) {
	t.Parallel()

	const spoofed = "9.9.9.9"
	proxies := newTrustedPeers([]string{"10.0.0.1"})

	t.Run("untrusted peer cannot steer the key", func(t *testing.T) {
		t.Parallel()

		// Same attacker, three different forged headers. All must key the same.
		bare := clientIP(newIPRequest("203.0.113.5:1234"), proxies)
		forged := clientIP(newIPRequest("203.0.113.5:1234", spoofed), proxies)
		chained := clientIP(newIPRequest("203.0.113.5:1234", "1.1.1.1, 2.2.2.2, "+spoofed), proxies)

		if bare != "203.0.113.5" {
			t.Fatalf("peer key = %q, want the socket peer 203.0.113.5", bare)
		}
		if forged != bare || chained != bare {
			t.Fatalf("X-Forwarded-For from an UNTRUSTED peer changed the key: "+
				"bare=%q forged=%q chained=%q; this is a complete rate-limit bypass",
				bare, forged, chained)
		}
	})

	t.Run("trusted proxy is honored", func(t *testing.T) {
		t.Parallel()

		got := clientIP(newIPRequest("10.0.0.1:9999", spoofed), proxies)
		if got != spoofed {
			t.Fatalf("clientIP behind a trusted proxy = %q, want %q; "+
				"a legitimate deployment would key every client onto the proxy", got, spoofed)
		}
	})

	t.Run("no configured proxies trusts nothing", func(t *testing.T) {
		t.Parallel()

		// The zero value trusts nothing, so even a request that CLAIMS to come
		// from the proxy address cannot use the header.
		none := newTrustedPeers(nil)
		got := clientIP(newIPRequest("10.0.0.1:9999", spoofed), none)
		if got != "10.0.0.1" {
			t.Fatalf("clientIP with no trusted proxies = %q, want the peer 10.0.0.1", got)
		}
	})
}

// TestClientIPWalksRightToLeft pins the direction of the walk. Taking the
// leftmost entry is the usual bug and it hands the key straight to the client,
// because a client's own prepended value ends up leftmost after the proxy
// appends the real address.
func TestClientIPWalksRightToLeft(t *testing.T) {
	t.Parallel()

	proxies := newTrustedPeers([]string{"10.0.0.0/8"})

	tests := []struct {
		name string
		peer string
		xff  []string
		want string
	}{
		{
			// The client sent "X-Forwarded-For: 9.9.9.9"; the edge proxy
			// appended the real address. The real one is rightmost.
			name: "client-prepended value is ignored",
			peer: "10.0.0.1:1",
			xff:  []string{"9.9.9.9, 203.0.113.5"},
			want: "203.0.113.5",
		},
		{
			name: "internal hops are skipped",
			peer: "10.0.0.1:1",
			xff:  []string{"203.0.113.5, 10.1.2.3, 10.4.5.6"},
			want: "203.0.113.5",
		},
		{
			name: "separate header lines are one ordered list",
			peer: "10.0.0.1:1",
			xff:  []string{"9.9.9.9", "203.0.113.5, 10.1.2.3"},
			want: "203.0.113.5",
		},
		{
			name: "entry with a port",
			peer: "10.0.0.1:1",
			xff:  []string{"203.0.113.5:4444"},
			want: "203.0.113.5",
		},
		{
			name: "bracketed ipv6 with a port",
			peer: "10.0.0.1:1",
			xff:  []string{"[2001:db8::1]:4444"},
			want: "2001:db8::1",
		},
		{
			name: "ipv4-mapped ipv6 entry normalizes to ipv4",
			peer: "10.0.0.1:1",
			xff:  []string{"::ffff:203.0.113.5"},
			want: "203.0.113.5",
		},
		{
			name: "whole chain trusted falls back to the peer",
			peer: "10.0.0.1:1",
			xff:  []string{"10.1.1.1, 10.2.2.2"},
			want: "10.0.0.1",
		},
		{
			name: "empty header falls back to the peer",
			peer: "10.0.0.1:1",
			xff:  []string{""},
			want: "10.0.0.1",
		},
		{
			name: "absent header falls back to the peer",
			peer: "10.0.0.1:1",
			xff:  nil,
			want: "10.0.0.1",
		},
		{
			// A malformed entry ENDS the walk. Skipping it would let a client
			// choose where our search stops, and therefore which entry we key
			// on; stopping yields the peer, which it cannot choose.
			name: "malformed entry ends the walk at the peer",
			peer: "10.0.0.1:1",
			xff:  []string{"203.0.113.5, not-an-ip"},
			want: "10.0.0.1",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := clientIP(newIPRequest(tc.peer, tc.xff...), proxies); got != tc.want {
				t.Fatalf("clientIP = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestClientIPHopBudget: the header is client-supplied, so an unbounded walk is
// work an unauthenticated caller can request by the kilobyte. Exceeding the
// budget must resolve to the peer, which groups those callers rather than
// giving each a fresh bucket.
func TestClientIPHopBudget(t *testing.T) {
	t.Parallel()

	proxies := newTrustedPeers([]string{"10.0.0.1"})

	// A chain of trusted hops longer than the budget, with the real client
	// unreachably far to the left.
	hops := make([]string, 0, maxForwardedHops+2)
	hops = append(hops, "203.0.113.5")
	for range maxForwardedHops + 1 {
		hops = append(hops, "10.0.0.1")
	}
	got := clientIP(newIPRequest("10.0.0.1:1", strings.Join(hops, ", ")), proxies)
	if got != "10.0.0.1" {
		t.Fatalf("clientIP over the hop budget = %q, want the peer 10.0.0.1", got)
	}

	// Exactly at the budget the real client is still reachable, proving the
	// bound is the stated one and not accidentally tighter.
	atBudget := []string{"203.0.113.5"}
	for range maxForwardedHops - 1 {
		atBudget = append(atBudget, "10.0.0.1")
	}
	got = clientIP(newIPRequest("10.0.0.1:1", strings.Join(atBudget, ", ")), proxies)
	if got != "203.0.113.5" {
		t.Fatalf("clientIP at the hop budget = %q, want 203.0.113.5", got)
	}
}

// TestClientIPUnparseablePeer: an unidentifiable caller yields the empty
// string, which callers must treat as a refusal. Returning something usable
// here would exempt exactly the callers we understand least.
func TestClientIPUnparseablePeer(t *testing.T) {
	t.Parallel()

	proxies := newTrustedPeers([]string{"10.0.0.1"})
	for _, peer := range []string{"", "garbage", "not-an-ip:80", "@"} {
		if got := clientIP(newIPRequest(peer, "9.9.9.9"), proxies); got != "" {
			t.Fatalf("clientIP(peer=%q) = %q, want \"\" so the caller refuses", peer, got)
		}
	}
}

// TestClientIPBarePeerAddress covers a custom listener that reports RemoteAddr
// without a port.
func TestClientIPBarePeerAddress(t *testing.T) {
	t.Parallel()

	proxies := newTrustedPeers([]string{"10.0.0.1"})
	if got := clientIP(newIPRequest("203.0.113.5"), proxies); got != "203.0.113.5" {
		t.Fatalf("clientIP = %q, want 203.0.113.5", got)
	}
	// And the same peer in mapped form normalizes to one key, so a dual-stack
	// listener does not give the same client two buckets.
	if got := clientIP(newIPRequest("::ffff:203.0.113.5"), proxies); got != "203.0.113.5" {
		t.Fatalf("clientIP(mapped) = %q, want 203.0.113.5", got)
	}
}

// TestTrustsAddrMatchesTrusts guards the refactor that split trustsAddr out of
// trusts: the two must agree, or the XFF walk would apply a different trust
// rule than the peer check.
func TestTrustsAddrMatchesTrusts(t *testing.T) {
	t.Parallel()

	proxies := newTrustedPeers([]string{"10.0.0.0/8", "2001:db8::/32"})
	for _, ip := range []string{"10.1.2.3", "203.0.113.5", "2001:db8::1", "2001:db9::1", "::ffff:10.1.2.3"} {
		addr, ok := parsePeerAddr(ip)
		if !ok {
			t.Fatalf("parsePeerAddr(%q) failed", ip)
		}
		if got, want := proxies.trustsAddr(addr), proxies.trusts(ip); got != want {
			t.Fatalf("trustsAddr(%q) = %v, trusts(%q) = %v; they must agree", ip, got, ip, want)
		}
	}

	// An empty trust list trusts nothing, including a well-formed address.
	none := newTrustedPeers(nil)
	addr, _ := parsePeerAddr("10.1.2.3")
	if none.trustsAddr(addr) {
		t.Fatal("trustsAddr with no configured proxies = true")
	}
}
