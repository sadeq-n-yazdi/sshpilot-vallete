package httpserver

import "testing"

// TestTrustedPeers covers the predicate that gates every forwarded-header
// decision. Its failure modes are all "denies when it should have allowed"
// (a functional bug) or "allows when it should have denied" (a trust bypass);
// the second kind is what the table below is weighted towards.
func TestTrustedPeers(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		entries []string
		addr    string
		want    bool
	}{
		{
			name:    "exact IPv4 match",
			entries: []string{"10.0.0.5"},
			addr:    "10.0.0.5:9000",
			want:    true,
		},
		{
			name:    "different IPv4 is untrusted",
			entries: []string{"10.0.0.5"},
			addr:    "10.0.0.6:9000",
			want:    false,
		},
		{
			name:    "inside CIDR",
			entries: []string{"192.168.1.0/24"},
			addr:    "192.168.1.254:1",
			want:    true,
		},
		{
			name:    "outside CIDR",
			entries: []string{"192.168.1.0/24"},
			addr:    "192.168.2.1:1",
			want:    false,
		},
		{
			// A CIDR written with host bits set must still match its block
			// rather than silently matching nothing.
			name:    "CIDR with host bits set is masked",
			entries: []string{"192.168.1.77/24"},
			addr:    "192.168.1.9:1",
			want:    true,
		},
		{
			name:    "IPv6 exact match",
			entries: []string{"2001:db8::1"},
			addr:    "[2001:db8::1]:9000",
			want:    true,
		},
		{
			name:    "IPv6 CIDR",
			entries: []string{"2001:db8::/32"},
			addr:    "[2001:db8:1234::99]:9000",
			want:    true,
		},
		{
			// A dual-stack listener may report an IPv4 peer in mapped form; it
			// must still match the IPv4 entry the operator configured.
			name:    "IPv4-mapped IPv6 peer matches its IPv4 entry",
			entries: []string{"10.0.0.5"},
			addr:    "[::ffff:10.0.0.5]:9000",
			want:    true,
		},
		{
			name:    "IPv4-mapped peer matches an IPv4 CIDR entry",
			entries: []string{"10.0.0.0/8"},
			addr:    "[::ffff:10.1.2.3]:9000",
			want:    true,
		},
		{
			name:    "empty trust list trusts nothing",
			entries: nil,
			addr:    "10.0.0.5:9000",
			want:    false,
		},
		{
			// Fail closed on anything unparseable: an inconclusive answer must
			// deny, or a malformed RemoteAddr becomes a trust bypass.
			name:    "unparseable RemoteAddr is untrusted",
			entries: []string{"10.0.0.5"},
			addr:    "garbage",
			want:    false,
		},
		{
			name:    "empty RemoteAddr is untrusted",
			entries: []string{"10.0.0.5"},
			addr:    "",
			want:    false,
		},
		{
			name:    "hostname RemoteAddr is untrusted",
			entries: []string{"10.0.0.5"},
			addr:    "proxy.internal:9000",
			want:    false,
		},
		{
			// A bare address with no port still resolves, since a custom
			// listener may produce one.
			name:    "bare address without a port matches",
			entries: []string{"10.0.0.5"},
			addr:    "10.0.0.5",
			want:    true,
		},
		{
			// Unparseable ENTRIES must match nothing rather than everything.
			// Config validation rejects these first; this is the second line.
			name:    "malformed entries match nothing",
			entries: []string{"not-an-ip", "", "999.999.999.999", "10.0.0.0/99"},
			addr:    "10.0.0.5:9000",
			want:    false,
		},
		{
			name:    "a malformed entry does not disturb a valid one",
			entries: []string{"not-an-ip", "10.0.0.5"},
			addr:    "10.0.0.5:9000",
			want:    true,
		},
		{
			name:    "matches the second of several entries",
			entries: []string{"10.0.0.5", "172.16.0.0/12"},
			addr:    "172.16.5.5:9000",
			want:    true,
		},
		{
			// A zero-length prefix would trust the entire internet. The operator
			// can still write it explicitly, but nothing may produce it by
			// accident; this pins the behavior so a regression is visible.
			name:    "explicit 0.0.0.0/0 trusts everything as written",
			entries: []string{"0.0.0.0/0"},
			addr:    "203.0.113.9:1",
			want:    true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got := newTrustedPeers(tc.entries).trusts(tc.addr); got != tc.want {
				t.Errorf("trusts(%q) with %v = %v, want %v", tc.addr, tc.entries, got, tc.want)
			}
		})
	}
}

// TestTrustedPeersZeroValue pins the default: a trustedPeers nobody configured
// trusts no one. A zero value that trusted anything would make every
// forwarded-header consumer insecure by default.
func TestTrustedPeersZeroValue(t *testing.T) {
	t.Parallel()

	var zero trustedPeers
	if !zero.empty() {
		t.Error("zero value should report empty")
	}
	for _, addr := range []string{"10.0.0.5:9000", "127.0.0.1:1", "[::1]:1", ""} {
		if zero.trusts(addr) {
			t.Errorf("zero value trusts %q", addr)
		}
	}
}

// TestTrustedPeersEmpty checks the fast-path predicate agrees with trusts.
func TestTrustedPeersEmpty(t *testing.T) {
	t.Parallel()

	if !newTrustedPeers(nil).empty() {
		t.Error("nil entries should be empty")
	}
	if !newTrustedPeers([]string{"bogus"}).empty() {
		t.Error("entries that all fail to parse should leave the set empty")
	}
	if newTrustedPeers([]string{"10.0.0.5"}).empty() {
		t.Error("a valid entry should not be empty")
	}
}
