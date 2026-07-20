package httpserver

import (
	"net/http"
	"net/netip"
	"strings"
)

// forwardedForHeader carries the chain of client addresses from reverse proxies.
//
// Like X-Forwarded-Proto it is attacker-controlled on any directly-exposed
// listener, and nothing may read it without first establishing, via
// trustedPeers, that the immediate peer is a configured proxy.
const forwardedForHeader = "X-Forwarded-For"

// maxForwardedHops bounds how far back through an X-Forwarded-For list this
// server will walk.
//
// The header is client-supplied and a client may prepend arbitrarily many
// entries, so an unbounded walk is work an unauthenticated caller can ask for
// by the kilobyte. Sixteen is far beyond any real proxy chain; a request whose
// chain is deeper than this resolves to the peer address, which is the safe
// direction — it groups those callers together rather than letting them each
// claim a fresh bucket.
const maxForwardedHops = 16

// clientIP resolves the address a rate-limit bucket should be keyed on.
//
// # This function is the rate limiter's security boundary
//
// A limiter keyed on a value the caller controls is not a limiter. If an
// attacker can put an arbitrary address into the key, every request lands in a
// fresh bucket, the limit is never reached, and the control is completely
// bypassed — while still looking enforced in the route table and still emitting
// plausible metrics. That is the failure mode this function exists to prevent,
// so its rules are stated rather than left to be inferred:
//
//  1. If the immediate peer is NOT a configured trusted proxy, X-Forwarded-For
//     is not read AT ALL. Not read and overridden, not read and preferred
//     against — never read. The key is the socket peer, which the attacker
//     cannot forge without actually holding that address.
//
//  2. If the immediate peer IS trusted, the list is walked RIGHT TO LEFT,
//     skipping entries that are themselves trusted proxies, and the first
//     untrusted address wins. This is the only correct direction: each hop
//     APPENDS, so the rightmost entries were written by infrastructure we
//     trust, while the leftmost were supplied by the client and may be entirely
//     invented. Taking the first (leftmost) element — the obvious reading of
//     "the client IP" and the usual bug — hands the attacker the key directly,
//     because they can simply send "X-Forwarded-For: <anything>" and have their
//     proxy append to it.
//
//  3. Anything inconclusive falls back to the peer address: an unparseable
//     entry, an exhausted hop budget, an empty or absent header, or a chain
//     consisting entirely of trusted proxies. Falling back can only ever
//     over-group callers into one bucket, which costs availability for those
//     callers; the opposite default would hand out unlimited buckets.
//
// It returns the empty string only when the peer address itself will not parse,
// which callers must treat as a refusal rather than as a free pass — an
// unidentifiable caller must not be exempt from the limit.
func clientIP(r *http.Request, proxies trustedPeers) string {
	peer, ok := parsePeerAddr(r.RemoteAddr)
	if !ok {
		return ""
	}

	// Rule 1. The header is not consulted unless the peer earns it. This
	// ordering is the whole control: everything below is unreachable for a
	// directly-connected client.
	if !proxies.trusts(r.RemoteAddr) {
		return peer.String()
	}

	forwarded := r.Header.Values(forwardedForHeader)
	if len(forwarded) == 0 {
		return peer.String()
	}

	// Multiple X-Forwarded-For header lines are semantically one comma-joined
	// list, in order. Joining them means a client cannot hide entries from the
	// walk by splitting the chain across header lines.
	hops := splitForwarded(forwarded)

	// Rule 2. Right to left, skipping trusted infrastructure.
	budget := maxForwardedHops
	for i := len(hops) - 1; i >= 0 && budget > 0; i-- {
		budget--

		addr, ok := parseForwardedHop(hops[i])
		if !ok {
			// Rule 3. A malformed entry ends the walk rather than being
			// skipped. Skipping it would let a client terminate our search
			// wherever it liked by inserting garbage, choosing which entry we
			// land on; stopping here yields the peer, which it cannot choose.
			return peer.String()
		}
		if proxies.trustsAddr(addr) {
			continue // Our own infrastructure; keep walking left.
		}
		return addr.String()
	}

	// Rule 3. The whole chain was trusted proxies, or the budget ran out.
	return peer.String()
}

// splitForwarded flattens one or more X-Forwarded-For header lines into their
// individual entries, preserving order.
func splitForwarded(values []string) []string {
	out := make([]string, 0, len(values))
	for _, v := range values {
		for _, part := range strings.Split(v, ",") {
			part = strings.TrimSpace(part)
			if part != "" {
				out = append(out, part)
			}
		}
	}
	return out
}

// parseForwardedHop parses one X-Forwarded-For entry.
//
// Entries are normally bare addresses, but some proxies append a port, and IPv6
// with a port arrives bracketed. Both forms are accepted; anything else is
// rejected rather than guessed at, because a guess here decides whose bucket a
// request lands in.
func parseForwardedHop(s string) (netip.Addr, bool) {
	if addr, err := netip.ParseAddr(s); err == nil {
		return addr.Unmap(), true
	}
	// Fall back to host:port, which also handles the bracketed IPv6 form.
	return parsePeerAddr(s)
}
