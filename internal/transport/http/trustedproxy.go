package httpserver

import (
	"net"
	"net/netip"
)

// trustedPeers answers one question: did this request arrive directly from a
// peer the operator has designated a trusted reverse proxy?
//
// It exists as its own type rather than as a closure inside the middleware that
// currently needs it, because it is the gate on every forwarded-header decision
// this server will ever make. HSTS is the first caller; rate-limit IP keying
// (which must resolve a client address from X-Forwarded-For) is the next, and
// getting "is this peer trusted" wrong there is a rate-limit bypass. One
// implementation, one set of tests, one place to audit.
//
// The rule it enforces: a forwarded header is evidence ONLY when the immediate
// peer is trusted. X-Forwarded-Proto, X-Forwarded-For and friends are ordinary
// request headers that any client can set, so on a directly-exposed listener
// they carry exactly as much authority as the request body. Callers must
// consult this type BEFORE reading such a header, and must not read it at all
// when the answer is false — "read it but prefer the real value" still lets an
// attacker steer behavior wherever the real value is absent.
//
// The zero value trusts nothing, which is the correct default: a server with no
// configured proxies is directly exposed.
type trustedPeers struct {
	prefixes []netip.Prefix
}

// newTrustedPeers compiles operator-configured proxy entries into prefixes.
//
// Entries are bare IPs or CIDR blocks, matching what config validation accepts
// (see validateTrustedProxies). A bare IP becomes a single-host prefix, so both
// forms share one match path.
//
// Unparseable entries are DROPPED rather than treated as wildcards. Config
// validation rejects them before startup, so reaching this with a bad entry
// means validation was bypassed — and the safe reading of an entry we cannot
// understand is "matches nothing", never "matches everything".
func newTrustedPeers(entries []string) trustedPeers {
	prefixes := make([]netip.Prefix, 0, len(entries))
	for _, entry := range entries {
		if p, err := netip.ParsePrefix(entry); err == nil {
			prefixes = append(prefixes, p.Masked())
			continue
		}
		if addr, err := netip.ParseAddr(entry); err == nil {
			// Unmap so a ::ffff:10.0.0.1 entry and a 10.0.0.1 entry compare
			// equal to the same peer.
			addr = addr.Unmap()
			prefixes = append(prefixes, netip.PrefixFrom(addr, addr.BitLen()))
		}
	}
	return trustedPeers{prefixes: prefixes}
}

// empty reports whether no proxy is trusted.
func (t trustedPeers) empty() bool { return len(t.prefixes) == 0 }

// trusts reports whether remoteAddr — an http.Request.RemoteAddr, in host:port
// form — is a configured trusted proxy.
//
// Every failure mode returns false. An address that will not split, a host that
// will not parse as an IP, and an empty trust list are all untrusted: this
// predicate guards forwarded-header handling, so an inconclusive answer must
// deny. Returning true on a parse failure would turn a malformed RemoteAddr
// into a trust bypass.
func (t trustedPeers) trusts(remoteAddr string) bool {
	if len(t.prefixes) == 0 {
		return false
	}

	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		// Not host:port. Accept a bare address too, since a custom listener may
		// produce one, but nothing else.
		host = remoteAddr
	}

	addr, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	// An IPv4 peer may be reported as ::ffff:a.b.c.d on a dual-stack listener;
	// unmapping makes it match an IPv4 prefix the operator configured.
	addr = addr.Unmap()

	for _, p := range t.prefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}
