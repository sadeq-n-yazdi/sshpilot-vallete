package dns01

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

// nsDialTimeout bounds a single UDP/TCP query to one authoritative nameserver.
// A nameserver that does not answer promptly is treated as not yet carrying the
// record, which is the fail-closed reading.
const nsDialTimeout = 5 * time.Second

// maxZoneLabels bounds the walk up the domain tree when locating the zone
// apex. It is a loop guard, not a policy: no real name has this many labels,
// and an unbounded walk on a hostile or malformed name would query the resolver
// once per label forever.
const maxZoneLabels = 32

// TXTLookup returns the TXT values published for a name.
//
// It is a function type rather than a concrete resolver so the solver's
// propagation gate can be driven deterministically in tests. That matters for
// more than convenience: the gate is a security control, and a control that can
// only be exercised against live DNS is a control that is never tested for the
// case it exists to catch — the record not being there yet.
type TXTLookup func(ctx context.Context, name string) ([]string, error)

// NewAuthoritativeTXTLookup returns a TXTLookup that queries the zone's
// authoritative nameservers directly and reports only the values ALL of them
// serve.
//
// # Why not the system resolver
//
// Two reasons, both of which produce wrong answers in opposite directions:
//
//   - Negative caching. A recursive resolver asked for "_acme-challenge.x"
//     before the record exists caches the NXDOMAIN/empty answer for the zone's
//     negative TTL. The record can then be fully published while the resolver
//     keeps answering "absent" for minutes, so the propagation wait times out
//     and issuance fails even though everything worked.
//   - False confidence. One resolver answering with the record proves only that
//     one nameserver had it when that resolver last asked. The CA will query the
//     authoritative set, possibly a different member of it.
//
// Querying every authoritative nameserver and INTERSECTING the answers makes a
// positive result mean "every server the CA could ask is already serving this",
// which is the only condition under which it is safe to tell the CA to
// validate. A nameserver that errors or times out contributes nothing, so it
// drags the result to empty — an unreachable authority is "not propagated",
// never "assume yes".
//
// That fail-closed rule applies per NAMESERVER, not per address; see
// commonTXT for why the distinction is load-bearing.
func NewAuthoritativeTXTLookup() TXTLookup {
	return func(ctx context.Context, name string) ([]string, error) {
		servers, err := authoritativeServers(ctx, name)
		if err != nil {
			return nil, err
		}
		return commonTXT(ctx, servers, name, lookupTXTAt)
	}
}

// commonTXT reports the values every authoritative nameserver serves for name,
// given those nameservers grouped by their addresses.
//
// It takes the per-address query as a parameter so the gate can be driven
// deterministically in tests. The gate is a security control, and the cases it
// exists to get right — an address with no route to it, two addresses of one
// nameserver disagreeing — cannot be produced against live DNS on demand.
func commonTXT(ctx context.Context, servers [][]string, name string,
	at func(ctx context.Context, server, name string) ([]string, error),
) ([]string, error) {
	var common map[string]bool
	for _, addrs := range servers {
		// A nameserver is one authority reachable at several addresses, and
		// the two must not be conflated. Requiring every ADDRESS to answer
		// is a deployment trap rather than extra safety: a dual-stack
		// nameserver on an IPv4-only host has an AAAA address this process
		// can never reach, so the intersection would be empty on every
		// poll, the deadline would always expire, and issuance would be
		// permanently blocked with nothing misconfigured. The CA itself
		// reaches each nameserver over whichever family it has.
		//
		// Strictness is kept where it is observable. Every address that
		// DOES answer is intersected, so two addresses of one nameserver
		// disagreeing -- distinct anycast instances converging at
		// different rates -- still reads as not-yet-propagated. Only
		// unreachability is skipped, and only per address.
		var answered map[string]bool
		for _, addr := range addrs {
			values, err := at(ctx, addr, name)
			if err != nil {
				continue
			}
			answered = intersect(answered, values)
		}
		if answered == nil {
			// No address of this nameserver answered at all, so this authority
			// is unobserved -- and an unobserved authority is never "assume
			// yes", because the CA may be the one that asks it. Reported as "no
			// values" rather than as an error so the caller keeps polling until
			// its bounded deadline, which is the correct behavior while a zone
			// is still converging.
			//
			// This branch is redundant today and is kept deliberately: falling
			// through would reach intersect with an empty set, which empties
			// common and returns the same verdict two lines later. Mutating the
			// branch away changes no test, and that is the honest reason it is
			// here -- the fail-closed reading of "unobserved" should be stated
			// where a reader looks for it, not left to be re-derived from
			// intersect's behavior on an empty set every time someone touches
			// this loop.
			return nil, nil
		}
		common = intersect(common, keys(answered))
		if len(common) == 0 {
			return nil, nil
		}
	}

	return keys(common), nil
}

// intersect narrows the running set of values to those also present in next. A
// nil running set means "first server", so its values seed the set.
func intersect(current map[string]bool, next []string) map[string]bool {
	seen := make(map[string]bool, len(next))
	for _, v := range next {
		seen[v] = true
	}
	if current == nil {
		return seen
	}
	for v := range current {
		if !seen[v] {
			delete(current, v)
		}
	}
	return current
}

// keys returns the members of a value set, so an inner intersection can seed an
// outer one.
func keys(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for v := range set {
		out = append(out, v)
	}
	return out
}

// authoritativeServers resolves the addresses of the nameservers authoritative
// for the zone containing name, GROUPED BY NAMESERVER.
//
// The grouping is what lets the caller distinguish "this authority cannot be
// reached at this address" from "this authority does not serve the value yet".
// Flattening the addresses into one list loses that distinction, and losing it
// means an address the host has no route to reads as a zone that never
// converges.
//
// The zone is found by walking up the labels until a name has NS records: the
// challenge record itself never has any, and a delegated subdomain must be
// preferred over its parent because only the subdomain's own nameservers will
// carry the record.
func authoritativeServers(ctx context.Context, name string) ([][]string, error) {
	zone := strings.TrimSuffix(name, ".")

	for range maxZoneLabels {
		idx := strings.IndexByte(zone, '.')
		if idx < 0 {
			break
		}
		// The record's own name is skipped deliberately: querying NS for
		// "_acme-challenge.example.com" answers about example.com's delegation
		// at best and NXDOMAIN at worst, and either way tells us nothing new.
		zone = zone[idx+1:]

		ns, err := net.DefaultResolver.LookupNS(ctx, zone)
		if err != nil || len(ns) == 0 {
			continue
		}

		var grouped [][]string
		for _, server := range ns {
			ips, err := net.DefaultResolver.LookupIPAddr(ctx, strings.TrimSuffix(server.Host, "."))
			if err != nil {
				continue
			}
			addrs := make([]string, 0, len(ips))
			for _, ip := range ips {
				addrs = append(addrs, net.JoinHostPort(ip.IP.String(), "53"))
			}
			if len(addrs) > 0 {
				grouped = append(grouped, addrs)
			}
		}
		if len(grouped) > 0 {
			return grouped, nil
		}
	}
	return nil, fmt.Errorf("dns01: no authoritative nameserver found for %q", name)
}

// lookupTXTAt asks one specific nameserver for a name's TXT records.
//
// PreferGo forces Go's own DNS client so that Dial is honored; with cgo
// resolution the query would go to the host's configured recursive resolver
// instead, silently reintroducing the caching this whole function avoids.
func lookupTXTAt(ctx context.Context, server, name string) ([]string, error) {
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: nsDialTimeout}
			return d.DialContext(ctx, network, server)
		},
	}
	return r.LookupTXT(ctx, name)
}
