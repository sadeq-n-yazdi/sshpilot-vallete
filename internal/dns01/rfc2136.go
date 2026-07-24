package dns01

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/safetext"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/secrets"
)

const (
	// rfc2136ChallengeTTL is the TTL on the challenge record. Low on purpose:
	// the record is deleted minutes later, and a long TTL would keep resolvers
	// serving a challenge answer after the authorization it belonged to is gone.
	rfc2136ChallengeTTL = 60

	// rfc2136Timeout bounds one DNS exchange (an SOA query, or an UPDATE).
	rfc2136Timeout = 30 * time.Second

	// rfc2136TSIGFudge is the permitted clock skew, in seconds, between this
	// host and the nameserver when it verifies the TSIG timestamp. 300s is the
	// conventional value; it is wide enough to tolerate ordinary NTP drift and
	// narrow enough that a captured signed message cannot be replayed for long.
	rfc2136TSIGFudge = 300

	// rfc2136MaxNameBytes bounds a domain name read out of a server's response
	// before it is used to build a request or reaches an error. A valid DNS name
	// is at most 255 bytes, so this is a no-op for legitimate input and only caps
	// a hostile authoritative server that answers with an oversized owner name.
	// Applied through [safetext.Bound] rather than a slice so a multi-byte rune
	// is never split into invalid UTF-8 for the log encoder downstream.
	rfc2136MaxNameBytes = 255
)

// ErrRFC2136 is returned when the RFC 2136 provider refuses a configuration or
// the nameserver rejects a dynamic update. It never carries the TSIG secret —
// see [rfc2136Provider].
var ErrRFC2136 = errors.New("dns01: rfc2136 dynamic update")

// tsigAlgorithms is the allowlist of TSIG HMAC algorithms this provider will
// sign with, mapping the config token to the wire constant miekg/dns expects.
//
// It is an allowlist, not a passthrough: HMAC-MD5 and HMAC-SHA1 are TSIG's
// historical defaults and are deliberately absent, because a signing primitive
// is an authentication primitive and a weak one lets a forged UPDATE rewrite the
// zone. An unknown or weak token is refused at construction rather than silently
// downgraded. SHA-224 is the floor.
var tsigAlgorithms = map[string]string{
	"hmac-sha224": dns.HmacSHA224,
	"hmac-sha256": dns.HmacSHA256,
	"hmac-sha384": dns.HmacSHA384,
	"hmac-sha512": dns.HmacSHA512,
}

// TSIGAlgorithm resolves a configured algorithm token (e.g. "hmac-sha256") to
// the wire constant used to sign the update, reporting whether it is supported.
//
// It is exported so config validation and this constructor share ONE allowlist:
// a token config accepts must be one this provider can actually sign with, and
// the reverse. The match is case-insensitive and tolerant of surrounding
// whitespace so a value pasted from a keyfile still resolves.
func TSIGAlgorithm(name string) (string, bool) {
	algo, ok := tsigAlgorithms[strings.ToLower(strings.TrimSpace(name))]
	return algo, ok
}

// TSIGAlgorithmNames returns the accepted algorithm tokens in sorted order. It
// exists so a package that keeps its own copy of the allowlist (config, to avoid
// importing this provider package) can pin the two lists to one source of truth
// with a parity test, rather than importing the whole DNS stack for four strings.
func TSIGAlgorithmNames() []string {
	names := make([]string, 0, len(tsigAlgorithms))
	for name := range tsigAlgorithms {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// rfc2136Provider creates and removes the challenge TXT record with an RFC 2136
// dynamic DNS UPDATE, authenticated with a TSIG key (RFC 8945).
//
// # Why this provider is different from the HTTP ones
//
// Every other provider in this package speaks a vendor's HTTPS API over the
// shared *http.Client the seam hands it. RFC 2136 speaks DNS: it sends a signed
// UPDATE message straight to an authoritative nameserver, so it ignores the
// *http.Client entirely and needs three non-secret settings the HTTP providers
// do not — the nameserver's address, the TSIG key name, and the TSIG algorithm.
// Those cannot ride the seam's (creds, client) signature, so this provider is
// constructed in the wiring layer from config rather than through NewAPIProvider;
// see internal/transport/http/tls.go and ADR-0034.
//
// # Credential custody
//
// The TSIG secret is the sensitive value: it is the key that authorizes rewrites
// of the zone. It enters as a [secrets.Redacted] and is revealed in EXACTLY ONE
// place — [rfc2136Provider.update], where it seeds the per-exchange TsigSecret
// map that miekg/dns uses to compute the MAC over the canonical wire form. The
// MAC is never hand-rolled here. Consequences, mirroring the other providers:
//
//   - This struct implements [fmt.Formatter], so no formatting of it can print
//     the secret. That method is required, not decorative: secrets.Redacted's own
//     redaction is bypassed by fmt for a value in an UNEXPORTED field, which fmt
//     renders by raw reflection without calling String/Format/GoString.
//   - The type holds no logger and no telemetry handle, so there is no local call
//     site that could emit it.
//   - Errors are built from the record name, the nameserver address (both
//     non-secret operator config) and the DNS rcode. A signed request is never
//     rendered into an error, and the SOA query used for zone discovery is
//     unsigned, so it has no Reveal at all.
//
// The server address, key name and algorithm are NOT secret and are held in
// plain form: the address travels in cleartext in every packet, the key name is
// sent in the clear inside every TSIG RR, and the algorithm names a public hash.
// Only the shared secret behind the MAC is sensitive, which is why only it is a
// secrets.Redacted.
type rfc2136Provider struct {
	// server is the host:port of the authoritative nameserver that accepts the
	// UPDATE. It is required config, never derived, and never a settable base a
	// misconfiguration could point the signing key at — the operator names the
	// one server their TSIG key is shared with.
	server string
	// keyName is the TSIG key name in canonical form (lowercase, fully qualified).
	// The same canonical value is used to sign and to key the secret map, because
	// a mismatch there is the classic TSIG failure.
	keyName string
	// algorithm is the wire TSIG algorithm constant (e.g. "hmac-sha256.").
	algorithm string
	// secret is the base64 TSIG shared secret, revealed only in update.
	secret secrets.Redacted

	// net is the transport for the DNS exchange, "udp" in production. It is a
	// field so a test can pin it; a signed TXT update is small enough for UDP.
	net string
	// now is injectable so the TSIG timestamp is deterministic in tests. It is
	// not configurable at runtime.
	now func() time.Time
}

var _ Provider = (*rfc2136Provider)(nil)

// NewRFC2136 builds the provider from its non-secret settings and the credential
// set carrying the TSIG secret.
//
// Every input is validated fail-closed at construction, so a misconfiguration is
// a startup error the operator sees rather than a failed renewal weeks later:
//
//   - the TSIG secret must be present and non-blank (checked through the wrapped
//     value, without revealing it);
//   - the algorithm must be on the [tsigAlgorithms] allowlist;
//   - the server must parse as host:port;
//   - the key name must be a syntactically valid domain name.
//
// The base64 well-formedness of the secret is deliberately NOT checked here: it
// would force a second reveal site, and a bad secret already fails loudly at the
// first exchange as a TSIG failure rather than as a silent wrong answer.
func NewRFC2136(server, keyName, algorithm string, creds Credentials) (Provider, error) {
	secret, ok := creds.Single()
	if !ok {
		return nil, fmt.Errorf("%w: exactly one tsig secret is required", ErrRFC2136)
	}
	if secret.IsBlank() {
		return nil, fmt.Errorf("%w: tsig secret must not be blank", ErrRFC2136)
	}

	algo, ok := TSIGAlgorithm(algorithm)
	if !ok {
		// The algorithm token is operator config, not a secret, so it is the
		// diagnostic and is echoed.
		return nil, fmt.Errorf("%w: unsupported tsig algorithm %q", ErrRFC2136, algorithm)
	}

	addr := strings.TrimSpace(server)
	if _, _, err := net.SplitHostPort(addr); err != nil {
		return nil, fmt.Errorf("%w: server %q must be host:port", ErrRFC2136, server)
	}

	name := strings.TrimSpace(keyName)
	if _, valid := dns.IsDomainName(name); name == "" || !valid {
		// The key name is not secret, but it is not echoed: it carries no
		// diagnostic value beyond "malformed", and keeping error text free of
		// operator identifiers is the cheaper habit.
		return nil, fmt.Errorf("%w: malformed tsig key name", ErrRFC2136)
	}

	return &rfc2136Provider{
		server:    addr,
		keyName:   dns.CanonicalName(name),
		algorithm: algo,
		secret:    secret,
		net:       "udp",
		now:       time.Now,
	}, nil
}

// Name identifies the provider. It is a constant, never derived from the
// credential.
func (p *rfc2136Provider) Name() string { return "rfc2136" }

// Format renders the provider as a constant under every fmt verb, so no
// formatting of this value can print the TSIG secret. See the type comment: this
// is load-bearing, because fmt walks unexported fields by reflection and never
// calls their redaction methods.
func (p *rfc2136Provider) Format(f fmt.State, _ rune) {
	_, _ = io.WriteString(f, "dns01.rfc2136Provider{secret:[REDACTED]}")
}

// Present publishes the challenge value with a signed UPDATE and returns the
// cleanup that withdraws exactly that value.
//
// It deliberately does NOT wait for propagation; that gate is the solver's, run
// once against the authoritative nameservers for every provider.
func (p *rfc2136Provider) Present(ctx context.Context, rec Record) (CleanupFunc, error) {
	zone, err := p.zoneFor(ctx, rec.Name)
	if err != nil {
		return nil, err
	}
	fqdn := dns.Fqdn(rec.Name)

	// The cleanup is built BEFORE the write and returned even when the write
	// reports failure, because a failed write can still have applied: a response
	// lost to a timeout leaves the record committed at the server with nothing
	// here knowing it. Returning nil in that case would leak a standing
	// _acme-challenge TXT record that no code path can withdraw — the seam's
	// contract requires a cleanup whenever anything may have been created,
	// including when Present goes on to fail. It is safe to return early because
	// the closure captures only the zone, fqdn and value, all known before the
	// call; and safe to run when the write never applied because deleting an
	// absent RR under RFC 2136 is a NOERROR no-op.
	cleanup := p.removeRecord(zone, fqdn, rec.Value)

	err = p.update(ctx, zone, func(m *dns.Msg) {
		m.Insert([]dns.RR{txtRR(fqdn, rec.Value, rfc2136ChallengeTTL)})
	})
	if err != nil {
		return cleanup, fmt.Errorf("%w: publish txt value for %q: %w", ErrRFC2136, rec.Name, err)
	}
	return cleanup, nil
}

// removeRecord returns the cleanup closure for one published value.
//
// The zone, name and exact value are CAPTURED, and the UPDATE removes precisely
// that (name, type, rdata) triple — miekg's Remove issues a class-NONE delete of
// the specific RR, never a delete of the whole record set — so it cannot remove
// a record this process did not create, including an operator's own TXT record
// at the same name. Deleting an already-absent RR is a NOERROR no-op under RFC
// 2136, which is what makes the closure idempotent on the retry and shutdown
// paths without an existence prerequisite.
func (p *rfc2136Provider) removeRecord(zone, fqdn, value string) CleanupFunc {
	return func(ctx context.Context) error {
		err := p.update(ctx, zone, func(m *dns.Msg) {
			m.Remove([]dns.RR{txtRR(fqdn, value, 0)})
		})
		if err != nil {
			return fmt.Errorf("%w: remove txt value for %q: %w", ErrRFC2136, fqdn, err)
		}
		return nil
	}
}

// txtRR builds the TXT resource record the UPDATE inserts or removes.
//
// The ACME challenge value is a base64url SHA-256 digest — 43 characters of
// [A-Za-z0-9_-] — so it fits a single character-string and needs no splitting.
func txtRR(fqdn, value string, ttl uint32) *dns.TXT {
	return &dns.TXT{
		Hdr: dns.RR_Header{Name: fqdn, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: ttl},
		Txt: []string{value},
	}
}

// update sends one TSIG-signed dynamic UPDATE to the configured nameserver.
//
// This is the ONLY function in the package that reveals the TSIG secret, and it
// does so into the per-exchange TsigSecret map miekg/dns reads when it computes
// the MAC over the canonical wire form. The signed message is never rendered
// into an error: a transport failure names only the server address and the DNS
// library's own error, and a protocol rejection names only the rcode.
func (p *rfc2136Provider) update(ctx context.Context, zone string, build func(*dns.Msg)) error {
	m := new(dns.Msg)
	m.SetUpdate(zone)
	build(m)
	m.SetTsig(p.keyName, p.algorithm, rfc2136TSIGFudge, p.now().Unix())

	client := &dns.Client{Net: p.net, Timeout: rfc2136Timeout}
	client.TsigSecret = map[string]string{p.keyName: p.secret.Reveal()}

	resp, _, err := client.ExchangeContext(ctx, m, p.server)
	if err != nil {
		return fmt.Errorf("exchange with %s: %w", p.server, err)
	}
	if resp.Rcode != dns.RcodeSuccess {
		return fmt.Errorf("nameserver rejected update (rcode %s)", rcodeString(resp.Rcode))
	}
	return nil
}

// zoneFor discovers the zone that should hold the record by querying the
// configured nameserver for the SOA of successively shorter suffixes of the
// record name, most-specific first, and returning the owner of the first SOA it
// finds.
//
// Most-specific-first matters for the same reason it does in the HTTP providers:
// a delegated "eu.example.com" must win over its parent "example.com", because
// only the delegated zone's server carries the record. The SOA discovery query
// is a read and is NOT TSIG-signed — signing is required only to WRITE — so this
// path holds no credential.
func (p *rfc2136Provider) zoneFor(ctx context.Context, name string) (string, error) {
	client := &dns.Client{Net: p.net, Timeout: rfc2136Timeout}
	labels := dns.SplitDomainName(dns.Fqdn(name))

	for i := 0; i < len(labels) && i < maxZoneLabels; i++ {
		candidate := dns.Fqdn(strings.Join(labels[i:], "."))

		msg := new(dns.Msg)
		msg.SetQuestion(candidate, dns.TypeSOA)
		resp, _, err := client.ExchangeContext(ctx, msg, p.server)
		if err != nil {
			return "", fmt.Errorf("%w: soa lookup for %q: %w", ErrRFC2136, name, err)
		}
		// NOERROR carries the SOA; NXDOMAIN/NODATA is the ordinary "not this
		// suffix, try the parent" answer. Anything else (SERVFAIL, REFUSED) is a
		// fault to surface, not a miss to walk past.
		if resp.Rcode != dns.RcodeSuccess && resp.Rcode != dns.RcodeNameError {
			return "", fmt.Errorf("%w: soa lookup for %q rejected (rcode %s)",
				ErrRFC2136, name, rcodeString(resp.Rcode))
		}
		if zone := soaOwner(resp); zone != "" {
			return zone, nil
		}
	}
	return "", fmt.Errorf("%w: no zone with an SOA found for %q", ErrRFC2136, name)
}

// soaOwner returns the owner name of the SOA in a response, or "".
//
// A query for a name at the zone apex answers with the SOA in the ANSWER
// section; a query for a name below the apex (and any NXDOMAIN/NODATA) answers
// with it in the AUTHORITY section. Both are checked, answer first, so the zone
// is found wherever the record name sits relative to the apex.
//
// The owner name is server-controlled, so it is bounded through [safetext.Bound]
// before it is used to build the UPDATE or reaches an error: a legitimate name
// is at most 255 bytes and passes unchanged, and a hostile oversized name cannot
// grow the request or corrupt the log encoding.
func soaOwner(resp *dns.Msg) string {
	for _, section := range [][]dns.RR{resp.Answer, resp.Ns} {
		for _, rr := range section {
			if soa, ok := rr.(*dns.SOA); ok {
				return safetext.Bound(soa.Hdr.Name, rfc2136MaxNameBytes)
			}
		}
	}
	return ""
}

// rcodeString renders a DNS response code from the library's fixed table, so no
// server-controlled free text reaches the error — only the structured code, or
// its number if the library does not name it.
func rcodeString(rcode int) string {
	if s, ok := dns.RcodeToString[rcode]; ok {
		return s
	}
	return fmt.Sprintf("%d", rcode)
}
