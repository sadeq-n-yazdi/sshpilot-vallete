package dns01

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/secrets"
)

// The TSIG key material every test in this file uses. The secret is distinctive
// so a leak into any output is unmistakable; it is carried in the base64 form a
// real TSIG secret takes, which is the exact string the provider stores and the
// only thing that may never appear in an error or a rendering.
const (
	testTSIGKeyName   = "acme-update.example.com."
	testTSIGSecretRaw = "tsig-secret-DO-NOT-LEAK-9c3f"
	testTSIGAlgorithm = "hmac-sha256"
)

// testTSIGSecret is the base64 secret handed to the provider and shared with the
// fake nameserver. A DIFFERENT valid secret is used to drive the bad-key path.
var (
	testTSIGSecret  = base64.StdEncoding.EncodeToString([]byte(testTSIGSecretRaw))
	wrongTSIGSecret = base64.StdEncoding.EncodeToString([]byte("a-different-secret"))
)

// rfc2136Server is a local stand-in for an authoritative nameserver that accepts
// TSIG-signed dynamic updates. No test in this package touches real DNS.
//
// It holds real state and APPLIES the updates it receives rather than only
// recording them: the add-my-value / remove-only-my-value logic is the part of
// this provider most likely to be wrong, and a fake that merely recorded
// requests would let a provider that clobbers a co-existing value pass.
type rfc2136Server struct {
	t *testing.T

	mu sync.Mutex
	// records maps a canonical fqdn to the TXT values published at it.
	records map[string][]string
	// zones are the apexes this server is authoritative for (canonical fqdns).
	zones []string

	// signedUpdates counts updates that arrived carrying a VALIDATED TSIG, so a
	// test can prove the provider signs its writes.
	signedUpdates int
	// rejectUpdates, when set, makes the server refuse every UPDATE with REFUSED
	// while still answering SOA discovery — the shape needed to exercise a
	// publish that fails after the zone is resolved.
	rejectUpdates bool

	// serverAddr is the listener's host:port, handed to the provider as its
	// nameserver.
	serverAddr string

	keyName   string
	secret    string
	algorithm string
}

// newRFC2136Server starts a fake nameserver on a random localhost UDP port and
// builds a provider pointed straight at it. Unlike the HTTP providers this needs
// no transport-rewrite hack: the nameserver address is a first-class provider
// setting, so the test passes the listener's own address as the server.
func newRFC2136Server(t *testing.T, zones ...string) (*rfc2136Server, *rfc2136Provider) {
	t.Helper()

	if len(zones) == 0 {
		zones = []string{"example.com."}
	}
	canonical := make([]string, len(zones))
	for i, z := range zones {
		canonical[i] = dns.CanonicalName(z)
	}

	srv := &rfc2136Server{
		t:         t,
		records:   map[string][]string{},
		zones:     canonical,
		keyName:   dns.CanonicalName(testTSIGKeyName),
		secret:    testTSIGSecret,
		algorithm: dns.HmacSHA256,
	}

	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}

	started := make(chan struct{})
	server := &dns.Server{
		PacketConn:        pc,
		Handler:           srv,
		TsigSecret:        map[string]string{srv.keyName: srv.secret},
		NotifyStartedFunc: func() { close(started) },
		// The default accept function rejects OpcodeUpdate with NOTIMP — it is
		// written for a resolver, not a primary that takes dynamic updates — so an
		// accept-all function is installed to let the UPDATE reach the handler.
		MsgAcceptFunc: func(dns.Header) dns.MsgAcceptAction { return dns.MsgAccept },
	}
	go func() { _ = server.ActivateAndServe() }()
	t.Cleanup(func() { _ = server.Shutdown() })
	<-started
	srv.serverAddr = pc.LocalAddr().String()

	provider, err := NewRFC2136(srv.serverAddr, testTSIGKeyName, testTSIGAlgorithm,
		NewSingleCredential(secrets.NewRedacted(testTSIGSecret)))
	if err != nil {
		t.Fatalf("NewRFC2136: %v", err)
	}
	return srv, provider.(*rfc2136Provider)
}

func (s *rfc2136Server) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)

	tsigValidated := false
	if r.IsTsig() != nil {
		if w.TsigStatus() == nil {
			tsigValidated = true
			// Sign the reply so a well-keyed client accepts it.
			m.SetTsig(s.keyName, s.algorithm, rfc2136TSIGFudge, time.Now().Unix())
		}
	}

	switch r.Opcode {
	case dns.OpcodeQuery:
		s.handleQuery(m, r)
	case dns.OpcodeUpdate:
		if !tsigValidated {
			// An unsigned or wrong-keyed update is refused, exactly as a real
			// server enforcing TSIG does.
			m.Rcode = dns.RcodeNotAuth
			break
		}
		s.applyUpdate(m, r)
	default:
		m.Rcode = dns.RcodeNotImplemented
	}
	_ = w.WriteMsg(m)
}

// handleQuery answers the unsigned SOA query the provider uses for zone
// discovery. The SOA lands in the ANSWER section for an apex query and in the
// AUTHORITY section for a name below the apex — the two places soaOwner must
// look — so this exercises that split.
func (s *rfc2136Server) handleQuery(m, r *dns.Msg) {
	q := r.Question[0]
	if q.Qtype != dns.TypeSOA {
		m.Rcode = dns.RcodeNameError
		return
	}
	zone := s.zoneOf(q.Name)
	if zone == "" {
		m.Rcode = dns.RcodeNameError
		return
	}
	soa := &dns.SOA{
		Hdr:     dns.RR_Header{Name: zone, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 3600},
		Ns:      "ns1." + zone,
		Mbox:    "hostmaster." + zone,
		Serial:  1,
		Refresh: 3600, Retry: 600, Expire: 86400, Minttl: 60,
	}
	if strings.EqualFold(dns.CanonicalName(q.Name), zone) {
		m.Answer = append(m.Answer, soa)
	} else {
		m.Ns = append(m.Ns, soa)
	}
}

// applyUpdate executes the add/delete RRs of a validated UPDATE against the
// fake's state. Update RRs travel in the message's authority (Ns) section: class
// INET is an add, class NONE is the delete of one specific rdata.
func (s *rfc2136Server) applyUpdate(m, r *dns.Msg) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.signedUpdates++

	if s.rejectUpdates {
		m.Rcode = dns.RcodeRefused
		return
	}
	if s.zoneOf(r.Question[0].Name) == "" {
		m.Rcode = dns.RcodeNotZone
		return
	}

	for _, rr := range r.Ns {
		txt, ok := rr.(*dns.TXT)
		if !ok {
			continue
		}
		name := dns.CanonicalName(rr.Header().Name)
		value := strings.Join(txt.Txt, "")
		switch rr.Header().Class {
		case dns.ClassINET:
			if !containsStr(s.records[name], value) {
				s.records[name] = append(s.records[name], value)
			}
		case dns.ClassNONE:
			s.records[name] = removeStr(s.records[name], value)
			if len(s.records[name]) == 0 {
				delete(s.records, name)
			}
		}
	}
}

// zoneOf returns the most specific configured zone that is a suffix of name at a
// label boundary, or "".
func (s *rfc2136Server) zoneOf(name string) string {
	name = dns.CanonicalName(name)
	best := ""
	for _, z := range s.zones {
		if name == z || strings.HasSuffix(name, "."+z) {
			if len(z) > len(best) {
				best = z
			}
		}
	}
	return best
}

func (s *rfc2136Server) txt(fqdn string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.records[dns.CanonicalName(fqdn)]...)
}

func (s *rfc2136Server) updates() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.signedUpdates
}

func (s *rfc2136Server) setRejectUpdates() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rejectUpdates = true
}

func containsStr(hay []string, needle string) bool {
	for _, h := range hay {
		if h == needle {
			return true
		}
	}
	return false
}

func removeStr(hay []string, needle string) []string {
	out := hay[:0:0]
	for _, h := range hay {
		if h != needle {
			out = append(out, h)
		}
	}
	return out
}

func rfc2136Record() Record {
	return Record{Name: "_acme-challenge.vallet.example.com", Value: "digest-value-one"}
}

// TestRFC2136PublishesAndRemovesTheChallengeRecord is the happy path: the value
// is published at the right name with a signed update, and the cleanup removes
// it. It also proves the write was TSIG-signed and validated.
func TestRFC2136PublishesAndRemovesTheChallengeRecord(t *testing.T) {
	srv, provider := newRFC2136Server(t)
	const fqdn = "_acme-challenge.vallet.example.com."

	cleanup, err := provider.Present(t.Context(), rfc2136Record())
	if err != nil {
		t.Fatalf("Present: %v", err)
	}
	if got := srv.txt(fqdn); !equalStrs(got, []string{"digest-value-one"}) {
		t.Fatalf("published values = %v, want the challenge digest", got)
	}
	if srv.updates() == 0 {
		t.Error("the update was not TSIG-signed and validated; an unsigned write " +
			"would let anyone on the path rewrite the zone")
	}

	if err := cleanup(t.Context()); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if got := srv.txt(fqdn); len(got) != 0 {
		t.Errorf("cleanup left the record behind: %v", got)
	}
}

// TestRFC2136CleanupLeavesACoexistingValueAlone is the scoping test.
//
// A certificate covering both example.com and *.example.com puts two digests at
// one name, and an operator may already hold a TXT record there. Cleanup must
// remove only the exact value this process published — miekg's Remove deletes
// one specific rdata, not the whole set — so every other value survives.
func TestRFC2136CleanupLeavesACoexistingValueAlone(t *testing.T) {
	srv, provider := newRFC2136Server(t)
	const fqdn = "_acme-challenge.vallet.example.com."

	srv.mu.Lock()
	srv.records[fqdn] = []string{"operator-owned-value"}
	srv.mu.Unlock()

	cleanup, err := provider.Present(t.Context(), rfc2136Record())
	if err != nil {
		t.Fatalf("Present: %v", err)
	}
	if got := srv.txt(fqdn); !sameStrSet(got, []string{"operator-owned-value", "digest-value-one"}) {
		t.Fatalf("publish produced %v, want the operator's value kept alongside ours", got)
	}

	if err := cleanup(t.Context()); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if got := srv.txt(fqdn); !equalStrs(got, []string{"operator-owned-value"}) {
		t.Errorf("cleanup produced %v, want the operator's value untouched: the "+
			"provider must not remove a value it did not publish", got)
	}
}

// TestRFC2136CleanupIsIdempotent proves an already-removed value is not an error.
// Cleanup runs on retry and shutdown paths and may run twice; RFC 2136 makes a
// delete of an absent RR a NOERROR no-op, so the second call must still succeed.
func TestRFC2136CleanupIsIdempotent(t *testing.T) {
	_, provider := newRFC2136Server(t)

	cleanup, err := provider.Present(t.Context(), rfc2136Record())
	if err != nil {
		t.Fatalf("Present: %v", err)
	}
	if err := cleanup(t.Context()); err != nil {
		t.Fatalf("first cleanup: %v", err)
	}
	if err := cleanup(t.Context()); err != nil {
		t.Errorf("second cleanup: %v, want nil", err)
	}
}

// TestRFC2136PresentReturnsCleanupEvenOnFailure pins the seam contract: a write
// that may have applied must still hand back a cleanup.
//
// The zone resolves but the nameserver refuses the UPDATE, so Present fails
// AFTER reaching the write — but a lost response could equally have left the
// record committed, so returning nil would leak it. The returned cleanup must
// also be safe to run when nothing was created, which the idempotent delete
// guarantees. (When zone discovery itself fails, nothing was created and a nil
// cleanup is correct — that path is covered by the no-zone test.)
func TestRFC2136PresentReturnsCleanupEvenOnFailure(t *testing.T) {
	srv, provider := newRFC2136Server(t)
	srv.setRejectUpdates()

	cleanup, err := provider.Present(t.Context(), rfc2136Record())
	if err == nil {
		t.Fatal("Present accepted an update the server refused")
	}
	if !errors.Is(err, ErrRFC2136) {
		t.Errorf("error = %v, want ErrRFC2136", err)
	}
	if cleanup == nil {
		t.Fatal("Present returned no cleanup for a write that may still have applied")
	}
}

// TestRFC2136RejectsABadTSIGSecret proves a wrong signing key cannot rewrite the
// zone. The provider signs with a secret the server does not share, so the
// server refuses and the record is never published.
func TestRFC2136RejectsABadTSIGSecret(t *testing.T) {
	srv, _ := newRFC2136Server(t)
	const fqdn = "_acme-challenge.vallet.example.com."

	bad, err := NewRFC2136(srv.addr(t), testTSIGKeyName, testTSIGAlgorithm,
		NewSingleCredential(secrets.NewRedacted(wrongTSIGSecret)))
	if err != nil {
		t.Fatalf("NewRFC2136: %v", err)
	}

	_, err = bad.Present(t.Context(), rfc2136Record())
	if err == nil {
		t.Fatal("Present succeeded with a TSIG secret the server does not share")
	}
	if got := srv.txt(fqdn); len(got) != 0 {
		t.Errorf("a wrongly-signed update published %v; it must be refused", got)
	}
	assertNoTSIGSecret(t, err.Error())
}

// TestRFC2136PrefersTheMostSpecificZone checks a delegated subdomain wins over
// its parent, so the record is written into the zone the CA will actually query.
// It also exercises the AUTHORITY-section SOA path, since the record name sits
// below each candidate apex.
func TestRFC2136PrefersTheMostSpecificZone(t *testing.T) {
	srv, provider := newRFC2136Server(t, "example.com.", "vallet.example.com.")
	const fqdn = "_acme-challenge.vallet.example.com."

	if _, err := provider.Present(t.Context(), rfc2136Record()); err != nil {
		t.Fatalf("Present: %v", err)
	}
	if got := srv.txt(fqdn); !equalStrs(got, []string{"digest-value-one"}) {
		t.Fatalf("record not published under the delegated zone: %v", got)
	}
}

// TestRFC2136RefusesWhenNoZoneMatches checks the name-not-hosted-here case fails
// rather than writing somewhere arbitrary.
func TestRFC2136RefusesWhenNoZoneMatches(t *testing.T) {
	_, provider := newRFC2136Server(t, "unrelated.test.")

	_, err := provider.Present(t.Context(), rfc2136Record())
	if err == nil {
		t.Fatal("Present succeeded with no zone for the name")
	}
	if !errors.Is(err, ErrRFC2136) {
		t.Errorf("error = %v, want ErrRFC2136", err)
	}
}

// TestRFC2136ConstructorFailsClosed proves every malformed input is refused at
// construction, where the operator sees it, rather than at the first renewal.
func TestRFC2136ConstructorFailsClosed(t *testing.T) {
	t.Parallel()

	good := NewSingleCredential(secrets.NewRedacted(testTSIGSecret))
	blank := NewSingleCredential(secrets.NewRedacted("   "))

	tests := []struct {
		name      string
		server    string
		keyName   string
		algorithm string
		creds     Credentials
	}{
		{"blank secret", "127.0.0.1:53", testTSIGKeyName, testTSIGAlgorithm, blank},
		{"empty credential set", "127.0.0.1:53", testTSIGKeyName, testTSIGAlgorithm, Credentials{}},
		{"unknown algorithm", "127.0.0.1:53", testTSIGKeyName, "hmac-md5", good},
		{"weak sha1 refused", "127.0.0.1:53", testTSIGKeyName, "hmac-sha1", good},
		{"empty algorithm", "127.0.0.1:53", testTSIGKeyName, "", good},
		{"missing server", "", testTSIGKeyName, testTSIGAlgorithm, good},
		{"server without port", "127.0.0.1", testTSIGKeyName, testTSIGAlgorithm, good},
		{"key name with over-long label", "127.0.0.1:53", strings.Repeat("x", 64) + ".example.com.", testTSIGAlgorithm, good},
		{"key name with empty label", "127.0.0.1:53", "bad..key.example.com.", testTSIGAlgorithm, good},
		{"empty key name", "127.0.0.1:53", "", testTSIGAlgorithm, good},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p, err := NewRFC2136(tc.server, tc.keyName, tc.algorithm, tc.creds)
			if !errors.Is(err, ErrRFC2136) {
				t.Fatalf("err = %v, want ErrRFC2136", err)
			}
			if p != nil {
				t.Fatal("a provider must not be returned when construction fails")
			}
			assertNoTSIGSecret(t, err.Error())
		})
	}
}

// TestRFC2136AcceptsEveryAllowlistedAlgorithm is the positive control for the
// refusals above: each strong HMAC the allowlist names must build a provider.
func TestRFC2136AcceptsEveryAllowlistedAlgorithm(t *testing.T) {
	t.Parallel()

	good := NewSingleCredential(secrets.NewRedacted(testTSIGSecret))
	for _, algo := range []string{"hmac-sha224", "hmac-sha256", "hmac-sha384", "hmac-sha512", "HMAC-SHA256"} {
		t.Run(algo, func(t *testing.T) {
			t.Parallel()
			p, err := NewRFC2136("127.0.0.1:53", testTSIGKeyName, algo, good)
			if err != nil {
				t.Fatalf("NewRFC2136(%q): %v", algo, err)
			}
			if p == nil {
				t.Fatal("provider must not be nil on success")
			}
			if p.Name() != "rfc2136" {
				t.Errorf("Name() = %q, want rfc2136", p.Name())
			}
		})
	}
}

// TestRFC2136SecretNeverAppearsInOutput checks every rendering path the TSIG
// secret could escape through, including the %+v case that fails without the
// Format method because fmt walks unexported fields by reflection.
func TestRFC2136SecretNeverAppearsInOutput(t *testing.T) {
	_, provider := newRFC2136Server(t)

	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
		assertNoTSIGSecret(t, fmt.Sprintf(verb, provider))
	}
	assertNoTSIGSecret(t, provider.Name())
}

// TestRFC2136ErrorsNeverCarryTheSecret drives the failure paths, which are where
// a secret most plausibly reaches a log.
func TestRFC2136ErrorsNeverCarryTheSecret(t *testing.T) {
	// The zone resolves and the update is refused, so the error comes from the
	// signed write path — where a secret is most likely to leak.
	srv, provider := newRFC2136Server(t)
	srv.setRejectUpdates()

	_, err := provider.Present(t.Context(), rfc2136Record())
	if err == nil {
		t.Fatal("expected an error to inspect")
	}
	assertNoTSIGSecret(t, err.Error())
}

// TestTSIGAlgorithmAllowlist pins the shared allowlist config validation and the
// provider both consult, in both directions.
func TestTSIGAlgorithmAllowlist(t *testing.T) {
	t.Parallel()

	for _, algo := range []string{"hmac-sha224", "hmac-sha256", "hmac-sha384", "hmac-sha512", "  HMAC-SHA256  "} {
		if _, ok := TSIGAlgorithm(algo); !ok {
			t.Errorf("TSIGAlgorithm(%q) = not ok, want a supported algorithm", algo)
		}
	}
	for _, algo := range []string{"", "hmac-md5", "hmac-sha1", "sha256", "gss-tsig"} {
		if _, ok := TSIGAlgorithm(algo); ok {
			t.Errorf("TSIGAlgorithm(%q) = ok, want refused", algo)
		}
	}
}

func (s *rfc2136Server) addr(t *testing.T) string {
	t.Helper()
	return s.serverAddr
}

func assertNoTSIGSecret(t *testing.T, rendered string) {
	t.Helper()
	if strings.Contains(rendered, testTSIGSecret) || strings.Contains(rendered, testTSIGSecretRaw) {
		t.Errorf("the TSIG secret leaked: %s", rendered)
	}
}

func equalStrs(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func sameStrSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	seen := map[string]int{}
	for _, v := range a {
		seen[v]++
	}
	for _, v := range b {
		seen[v]--
	}
	for _, n := range seen {
		if n != 0 {
			return false
		}
	}
	return true
}
