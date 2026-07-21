package httpserver

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sync"
	"time"

	"golang.org/x/crypto/acme"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/dns01"
)

const (
	// dns01PropagationTimeout bounds the wait for the challenge TXT record to
	// appear on every authoritative nameserver.
	//
	// Ten minutes suits both modes: an API provider normally converges in
	// seconds, while manual mode is waiting for a human to log into a DNS
	// console. It is deliberately not longer — a wait measured in hours would
	// pin an order open across a shutdown, and the renewal loop retries with
	// backoff anyway, so a slow operator loses nothing but a retry.
	dns01PropagationTimeout = 10 * time.Minute

	// dns01PollInterval is how often propagation is re-checked.
	dns01PollInterval = 10 * time.Second
)

// ErrDNS01Propagation is returned when the challenge record did not appear on
// the authoritative nameservers within the bounded wait.
//
// It fails the order. It does NOT fall back to TLS-ALPN-01, does not tell the
// CA to validate anyway, and does not produce a certificate: a challenge the CA
// cannot satisfy is not a challenge to accept, and accepting one burns a
// validation attempt against the CA's failed-authorization rate limit for
// nothing.
var ErrDNS01Propagation = errors.New("httpserver: dns-01 challenge record did not propagate")

// dns01Solver answers DNS-01 by publishing a TXT record through a
// [dns01.Provider] and waiting until the authoritative nameservers serve it.
//
// # Why the propagation gate lives here and not in the provider
//
// It is a security control, so it is implemented exactly once, above the
// pluggable seam. Every provider in ADR-0015's phase-1 list gets it without
// writing any of it, and — more importantly — no provider can omit it. A
// provider that returned from Present before its API had pushed the record to
// the edge would otherwise have the CA query a nameserver that does not have
// the record yet; the authorization goes to "invalid", and on Let's Encrypt a
// run of invalid authorizations is itself rate limited.
type dns01Solver struct {
	provider dns01.Provider
	lookup   dns01.TXTLookup
	logger   *slog.Logger

	// propagationTimeout and pollInterval are fields rather than constants so a
	// test can exercise the timeout path in milliseconds. Production values are
	// set from the constants above at construction.
	propagationTimeout time.Duration
	pollInterval       time.Duration

	// mu guards pending, which maps an ACME identifier to the cleanup for the
	// record created for it. Orders run one identifier at a time today, but the
	// map is guarded because cleanup also runs from the detached shutdown path.
	mu      sync.Mutex
	pending map[string]dns01.CleanupFunc
}

var _ acmeSolver = (*dns01Solver)(nil)

// newDNS01Solver builds the solver around a provider and a TXT lookup.
func newDNS01Solver(provider dns01.Provider, lookup dns01.TXTLookup, logger *slog.Logger) *dns01Solver {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &dns01Solver{
		provider:           provider,
		lookup:             lookup,
		logger:             logger,
		propagationTimeout: dns01PropagationTimeout,
		pollInterval:       dns01PollInterval,
		pending:            make(map[string]dns01.CleanupFunc),
	}
}

func (s *dns01Solver) name() string          { return "dns_01" }
func (s *dns01Solver) challengeType() string { return "dns-01" }

// present publishes the challenge record and returns only once every
// authoritative nameserver is serving it.
//
// The order of operations is the security content of this function:
//
//  1. The cleanup is registered the moment the provider returns one, BEFORE
//     anything can fail. The caller's deferred release therefore removes the
//     record even if this function goes on to return an error, and even if the
//     process is shutting down.
//  2. Propagation is confirmed before returning nil. Returning nil is what
//     causes the caller to tell the CA to validate, so nil must mean "the CA
//     will find this record", not "the API accepted my request".
func (s *dns01Solver) present(
	ctx context.Context, client *acme.Client, chal *acme.Challenge, identifier string,
) error {
	// DNS01ChallengeRecord returns the base64url SHA-256 digest of the key
	// authorization. The key authorization itself never leaves this call, and
	// the digest is a value designed to be published in public DNS — so the
	// record's name and value may be logged, and the input to the digest may
	// not be, which is why only the return value is ever carried onward.
	value, err := client.DNS01ChallengeRecord(chal.Token)
	if err != nil {
		return fmt.Errorf("build dns-01 record value: %w", err)
	}

	rec := dns01.Record{Name: dns01.ChallengeRecordName(identifier), Value: value}

	cleanup, presentErr := s.provider.Present(ctx, rec)
	if cleanup != nil {
		// Registered even when Present also returned an error: a provider that
		// created the record and then failed still hands back the cleanup, and
		// dropping it here would leak the record with nothing able to remove it.
		s.mu.Lock()
		s.pending[identifier] = cleanup
		s.mu.Unlock()
	}
	if presentErr != nil {
		return fmt.Errorf("%s provider: %w", s.provider.Name(), presentErr)
	}

	return s.awaitPropagation(ctx, rec)
}

// awaitPropagation polls until every authoritative nameserver serves the
// record's value, or fails closed.
//
// Every exit that is not "the value was observed" is an error. Not a warning,
// not a shorter wait, not a proceed-and-hope: an expired deadline and a
// canceled context both mean the record was never seen, and the only safe
// reading of "never seen" is that the CA will not see it either.
func (s *dns01Solver) awaitPropagation(ctx context.Context, rec dns01.Record) error {
	deadline, cancel := context.WithTimeout(ctx, s.propagationTimeout)
	defer cancel()

	ticker := time.NewTicker(s.pollInterval)
	defer ticker.Stop()

	for {
		values, err := s.lookup(deadline, rec.Name)
		// A lookup error is treated as "not yet", not as a failure: a zone
		// mid-update legitimately answers SERVFAIL or NXDOMAIN, and the bounded
		// deadline is what stops that from becoming an unbounded wait.
		if err == nil && slices.Contains(values, rec.Value) {
			return nil
		}

		select {
		case <-deadline.Done():
			// The record name is named; the value is not, because there is
			// nothing to diagnose in a digest and the name is what the operator
			// must go and check.
			//
			// A canceled parent and an expired budget both arrive here, because
			// deadline derives from ctx. They fail identically — the record was
			// never seen either way, which is the only safe reading — but they
			// are reported differently. Saying "not visible after 10m0s" when
			// the process was shut down two seconds in sends the operator to
			// investigate a DNS problem that never existed.
			//
			// The ErrDNS01Propagation identity is kept on BOTH paths rather
			// than replaced by ctx.Err(), so callers and tests matching the
			// sentinel keep working; the cancellation cause is wrapped
			// alongside it, so errors.Is finds context.Canceled too.
			if cause := ctx.Err(); cause != nil {
				return fmt.Errorf("%w: %q not confirmed before the wait was canceled: %w",
					ErrDNS01Propagation, rec.Name, cause)
			}
			return fmt.Errorf("%w: %q not visible on all authoritative nameservers after %s",
				ErrDNS01Propagation, rec.Name, s.propagationTimeout)
		case <-ticker.C:
		}
	}
}

// cleanup removes the record present created, and reports failure loudly.
//
// A cleanup failure is the one DNS-01 error worth logging on its own: it leaves
// an _acme-challenge TXT record published in a zone this process will not touch
// again, which is a standing authorization for whoever can still answer it. The
// operator has to remove it by hand, so they have to be told.
//
// Only the record NAME reaches the log. The provider's error is included
// because no provider may put a credential in one; the credential is never in
// scope at this layer at all.
func (s *dns01Solver) cleanup(ctx context.Context, identifier string) error {
	s.mu.Lock()
	fn, ok := s.pending[identifier]
	delete(s.pending, identifier)
	s.mu.Unlock()

	if !ok {
		// present never got as far as creating anything, or cleanup already
		// ran. Nothing to withdraw is success, which is what makes the caller's
		// unconditional deferred release safe.
		return nil
	}

	if err := fn(ctx); err != nil {
		s.logger.Error(
			"dns-01 challenge record could not be removed and must be deleted by hand",
			slog.String("record_type", "TXT"),
			slog.String("record_name", dns01.ChallengeRecordName(identifier)),
			slog.String("dns_provider", s.provider.Name()),
			slog.String("error", err.Error()),
		)
		return err
	}
	return nil
}
