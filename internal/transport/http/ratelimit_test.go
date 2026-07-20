package httpserver

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/config"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/counter"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/ratelimit"
)

// rlClock is a hand-wound clock, so Retry-After can be asserted at an exact
// instant instead of being sampled from a real one.
type rlClock struct {
	mu sync.Mutex
	t  time.Time
}

func newRLClock() *rlClock {
	return &rlClock{t: time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)}
}

func (c *rlClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *rlClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// rlFailingStore is an always-unavailable counter store, for the outage tests.
type rlFailingStore struct{}

func (rlFailingStore) Increment(context.Context, string, int64, time.Duration) (counter.Count, error) {
	return counter.Count{}, fmt.Errorf("down: %w", counter.ErrStoreUnavailable)
}

func (rlFailingStore) Get(context.Context, string) (counter.Count, error) {
	return counter.Count{}, fmt.Errorf("down: %w", counter.ErrStoreUnavailable)
}

func (rlFailingStore) Delete(context.Context, string) error {
	return fmt.Errorf("down: %w", counter.ErrStoreUnavailable)
}

// limitedHandler wraps an always-200 handler in the limiter under test.
func limitedHandler(t *testing.T, tier ratelimit.Tier, proxies trustedPeers, clk *rlClock) http.Handler {
	t.Helper()
	store, err := counter.NewMemoryStore(clk.now)
	if err != nil {
		t.Fatalf("NewMemoryStore: %v", err)
	}
	lim, err := ratelimit.NewLimiter(store, ratelimit.TierPublish, tier)
	if err != nil {
		t.Fatalf("NewLimiter: %v", err)
	}
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	return rateLimitMiddleware(lim, proxies, slog.New(slog.DiscardHandler))(ok)
}

func rlRequest(remoteAddr string, xff ...string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/alice/default", nil)
	r.RemoteAddr = remoteAddr
	for _, v := range xff {
		r.Header.Add(forwardedForHeader, v)
	}
	return r
}

// TestMiddlewareBoundaryAndRetryAfter covers the limit boundary and asserts the
// Retry-After VALUE, not merely its presence. A constant Retry-After is the
// easy bug: it looks correct in a header dump and is wrong for every request
// that is not the first in its window.
func TestMiddlewareBoundaryAndRetryAfter(t *testing.T) {
	t.Parallel()

	clk := newRLClock()
	h := limitedHandler(t, ratelimit.Tier{Limit: 3, Window: time.Minute}, newTrustedPeers(nil), clk)

	// Exactly at the limit: allowed.
	for i := 1; i <= 3; i++ {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, rlRequest("203.0.113.5:1"))
		if rec.Code != http.StatusOK {
			t.Fatalf("request #%d: status %d, want 200", i, rec.Code)
		}
		if got := rec.Header().Get(RetryAfterHeader); got != "" {
			t.Fatalf("request #%d carried Retry-After %q on a 200", i, got)
		}
	}

	// One over, 20s into the window: refused, and told to wait the REMAINING
	// 40s rather than the full window.
	clk.advance(20 * time.Second)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, rlRequest("203.0.113.5:1"))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("request #4: status %d, want 429", rec.Code)
	}
	if got, want := rec.Header().Get(RetryAfterHeader), "40"; got != want {
		t.Fatalf("Retry-After = %q, want %q (remaining window, not the full window)", got, want)
	}

	// Window rollover restores the budget.
	clk.advance(40 * time.Second)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, rlRequest("203.0.113.5:1"))
	if rec.Code != http.StatusOK {
		t.Fatalf("after rollover: status %d, want 200", rec.Code)
	}
}

// TestMiddlewareRetryAfterRoundsUp: a fractional remainder must round up, or a
// client obeying the header retries while the window is still open.
func TestMiddlewareRetryAfterRoundsUp(t *testing.T) {
	t.Parallel()

	clk := newRLClock()
	h := limitedHandler(t, ratelimit.Tier{Limit: 1, Window: time.Minute}, newTrustedPeers(nil), clk)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, rlRequest("203.0.113.5:1"))
	if rec.Code != http.StatusOK {
		t.Fatalf("first request: status %d, want 200", rec.Code)
	}

	// 19.5s in; 40.5s remain, which must be reported as 41, not 40.
	clk.advance(19*time.Second + 500*time.Millisecond)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, rlRequest("203.0.113.5:1"))
	if got, want := rec.Header().Get(RetryAfterHeader), "41"; got != want {
		t.Fatalf("Retry-After = %q, want %q (must round up)", got, want)
	}
}

// TestMiddlewareSpoofingDoesNotMultiplyBuckets is the spoofing test at the
// middleware level. An attacker who can steer the key gets an unbounded number
// of buckets, so the limit is never reached -- a complete bypass rather than a
// weakened limit.
func TestMiddlewareSpoofingDoesNotMultiplyBuckets(t *testing.T) {
	t.Parallel()

	t.Run("untrusted peer cannot escape its bucket", func(t *testing.T) {
		t.Parallel()

		clk := newRLClock()
		h := limitedHandler(t, ratelimit.Tier{Limit: 2, Window: time.Minute},
			newTrustedPeers([]string{"10.0.0.1"}), clk)

		// One attacker, a fresh forged X-Forwarded-For on every request. All of
		// them must land in the same bucket.
		var last int
		for i := range 5 {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, rlRequest("203.0.113.5:1", fmt.Sprintf("9.9.9.%d", i)))
			last = rec.Code
		}
		if last != http.StatusTooManyRequests {
			t.Fatalf("5 requests with rotating forged X-Forwarded-For ended in %d, want 429; "+
				"the attacker got a fresh bucket per request", last)
		}
	})

	t.Run("trusted proxy separates real clients", func(t *testing.T) {
		t.Parallel()

		clk := newRLClock()
		h := limitedHandler(t, ratelimit.Tier{Limit: 2, Window: time.Minute},
			newTrustedPeers([]string{"10.0.0.1"}), clk)

		// Exhaust one client's budget through the proxy.
		for range 3 {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, rlRequest("10.0.0.1:1", "198.51.100.7"))
			_ = rec
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, rlRequest("10.0.0.1:1", "198.51.100.7"))
		if rec.Code != http.StatusTooManyRequests {
			t.Fatalf("exhausted client got %d, want 429", rec.Code)
		}

		// A DIFFERENT real client behind the same proxy must be unaffected;
		// otherwise one client could lock out everyone behind the proxy.
		rec = httptest.NewRecorder()
		h.ServeHTTP(rec, rlRequest("10.0.0.1:1", "198.51.100.8"))
		if rec.Code != http.StatusOK {
			t.Fatalf("second client behind the proxy got %d, want 200", rec.Code)
		}
	})
}

// TestMiddlewareOutagePolicy drives both tier policies through the HTTP layer,
// against a store that is genuinely down.
func TestMiddlewareOutagePolicy(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		failOpen bool
		want     int
	}{
		{"fail-open tier keeps serving", true, http.StatusOK},
		{"fail-closed tier refuses", false, http.StatusTooManyRequests},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			lim, err := ratelimit.NewLimiter(rlFailingStore{}, ratelimit.TierPublish,
				ratelimit.Tier{Limit: 5, Window: time.Minute, FailOpen: tc.failOpen})
			if err != nil {
				t.Fatalf("NewLimiter: %v", err)
			}
			ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
			h := rateLimitMiddleware(lim, newTrustedPeers(nil), slog.New(slog.DiscardHandler))(ok)

			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, rlRequest("203.0.113.5:1"))
			if rec.Code != tc.want {
				t.Fatalf("status %d, want %d", rec.Code, tc.want)
			}
			if tc.want == http.StatusTooManyRequests && rec.Header().Get(RetryAfterHeader) != "60" {
				t.Fatalf("Retry-After = %q, want the full window \"60\"", rec.Header().Get(RetryAfterHeader))
			}
		})
	}
}

// TestMiddlewareUnresolvableClientIsRefused: an exemption for callers whose
// origin we cannot parse is one an attacker would reach for first.
func TestMiddlewareUnresolvableClientIsRefused(t *testing.T) {
	t.Parallel()

	clk := newRLClock()
	// A fail-OPEN tier, to prove the refusal is about the missing key rather
	// than about the outage policy.
	h := limitedHandler(t, ratelimit.Tier{Limit: 100, Window: time.Minute, FailOpen: true},
		newTrustedPeers(nil), clk)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, rlRequest("garbage"))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status %d, want 429 for an unresolvable client address", rec.Code)
	}
	if rec.Header().Get(RetryAfterHeader) != "60" {
		t.Fatalf("Retry-After = %q, want \"60\"", rec.Header().Get(RetryAfterHeader))
	}
}

// TestMiddlewareNilLimiterIsPassThrough covers the disabled state ADR-0023
// requires for deployments behind an external limiter.
func TestMiddlewareNilLimiterIsPassThrough(t *testing.T) {
	t.Parallel()

	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	h := rateLimitMiddleware(nil, newTrustedPeers(nil), nil)(ok)
	for range 50 {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, rlRequest("203.0.113.5:1"))
		if rec.Code != http.StatusOK {
			t.Fatalf("status %d with rate limiting disabled, want 200", rec.Code)
		}
	}
}

// TestMiddlewareNilLoggerIsTolerated: losing logs must never be why a request
// fails.
func TestMiddlewareNilLoggerIsTolerated(t *testing.T) {
	t.Parallel()

	lim, err := ratelimit.NewLimiter(rlFailingStore{}, ratelimit.TierPublish,
		ratelimit.Tier{Limit: 1, Window: time.Minute, FailOpen: true})
	if err != nil {
		t.Fatalf("NewLimiter: %v", err)
	}
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	h := rateLimitMiddleware(lim, newTrustedPeers(nil), nil)(ok)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, rlRequest("203.0.113.5:1"))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200", rec.Code)
	}
	// And the unresolvable-address branch, which also logs.
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, rlRequest("garbage"))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status %d, want 429", rec.Code)
	}
}

// TestRateLimitedResponseLeaksNothing: the body must not report the count, the
// limit, or the tier, which would be a calibration oracle for pacing a slower
// campaign under the threshold.
func TestRateLimitedResponseLeaksNothing(t *testing.T) {
	t.Parallel()

	clk := newRLClock()
	h := limitedHandler(t, ratelimit.Tier{Limit: 1, Window: time.Minute}, newTrustedPeers(nil), clk)
	h.ServeHTTP(httptest.NewRecorder(), rlRequest("203.0.113.5:1"))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, rlRequest("203.0.113.5:1"))
	if got, want := rec.Body.String(), "{\"status\":\"error\"}\n"; got != want {
		t.Fatalf("body = %q, want %q", got, want)
	}
}

// TestPublishRoutesAreLimitedButHealthIsNot: a shared limit would let publish
// traffic starve the liveness probe and get a healthy instance killed.
func TestPublishRoutesAreLimitedButHealthIsNot(t *testing.T) {
	t.Parallel()

	cfg := config.Default()
	cfg.RateLimit.Tiers.Publish = config.Tier{Requests: 2, Window: config.Duration(time.Minute)}
	h := NewHandler(&cfg, slog.New(slog.DiscardHandler), okPinger{}, stubPublisher{body: []byte("k\n")})

	// Publish is limited.
	var last int
	for range 5 {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/alice/default", nil)
		req.RemoteAddr = "203.0.113.5:1"
		h.ServeHTTP(rec, req)
		last = rec.Code
	}
	if last != http.StatusTooManyRequests {
		t.Fatalf("publish route status after 5 requests over a limit of 2 = %d, want 429", last)
	}

	// Health is not, from the very same address that just got limited.
	for range 20 {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
		req.RemoteAddr = "203.0.113.5:1"
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("/healthz status %d, want 200; the probe must never be rate limited", rec.Code)
		}
	}
}

// TestUnauthenticatedPublishingStillWorks: the tier keys on IP alone, so a
// bare curl with no credential must be served. Requiring auth here would break
// the deliberately-public surface of ADR-0019.
func TestUnauthenticatedPublishingStillWorks(t *testing.T) {
	t.Parallel()

	cfg := config.Default()
	h := NewHandler(&cfg, slog.New(slog.DiscardHandler), okPinger{}, stubPublisher{body: []byte("ssh-ed25519 AAAA x\n")})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/alice/default", nil)
	req.RemoteAddr = "203.0.113.5:1"
	// Deliberately no Authorization header.
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("unauthenticated publish fetch = %d, want 200", rec.Code)
	}
	if rec.Body.String() != "ssh-ed25519 AAAA x\n" {
		t.Fatalf("body = %q", rec.Body.String())
	}
}

// TestRateLimitDisabledByConfig covers the ADR's requirement that limits be
// disableable for deployments behind a trusted external limiter.
func TestRateLimitDisabledByConfig(t *testing.T) {
	t.Parallel()

	cfg := config.Default()
	cfg.RateLimit.Enabled = false
	h := NewHandler(&cfg, slog.New(slog.DiscardHandler), okPinger{}, stubPublisher{body: []byte("k\n")})

	for i := range 100 {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/alice/default", nil)
		req.RemoteAddr = "203.0.113.5:1"
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("request #%d = %d with rate limiting disabled, want 200", i+1, rec.Code)
		}
	}
}

func TestTiersFromConfig(t *testing.T) {
	t.Parallel()

	t.Run("nil config yields the defaults", func(t *testing.T) {
		t.Parallel()
		if got, want := tiersFromConfig(nil), ratelimit.DefaultTiers(); got != want {
			t.Fatalf("tiersFromConfig(nil) = %+v, want %+v", got, want)
		}
	})

	t.Run("config overrides the numbers", func(t *testing.T) {
		t.Parallel()

		cfg := config.Default()
		cfg.RateLimit.Tiers = config.RateLimitTiers{
			Auth:       config.Tier{Requests: 7, Window: config.Duration(2 * time.Minute)},
			Publish:    config.Tier{Requests: 11, Window: config.Duration(3 * time.Minute)},
			Management: config.Tier{Requests: 13, Window: config.Duration(4 * time.Minute)},
			Admin:      config.Tier{Requests: 17, Window: config.Duration(5 * time.Minute)},
		}
		got := tiersFromConfig(&cfg)

		if got.Auth.Limit != 7 || got.Auth.Window != 2*time.Minute {
			t.Errorf("auth = %+v", got.Auth)
		}
		if got.Publish.Limit != 11 || got.Publish.Window != 3*time.Minute {
			t.Errorf("publish = %+v", got.Publish)
		}
		if got.Management.Limit != 13 || got.Management.Window != 4*time.Minute {
			t.Errorf("management = %+v", got.Management)
		}
		if got.Admin.Limit != 17 || got.Admin.Window != 5*time.Minute {
			t.Errorf("admin = %+v", got.Admin)
		}

		// The outage policy and the backoff constants are NOT config-derived;
		// they must survive an override of the numbers.
		def := ratelimit.DefaultTiers()
		if got.Publish.FailOpen != def.Publish.FailOpen || got.Management.FailOpen != def.Management.FailOpen {
			t.Error("config override changed the fail-open policy")
		}
		if got.Auth.Horizon != def.Auth.Horizon || got.Auth.Cap != def.Auth.Cap {
			t.Error("config override changed the backoff constants")
		}
	})

	t.Run("non-positive values keep the defaults", func(t *testing.T) {
		t.Parallel()

		// Config validation rejects these, so reaching here means validation
		// was bypassed; a zero must never be read as "no limit".
		cfg := config.Default()
		cfg.RateLimit.Tiers = config.RateLimitTiers{}
		if got, want := tiersFromConfig(&cfg), ratelimit.DefaultTiers(); got != want {
			t.Fatalf("tiersFromConfig(zeroed) = %+v, want the defaults %+v", got, want)
		}
	})
}

func TestNewLimitStore(t *testing.T) {
	t.Parallel()

	if newLimitStore(nil, nil) == nil {
		t.Error("newLimitStore(nil cfg) = nil, want the memory store")
	}

	cfg := config.Default()
	cfg.RateLimit.Enabled = false
	if newLimitStore(&cfg, nil) != nil {
		t.Error("newLimitStore with rate limiting disabled returned a store")
	}

	// store: shared is not implemented yet; it must degrade to the memory store
	// rather than to no limiting at all.
	shared := config.Default()
	shared.RateLimit.Store = "shared"
	if newLimitStore(&shared, slog.New(slog.DiscardHandler)) == nil {
		t.Error("newLimitStore(shared) = nil, want a memory-store fallback")
	}
	if newLimitStore(&shared, nil) == nil {
		t.Error("newLimitStore(shared, nil logger) = nil")
	}
}

func TestNewPublishLimiter(t *testing.T) {
	t.Parallel()

	store, err := counter.NewMemoryStore(time.Now)
	if err != nil {
		t.Fatalf("NewMemoryStore: %v", err)
	}

	lim, err := newPublishLimiter(nil, store)
	if err != nil {
		t.Fatalf("newPublishLimiter: %v", err)
	}
	if lim == nil {
		t.Fatal("newPublishLimiter(nil cfg) = nil, want a limiter")
	}
	if lim.Tier().Limit != ratelimit.DefaultTiers().Publish.Limit {
		t.Errorf("limit = %d, want the default", lim.Tier().Limit)
	}

	// A nil store means disabled, and so does the config flag.
	if lim, err := newPublishLimiter(nil, nil); lim != nil || err != nil {
		t.Errorf("newPublishLimiter(nil store) = %v, %v; want nil, nil", lim, err)
	}
	cfg := config.Default()
	cfg.RateLimit.Enabled = false
	if lim, err := newPublishLimiter(&cfg, store); lim != nil || err != nil {
		t.Errorf("newPublishLimiter(disabled) = %v, %v; want nil, nil", lim, err)
	}
}

// TestMiddlewareConcurrentSameKey is the -race case at the HTTP layer: many
// simultaneous requests from one address must not over-admit. A non-atomic
// increment under-counts here and lets more than Limit through.
func TestMiddlewareConcurrentSameKey(t *testing.T) {
	t.Parallel()

	const (
		limit   = 25
		callers = 200
	)
	clk := newRLClock()
	h := limitedHandler(t, ratelimit.Tier{Limit: limit, Window: time.Minute}, newTrustedPeers(nil), clk)

	var (
		mu sync.Mutex
		ok int
		wg sync.WaitGroup
	)
	start := make(chan struct{})
	for range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, rlRequest("203.0.113.5:1"))
			if rec.Code == http.StatusOK {
				mu.Lock()
				ok++
				mu.Unlock()
			}
		}()
	}
	close(start)
	wg.Wait()

	if ok != limit {
		t.Fatalf("%d of %d concurrent requests admitted, want exactly %d", ok, callers, limit)
	}
}
