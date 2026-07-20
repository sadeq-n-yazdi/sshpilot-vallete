package httpserver

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/acme"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/dns01"
)

// fakeDNSProvider is a [dns01.Provider] that records what was published and
// whether it was withdrawn. No test in this file contacts Cloudflare or any
// other DNS host.
type fakeDNSProvider struct {
	mu sync.Mutex

	// live holds the records currently published. A leaked challenge record is
	// exactly a non-empty live set after an order has settled, which is what the
	// cleanup tests assert on.
	live map[string]string
	// presented counts Present calls, so a test can tell "never created" apart
	// from "created and removed".
	presented int
	// cleaned counts successful cleanups.
	cleaned int

	// presentErr makes Present fail AFTER creating the record, which is the
	// dangerous shape: a provider that half-succeeded still owes the caller a
	// cleanup, and dropping it would leak the record with nothing able to
	// remove it.
	presentErr error
	// cleanupErr makes the cleanup itself fail.
	cleanupErr error
}

func newFakeDNSProvider() *fakeDNSProvider {
	return &fakeDNSProvider{live: map[string]string{}}
}

func (f *fakeDNSProvider) Name() string { return "fake" }

func (f *fakeDNSProvider) Present(_ context.Context, rec dns01.Record) (dns01.CleanupFunc, error) {
	f.mu.Lock()
	f.presented++
	f.live[rec.Name] = rec.Value
	f.mu.Unlock()

	cleanup := func(context.Context) error {
		if f.cleanupErr != nil {
			return f.cleanupErr
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		delete(f.live, rec.Name)
		f.cleaned++
		return nil
	}
	return cleanup, f.presentErr
}

func (f *fakeDNSProvider) liveCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.live)
}

// publishedValue returns the value the provider currently serves for a name, so
// the propagation fake can be wired to the provider's real state.
func (f *fakeDNSProvider) publishedValue(name string) (string, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.live[name]
	return v, ok
}

// propagatedLookup is a [dns01.TXTLookup] that reports whatever the fake
// provider has actually published — so propagation succeeds only when the
// record genuinely exists.
func propagatedLookup(f *fakeDNSProvider) dns01.TXTLookup {
	return func(_ context.Context, name string) ([]string, error) {
		if v, ok := f.publishedValue(name); ok {
			return []string{v}, nil
		}
		return nil, nil
	}
}

// neverPropagates is a [dns01.TXTLookup] that never sees the record, modeling
// a zone that has not converged (or, in manual mode, an operator who never
// published anything).
func neverPropagates(context.Context, string) ([]string, error) { return nil, nil }

// testSolver builds a DNS-01 solver with a millisecond propagation budget, so
// the timeout path runs in a test rather than in ten real minutes.
func testSolver(t *testing.T, provider dns01.Provider, lookup dns01.TXTLookup) (*dns01Solver, *bytes.Buffer) {
	t.Helper()

	var logs bytes.Buffer
	s := newDNS01Solver(provider, lookup, slog.New(slog.NewTextHandler(&logs, nil)))
	s.propagationTimeout = 200 * time.Millisecond
	s.pollInterval = 5 * time.Millisecond
	return s, &logs
}

// testACMEClient builds a client good enough to derive a DNS-01 record value.
// DNS01ChallengeRecord is a local computation over the challenge token and the
// account key's public part, so it needs no CA.
func testACMEClient(t *testing.T) *acme.Client {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate account key: %v", err)
	}
	return &acme.Client{Key: key}
}

func testChallenge() *acme.Challenge {
	return &acme.Challenge{Type: "dns-01", Token: "challenge-token", URI: "https://ca.invalid/chal/1"}
}

const testIdentifier = "vallet.example.com"

// TestDNS01RecordIsRemovedOnSuccess proves the ordinary path leaves nothing
// behind. A leftover _acme-challenge record is a standing authorization for
// whoever can still satisfy it, so it must not survive even a successful order.
func TestDNS01RecordIsRemovedOnSuccess(t *testing.T) {
	t.Parallel()

	provider := newFakeDNSProvider()
	solver, _ := testSolver(t, provider, propagatedLookup(provider))

	if err := solver.present(t.Context(), testACMEClient(t), testChallenge(), testIdentifier); err != nil {
		t.Fatalf("present: %v", err)
	}
	if provider.liveCount() != 1 {
		t.Fatal("present published no record")
	}

	if err := solver.cleanup(t.Context(), testIdentifier); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if provider.liveCount() != 0 {
		t.Error("the challenge record survived a successful order; it is a standing " +
			"authorization for anyone who can still answer it")
	}
}

// TestDNS01RecordIsRemovedWhenPresentFails is the leak-on-failure test.
//
// The provider creates the record and THEN reports failure. That is the shape
// that leaks: the record exists, but the naive reading of the error is "nothing
// happened, nothing to clean up". The cleanup must still remove it.
func TestDNS01RecordIsRemovedWhenPresentFails(t *testing.T) {
	t.Parallel()

	provider := newFakeDNSProvider()
	provider.presentErr = errors.New("api rejected the change after creating it")
	solver, _ := testSolver(t, provider, propagatedLookup(provider))

	if err := solver.present(t.Context(), testACMEClient(t), testChallenge(), testIdentifier); err == nil {
		t.Fatal("present succeeded against a failing provider")
	}
	if provider.liveCount() != 1 {
		t.Fatal("the fake provider did not create the record it was supposed to leak")
	}

	if err := solver.cleanup(t.Context(), testIdentifier); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if provider.liveCount() != 0 {
		t.Error("a record created by a Present that then failed was never removed")
	}
}

// TestDNS01RecordIsRemovedOnPropagationTimeout covers the most likely real
// failure: the record was created, the zone never converged, the order is
// abandoned. The record must not be abandoned with it.
func TestDNS01RecordIsRemovedOnPropagationTimeout(t *testing.T) {
	t.Parallel()

	provider := newFakeDNSProvider()
	solver, _ := testSolver(t, provider, neverPropagates)

	err := solver.present(t.Context(), testACMEClient(t), testChallenge(), testIdentifier)
	if !errors.Is(err, ErrDNS01Propagation) {
		t.Fatalf("present: %v, want ErrDNS01Propagation", err)
	}

	if err := solver.cleanup(t.Context(), testIdentifier); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if provider.liveCount() != 0 {
		t.Error("the challenge record outlived a timed-out order")
	}
}

// TestDNS01RecordIsRemovedOnCancellation proves cleanup still works once the
// caller's context is dead.
//
// This is the shutdown case. Close cancels the renewal loop's context, so a
// shutdown mid-order hands cleanup an already-canceled context; a cleanup that
// used it would have its delete fail without ever being sent, leaving the
// record published beyond the life of the process that created it. The solver's
// caller detaches the context precisely so this works.
func TestDNS01RecordIsRemovedOnCancellation(t *testing.T) {
	t.Parallel()

	provider := newFakeDNSProvider()
	solver, _ := testSolver(t, provider, neverPropagates)

	ctx, cancel := context.WithCancel(t.Context())
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()

	if err := solver.present(ctx, testACMEClient(t), testChallenge(), testIdentifier); err == nil {
		t.Fatal("present succeeded despite cancellation and no propagation")
	}
	if provider.liveCount() != 1 {
		t.Fatal("the record under test was never created")
	}

	// The detached context the provider's caller supplies. A canceled ctx here
	// is what the naive implementation would pass.
	detached, detachedCancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
	defer detachedCancel()

	if err := solver.cleanup(detached, testIdentifier); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if provider.liveCount() != 0 {
		t.Error("the challenge record survived a canceled order")
	}
}

// TestDNS01FailsClosedWithoutPropagation is the must-not-regress invariant.
//
// present returning nil is what causes the caller to tell the CA to validate.
// It must therefore mean "every authoritative nameserver is already serving
// this record", never "the provider's API accepted my request". A solver that
// skipped the wait would return nil here, the CA would query a nameserver
// without the record, and the authorization would go invalid — which on Let's
// Encrypt counts against a failed-authorization rate limit.
func TestDNS01FailsClosedWithoutPropagation(t *testing.T) {
	t.Parallel()

	provider := newFakeDNSProvider()
	solver, _ := testSolver(t, provider, neverPropagates)

	start := time.Now()
	err := solver.present(t.Context(), testACMEClient(t), testChallenge(), testIdentifier)

	if !errors.Is(err, ErrDNS01Propagation) {
		t.Fatalf("present with an unpropagated record = %v, want ErrDNS01Propagation: "+
			"proceeding would tell the CA to validate a record it cannot see", err)
	}
	if elapsed := time.Since(start); elapsed < solver.propagationTimeout {
		t.Errorf("present returned after %s, before the %s propagation budget elapsed",
			elapsed, solver.propagationTimeout)
	}
}

// TestDNS01WaitsForTheExactValue proves the gate checks the VALUE, not merely
// that some record exists at the name.
//
// A stale TXT record from a previous order sits at the same name. Accepting it
// would let a leftover from an earlier attempt satisfy the gate for a challenge
// whose token is different, and the CA would then reject the authorization.
func TestDNS01WaitsForTheExactValue(t *testing.T) {
	t.Parallel()

	provider := newFakeDNSProvider()
	stale := func(context.Context, string) ([]string, error) {
		return []string{"a-value-from-a-previous-order"}, nil
	}
	solver, _ := testSolver(t, provider, stale)

	if err := solver.present(t.Context(), testACMEClient(t), testChallenge(), testIdentifier); !errors.Is(err, ErrDNS01Propagation) {
		t.Errorf("present with only a stale value visible = %v, want ErrDNS01Propagation", err)
	}
}

// TestManualDNS01CannotSucceedWithoutTheRecord is the manual-mode invariant.
//
// The manual provider creates nothing, so the only thing that can make the
// order proceed is an operator publishing the record. With nobody publishing,
// present must fail rather than time out into a success — an unattended manual
// deployment must never look like it issued.
func TestManualDNS01CannotSucceedWithoutTheRecord(t *testing.T) {
	t.Parallel()

	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	solver, _ := testSolver(t, dns01.NewManualProvider(logger), neverPropagates)

	err := solver.present(t.Context(), testACMEClient(t), testChallenge(), testIdentifier)
	if !errors.Is(err, ErrDNS01Propagation) {
		t.Fatalf("manual present with no record published = %v, want ErrDNS01Propagation", err)
	}
	if !strings.Contains(logs.String(), "_acme-challenge."+testIdentifier) {
		t.Error("the operator was never shown the record they must publish")
	}
}

// TestDNS01CleanupIsSafeWhenNothingWasPresented proves the caller's
// unconditional deferred release is safe.
//
// The release runs even when present never got as far as creating anything —
// for instance when the CA offered no dns-01 challenge at all. That must be a
// no-op, because making it an error would turn "nothing to clean up" into a
// failure that masks the real one.
func TestDNS01CleanupIsSafeWhenNothingWasPresented(t *testing.T) {
	t.Parallel()

	provider := newFakeDNSProvider()
	solver, _ := testSolver(t, provider, propagatedLookup(provider))

	if err := solver.cleanup(t.Context(), testIdentifier); err != nil {
		t.Errorf("cleanup with nothing pending: %v, want nil", err)
	}
	// Twice, because cleanup runs from both the deferred release and any
	// caller-side retry.
	if err := solver.cleanup(t.Context(), testIdentifier); err != nil {
		t.Errorf("second cleanup: %v, want nil", err)
	}
}

// TestDNS01CleanupFailureIsReportedLoudly proves a failed withdrawal is not
// swallowed.
//
// It is the one DNS-01 error worth logging on its own: it leaves a challenge
// record published in a zone this process will not touch again, so the operator
// has to delete it by hand and therefore has to be told which record.
func TestDNS01CleanupFailureIsReportedLoudly(t *testing.T) {
	t.Parallel()

	provider := newFakeDNSProvider()
	provider.cleanupErr = errors.New("api unavailable")
	solver, logs := testSolver(t, provider, propagatedLookup(provider))

	if err := solver.present(t.Context(), testACMEClient(t), testChallenge(), testIdentifier); err != nil {
		t.Fatalf("present: %v", err)
	}
	if err := solver.cleanup(t.Context(), testIdentifier); err == nil {
		t.Fatal("a failed cleanup reported success")
	}

	out := logs.String()
	if !strings.Contains(out, "level=ERROR") || !strings.Contains(out, "_acme-challenge."+testIdentifier) {
		t.Errorf("a record that must be deleted by hand was not reported with its name: %s", out)
	}
}

// TestSolveAuthorizationCleansUpWhenPresentFails is the ORDERING test.
//
// The invariant is not "cleanup exists" but "cleanup is armed BEFORE the
// challenge is presented". A solver that publishes a record and then fails has
// already created the thing that must be withdrawn, so arming cleanup only
// after a successful present leaks on exactly the paths where a leftover
// challenge record is most likely.
//
// It is driven through the real solveAuthorization against a local fake CA, so
// what is asserted is the production call path rather than a hand-rolled
// imitation of it.
func TestSolveAuthorizationCleansUpWhenPresentFails(t *testing.T) {
	t.Parallel()

	recorder := &recordingSolver{presentErr: errors.New("propagation never confirmed")}
	p, authzURL := acmeProviderAgainstFakeCA(t, recorder)

	if err := p.solveAuthorization(t.Context(), authzURL); err == nil {
		t.Fatal("solveAuthorization succeeded with a failing solver")
	}

	if recorder.cleanups != 1 {
		t.Errorf("cleanup ran %d times after a failed present, want 1: a challenge "+
			"created by a present that then failed would otherwise be left standing",
			recorder.cleanups)
	}
	if recorder.accepts != 0 {
		t.Error("the CA was told to validate a challenge that was never successfully presented")
	}
}

// TestSolveAuthorizationCleansUpOnSuccess proves the withdrawal is not
// conditional on failure either: a settled authorization needs no challenge
// left installed.
func TestSolveAuthorizationCleansUpOnSuccess(t *testing.T) {
	t.Parallel()

	recorder := &recordingSolver{}
	p, authzURL := acmeProviderAgainstFakeCA(t, recorder)

	if err := p.solveAuthorization(t.Context(), authzURL); err != nil {
		t.Fatalf("solveAuthorization: %v", err)
	}
	if recorder.cleanups != 1 {
		t.Errorf("cleanup ran %d times on the success path, want 1", recorder.cleanups)
	}
}

// TestSolveAuthorizationRefusesAChallengeTypeItDidNotChoose proves no silent
// downgrade. The fake CA offers only tls-alpn-01; a dns-01 solver must refuse
// rather than answer the challenge that happens to be on offer.
func TestSolveAuthorizationRefusesAChallengeTypeItDidNotChoose(t *testing.T) {
	t.Parallel()

	recorder := &recordingSolver{challenge: "dns-01"}
	p, authzURL := acmeProviderAgainstFakeCA(t, recorder)

	err := p.solveAuthorization(t.Context(), authzURL)
	if !errors.Is(err, ErrACMEIssuance) {
		t.Fatalf("solveAuthorization = %v, want ErrACMEIssuance", err)
	}
	if recorder.presents != 0 || recorder.accepts != 0 {
		t.Error("a challenge type the operator did not select was answered anyway")
	}
}

// recordingSolver is an [acmeSolver] that counts calls, so the ordering of
// present, accept and cleanup can be asserted directly.
type recordingSolver struct {
	challenge  string
	presentErr error

	presents int
	cleanups int
	accepts  int
}

func (r *recordingSolver) name() string { return "recording" }

func (r *recordingSolver) challengeType() string {
	if r.challenge != "" {
		return r.challenge
	}
	return "tls-alpn-01"
}

func (r *recordingSolver) present(context.Context, *acme.Client, *acme.Challenge, string) error {
	r.presents++
	return r.presentErr
}

func (r *recordingSolver) cleanup(context.Context, string) error {
	r.cleanups++
	return nil
}

// acmeProviderAgainstFakeCA builds a provider wired to a local HTTP stand-in
// for an ACME CA, returning the authorization URL to solve.
//
// The fake answers only what solveAuthorization needs — a directory, nonces, an
// authorization and a challenge accept — which is enough to exercise the real
// ordering without a CA. Nothing here reaches the network.
func acmeProviderAgainstFakeCA(t *testing.T, solver acmeSolver) (*acmeProvider, string) {
	t.Helper()

	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	nonce := func(w http.ResponseWriter) { w.Header().Set("Replay-Nonce", "AAAAAAAAAAAAAAAAAAAAAAAA") }

	mux.HandleFunc("/dir", func(w http.ResponseWriter, _ *http.Request) {
		nonce(w)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"newNonce":   srv.URL + "/nonce",
			"newAccount": srv.URL + "/acct",
			"newOrder":   srv.URL + "/order",
		})
	})
	mux.HandleFunc("/nonce", func(w http.ResponseWriter, _ *http.Request) { nonce(w) })

	// accepted flips once the challenge has been accepted, so the first
	// GetAuthorization sees "pending" (otherwise solveAuthorization would
	// short-circuit on an already-valid authorization and never call the
	// solver) and the WaitAuthorization poll afterwards sees "valid".
	var mu sync.Mutex
	accepted := false

	mux.HandleFunc("/authz/1", func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		status := "pending"
		if accepted {
			status = "valid"
		}
		mu.Unlock()

		nonce(w)
		// Only tls-alpn-01 is offered, which is what makes the
		// wrong-challenge-type case above meaningful.
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":     status,
			"identifier": map[string]string{"type": "dns", "value": testIdentifier},
			"challenges": []map[string]string{
				{"type": "tls-alpn-01", "url": srv.URL + "/chal/1", "token": "tok", "status": "pending"},
			},
		})
	})
	mux.HandleFunc("/chal/1", func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		accepted = true
		if r, ok := solver.(*recordingSolver); ok {
			r.accepts++
		}
		mu.Unlock()

		nonce(w)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"type": "tls-alpn-01", "url": srv.URL + "/chal/1", "token": "tok", "status": "valid",
		})
	})

	client := testACMEClient(t)
	client.DirectoryURL = srv.URL + "/dir"

	p := &acmeProvider{
		client:    client,
		domains:   []string{testIdentifier},
		cacheDir:  t.TempDir(),
		now:       time.Now,
		challenge: map[string]*tls.Certificate{},
		solver:    solver,
		stop:      func() {},
		done:      make(chan struct{}),
	}
	return p, srv.URL + "/authz/1"
}
