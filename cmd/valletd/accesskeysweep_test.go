package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/config"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/repository"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/secrets"
)

// testPepper is a fixed pepper of the required length. A constant is correct
// here: nothing in these tests turns on it being secret, only on it being long
// enough that the service consents to be constructed.
const testPepper = secrets.Redacted("0123456789abcdef0123456789abcdef")

// fakeKeySets satisfies the key set port so accesskey.New consents to build.
// The grace sweep never reaches it -- ExpireGrace lists and revokes, and only
// Mint resolves a key set -- but the constructor requires one, and embedding the
// port means a change that did reach for it would panic loudly here.
type fakeKeySets struct{ repository.KeySetRepository }

// fakeAccessKeys is an AccessKeyRepository holding rows in memory and enforcing
// the two predicates the real adapter enforces in SQL: only grace rows with an
// elapsed deadline are listed, and Revoke is keyed on id and owner. It embeds
// the port so a wiring change reaching for a method these tests do not model
// panics loudly rather than passing quietly.
type fakeAccessKeys struct {
	repository.AccessKeyRepository

	mu      sync.Mutex
	rows    map[domain.AccessKeyID]domain.AccessKey
	revoked chan domain.AccessKeyID
	limits  chan int
}

func newFakeAccessKeys(rows ...domain.AccessKey) *fakeAccessKeys {
	f := &fakeAccessKeys{
		rows:    make(map[domain.AccessKeyID]domain.AccessKey, len(rows)),
		revoked: make(chan domain.AccessKeyID, 16),
		limits:  make(chan int, 16),
	}
	for _, k := range rows {
		f.rows[k.ID] = k
	}
	return f
}

func (f *fakeAccessKeys) ListExpiredGrace(_ context.Context, now time.Time, limit int) ([]domain.AccessKey, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	select {
	case f.limits <- limit:
	default:
	}

	// The real adapter refuses a non-positive limit rather than coercing it, and
	// so does this: a wiring change that passed 0 must fail here rather than
	// quietly sweep under a bound nobody configured.
	if limit < 1 {
		return nil, domain.ErrInvalidInput
	}

	var out []domain.AccessKey
	for _, k := range f.rows {
		if k.Status != domain.AccessKeyStatusGrace || k.GraceUntil == nil {
			continue
		}
		if k.GraceUntil.After(now) {
			continue
		}
		if len(out) >= limit {
			break
		}
		out = append(out, k)
	}
	return out, nil
}

func (f *fakeAccessKeys) Revoke(_ context.Context, ownerID domain.OwnerID, id domain.AccessKeyID, now time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	k, ok := f.rows[id]
	if !ok || k.OwnerID != ownerID {
		return domain.ErrNotFound
	}
	k.Status = domain.AccessKeyStatusRevoked
	k.GraceUntil = nil
	k.RevokedAt = &now
	f.rows[id] = k
	select {
	case f.revoked <- id:
	default:
	}
	return nil
}

func (f *fakeAccessKeys) statusOf(id domain.AccessKeyID) domain.AccessKeyStatus {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.rows[id].Status
}

func graceKey(id domain.AccessKeyID, until time.Time) domain.AccessKey {
	return domain.AccessKey{
		ID:         id,
		OwnerID:    domain.OwnerID("owner-" + string(id)),
		KeySetID:   domain.KeySetID("set-" + string(id)),
		Name:       "name-" + string(id),
		Status:     domain.AccessKeyStatusGrace,
		GraceUntil: &until,
	}
}

// graceCfg enables the grace sweep at the given cadence and disables the handle
// sweep, so a test asserting on the grace sweep cannot be satisfied by the
// other one running.
func graceCfg(interval time.Duration) *config.Config {
	c := testCfg()
	c.Retention.HandleQuarantineSweepInterval = 0
	c.Retention.AccessKeyGraceSweepInterval = config.Duration(interval)
	return c
}

// TestAccessKeyGraceSweepIsWiredAndRuns is the regression test for the gap this
// change closes: ExpireGrace did not exist and ListExpiredGrace had no caller
// anywhere, so a lapsed grace row kept its grace status forever.
//
// Nothing here calls ExpireGrace. The only thing that can retire the row is the
// runner built from config and started by startSweeps, so a change that builds
// the runner and forgets the job fails here.
func TestAccessKeyGraceSweepIsWiredAndRuns(t *testing.T) {
	t.Parallel()

	const id = domain.AccessKeyID("lapsed")
	keys := newFakeAccessKeys(graceKey(id, time.Now().Add(-time.Hour)))

	runner, err := newSweepRunner(graceCfg(time.Millisecond), discardLogger(),
		fakeStore{keys: keys, keySets: fakeKeySets{}}, nopAppender{}, testPepper)
	if err != nil {
		t.Fatalf("newSweepRunner: %v", err)
	}
	if runner == nil {
		t.Fatal("runner is nil with a positive interval; the sweep would never run")
	}

	ctx, cancel := context.WithCancel(context.Background())
	join := startSweeps(ctx, runner)
	defer func() { cancel(); join() }()

	select {
	case got := <-keys.revoked:
		if got != id {
			t.Errorf("retired %q, want %q", got, id)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the grace expiry sweep never ran; it is not wired to anything")
	}
	if got := keys.statusOf(id); got != domain.AccessKeyStatusRevoked {
		t.Errorf("status after the sweep = %q, want %q", got, domain.AccessKeyStatusRevoked)
	}
}

// TestAccessKeyGraceSweepLeavesLiveWindowsAlone pins the deadline predicate. A
// credential inside the window it was promised must survive however often the
// sweep runs; retiring it early would break the rotation the window exists for.
func TestAccessKeyGraceSweepLeavesLiveWindowsAlone(t *testing.T) {
	t.Parallel()

	const (
		live   = domain.AccessKeyID("still-in-grace")
		lapsed = domain.AccessKeyID("elapsed")
	)
	keys := newFakeAccessKeys(
		graceKey(live, time.Now().Add(24*time.Hour)),
		graceKey(lapsed, time.Now().Add(-time.Hour)),
	)

	runner, err := newSweepRunner(graceCfg(time.Millisecond), discardLogger(),
		fakeStore{keys: keys, keySets: fakeKeySets{}}, nopAppender{}, testPepper)
	if err != nil {
		t.Fatalf("newSweepRunner: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	join := startSweeps(ctx, runner)

	select {
	case <-keys.revoked:
	case <-time.After(10 * time.Second):
		cancel()
		join()
		t.Fatal("the sweep never retired the lapsed credential")
	}
	// Several more passes at a 1ms cadence to get the live one wrong.
	time.Sleep(50 * time.Millisecond)
	cancel()
	join()

	if got := keys.statusOf(live); got != domain.AccessKeyStatusGrace {
		t.Errorf("a credential inside its grace window was retired: status = %q", got)
	}
	if got := keys.statusOf(lapsed); got != domain.AccessKeyStatusRevoked {
		t.Errorf("the lapsed credential was not retired: status = %q", got)
	}
}

// TestAccessKeyGraceSweepPassesTheConfiguredBatch pins that the operator's
// bound reaches the query. Unlike the handle sweep this is not merely tidiness:
// the access key repository rejects a non-positive limit, so a 0 would fail
// every pass rather than run a small one.
func TestAccessKeyGraceSweepPassesTheConfiguredBatch(t *testing.T) {
	t.Parallel()

	cfg := graceCfg(time.Millisecond)
	cfg.Retention.AccessKeyGraceSweepBatch = 9

	keys := newFakeAccessKeys()
	runner, err := newSweepRunner(cfg, discardLogger(), fakeStore{keys: keys, keySets: fakeKeySets{}}, nopAppender{}, testPepper)
	if err != nil {
		t.Fatalf("newSweepRunner: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	join := startSweeps(ctx, runner)
	defer func() { cancel(); join() }()

	select {
	case got := <-keys.limits:
		if got != 9 {
			t.Errorf("sweep asked for limit %d, want the configured 9", got)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the sweep never queried the repository")
	}
}

// TestAccessKeyGraceSweepDisabledByZeroInterval pins the off switch, which this
// sweep is entitled to because it enforces nothing: a credential past its
// deadline is refused by accesskey.Verify whether or not this ever runs.
func TestAccessKeyGraceSweepDisabledByZeroInterval(t *testing.T) {
	t.Parallel()

	const id = domain.AccessKeyID("lapsed")
	keys := newFakeAccessKeys(graceKey(id, time.Now().Add(-time.Hour)))

	runner, err := newSweepRunner(graceCfg(0), discardLogger(),
		fakeStore{keys: keys, keySets: fakeKeySets{}}, nopAppender{}, testPepper)
	if err != nil {
		t.Fatalf("newSweepRunner: %v", err)
	}
	if runner != nil {
		t.Fatal("both sweeps disabled must yield no runner")
	}

	ctx, cancel := context.WithCancel(context.Background())
	join := startSweeps(ctx, runner)
	time.Sleep(20 * time.Millisecond)
	cancel()
	join()

	if got := keys.statusOf(id); got != domain.AccessKeyStatusGrace {
		t.Errorf("a disabled sweep retired a credential: status = %q", got)
	}
}

// TestAccessKeyGraceSweepRefusesAnInadequatePepper is the fail-closed gate on
// construction. The sweep never hashes anything, so it would have been possible
// to satisfy the constructor with a throwaway value -- and the service that
// resulted would verify bearer tokens under a key nobody chose. Startup must
// refuse instead.
func TestAccessKeyGraceSweepRefusesAnInadequatePepper(t *testing.T) {
	t.Parallel()

	for _, pepper := range []secrets.Redacted{"", "too-short"} {
		_, err := newSweepRunner(graceCfg(time.Hour), discardLogger(),
			fakeStore{keys: newFakeAccessKeys(), keySets: fakeKeySets{}}, nopAppender{}, pepper)
		if err == nil {
			t.Errorf("a %d-byte pepper was accepted; startup must fail closed", len(pepper))
		}
	}
}

// TestSweepRunnerRegistersBothSweeps pins that enabling both yields both, and
// in particular that adding the second one did not displace the first.
func TestSweepRunnerRegistersBothSweeps(t *testing.T) {
	t.Parallel()

	cfg := testCfg()
	cfg.Retention.HandleQuarantineSweepInterval = config.Duration(time.Millisecond)
	cfg.Retention.AccessKeyGraceSweepInterval = config.Duration(time.Millisecond)

	handles := newFakeHandles(expiredHandle("h", time.Now().Add(-time.Hour)))
	keys := newFakeAccessKeys(graceKey("k", time.Now().Add(-time.Hour)))

	runner, err := newSweepRunner(cfg, discardLogger(),
		fakeStore{handles: handles, keys: keys, keySets: fakeKeySets{}}, nopAppender{}, testPepper)
	if err != nil {
		t.Fatalf("newSweepRunner: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	join := startSweeps(ctx, runner)
	defer func() { cancel(); join() }()

	deadline := time.After(10 * time.Second)
	for gotHandle, gotKey := false, false; !gotHandle || !gotKey; {
		select {
		case <-handles.released:
			gotHandle = true
		case <-keys.revoked:
			gotKey = true
		case <-deadline:
			t.Fatalf("only one sweep ran: handle=%v accesskey=%v", gotHandle, gotKey)
		}
	}
}

// TestGraceSweepConfigErrorsAreFatal pins that a misconfigured cadence stops
// startup rather than being clamped into something that looks like it works.
func TestGraceSweepConfigErrorsAreFatal(t *testing.T) {
	t.Parallel()

	_, err := newSweepRunner(graceCfg(-time.Second), discardLogger(),
		fakeStore{keys: newFakeAccessKeys(), keySets: fakeKeySets{}}, nopAppender{}, testPepper)
	if !errors.Is(err, domain.ErrInvalidInput) {
		t.Errorf("newSweepRunner with a negative grace interval = %v, want ErrInvalidInput", err)
	}
}

// TestRunStartsTheAccessKeyGraceSweep is the end-to-end guard on the CALL SITE,
// and it is the test the rest of this file cannot substitute for.
//
// Every other test here calls newSweepRunner and startSweeps directly. That
// proves the machinery works and proves nothing about anything invoking it: a
// change that stopped building the runner in run, or stopped passing it to
// serve, or stopped resolving the pepper, would leave those tests green while
// the sweep silently never ran. A test entering below the production entry
// point cannot observe an un-wiring, so this one drives run itself.
//
// The assertion is the line the runner logs on entering the job's loop, matched
// on the grace sweep's own name -- not on the generic "started" text, which the
// handle sweep would satisfy on its own.
func TestRunStartsTheAccessKeyGraceSweep(t *testing.T) {
	// Not parallel: this test signals its own process.
	dir := t.TempDir()

	// A real 32-byte pepper in a real file, referenced the way an operator
	// would. Resolution is part of what is under test: a run that could not
	// resolve it never reaches the sweep.
	pepperPath := filepath.Join(dir, "pepper")
	if err := os.WriteFile(pepperPath, []byte(testPepper.Reveal()), 0o600); err != nil {
		t.Fatalf("write pepper: %v", err)
	}

	cfgPath := filepath.Join(dir, "vallet.yaml")
	cfg := "" +
		"server:\n" +
		"  environment: development\n" +
		"  listen_addr: 127.0.0.1:0\n" +
		"tls:\n" +
		"  mode: self_signed\n" +
		"database:\n" +
		"  driver: sqlite\n" +
		"  sqlite:\n" +
		"    path: " + filepath.Join(dir, "vallet.db") + "\n" +
		"telemetry:\n" +
		"  log:\n" +
		"    level: info\n" +
		"    format: text\n" +
		"auth:\n" +
		"  access_key_pepper_ref: file:" + pepperPath + "\n" +
		"retention:\n" +
		"  access_key_grace_sweep_interval: 1h\n"
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	var logs syncBuffer
	done := make(chan error, 1)
	go func() { done <- run([]string{"-config", cfgPath}, &logs, &logs) }()

	const started = accessKeyGraceSweep
	deadline := time.After(30 * time.Second)
	for !strings.Contains(logs.String(), started) {
		select {
		case err := <-done:
			t.Fatalf("valletd exited before starting the grace sweep: %v\nlogs:\n%s", err, logs.String())
		case <-deadline:
			t.Fatalf("the access key grace sweep never started; run does not wire it up.\nlogs:\n%s", logs.String())
		case <-time.After(10 * time.Millisecond):
		}
	}

	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatalf("signal self: %v", err)
	}
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatalf("valletd did not shut down after SIGTERM.\nlogs:\n%s", logs.String())
	}
}
