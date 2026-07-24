package main

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/config"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/repository"
)

// fakeHandles is a HandleRepository holding quarantined rows in memory and
// enforcing the two predicates the real adapters enforce in SQL: only
// quarantined rows are listed, and only a row whose deadline has passed is
// deleted. It embeds the port so a wiring change that reached for a method
// these tests do not model would panic loudly rather than pass quietly.
type fakeHandles struct {
	repository.HandleRepository

	mu       sync.Mutex
	rows     map[domain.HandleID]domain.Handle
	released chan domain.HandleID
	limits   chan int
}

func newFakeHandles(rows ...domain.Handle) *fakeHandles {
	f := &fakeHandles{
		rows:     make(map[domain.HandleID]domain.Handle, len(rows)),
		released: make(chan domain.HandleID, 16),
		limits:   make(chan int, 16),
	}
	for _, h := range rows {
		f.rows[h.ID] = h
	}
	return f
}

func (f *fakeHandles) ListExpiredQuarantine(_ context.Context, now time.Time, limit int) ([]domain.Handle, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	select {
	case f.limits <- limit:
	default:
	}

	var out []domain.Handle
	for _, h := range f.rows {
		if h.State != domain.NameStateQuarantined || h.QuarantineUntil == nil {
			continue
		}
		if h.QuarantineUntil.After(now) {
			continue
		}
		if len(out) >= limit {
			break
		}
		out = append(out, h)
	}
	return out, nil
}

func (f *fakeHandles) Release(_ context.Context, id domain.HandleID, now time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	h, ok := f.rows[id]
	// The deadline is re-checked inside the delete, exactly as the adapters do,
	// so a mutation that lets the sweep act on a live hold is caught here too.
	if !ok || h.State != domain.NameStateQuarantined || h.QuarantineUntil == nil || h.QuarantineUntil.After(now) {
		return domain.ErrNotFound
	}
	delete(f.rows, id)
	select {
	case f.released <- id:
	default:
	}
	return nil
}

func (f *fakeHandles) has(id domain.HandleID) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.rows[id]
	return ok
}

// fakeStore hands out only the handle repository. Everything else is the zero
// value, so a sweep that touched another entity would nil-panic in test rather
// than reach production unnoticed.
type fakeStore struct {
	handles repository.HandleRepository
	keys    repository.AccessKeyRepository
	keySets repository.KeySetRepository
}

func (s fakeStore) Repos() repository.Repos {
	return repository.Repos{
		Handles:    s.handles,
		AccessKeys: s.keys,
		KeySets:    s.keySets,
		// The release sweep records each freed name through the
		// transaction-bound Audit repository so the delete and the record commit
		// together; a store without one could not complete a release.
		Audit: fakeAudit{},
	}
}

func (s fakeStore) WithTx(ctx context.Context, fn func(context.Context, repository.Repos) error) error {
	return fn(ctx, s.Repos())
}

// nopAppender accepts every audit record. The sweep emits one per released
// name and fails the pass if the emit fails, so a recording sink is required
// for the release to complete at all.
type nopAppender struct{}

func (nopAppender) Append(context.Context, *domain.AuditRecord) error { return nil }

// fakeAudit is the transaction-bound audit repository the release sweep writes
// through. It accepts appends and embeds the port so any read, purge, or
// pseudonymize a sweep has no business calling nil-panics loudly rather than
// passing quietly.
type fakeAudit struct{ repository.AuditRepository }

func (fakeAudit) Append(context.Context, *domain.AuditRecord) error { return nil }

func expiredHandle(id domain.HandleID, until time.Time) domain.Handle {
	return domain.Handle{
		ID:              id,
		OwnerID:         domain.OwnerID("owner-" + string(id)),
		Name:            "name-" + string(id),
		State:           domain.NameStateQuarantined,
		QuarantineUntil: &until,
	}
}

func sweepCfg(interval time.Duration) *config.Config {
	c := testCfg()
	c.Retention.HandleQuarantineSweepInterval = config.Duration(interval)
	return c
}

// TestHandleQuarantineSweepIsWiredAndRuns is the regression test for the gap
// this change closes: handle.Service.ReleaseExpired existed and nothing in the
// process ever called it, so a quarantined name was held forever.
//
// Nothing here calls ReleaseExpired. The only thing that can free the row is
// the runner built from config and started by startSweeps, so a change that
// builds the runner and forgets to start it -- or drops the job -- fails here.
func TestHandleQuarantineSweepIsWiredAndRuns(t *testing.T) {
	t.Parallel()

	const id = domain.HandleID("expired")
	handles := newFakeHandles(expiredHandle(id, time.Now().Add(-time.Hour)))

	runner, err := newSweepRunner(sweepCfg(time.Millisecond), discardLogger(),
		fakeStore{handles: handles}, nopAppender{}, testPepper)
	if err != nil {
		t.Fatalf("newSweepRunner: %v", err)
	}
	if runner == nil {
		t.Fatal("runner is nil with a positive interval; the sweep would never run")
	}

	ctx, cancel := context.WithCancel(context.Background())
	join := startSweeps(ctx, runner)

	select {
	case got := <-handles.released:
		if got != id {
			t.Errorf("released %q, want %q", got, id)
		}
	case <-time.After(10 * time.Second):
		cancel()
		join()
		t.Fatal("the quarantine release sweep never ran; it is not wired to anything")
	}
	if handles.has(id) {
		t.Error("the expired quarantine is still held after the sweep released it")
	}

	cancel()
	joined := make(chan struct{})
	go func() { defer close(joined); join() }()
	select {
	case <-joined:
	case <-time.After(5 * time.Second):
		t.Fatal("the sweep goroutines were not joined after cancellation")
	}
}

// TestHandleQuarantineSweepLeavesLiveHoldsAlone pins the deadline predicate: a
// quarantine whose window has not elapsed must survive however often the sweep
// runs. Without it, the sweep would hand a name to a stranger during the
// cooling-off period that exists to prevent exactly that.
func TestHandleQuarantineSweepLeavesLiveHoldsAlone(t *testing.T) {
	t.Parallel()

	const (
		live    = domain.HandleID("still-held")
		expired = domain.HandleID("elapsed")
	)
	handles := newFakeHandles(
		expiredHandle(live, time.Now().Add(24*time.Hour)),
		expiredHandle(expired, time.Now().Add(-time.Hour)),
	)

	runner, err := newSweepRunner(sweepCfg(time.Millisecond), discardLogger(),
		fakeStore{handles: handles}, nopAppender{}, testPepper)
	if err != nil {
		t.Fatalf("newSweepRunner: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	join := startSweeps(ctx, runner)

	// Wait for the elapsed one, which proves the sweep both ran and reached the
	// release. Only then is the live one's survival meaningful.
	select {
	case <-handles.released:
	case <-time.After(10 * time.Second):
		cancel()
		join()
		t.Fatal("the sweep never released the elapsed hold")
	}
	// Give it several more passes at a 1ms cadence to get the live one wrong.
	time.Sleep(50 * time.Millisecond)
	cancel()
	join()

	if !handles.has(live) {
		t.Error("the sweep released a quarantine whose window has not elapsed")
	}
	if handles.has(expired) {
		t.Error("the elapsed quarantine was not released")
	}
}

// TestHandleQuarantineSweepPassesTheConfiguredBatch pins that the wiring hands
// the repository a positive, operator-chosen limit rather than 0. The handle
// adapters coerce a non-positive limit to their page-size default instead of
// rejecting it, so passing 0 would silently hand the bound to a storage
// constant nobody configured.
func TestHandleQuarantineSweepPassesTheConfiguredBatch(t *testing.T) {
	t.Parallel()

	cfg := sweepCfg(time.Millisecond)
	cfg.Retention.HandleQuarantineSweepBatch = 7

	handles := newFakeHandles()
	runner, err := newSweepRunner(cfg, discardLogger(), fakeStore{handles: handles}, nopAppender{}, testPepper)
	if err != nil {
		t.Fatalf("newSweepRunner: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	join := startSweeps(ctx, runner)
	defer func() { cancel(); join() }()

	select {
	case got := <-handles.limits:
		if got != 7 {
			t.Errorf("sweep asked for limit %d, want the configured 7", got)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the sweep never queried the repository")
	}
}

// TestHandleQuarantineSweepDisabledByZeroInterval pins the off switch: a zero
// interval yields no runner and no sweep, and startSweeps still returns a
// usable join so no caller has a branch to forget.
func TestHandleQuarantineSweepDisabledByZeroInterval(t *testing.T) {
	t.Parallel()

	const id = domain.HandleID("expired")
	handles := newFakeHandles(expiredHandle(id, time.Now().Add(-time.Hour)))

	runner, err := newSweepRunner(sweepCfg(0), discardLogger(),
		fakeStore{handles: handles}, nopAppender{}, testPepper)
	if err != nil {
		t.Fatalf("newSweepRunner: %v", err)
	}
	if runner != nil {
		t.Fatal("a zero interval must disable the sweep entirely")
	}

	ctx, cancel := context.WithCancel(context.Background())
	join := startSweeps(ctx, runner)
	time.Sleep(20 * time.Millisecond)
	cancel()
	join()

	if !handles.has(id) {
		t.Error("a disabled sweep released a quarantine")
	}
}

// TestSweepRunnerRejectsANegativeInterval pins that a misconfigured cadence
// fails startup rather than being clamped into something that looks like it
// works.
func TestSweepRunnerRejectsANegativeInterval(t *testing.T) {
	t.Parallel()

	_, err := newSweepRunner(sweepCfg(-time.Second), discardLogger(),
		fakeStore{handles: newFakeHandles()}, nopAppender{}, testPepper)
	if !errors.Is(err, domain.ErrInvalidInput) {
		t.Errorf("newSweepRunner with a negative interval = %v, want ErrInvalidInput", err)
	}
}
