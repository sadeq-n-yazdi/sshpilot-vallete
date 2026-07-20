package handle_test

import (
	"context"
	"database/sql"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/audit"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/blocklist"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/migrate"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/nameguard"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/repository"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/schema"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/service/handle"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/storage/sqlite"
)

// These tests run against the REAL SQLite adapter rather than a fake
// repository, and that is the load-bearing choice in this file.
//
// The invariants worth protecting here — that a quarantined name stays claimed,
// that another owner cannot take it, that a released name is genuinely gone —
// are enforced by unique indexes and by the predicates inside Release, not by
// any line of Go in the service. A fake repository would be written to honor
// them by construction, so a test against one would keep passing with the
// indexes dropped from the migration: it would assert the artifact (an error
// came back) rather than the mechanism (the database refused). Driving the real
// adapter means deleting an index makes these tests fail.

// ownerA and ownerB are two distinct owners. The cross-owner tests act as B
// against a name A vacated.
const (
	ownerA domain.OwnerID = "owner-a"
	ownerB domain.OwnerID = "owner-b"
)

// fixedNow is the clock every test runs on, so quarantine deadlines are
// deterministic.
var fixedNow = time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)

// recordingAuditor captures emitted events so a test can assert that a change
// of who serves keys at a public address was recorded.
type recordingAuditor struct {
	mu     sync.Mutex
	events []audit.Event
	err    error
}

func (a *recordingAuditor) Emit(_ context.Context, ev audit.Event) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.err != nil {
		return a.err
	}
	a.events = append(a.events, ev)
	return nil
}

func (a *recordingAuditor) captured() []audit.Event {
	a.mu.Lock()
	defer a.mu.Unlock()
	return slices.Clone(a.events)
}

func (a *recordingAuditor) actions() []domain.AuditAction {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]domain.AuditAction, 0, len(a.events))
	for _, ev := range a.events {
		out = append(out, ev.Action)
	}
	return out
}

// clock is a movable test clock, so a test can step past a quarantine deadline
// rather than sleep through thirty days of it.
type clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clock) get() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// fixture is one test's world: a migrated in-memory database, the store behind
// it, the service under test, the clock it reads, and the auditor it emits to.
type fixture struct {
	t       *testing.T
	store   repository.Store
	svc     *handle.Service
	auditor *recordingAuditor
	clock   *clock
}

func newFixture(t *testing.T, opts ...handle.Option) *fixture {
	t.Helper()

	db, err := sqlite.Open(sqlite.Options{Path: ":memory:"})
	if err != nil {
		t.Fatalf("sqlite.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	migrateUp(t, db)

	store := sqlite.NewStore(db)
	// Both owners exist before any test runs. handles carries a foreign key to
	// owners, so the cross-owner tests act as a REAL second owner rather than as
	// a string that happens not to match.
	for _, id := range []domain.OwnerID{ownerA, ownerB} {
		if err := store.Repos().Owners.Create(context.Background(), &domain.Owner{
			ID: id, Status: domain.OwnerStatusActive,
			CreatedAt: fixedNow, UpdatedAt: fixedNow,
		}); err != nil {
			t.Fatalf("Owners.Create(%s): %v", id, err)
		}
	}

	c := &clock{now: fixedNow}
	auditor := &recordingAuditor{}
	opts = append([]handle.Option{handle.WithClock(c.get)}, opts...)
	// The real blocklist guard, not a permissive stand-in: a name these tests
	// use is a name the product actually permits.
	svc, err := handle.New(store, mustGuard(t), auditor, opts...)
	if err != nil {
		t.Fatalf("handle.New: %v", err)
	}
	return &fixture{t: t, store: store, svc: svc, auditor: auditor, clock: c}
}

func migrateUp(t *testing.T, db *sql.DB) {
	t.Helper()
	reg, err := schema.Registry()
	if err != nil {
		t.Fatalf("schema.Registry: %v", err)
	}
	runner, err := migrate.NewRunner(sqlite.NewMigrateDB(db), migrate.EngineSQLite, reg)
	if err != nil {
		t.Fatalf("migrate.NewRunner: %v", err)
	}
	if _, err := runner.Up(context.Background()); err != nil {
		t.Fatalf("migrate Up: %v", err)
	}
}

func mustGuard(t *testing.T) *nameguard.Guard {
	t.Helper()
	g, err := nameguard.Default()
	if err != nil {
		t.Fatalf("nameguard.Default(): %v", err)
	}
	return g
}

// seed registers an owner's first active handle directly through the
// repository, because claiming a first name is bootstrap's job and not this
// service's — this service only moves an existing one.
func (f *fixture) seed(owner domain.OwnerID, name string) *domain.Handle {
	f.t.Helper()
	h := &domain.Handle{
		ID:          domain.HandleID("h-" + name),
		OwnerID:     owner,
		Name:        name,
		NameFold:    blocklist.Skeleton(name),
		FoldVersion: blocklist.TableVersion,
		State:       domain.NameStateActive,
		CreatedAt:   f.clock.get(),
		UpdatedAt:   f.clock.get(),
	}
	if err := f.store.Repos().Handles.Register(context.Background(), h); err != nil {
		f.t.Fatalf("seed handle %q for %s: %v", name, owner, err)
	}
	return h
}

// byName reads a name-claim straight from the store, bypassing the service, so
// an assertion about persisted state cannot be satisfied by the service simply
// returning what the test hoped for.
func (f *fixture) byName(name string) (*domain.Handle, error) {
	f.t.Helper()
	return f.store.Repos().Handles.GetByName(context.Background(), name)
}

// auditSink collects the records a real emitter produces.
type auditSink struct{ records []*domain.AuditRecord }

func (s *auditSink) Append(_ context.Context, rec *domain.AuditRecord) error {
	s.records = append(s.records, rec)
	return nil
}

// replay pushes captured events through a real audit.Emitter and returns the
// records it produced. Details keeps its pairs unexported on purpose, so what a
// stored record ends up carrying is the only observable worth asserting on --
// and going through the real emitter means a detail the screen would reject is
// caught here rather than passing because a test read the struct directly.
func replay(t *testing.T, events []audit.Event) []*domain.AuditRecord {
	t.Helper()
	sink := &auditSink{}
	emitter, err := audit.NewEmitter(sink)
	if err != nil {
		t.Fatalf("audit.NewEmitter: %v", err)
	}
	for _, ev := range events {
		if err := emitter.Emit(context.Background(), ev); err != nil {
			t.Fatalf("Emit %s: %v", ev.Action, err)
		}
	}
	return sink.records
}

// recordsFor returns the records of one action, in the order they were emitted.
func recordsFor(records []*domain.AuditRecord, action domain.AuditAction) []*domain.AuditRecord {
	out := make([]*domain.AuditRecord, 0, len(records))
	for _, rec := range records {
		if rec.Action == action {
			out = append(out, rec)
		}
	}
	return out
}

// wantDetail asserts one detail of a stored record.
func wantDetail(t *testing.T, rec *domain.AuditRecord, key audit.DetailKey, want string) {
	t.Helper()
	if got := rec.Metadata[string(key)]; got != want {
		t.Errorf("%s record: %s = %q, want %q", rec.Action, key, got, want)
	}
}
