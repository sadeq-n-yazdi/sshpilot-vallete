package keyset_test

import (
	"context"
	"database/sql"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/audit"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/migrate"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/nameguard"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/repository"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/schema"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/service/keyset"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/storage/sqlite"
)

// These tests run against the REAL SQLite adapter rather than a fake
// repository, and that is the load-bearing choice in this file.
//
// The invariant most worth protecting here — that another owner's key set is
// indistinguishable from one that never existed — is enforced by the owner_id
// predicate in each query, not by any line of Go in the service. A fake
// repository would be written to honor that predicate by construction, so a
// test against one would pass just as happily with the predicate deleted from
// the adapter: it would assert the artifact (a 404 came back) rather than the
// mechanism (the query could not see the row). Driving the real adapter means
// dropping an owner_id predicate makes these tests fail.

// ownerA and ownerB are two distinct owners. Every cross-owner test acts as B
// against A's data and asserts the answer is the one an invented identifier
// gets.
const (
	ownerA domain.OwnerID = "owner-a"
	ownerB domain.OwnerID = "owner-b"
)

// fixedNow is the clock every test runs on, so timestamps and quarantine
// windows are deterministic.
var fixedNow = time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)

// recordingAuditor captures emitted events so a test can assert that an
// access-affecting change was recorded, and can make recording fail.
//
// It is mutex-guarded because the concurrency test drives one Service from many
// goroutines, and *audit.Emitter -- the production implementation this stands in
// for -- is safe for concurrent use. A stand-in that was not would report a race
// in the fixture and say nothing about the code under test.
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

// fail makes every subsequent Emit return err.
func (a *recordingAuditor) fail(err error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.err = err
}

// captured returns a copy of the events emitted so far, for a test that needs
// to assert on what a record carries and not only on which actions were taken.
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

// fixture is one test's world: a migrated in-memory database, the store behind
// it, the service under test, and the auditor it emits to.
type fixture struct {
	t       *testing.T
	store   repository.Store
	svc     *keyset.Service
	auditor *recordingAuditor
}

func newFixture(t *testing.T, opts ...keyset.Option) *fixture {
	t.Helper()

	db, err := sqlite.Open(sqlite.Options{Path: ":memory:"})
	if err != nil {
		t.Fatalf("sqlite.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	migrateUp(t, db)

	store := sqlite.NewStore(db)
	// Both owners exist before any test runs. key_sets carries a foreign key to
	// owners, so a set cannot be created for an owner that does not exist --
	// which also means the cross-owner tests act as a REAL second owner rather
	// than as a string that happens not to match.
	for _, id := range []domain.OwnerID{ownerA, ownerB} {
		if err := store.Repos().Owners.Create(context.Background(), &domain.Owner{
			ID: id, Status: domain.OwnerStatusActive,
			CreatedAt: fixedNow, UpdatedAt: fixedNow,
		}); err != nil {
			t.Fatalf("Owners.Create(%s): %v", id, err)
		}
	}

	auditor := &recordingAuditor{}
	opts = append([]keyset.Option{keyset.WithClock(func() time.Time { return fixedNow })}, opts...)
	// The real blocklist guard, not a permissive stand-in: a name these tests
	// use is a name the product actually permits.
	svc, err := keyset.New(store, mustGuard(t), auditor, opts...)
	if err != nil {
		t.Fatalf("keyset.New: %v", err)
	}
	return &fixture{t: t, store: store, svc: svc, auditor: auditor}
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

// mustCreate creates a set and fails the test if it cannot.
func (f *fixture) mustCreate(owner domain.OwnerID, name string) *domain.KeySet {
	f.t.Helper()
	set, err := f.svc.Create(context.Background(), owner, name, "req-1")
	if err != nil {
		f.t.Fatalf("Create(%s, %q): %v", owner, name, err)
	}
	return set
}

// makeDefault designates a set as the owner's default through the repository,
// because designating a default is C4's endpoint and not this service's.
func (f *fixture) makeDefault(owner domain.OwnerID, id domain.KeySetID) {
	f.t.Helper()
	if err := f.store.Repos().KeySets.SetDefault(context.Background(), owner, id); err != nil {
		f.t.Fatalf("SetDefault: %v", err)
	}
}

// addMember puts a key in a set so the set counts as non-empty. It inserts the
// device and public key rows the composite foreign keys require.
func (f *fixture) addMember(owner domain.OwnerID, setID domain.KeySetID, keyID domain.PublicKeyID) {
	f.t.Helper()
	ctx := context.Background()
	r := f.store.Repos()

	deviceID := domain.DeviceID(string(keyID) + "-dev")
	if err := r.Devices.Create(ctx, &domain.Device{
		ID: deviceID, OwnerID: owner, Name: string(keyID) + " device",
		Status: domain.DeviceStatusActive, CreatedAt: fixedNow, UpdatedAt: fixedNow,
	}); err != nil {
		f.t.Fatalf("Devices.Create: %v", err)
	}
	if err := r.PublicKeys.Create(ctx, &domain.PublicKey{
		ID: keyID, OwnerID: owner, DeviceID: deviceID,
		Algorithm: domain.AlgEd25519, Blob: []byte(keyID),
		Fingerprint: "SHA256:" + string(keyID), BitLen: 256,
		Status: domain.KeyStatusActive, CreatedAt: fixedNow, UpdatedAt: fixedNow,
	}); err != nil {
		f.t.Fatalf("PublicKeys.Create: %v", err)
	}
	if err := r.KeySets.AddMember(ctx, owner, setID, keyID, fixedNow); err != nil {
		f.t.Fatalf("AddMember: %v", err)
	}
}

// names lists the names of the owner's live sets, for asserting on List.
func (f *fixture) names(owner domain.OwnerID) []string {
	f.t.Helper()
	sets, err := f.svc.List(context.Background(), owner)
	if err != nil {
		f.t.Fatalf("List(%s): %v", owner, err)
	}
	out := make([]string, 0, len(sets))
	for _, s := range sets {
		out = append(out, s.Name)
	}
	return out
}

// wantErr asserts err is the expected sentinel, naming both in the failure.
func wantErr(t *testing.T, got, want error, what string) {
	t.Helper()
	if !errors.Is(got, want) {
		t.Fatalf("%s: error = %v, want %v", what, got, want)
	}
}
