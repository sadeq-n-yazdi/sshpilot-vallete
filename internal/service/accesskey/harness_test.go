package accesskey

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/audit"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/migrate"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/nameguard"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/schema"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/secrets"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/service/bootstrap"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/storage/sqlite"
)

// fixedNow is the instant the fixture's clock reports unless a test moves it.
var fixedNow = time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)

// testPepper is a fixed 32-byte pepper. A constant is correct for a test: the
// property under test is that the digest is keyed and bound to the id, not that
// this particular key is secret.
var testPepper = []byte("0123456789abcdef0123456789abcdef")

// fixture is an access key service over a real, migrated SQLite store.
//
// The tests drive the real adapter rather than a fake repository on purpose.
// The invariant that matters most here — that one owner can never load
// another's credential — lives in the SQL predicate itself, and a fake would be
// written to honor it by construction, which is to say it would pass whether or
// not the query did. The audit emitter IS a fake, because what is asserted
// about it is that this package calls it and propagates its failures, not how
// records are stored.
type fixture struct {
	t     *testing.T
	db    *sql.DB
	store *sqlite.Store
	svc   *Service
	audit *fakeAuditor
	// now is the clock the service reads. A test moves it by assignment, which
	// is what makes the grace boundary assertable at the exact instant.
	now time.Time
}

func newFixture(t *testing.T) *fixture {
	t.Helper()

	db, err := sqlite.Open(sqlite.Options{Path: ":memory:"})
	if err != nil {
		t.Fatalf("sqlite.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

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

	f := &fixture{t: t, db: db, store: sqlite.NewStore(db), audit: &fakeAuditor{}, now: fixedNow}
	repos := f.store.Repos()
	svc, err := New(repos.AccessKeys, repos.KeySets, f.audit, testPepper, WithClock(func() time.Time { return f.now }))
	if err != nil {
		t.Fatalf("accesskey.New: %v", err)
	}
	f.svc = svc
	return f
}

// seedOwner creates an owner with the given handle and an empty default key
// set, returning the bootstrap result.
func (f *fixture) seedOwner(handle string) bootstrap.Result {
	f.t.Helper()

	res, err := bootstrap.Seed(context.Background(), f.store, bootstrap.Params{
		Handle: handle,
		Now:    fixedNow,
		Guard:  mustGuard(f.t),
	})
	if err != nil {
		f.t.Fatalf("bootstrap.Seed(%q): %v", handle, err)
	}
	return res
}

// seedSet creates an additional key set for an owner, so a test can mint a
// credential for one set and present it against another.
func (f *fixture) seedSet(ownerID domain.OwnerID, name string, state domain.NameState) domain.KeySetID {
	f.t.Helper()

	set := &domain.KeySet{
		ID:         domain.KeySetID("set-" + name + "-" + string(ownerID)),
		OwnerID:    ownerID,
		Name:       name,
		Visibility: domain.VisibilityProtected,
		State:      state,
		CreatedAt:  fixedNow,
		UpdatedAt:  fixedNow,
	}
	if err := f.store.Repos().KeySets.Create(context.Background(), set); err != nil {
		f.t.Fatalf("KeySets.Create(%q): %v", name, err)
	}
	return set.ID
}

// mint issues a credential and fails the test on an unexpected error.
func (f *fixture) mint(ownerID domain.OwnerID, setID domain.KeySetID, name string) (*domain.AccessKey, secrets.Redacted) {
	f.t.Helper()

	k, token, err := f.svc.Mint(context.Background(), ownerID, setID, name, "req-1")
	if err != nil {
		f.t.Fatalf("Mint(%q, %q): %v", ownerID, setID, err)
	}
	return k, token
}

// exec runs raw SQL against the fixture database. It is how a test manufactures
// a row the write path correctly refuses to produce — a grace-status key with
// no deadline, or a status this code does not recognize — because those are
// precisely the states the defenses under test exist to survive.
func (f *fixture) exec(query string, args ...any) {
	f.t.Helper()

	if _, err := f.db.Exec(query, args...); err != nil {
		f.t.Fatalf("exec %q: %v", query, err)
	}
}

// denied asserts that err is the single negative verdict, and that it wraps the
// domain sentinel the transport maps to a uniform 404.
func denied(t *testing.T, what string, err error) {
	t.Helper()

	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("%s: got %v, want ErrNotFound", what, err)
	}
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("%s: verdict does not wrap domain.ErrNotFound: %v", what, err)
	}
}

// fakeAuditor records emitted events and can be made to fail, so a test can
// assert that a failure to record is returned rather than swallowed.
type fakeAuditor struct {
	events []audit.Event
	err    error
}

func (a *fakeAuditor) Emit(_ context.Context, ev audit.Event) error {
	if a.err != nil {
		return a.err
	}
	a.events = append(a.events, ev)
	return nil
}

// mustGuard builds the real blocklist guard, so a name these fixtures use is a
// name the product actually permits.
func mustGuard(t *testing.T) *nameguard.Guard {
	t.Helper()

	g, err := nameguard.Default()
	if err != nil {
		t.Fatalf("nameguard.Default(): %v", err)
	}
	return g
}
