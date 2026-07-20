package publish

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/keys"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/migrate"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/nameguard"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/repository"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/schema"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/service/bootstrap"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/storage/sqlite"
)

// testNow is the fixed timestamp stamped on seeded rows.
var testNow = time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)

// sqliteTimeLayout mirrors the fixed-width UTC layout the SQLite adapter
// encodes timestamps with. Raw-SQL fixtures must write the same shape, or the
// adapter fails to decode the row and the test reports a parse error instead of
// the behavior it meant to assert.
const sqliteTimeLayout = "2006-01-02T15:04:05.000000000Z07:00"

// fixture is a publish service over a real, migrated SQLite store.
//
// The tests run against the real adapter rather than hand-written fakes on
// purpose: the security properties under test — owner scoping, the active-only
// filter, and the id ordering the ETag depends on — are enforced by the SQL
// predicates themselves, and a fake would happily reimplement them correctly
// while the real query regressed.
type fixture struct {
	t     *testing.T
	db    *sql.DB
	store *sqlite.Store
	svc   *Service
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

	store := sqlite.NewStore(db)
	svc, err := New(store.Repos())
	if err != nil {
		t.Fatalf("publish.New: %v", err)
	}
	return &fixture{t: t, db: db, store: store, svc: svc}
}

// seedOwner creates an owner with the given handle and an empty, public,
// default key set.
func (f *fixture) seedOwner(handle string) bootstrap.Result {
	f.t.Helper()

	res, err := bootstrap.Seed(context.Background(), f.store, bootstrap.Params{
		Handle: handle,
		Now:    testNow,
		Guard:  mustGuard(f.t),
	})
	if err != nil {
		f.t.Fatalf("bootstrap.Seed(%q): %v", handle, err)
	}
	return res
}

// addKey generates a fresh ed25519 key with the given comment and attaches it
// to the owner's set, returning the stored key's ID.
func (f *fixture) addKey(ownerID domain.OwnerID, setID domain.KeySetID, comment string) domain.PublicKeyID {
	f.t.Helper()

	parsed, err := keys.Parse(generateKeyLine(f.t, comment))
	if err != nil {
		f.t.Fatalf("keys.Parse: %v", err)
	}

	var res bootstrap.Result
	err = f.store.WithTx(context.Background(), func(ctx context.Context, r repository.Repos) error {
		var addErr error
		res, addErr = bootstrap.AddKey(ctx, r, bootstrap.AddKeyParams{
			OwnerID:    ownerID,
			KeySetID:   setID,
			DeviceName: "test-device",
			Key:        parsed,
			Now:        testNow,
			Guard:      mustGuard(f.t),
		})
		return addErr
	})
	if err != nil {
		f.t.Fatalf("bootstrap.AddKey: %v", err)
	}
	return res.PublicKeyID
}

// resolve calls the service and fails the test on an unexpected error.
func (f *fixture) resolve(handle, setName string) string {
	f.t.Helper()

	body, err := f.svc.Resolve(context.Background(), handle, setName)
	if err != nil {
		f.t.Fatalf("Resolve(%q, %q): %v", handle, setName, err)
	}
	return string(body)
}

// exec runs raw SQL against the fixture database.
//
// It is the only way to create the states this service must defend against but
// which the write path correctly refuses to produce: a membership row linking
// another owner's key, and a stored comment containing a line break. Testing
// those defenses requires manufacturing the corruption they exist to survive.
func (f *fixture) exec(query string, args ...any) {
	f.t.Helper()

	if _, err := f.db.Exec(query, args...); err != nil {
		f.t.Fatalf("exec %q: %v", query, err)
	}
}

// generateKeyLine returns a fresh authorized_keys line with the given comment.
// A new key per call keeps fingerprints unique, so the per-owner uniqueness
// index never masks a test's real intent.
func generateKeyLine(t *testing.T, comment string) []byte {
	t.Helper()

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("ssh.NewPublicKey: %v", err)
	}

	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub)))
	if comment != "" {
		line += " " + comment
	}
	return []byte(line + "\n")
}

// lines splits an authorized_keys body into its non-empty lines.
func lines(body string) []string {
	trimmed := strings.TrimSuffix(body, "\n")
	if trimmed == "" {
		return nil
	}
	return strings.Split(trimmed, "\n")
}

// mustGuard builds the real blocklist guard. Tests seed through the same
// enforcement an operator gets, so a name these fixtures use is a name the
// product actually permits.
func mustGuard(t *testing.T) *nameguard.Guard {
	t.Helper()
	g, err := nameguard.Default()
	if err != nil {
		t.Fatalf("nameguard.Default(): %v", err)
	}
	return g
}
