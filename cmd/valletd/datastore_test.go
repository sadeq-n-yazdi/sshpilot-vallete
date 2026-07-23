package main

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/config"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/secrets"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/storage/postgres"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/storage/sqlite"
)

// openSQLiteHandle returns a live SQLite handle for the factory tests. newStore
// does not contact the database -- it only wraps the handle -- so this same
// handle stands in for both driver branches; the branch under test is chosen by
// cfg.Database.Driver, not by what the handle actually is.
func openSQLiteHandle(t *testing.T) (*config.Config, *sqlite.Store) {
	t.Helper()
	cfg := sqliteConfig(t)
	db, err := sqlite.Open(sqlite.Options{Path: cfg.Database.SQLite.Path})
	if err != nil {
		t.Fatalf("sqlite.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return cfg, sqlite.NewStore(db)
}

// TestNewStoreSelectsAdapterPerDriver proves the factory dispatches on the
// configured driver and that postgres is now a supported branch -- not the
// fail-closed default. The type assertions are the strong form of "the right
// branch ran": a *postgres.Store back from the postgres driver can only come
// from the postgres case. Neither branch contacts the database, so this needs no
// live server.
func TestNewStoreSelectsAdapterPerDriver(t *testing.T) {
	cfg := sqliteConfig(t)
	db, err := sqlite.Open(sqlite.Options{Path: cfg.Database.SQLite.Path})
	if err != nil {
		t.Fatalf("sqlite.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	cfg.Database.Driver = "sqlite"
	store, err := newStore(cfg, db)
	if err != nil {
		t.Fatalf("newStore(sqlite) = %v, want success", err)
	}
	if _, ok := store.(*sqlite.Store); !ok {
		t.Fatalf("newStore(sqlite) returned %T, want *sqlite.Store", store)
	}

	cfg.Database.Driver = "postgres"
	store, err = newStore(cfg, db)
	if err != nil {
		t.Fatalf("newStore(postgres) = %v, want success (postgres is a supported branch)", err)
	}
	if _, ok := store.(*postgres.Store); !ok {
		t.Fatalf("newStore(postgres) returned %T, want *postgres.Store", store)
	}
}

// TestNewStoreRejectsUnsupportedDriver pins the fail-closed default of the
// factory: an unknown driver is a construction error naming the driver, never a
// silent fallback to one engine.
func TestNewStoreRejectsUnsupportedDriver(t *testing.T) {
	cfg, _ := openSQLiteHandle(t)
	cfg.Database.Driver = "mysql"

	db, err := sqlite.Open(sqlite.Options{Path: filepath.Join(t.TempDir(), "x.db")})
	if err != nil {
		t.Fatalf("sqlite.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	store, err := newStore(cfg, db)
	if err == nil {
		t.Fatal("newStore with an unsupported driver returned nil error, want fail-closed error")
	}
	if store != nil {
		t.Fatalf("newStore with an unsupported driver returned a non-nil store %T", store)
	}
	if !strings.Contains(err.Error(), "mysql") || !strings.Contains(err.Error(), "not supported") {
		t.Fatalf("newStore error = %q, want the fail-closed default naming the driver", err)
	}
}

// TestOpenDatabaseReachesPostgresBranch proves the server's openDatabase switch
// selects the postgres adapter, not the unsupported-driver default, when the
// driver is postgres. It drives the branch with a malformed DSN (invalid port)
// so pgx rejects it during config parse and the failure lands immediately --
// without a network dial or the ping timeout against a live host -- so it needs
// no database and still proves the branch was taken: the error is the adapter's,
// not "not supported".
//
// A real Postgres integration lives elsewhere and gates on
// VALLET_TEST_POSTGRES_DSN; this test deliberately stays in the no-database lane
// so `go test ./...` with no DSN set exercises the postgres wiring path.
func TestOpenDatabaseReachesPostgresBranch(t *testing.T) {
	cfg := sqliteConfig(t)
	cfg.Database.Driver = "postgres"
	cfg.Database.SQLite.Path = "" // unused on the postgres branch; blanked to be sure

	// A malformed connection string pgx rejects during config parse (invalid
	// port), so the failure lands immediately without a network dial. The
	// password is a distinctive token so the leak assertion below is meaningful.
	const dsnPassword = "topSecretPW123"
	t.Setenv("VALLET_TEST_PG_BAD_DSN", "postgres://user:"+dsnPassword+"@host:notaport/db")
	cfg.Database.Postgres.DSNRef = secrets.Ref("env:VALLET_TEST_PG_BAD_DSN")

	done := make(chan error, 1)
	go func() {
		db, err := openDatabase(cfg)
		if db != nil {
			_ = db.Close()
		}
		done <- err
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("openDatabase(postgres, malformed DSN) = nil, want an error from the postgres branch")
		}
		// The distinguishing assertion: reaching the postgres adapter, NOT the
		// unsupported-driver default. The default's message contains "not
		// supported"; the adapter's does not.
		if strings.Contains(err.Error(), "not supported") {
			t.Fatalf("openDatabase error = %q; the postgres driver was rejected as unsupported, so the branch was not reached", err)
		}
		// And the connection secret must never reach the error: pgx redacts the
		// DSN password in its own error text, and openPostgres reveals the DSN
		// only at the postgres.Open boundary, so the password cannot survive to a
		// log or a returned error.
		if strings.Contains(err.Error(), dsnPassword) {
			t.Fatalf("openDatabase error leaked the DSN password: %q", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("openDatabase(postgres, malformed DSN) did not fail fast; it should reject at parse, not dial")
	}
}
