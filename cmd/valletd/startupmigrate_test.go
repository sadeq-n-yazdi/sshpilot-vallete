package main

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/config"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/migrate"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/schema"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/storage/sqlite"
)

// sqliteConfig returns a config pointed at a throwaway SQLite file, matching the
// driver the server startup path opens.
func sqliteConfig(t *testing.T) *config.Config {
	t.Helper()
	defaults := config.Default()
	cfg := &defaults
	cfg.Database.Driver = "sqlite"
	cfg.Database.SQLite.Path = filepath.Join(t.TempDir(), "vallet.db")
	return cfg
}

// pendingCount reports how many forward migrations are not yet applied to db,
// using the same registry and engine the startup path migrates with. It is the
// direct measure of "the schema is ready": zero pending means the database
// matches the code.
func pendingCount(t *testing.T, db migrate.DB) int {
	t.Helper()
	reg, err := schema.Registry()
	if err != nil {
		t.Fatalf("schema.Registry: %v", err)
	}
	runner, err := migrate.NewRunner(db, migrate.EngineSQLite, reg)
	if err != nil {
		t.Fatalf("migrate.NewRunner: %v", err)
	}
	st, err := runner.Status(context.Background())
	if err != nil {
		t.Fatalf("runner.Status: %v", err)
	}
	return len(st.Pending)
}

// TestMigrateDatabaseBringsFreshSchemaUp is the core startup guarantee: a
// server opening a brand-new, unmigrated database has its schema brought fully
// up to date before anything is built on top of it. It asserts the real
// property -- zero pending migrations afterward -- not merely that the call
// returned nil, so a helper that silently applied nothing would fail here.
func TestMigrateDatabaseBringsFreshSchemaUp(t *testing.T) {
	cfg := sqliteConfig(t)
	db, err := openDatabase(cfg)
	if err != nil {
		t.Fatalf("openDatabase: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	// A brand-new database is behind: there is at least one pending migration,
	// which is exactly the state the old startup path served traffic against.
	if got := pendingCount(t, sqlite.NewMigrateDB(db)); got == 0 {
		t.Fatalf("fresh database reported 0 pending migrations; test cannot prove anything")
	}

	if err := migrateDatabase(context.Background(), cfg, db); err != nil {
		t.Fatalf("migrateDatabase on fresh database = %v, want success", err)
	}

	if got := pendingCount(t, sqlite.NewMigrateDB(db)); got != 0 {
		t.Fatalf("after startup migration: %d pending migrations, want 0", got)
	}
}

// TestMigrateDatabaseIsIdempotent mirrors the bootstrap guarantee and the
// multi-replica "second process sees it applied" case: running the startup
// migration again against an already-migrated database is a no-op, not an
// error.
func TestMigrateDatabaseIsIdempotent(t *testing.T) {
	cfg := sqliteConfig(t)
	db, err := openDatabase(cfg)
	if err != nil {
		t.Fatalf("openDatabase: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	if err := migrateDatabase(context.Background(), cfg, db); err != nil {
		t.Fatalf("first migrateDatabase = %v, want success", err)
	}
	if err := migrateDatabase(context.Background(), cfg, db); err != nil {
		t.Fatalf("second migrateDatabase = %v, want success (idempotent)", err)
	}
}

// TestMigrateDatabaseFailsClosedWhenSchemaCannotApply is the security property:
// when migrations cannot be applied, startup fails closed. A closed database
// cannot be migrated, so the helper must return an error -- the run() caller
// propagates it and never reaches store construction or serving.
func TestMigrateDatabaseFailsClosedWhenSchemaCannotApply(t *testing.T) {
	cfg := sqliteConfig(t)
	db, err := openDatabase(cfg)
	if err != nil {
		t.Fatalf("openDatabase: %v", err)
	}
	// Close the handle out from under the migrator so every statement fails.
	if err := db.Close(); err != nil {
		t.Fatalf("db.Close: %v", err)
	}

	if err := migrateDatabase(context.Background(), cfg, db); err == nil {
		t.Fatal("migrateDatabase against a closed database returned nil; startup would serve against an unmigrated schema")
	}
}

// TestMigrateDatabaseRejectsUnsupportedDriver pins the fail-closed default of
// the driver switch: a driver the server cannot open is a startup error, never
// a silent skip of migrations.
func TestMigrateDatabaseRejectsUnsupportedDriver(t *testing.T) {
	cfg := sqliteConfig(t)
	db, err := openDatabase(cfg)
	if err != nil {
		t.Fatalf("openDatabase: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	cfg.Database.Driver = "postgres"
	if err := migrateDatabase(context.Background(), cfg, db); err == nil {
		t.Fatal("migrateDatabase with an unsupported driver returned nil, want fail-closed error")
	}
}
