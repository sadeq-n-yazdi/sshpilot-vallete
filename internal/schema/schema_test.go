package schema_test

import (
	"context"
	"database/sql"
	"sort"
	"testing"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/migrate"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/schema"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/storage/sqlite"
)

// domainTables are the tables the migrations create, excluding the ledger.
var domainTables = []string{
	"owners",
	"handles",
	"devices",
	"public_keys",
	"key_sets",
	"key_set_members",
}

// namedIndexes are the explicitly named indexes the migrations create. SQLite
// auto-indexes (for primary keys and inline uniqueness) are intentionally not
// listed: only stable, portable names are asserted.
var namedIndexes = []string{
	"ux_handles_name",
	"ix_handles_owner_id",
	"ix_devices_owner_id",
	"ux_public_keys_owner_fingerprint",
	"ix_public_keys_owner_id",
	"ix_public_keys_device_id",
	"ux_key_sets_owner_name",
	"ix_key_sets_owner_id",
	"ix_key_set_members_public_key_id",
}

// migrationIDs are the IDs the registry is expected to apply, in order.
var migrationIDs = []string{"0001", "0002", "0003"}

// newRunner opens a fresh in-memory SQLite database, wraps it for the migrate
// runner, and returns both the raw handle (for assertions) and the runner.
func newRunner(t *testing.T) (*sql.DB, *migrate.Runner) {
	t.Helper()

	reg, err := schema.Registry()
	if err != nil {
		t.Fatalf("Registry: %v", err)
	}

	raw, err := sqlite.Open(sqlite.Options{})
	if err != nil {
		t.Fatalf("open in-memory sqlite: %v", err)
	}
	t.Cleanup(func() {
		if cerr := raw.Close(); cerr != nil {
			t.Errorf("close db: %v", cerr)
		}
	})

	runner, err := migrate.NewRunner(sqlite.NewMigrateDB(raw), migrate.EngineSQLite, reg)
	if err != nil {
		t.Fatalf("NewRunner: %v", err)
	}
	return raw, runner
}

// names returns the set of object names of the given sqlite_master type.
func names(t *testing.T, raw *sql.DB, objType string) map[string]bool {
	t.Helper()
	rows, err := raw.QueryContext(context.Background(),
		"SELECT name FROM sqlite_master WHERE type = ? ORDER BY name", objType)
	if err != nil {
		t.Fatalf("query %s names: %v", objType, err)
	}
	defer func() { _ = rows.Close() }()

	out := make(map[string]bool)
	for rows.Next() {
		var n string
		if serr := rows.Scan(&n); serr != nil {
			t.Fatalf("scan %s name: %v", objType, serr)
		}
		out[n] = true
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate %s names: %v", objType, err)
	}
	return out
}

// ledgerIDs returns the migration IDs recorded in the ledger, in order.
func ledgerIDs(t *testing.T, runner *migrate.Runner) []string {
	t.Helper()
	st, err := runner.Status(context.Background())
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	ids := make([]string, len(st.Applied))
	for i, l := range st.Applied {
		if l.Engine != migrate.EngineSQLite {
			t.Errorf("ledger row %q engine = %q, want sqlite", l.ID, l.Engine)
		}
		ids[i] = l.ID
	}
	return ids
}

func TestRegistryValid(t *testing.T) {
	t.Parallel()
	reg, err := schema.Registry()
	if err != nil {
		t.Fatalf("Registry: %v", err)
	}
	got := reg.All()
	if len(got) != len(migrationIDs) {
		t.Fatalf("registry has %d migrations, want %d", len(got), len(migrationIDs))
	}
	for i, want := range migrationIDs {
		if got[i].ID != want {
			t.Errorf("migration %d id = %q, want %q", i, got[i].ID, want)
		}
	}
}

func TestUpCreatesSchemaAndLedger(t *testing.T) {
	t.Parallel()
	raw, runner := newRunner(t)

	if _, err := runner.Up(context.Background()); err != nil {
		t.Fatalf("Up: %v", err)
	}

	tables := names(t, raw, "table")
	for _, want := range domainTables {
		if !tables[want] {
			t.Errorf("table %q missing after Up", want)
		}
	}
	if !tables["schema_migrations"] {
		t.Error("ledger table schema_migrations missing after Up")
	}

	indexes := names(t, raw, "index")
	for _, want := range namedIndexes {
		if !indexes[want] {
			t.Errorf("index %q missing after Up", want)
		}
	}

	if got := ledgerIDs(t, runner); !equalStrings(got, migrationIDs) {
		t.Errorf("ledger ids = %v, want %v", got, migrationIDs)
	}
}

func TestUpIsIdempotent(t *testing.T) {
	t.Parallel()
	_, runner := newRunner(t)
	ctx := context.Background()

	first, err := runner.Up(ctx)
	if err != nil {
		t.Fatalf("first Up: %v", err)
	}
	if len(first) != len(migrationIDs) {
		t.Fatalf("first Up applied %d migrations, want %d", len(first), len(migrationIDs))
	}

	second, err := runner.Up(ctx)
	if err != nil {
		t.Fatalf("second Up: %v", err)
	}
	if second != nil {
		t.Errorf("second Up applied %v, want nothing", second)
	}

	if got := ledgerIDs(t, runner); !equalStrings(got, migrationIDs) {
		t.Errorf("ledger ids after two Ups = %v, want %v", got, migrationIDs)
	}
}

func TestDownToEmptyRemovesDomainTables(t *testing.T) {
	t.Parallel()
	raw, runner := newRunner(t)
	ctx := context.Background()

	if _, err := runner.Up(ctx); err != nil {
		t.Fatalf("Up: %v", err)
	}
	// An empty target reverts everything. The migrations are plain reversible
	// schema, so no AllowDestructive is required.
	if _, err := runner.Down(ctx, ""); err != nil {
		t.Fatalf("Down: %v", err)
	}

	tables := names(t, raw, "table")
	for _, gone := range domainTables {
		if tables[gone] {
			t.Errorf("table %q still present after Down to empty", gone)
		}
	}
	indexes := names(t, raw, "index")
	for _, gone := range namedIndexes {
		if indexes[gone] {
			t.Errorf("index %q still present after Down to empty", gone)
		}
	}
	// The ledger table itself is owned by the runner, not the migrations, and
	// remains — but it must record nothing.
	if got := ledgerIDs(t, runner); len(got) != 0 {
		t.Errorf("ledger ids after Down = %v, want none", got)
	}
}

// TestForeignKeyEnforced confirms the FOREIGN KEY constraints that back
// owner-scoping actually reject rows referencing a non-existent parent. This is
// the security invariant, not merely the foreign_keys pragma being on.
func TestForeignKeyEnforced(t *testing.T) {
	t.Parallel()
	raw, runner := newRunner(t)
	ctx := context.Background()

	if _, err := runner.Up(ctx); err != nil {
		t.Fatalf("Up: %v", err)
	}

	// A device referencing an owner that does not exist must be rejected.
	_, err := raw.ExecContext(ctx,
		`INSERT INTO devices (id, owner_id, name, status, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		"dev-1", "ghost-owner", "laptop", "active", "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z")
	if err == nil {
		t.Fatal("insert device with non-existent owner_id succeeded, want FK violation")
	}

	// A public key referencing a non-existent owner and device must be rejected.
	_, err = raw.ExecContext(ctx,
		`INSERT INTO public_keys
		 (id, owner_id, device_id, algorithm, blob, comment, fingerprint, bit_len, status, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"key-1", "ghost-owner", "ghost-device", "ssh-ed25519", []byte{0x01},
		"", "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", 256, "active",
		"2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z")
	if err == nil {
		t.Fatal("insert public_key with non-existent owner/device succeeded, want FK violation")
	}
}

// TestOwnerScopedInsertsSucceed exercises the happy path so the FK test above is
// rejecting for the right reason: with valid parents present, the same shape of
// inserts is accepted and the unique-per-owner fingerprint index holds.
func TestOwnerScopedInsertsSucceed(t *testing.T) {
	t.Parallel()
	raw, runner := newRunner(t)
	ctx := context.Background()

	if _, err := runner.Up(ctx); err != nil {
		t.Fatalf("Up: %v", err)
	}

	exec := func(query string, args ...any) error {
		_, err := raw.ExecContext(ctx, query, args...)
		return err
	}

	if err := exec(
		`INSERT INTO owners (id, status, created_at, updated_at) VALUES (?, ?, ?, ?)`,
		"own-1", "active", "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z"); err != nil {
		t.Fatalf("insert owner: %v", err)
	}
	if err := exec(
		`INSERT INTO devices (id, owner_id, name, status, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		"dev-1", "own-1", "laptop", "active", "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z"); err != nil {
		t.Fatalf("insert device: %v", err)
	}
	fp := "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	if err := exec(
		`INSERT INTO public_keys
		 (id, owner_id, device_id, algorithm, blob, comment, fingerprint, bit_len, status, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"key-1", "own-1", "dev-1", "ssh-ed25519", []byte{0x01}, "",
		fp, 256, "active", "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z"); err != nil {
		t.Fatalf("insert public_key: %v", err)
	}

	// A second key with the same fingerprint for the same owner violates the
	// unique-per-owner fingerprint index.
	err := exec(
		`INSERT INTO public_keys
		 (id, owner_id, device_id, algorithm, blob, comment, fingerprint, bit_len, status, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"key-2", "own-1", "dev-1", "ssh-ed25519", []byte{0x02}, "",
		fp, 256, "active", "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z")
	if err == nil {
		t.Error("duplicate fingerprint for same owner accepted, want unique-index violation")
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	x := append([]string(nil), a...)
	y := append([]string(nil), b...)
	sort.Strings(x)
	sort.Strings(y)
	for i := range x {
		if x[i] != y[i] {
			return false
		}
	}
	return true
}
