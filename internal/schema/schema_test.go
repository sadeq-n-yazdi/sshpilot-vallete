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
	"audit_records",
	"owner_erasure_salts",
	"linked_identities",
	"refresh_credentials",
	"device_pairings",
	"administrators",
	"access_keys",
}

// namedIndexes are the explicitly named indexes the migrations create. SQLite
// auto-indexes (for primary keys and inline uniqueness) are intentionally not
// listed: only stable, portable names are asserted.
var namedIndexes = []string{
	"ux_handles_name",
	"ux_handles_name_fold",
	"ux_handles_owner_active",
	"ix_handles_owner_id",
	"ix_devices_owner_id",
	"ux_public_keys_owner_fingerprint",
	"ix_public_keys_owner_id",
	"ix_public_keys_device_id",
	"ux_key_sets_owner_name",
	"ux_key_sets_owner_default",
	"ix_key_sets_owner_id",
	"ix_key_set_members_public_key_id",
	"ix_audit_records_occurred_at",
	"ix_audit_records_actor",
	"ix_audit_records_target",
	"ux_linked_identities_provider_subject",
	"ix_linked_identities_owner_id",
	"ix_refresh_credentials_owner_id",
	"ix_refresh_credentials_lineage",
	"ix_refresh_credentials_expires_at",
	"ix_device_pairings_user_code_hash",
	"ix_device_pairings_owner_id",
	"ix_device_pairings_expires_at",
	"ix_access_keys_owner_key_set",
	"ix_access_keys_grace_until",
}

// migrationIDs are the IDs the registry is expected to apply, in order.
var migrationIDs = []string{"0001", "0002", "0003", "0004", "0005", "0006", "0007", "0008", "0009", "0010", "0012"}

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

// TestCrossOwnerDeviceAttachmentRejected confirms the composite (device_id,
// owner_id) FOREIGN KEY blocks the cross-tenant attachment a single-column
// device_id reference would allow: a public key of owner B cannot point at a
// device of owner A even though that device id exists.
func TestCrossOwnerDeviceAttachmentRejected(t *testing.T) {
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

	// Two owners; a device owned by A.
	for _, id := range []string{"own-a", "own-b"} {
		if err := exec(
			`INSERT INTO owners (id, status, created_at, updated_at) VALUES (?, ?, ?, ?)`,
			id, "active", "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z"); err != nil {
			t.Fatalf("insert owner %s: %v", id, err)
		}
	}
	if err := exec(
		`INSERT INTO devices (id, owner_id, name, status, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		"dev-a", "own-a", "laptop", "active", "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z"); err != nil {
		t.Fatalf("insert device: %v", err)
	}

	fp := "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	// Owner B attaching a key to owner A's device must be rejected by the
	// composite FK, even though both dev-a and own-b exist individually.
	err := exec(
		`INSERT INTO public_keys
		 (id, owner_id, device_id, algorithm, blob, comment, fingerprint, bit_len, status, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"key-x", "own-b", "dev-a", "ssh-ed25519", []byte{0x01}, "",
		fp, 256, "active", "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z")
	if err == nil {
		t.Fatal("owner B attached a key to owner A's device, want composite FK violation")
	}

	// The same key attached to A's own device (matching owner) is accepted,
	// proving the rejection above is about ownership, not a malformed insert.
	if err := exec(
		`INSERT INTO public_keys
		 (id, owner_id, device_id, algorithm, blob, comment, fingerprint, bit_len, status, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"key-a", "own-a", "dev-a", "ssh-ed25519", []byte{0x01}, "",
		fp, 256, "active", "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z"); err != nil {
		t.Fatalf("same-owner key attach rejected, want accepted: %v", err)
	}
}

// TestSingleDefaultKeySetPerOwner confirms ux_key_sets_owner_default allows at
// most one default set per owner while leaving non-default sets unconstrained and
// permitting each owner their own default.
func TestSingleDefaultKeySetPerOwner(t *testing.T) {
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

	for _, id := range []string{"own-a", "own-b"} {
		if err := exec(
			`INSERT INTO owners (id, status, created_at, updated_at) VALUES (?, ?, ?, ?)`,
			id, "active", "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z"); err != nil {
			t.Fatalf("insert owner %s: %v", id, err)
		}
	}

	insertSet := func(id, owner, name string, isDefault int) error {
		return exec(
			`INSERT INTO key_sets (id, owner_id, name, visibility, is_default, state, created_at, updated_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			id, owner, name, "public", isDefault, "active",
			"2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z")
	}

	if err := insertSet("set-a1", "own-a", "default", 1); err != nil {
		t.Fatalf("first default for own-a: %v", err)
	}
	// A second default for the same owner violates the partial unique index.
	if err := insertSet("set-a2", "own-a", "other", 1); err == nil {
		t.Error("second default set for own-a accepted, want unique-index violation")
	}
	// Non-default sets are unconstrained: two are fine.
	if err := insertSet("set-a3", "own-a", "work", 0); err != nil {
		t.Fatalf("first non-default for own-a: %v", err)
	}
	if err := insertSet("set-a4", "own-a", "play", 0); err != nil {
		t.Fatalf("second non-default for own-a rejected, want accepted: %v", err)
	}
	// A different owner may have their own default.
	if err := insertSet("set-b1", "own-b", "default", 1); err != nil {
		t.Fatalf("default for own-b rejected, want accepted: %v", err)
	}
}

// TestEnumCheckConstraintsReject confirms the lifecycle-enum CHECK constraints
// reject out-of-domain values the repository must never write.
func TestEnumCheckConstraintsReject(t *testing.T) {
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

	// An owner with a status outside {active, suspended, deleted} is rejected.
	if err := exec(
		`INSERT INTO owners (id, status, created_at, updated_at) VALUES (?, ?, ?, ?)`,
		"own-bad", "bogus", "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z"); err == nil {
		t.Error("owner with out-of-range status accepted, want CHECK violation")
	}

	// Seed a valid owner, then reject an out-of-range key set visibility.
	if err := exec(
		`INSERT INTO owners (id, status, created_at, updated_at) VALUES (?, ?, ?, ?)`,
		"own-ok", "active", "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z"); err != nil {
		t.Fatalf("insert owner: %v", err)
	}
	if err := exec(
		`INSERT INTO key_sets (id, owner_id, name, visibility, is_default, state, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		"set-bad", "own-ok", "s", "world-readable", 0, "active",
		"2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z"); err == nil {
		t.Error("key set with out-of-range visibility accepted, want CHECK violation")
	}
}

// TestDownWithDataRemovesDomainTables exercises the DROP-with-live-data path:
// after seeding a full owner→device→key→set→membership chain, Down to empty must
// still succeed and remove every domain table (no rows block the teardown).
func TestDownWithDataRemovesDomainTables(t *testing.T) {
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

	ts := "2026-01-01T00:00:00Z"
	if err := exec(`INSERT INTO owners (id, status, created_at, updated_at) VALUES (?, ?, ?, ?)`,
		"own-1", "active", ts, ts); err != nil {
		t.Fatalf("seed owner: %v", err)
	}
	if err := exec(`INSERT INTO handles (id, owner_id, name, state, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)`,
		"h-1", "own-1", "alice", "active", ts, ts); err != nil {
		t.Fatalf("seed handle: %v", err)
	}
	if err := exec(`INSERT INTO devices (id, owner_id, name, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)`,
		"dev-1", "own-1", "laptop", "active", ts, ts); err != nil {
		t.Fatalf("seed device: %v", err)
	}
	if err := exec(
		`INSERT INTO public_keys (id, owner_id, device_id, algorithm, blob, comment, fingerprint, bit_len, status, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"key-1", "own-1", "dev-1", "ssh-ed25519", []byte{0x01}, "",
		"SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", 256, "active", ts, ts); err != nil {
		t.Fatalf("seed public key: %v", err)
	}
	if err := exec(
		`INSERT INTO key_sets (id, owner_id, name, visibility, is_default, state, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		"set-1", "own-1", "default", "public", 1, "active", ts, ts); err != nil {
		t.Fatalf("seed key set: %v", err)
	}
	if err := exec(`INSERT INTO key_set_members (key_set_id, public_key_id, added_at) VALUES (?, ?, ?)`,
		"set-1", "key-1", ts); err != nil {
		t.Fatalf("seed membership: %v", err)
	}

	if _, err := runner.Down(ctx, ""); err != nil {
		t.Fatalf("Down with data present: %v", err)
	}

	tables := names(t, raw, "table")
	for _, gone := range domainTables {
		if tables[gone] {
			t.Errorf("table %q still present after Down with data", gone)
		}
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

// TestAuditRecordEnumCheckConstraintsReject confirms the audit_records CHECK
// constraints reject actor and target types outside the domain value sets, as
// defense-in-depth behind the repository.
func TestAuditRecordEnumCheckConstraintsReject(t *testing.T) {
	t.Parallel()
	raw, runner := newRunner(t)
	ctx := context.Background()

	if _, err := runner.Up(ctx); err != nil {
		t.Fatalf("Up: %v", err)
	}

	ts := "2026-01-01T00:00:00.000000000Z"
	insert := func(actorType, targetType string) error {
		_, err := raw.ExecContext(ctx,
			`INSERT INTO audit_records
			 (id, actor_type, actor_id, action, target_type, target_id, occurred_at, metadata, pseudonymized)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			"aud-"+actorType+"-"+targetType, actorType, "act-1", "key.added",
			targetType, "tgt-1", ts, "{}", 0)
		return err
	}

	if err := insert("intruder", "device"); err == nil {
		t.Error("audit record with out-of-range actor_type accepted, want CHECK violation")
	}
	if err := insert("owner", "shadow_table"); err == nil {
		t.Error("audit record with out-of-range target_type accepted, want CHECK violation")
	}
	if err := insert("owner", "device"); err != nil {
		t.Errorf("audit record with in-range enums rejected: %v", err)
	}
}

// TestAuditRecordSurvivesOwnerDeletion is the ADR-0024 property: audit rows
// carry no foreign key to owners, so deleting the owner they name must neither
// be blocked by the audit row nor cascade it away. If a well-meaning change ever
// adds a REFERENCES owners(id) to audit_records, this test fails — which is the
// point, because that FK would make owner erasure destroy the audit trail.
func TestAuditRecordSurvivesOwnerDeletion(t *testing.T) {
	t.Parallel()
	raw, runner := newRunner(t)
	ctx := context.Background()

	if _, err := runner.Up(ctx); err != nil {
		t.Fatalf("Up: %v", err)
	}

	ts := "2026-01-01T00:00:00.000000000Z"
	if _, err := raw.ExecContext(ctx,
		`INSERT INTO owners (id, status, created_at, updated_at) VALUES (?, ?, ?, ?)`,
		"own-gone", "active", ts, ts); err != nil {
		t.Fatalf("seed owner: %v", err)
	}
	if _, err := raw.ExecContext(ctx,
		`INSERT INTO audit_records
		 (id, actor_type, actor_id, action, target_type, target_id, occurred_at, metadata, pseudonymized)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"aud-1", "owner", "own-gone", "owner.deleted", "owner", "own-gone", ts, "{}", 0); err != nil {
		t.Fatalf("seed audit record: %v", err)
	}

	if _, err := raw.ExecContext(ctx, `DELETE FROM owners WHERE id = ?`, "own-gone"); err != nil {
		t.Fatalf("delete owner: %v", err)
	}

	var n int
	if err := raw.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM audit_records WHERE actor_id = ?`, "own-gone").Scan(&n); err != nil {
		t.Fatalf("count audit records: %v", err)
	}
	if n != 1 {
		t.Errorf("audit records naming the deleted owner = %d, want 1 (record must outlive the owner)", n)
	}
}
