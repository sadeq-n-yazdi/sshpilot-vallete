package erasure_test

import (
	"context"
	"database/sql"
	"sort"
	"testing"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/erasure"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/migrate"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/repository"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/schema"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/storage/sqlite"
)

// These tests run the traversal against the real SQLite adapters and the real
// schema rather than against fakes. That is deliberate: the property under test
// is that no owner-scoped table is missed, and a fake set of ports can only ever
// prove that the tables the test author remembered are visited. Driving the
// expectation from the migrated schema is what makes a newly added table fail
// the suite instead of silently escaping erasure.

var testClock = time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)

// saltTable is the one table with an owner_id column that the traversal must
// NOT collect from. It stores the erasure key itself: it is destroyed by the
// erasure, and it names no subject whose identifier could appear in the audit
// log. Every other owner_id-bearing table must be traversed, and the drift test
// below enforces exactly that.
const saltTable = "owner_erasure_salts"

// newStore returns a migrated in-memory store and its raw handle.
func newStore(t *testing.T) (*sql.DB, *sqlite.Store) {
	t.Helper()

	db, err := sqlite.Open(sqlite.Options{})
	if err != nil {
		t.Fatalf("sqlite.Open: %v", err)
	}
	t.Cleanup(func() {
		if cerr := db.Close(); cerr != nil {
			t.Errorf("close db: %v", cerr)
		}
	})
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
	return db, sqlite.NewStore(db)
}

// ownerScopedTables reads the migrated schema and returns every table carrying
// an owner_id column.
//
// This is the completeness oracle. It is computed from the database that the
// migrations actually produced, so adding an owner-scoped table changes it
// without anyone remembering to update a list here.
func ownerScopedTables(t *testing.T, db *sql.DB) []string {
	t.Helper()
	ctx := context.Background()

	rows, err := db.QueryContext(ctx,
		`SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name`)
	if err != nil {
		t.Fatalf("list tables: %v", err)
	}
	var tables []string
	for rows.Next() {
		var n string
		if serr := rows.Scan(&n); serr != nil {
			t.Fatalf("scan table name: %v", serr)
		}
		tables = append(tables, n)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate tables: %v", err)
	}
	if cerr := rows.Close(); cerr != nil {
		t.Fatalf("close tables: %v", cerr)
	}

	var scoped []string
	for _, table := range tables {
		// PRAGMA does not accept a bound parameter for the table name. The
		// value comes from sqlite_master in this same test process, not from
		// any caller, so there is no injection surface.
		cols, cerr := db.QueryContext(ctx, `SELECT name FROM pragma_table_info(?)`, table)
		if cerr != nil {
			t.Fatalf("table_info %s: %v", table, cerr)
		}
		for cols.Next() {
			var col string
			if serr := cols.Scan(&col); serr != nil {
				t.Fatalf("scan column of %s: %v", table, serr)
			}
			if col == "owner_id" {
				scoped = append(scoped, table)
			}
		}
		if err := cols.Err(); err != nil {
			t.Fatalf("iterate columns of %s: %v", table, err)
		}
		if err := cols.Close(); err != nil {
			t.Fatalf("close columns of %s: %v", table, err)
		}
	}
	sort.Strings(scoped)
	return scoped
}

// seeded is the set of identifiers written for one owner, indexed by the table
// they live in, so a test can assert coverage per table rather than in bulk.
type seeded map[string][]string

// tables returns the seeded table names, sorted.
func (s seeded) tables() []string {
	var out []string
	for table := range s {
		out = append(out, table)
	}
	sort.Strings(out)
	return out
}

// seedOwner creates an owner and one row in every owner-scoped table, in two
// lifecycle states wherever the table has one.
//
// The inactive rows are the point of the helper. Revoked devices, revoked keys
// and revoked credentials are the likeliest subjects in the audit log —
// device.revoked and key.revoked name them directly — so a traversal built on
// active-only reads would miss precisely the identities most worth erasing. By
// seeding both states and asserting on both, a lister that grew a status filter
// fails this suite rather than shipping a silent leak.
func seedOwner(t *testing.T, s *sqlite.Store, ownerID, prefix string) seeded {
	t.Helper()
	ctx := context.Background()
	r := s.Repos()
	out := seeded{}

	owner := &domain.Owner{
		ID:        domain.OwnerID(ownerID),
		Status:    domain.OwnerStatusActive,
		CreatedAt: testClock,
		UpdatedAt: testClock,
	}
	if err := r.Owners.Create(ctx, owner); err != nil {
		t.Fatalf("create owner %s: %v", ownerID, err)
	}
	out["owners"] = []string{ownerID}

	handleID := prefix + "-handle"
	if err := r.Handles.Register(ctx, &domain.Handle{
		ID: domain.HandleID(handleID), OwnerID: domain.OwnerID(ownerID),
		Name: prefix + "name", State: domain.NameStateActive,
		CreatedAt: testClock, UpdatedAt: testClock,
	}); err != nil {
		t.Fatalf("register handle: %v", err)
	}
	out["handles"] = []string{handleID}

	activeDevice, revokedDevice := prefix+"-dev-active", prefix+"-dev-revoked"
	for _, id := range []string{activeDevice, revokedDevice} {
		if err := r.Devices.Create(ctx, &domain.Device{
			ID: domain.DeviceID(id), OwnerID: domain.OwnerID(ownerID),
			Name: id, Status: domain.DeviceStatusActive,
			CreatedAt: testClock, UpdatedAt: testClock,
		}); err != nil {
			t.Fatalf("create device %s: %v", id, err)
		}
	}
	if err := r.Devices.Revoke(ctx, domain.OwnerID(ownerID), domain.DeviceID(revokedDevice), testClock); err != nil {
		t.Fatalf("revoke device: %v", err)
	}
	out["devices"] = []string{activeDevice, revokedDevice}

	activeKey, revokedKey := prefix+"-key-active", prefix+"-key-revoked"
	for i, id := range []string{activeKey, revokedKey} {
		if err := r.PublicKeys.Create(ctx, &domain.PublicKey{
			ID: domain.PublicKeyID(id), OwnerID: domain.OwnerID(ownerID),
			DeviceID:    domain.DeviceID(activeDevice),
			Algorithm:   "ssh-ed25519",
			Fingerprint: prefix + "-fp-" + string(rune('a'+i)),
			Blob:        []byte("blob-" + id),
			Status:      domain.KeyStatusActive,
			CreatedAt:   testClock, UpdatedAt: testClock,
		}); err != nil {
			t.Fatalf("create public key %s: %v", id, err)
		}
	}
	if err := r.PublicKeys.Revoke(ctx, domain.OwnerID(ownerID), domain.PublicKeyID(revokedKey), testClock); err != nil {
		t.Fatalf("revoke public key: %v", err)
	}
	out["public_keys"] = []string{activeKey, revokedKey}

	setID := prefix + "-set"
	if err := r.KeySets.Create(ctx, &domain.KeySet{
		ID: domain.KeySetID(setID), OwnerID: domain.OwnerID(ownerID),
		Name: prefix + "set", Visibility: domain.VisibilityProtected,
		State: domain.NameStateActive, IsDefault: true,
		CreatedAt: testClock, UpdatedAt: testClock,
	}); err != nil {
		t.Fatalf("create key set: %v", err)
	}
	out["key_sets"] = []string{setID}

	activeAK, revokedAK := prefix+"-ak-active", prefix+"-ak-revoked"
	for i, id := range []string{activeAK, revokedAK} {
		if err := r.AccessKeys.Create(ctx, &domain.AccessKey{
			ID: domain.AccessKeyID(id), OwnerID: domain.OwnerID(ownerID),
			KeySetID:   domain.KeySetID(setID),
			Name:       id,
			SecretHash: []byte(prefix + "-akhash-" + string(rune('a'+i))),
			Status:     domain.AccessKeyStatusActive,
			CreatedAt:  testClock,
		}); err != nil {
			t.Fatalf("create access key %s: %v", id, err)
		}
	}
	if err := r.AccessKeys.Revoke(ctx, domain.OwnerID(ownerID), domain.AccessKeyID(revokedAK), testClock); err != nil {
		t.Fatalf("revoke access key: %v", err)
	}
	out["access_keys"] = []string{activeAK, revokedAK}

	activeRC, revokedRC := prefix+"-rc-active", prefix+"-rc-revoked"
	for i, id := range []string{activeRC, revokedRC} {
		if err := r.RefreshCredentials.Create(ctx, &domain.RefreshCredential{
			ID: domain.RefreshCredentialID(id), OwnerID: domain.OwnerID(ownerID),
			LineageID:  domain.LineageID(prefix + "-lineage"),
			SecretHash: []byte(prefix + "-rchash-" + string(rune('a'+i))),
			Status:     domain.CredentialStatusActive,
			IssuedAt:   testClock, ExpiresAt: testClock.Add(time.Hour),
		}); err != nil {
			t.Fatalf("create refresh credential %s: %v", id, err)
		}
	}
	if err := r.RefreshCredentials.Revoke(ctx, domain.OwnerID(ownerID), domain.RefreshCredentialID(revokedRC), testClock); err != nil {
		t.Fatalf("revoke refresh credential: %v", err)
	}
	out["refresh_credentials"] = []string{activeRC, revokedRC}

	liID := prefix + "-li"
	if err := r.LinkedIdentities.Create(ctx, &domain.LinkedIdentity{
		ID: domain.LinkedIdentityID(liID), OwnerID: domain.OwnerID(ownerID),
		Provider: "oidc", Subject: prefix + "-subject",
		CreatedAt: testClock, UpdatedAt: testClock,
	}); err != nil {
		t.Fatalf("create linked identity: %v", err)
	}
	out["linked_identities"] = []string{liID}

	pairingID := prefix + "-pairing"
	if err := r.DevicePairings.Create(ctx, &domain.DevicePairing{
		ID: domain.PairingID(pairingID), OwnerID: domain.OwnerID(ownerID),
		DeviceCodeHash: []byte(prefix + "-dch"), UserCodeHash: []byte(prefix + "-uch"),
		Status:    domain.PairingStatusApproved,
		CreatedAt: testClock,
		ExpiresAt: testClock.Add(time.Hour), NextPollAt: testClock,
	}); err != nil {
		t.Fatalf("create device pairing: %v", err)
	}
	out["device_pairings"] = []string{pairingID}

	// The salt is created but never expected in a collection: it is the erasure
	// key, not an identifier. Seeding it keeps the drift test honest — the table
	// exists and is populated, so its absence from the collected set is a real
	// exclusion rather than an empty table trivially satisfying the assertion.
	if _, err := r.OwnerSalts.Ensure(ctx, ownerID); err != nil {
		t.Fatalf("ensure salt: %v", err)
	}

	return out
}

// newGraph builds a Graph over the store's real owner-scoped repositories.
func newGraph(t *testing.T, r repository.Repos) *erasure.Graph {
	t.Helper()
	g, err := erasure.NewGraph(erasure.GraphPorts{
		Handles:            r.Handles,
		Devices:            r.Devices,
		PublicKeys:         r.PublicKeys,
		KeySets:            r.KeySets,
		AccessKeys:         r.AccessKeys,
		RefreshCredentials: r.RefreshCredentials,
		LinkedIdentities:   r.LinkedIdentities,
		Pairings:           r.DevicePairings,
	})
	if err != nil {
		t.Fatalf("NewGraph: %v", err)
	}
	return g
}

// TestSeedCoversEveryOwnerScopedTable is the drift guard.
//
// It compares the tables the seed helper writes against the tables the migrated
// schema says are owner-scoped. A new owner-scoped migration fails here first,
// which is the signal that the traversal needs extending — without it, the
// coverage test below would keep passing while quietly testing less.
func TestSeedCoversEveryOwnerScopedTable(t *testing.T) {
	t.Parallel()
	db, store := newStore(t)
	got := seedOwner(t, store, "owner-drift", "d")

	// The owners table is the root of the graph and identifies an owner by its
	// own id column, not by owner_id, so the column-driven oracle cannot see it.
	// It is added here rather than exempted: the owner ID is the identifier that
	// appears in the most audit records, and omitting it would be the single
	// worst leak this suite could miss.
	want := []string{"owners"}
	for _, table := range ownerScopedTables(t, db) {
		if table == saltTable {
			continue
		}
		want = append(want, table)
	}
	sort.Strings(want)

	seededTables := got.tables()
	if len(seededTables) != len(want) {
		t.Fatalf("seeded tables %v, schema owner-scoped tables %v", seededTables, want)
	}
	for i := range want {
		if seededTables[i] != want[i] {
			t.Errorf("seeded table %d = %q, schema says %q", i, seededTables[i], want[i])
		}
	}
}

// TestCollectVisitsEveryOwnerScopedTable asserts per table, not in bulk, so a
// failure names the table that was missed.
func TestCollectVisitsEveryOwnerScopedTable(t *testing.T) {
	t.Parallel()
	_, store := newStore(t)
	want := seedOwner(t, store, "owner-a", "a")

	got, err := newGraph(t, store.Repos()).Collect(context.Background(), "owner-a")
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	have := index(got)

	for table, ids := range want {
		for _, id := range ids {
			if !have[id] {
				t.Errorf("identifier %q from table %s was not collected; that owner's %s records stay identifiable after erasure", id, table, table)
			}
		}
	}
}

// TestCollectIncludesRevokedRows pins the lifecycle-blind read explicitly, so a
// status filter added to any ListByOwner fails with a message that says why it
// matters rather than as an opaque count mismatch.
func TestCollectIncludesRevokedRows(t *testing.T) {
	t.Parallel()
	_, store := newStore(t)
	seedOwner(t, store, "owner-a", "a")

	got, err := newGraph(t, store.Repos()).Collect(context.Background(), "owner-a")
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	have := index(got)

	for _, id := range []string{"a-dev-revoked", "a-key-revoked", "a-ak-revoked", "a-rc-revoked"} {
		if !have[id] {
			t.Errorf("revoked row %q not collected: revocation events name it in the audit log, so it must be erasable", id)
		}
	}
}

// TestCollectNeverReachesAnotherOwner is asserted across every table, not just
// one. A cross-owner leak would most likely appear in a single adapter, so an
// assertion on one table would miss it.
func TestCollectNeverReachesAnotherOwner(t *testing.T) {
	t.Parallel()
	_, store := newStore(t)
	seedOwner(t, store, "owner-a", "a")
	other := seedOwner(t, store, "owner-b", "b")

	got, err := newGraph(t, store.Repos()).Collect(context.Background(), "owner-a")
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	have := index(got)

	for table, ids := range other {
		for _, id := range ids {
			if have[id] {
				t.Errorf("collecting owner-a returned %q from owner-b's %s: erasing owner-a would tombstone another owner's history", id, table)
			}
		}
	}
	if !have["owner-a"] {
		t.Error("collect did not include the owner id itself")
	}
}

// TestCollectToleratesPartiallyDeletedOwner covers the second pass over an
// owner whose rows are already going away: it must converge, not fail.
func TestCollectToleratesPartiallyDeletedOwner(t *testing.T) {
	t.Parallel()
	_, store := newStore(t)
	seedOwner(t, store, "owner-a", "a")
	ctx := context.Background()

	if _, err := store.Repos().LinkedIdentities.DeleteByOwner(ctx, "owner-a"); err != nil {
		t.Fatalf("DeleteByOwner: %v", err)
	}

	got, err := newGraph(t, store.Repos()).Collect(ctx, "owner-a")
	if err != nil {
		t.Fatalf("Collect after partial delete: %v", err)
	}
	have := index(got)
	if have["a-li"] {
		t.Error("collected a linked identity that was deleted")
	}
	if !have["a-dev-active"] || !have["owner-a"] {
		t.Error("collect dropped surviving identifiers after a partial delete")
	}
}

// TestCollectIsDeterministicAndDeduplicated backs the idempotence claim: two
// passes agree, so re-running an erasure mints the same tombstones.
func TestCollectIsDeterministicAndDeduplicated(t *testing.T) {
	t.Parallel()
	_, store := newStore(t)
	seedOwner(t, store, "owner-a", "a")
	g := newGraph(t, store.Repos())
	ctx := context.Background()

	first, err := g.Collect(ctx, "owner-a")
	if err != nil {
		t.Fatalf("first Collect: %v", err)
	}
	second, err := g.Collect(ctx, "owner-a")
	if err != nil {
		t.Fatalf("second Collect: %v", err)
	}
	if len(first) != len(second) {
		t.Fatalf("collect is not stable: %d then %d identifiers", len(first), len(second))
	}
	for i := range first {
		if first[i] != second[i] {
			t.Errorf("collect[%d] = %q then %q", i, first[i], second[i])
		}
	}
	if len(index(first)) != len(first) {
		t.Errorf("collect returned duplicates: %d unique of %d", len(index(first)), len(first))
	}
}

func TestCollectRejectsEmptyOwner(t *testing.T) {
	t.Parallel()
	_, store := newStore(t)
	if _, err := newGraph(t, store.Repos()).Collect(context.Background(), ""); err == nil {
		t.Fatal("Collect(\"\") succeeded, want an invalid-input error")
	}
}

// TestNewGraphRequiresEveryPort covers each field independently: a constructor
// that checked only some of them would pass a test that omitted only one.
func TestNewGraphRequiresEveryPort(t *testing.T) {
	t.Parallel()
	_, store := newStore(t)
	r := store.Repos()

	full := erasure.GraphPorts{
		Handles: r.Handles, Devices: r.Devices, PublicKeys: r.PublicKeys,
		KeySets: r.KeySets, AccessKeys: r.AccessKeys,
		RefreshCredentials: r.RefreshCredentials,
		LinkedIdentities:   r.LinkedIdentities, Pairings: r.DevicePairings,
	}
	clear := map[string]func(*erasure.GraphPorts){
		"Handles":            func(p *erasure.GraphPorts) { p.Handles = nil },
		"Devices":            func(p *erasure.GraphPorts) { p.Devices = nil },
		"PublicKeys":         func(p *erasure.GraphPorts) { p.PublicKeys = nil },
		"KeySets":            func(p *erasure.GraphPorts) { p.KeySets = nil },
		"AccessKeys":         func(p *erasure.GraphPorts) { p.AccessKeys = nil },
		"RefreshCredentials": func(p *erasure.GraphPorts) { p.RefreshCredentials = nil },
		"LinkedIdentities":   func(p *erasure.GraphPorts) { p.LinkedIdentities = nil },
		"Pairings":           func(p *erasure.GraphPorts) { p.Pairings = nil },
	}
	for name, drop := range clear {
		ports := full
		drop(&ports)
		if _, err := erasure.NewGraph(ports); err == nil {
			t.Errorf("NewGraph accepted a nil %s port; that table would be silently skipped", name)
		}
	}
	if _, err := erasure.NewGraph(full); err != nil {
		t.Errorf("NewGraph rejected a complete port set: %v", err)
	}
}

// index turns a collected slice into a set for membership assertions.
func index(ids []string) map[string]bool {
	out := make(map[string]bool, len(ids))
	for _, id := range ids {
		out[id] = true
	}
	return out
}
