// Package schema holds the domain database migrations for sshpilot-vallet and
// assembles them into a validated migrate.Registry.
//
// The migrations create the core publish-path schema — owners, handles,
// devices, public keys, key sets, and the key-set membership relation — with
// portable DDL that runs on both SQLite and PostgreSQL. The only engine-level
// differences are the byte-blob type (SQLite BLOB, Postgres BYTEA) and booleans
// (SQLite INTEGER constrained to 0/1, Postgres BOOLEAN); column semantics are
// identical across engines.
//
// Security posture: every owner-scoped table carries an owner_id column with a
// FOREIGN KEY to owners(id), so repository queries can enforce owner scoping and
// the database rejects rows that reference a non-existent owner. Cross-owner
// mixing is additionally blocked at the DB level where a child row references a
// sibling that also belongs to an owner: public_keys references its device by
// the composite (device_id, owner_id), so a key can only ever attach to a device
// of the same owner. Lifecycle enum columns (status/state/visibility) carry
// CHECK constraints restricting them to their domain-defined value sets, matching
// the boolean 0/1 checks, as defense-in-depth against a repository writing an
// out-of-range value. Timestamps are stored as RFC3339 UTC text to match the
// ledger and adapter convention.
package schema

import "github.com/sadeq-n-yazdi/sshpilot-vallete/internal/migrate"

// Registry returns the validated registry of all domain migrations in
// application order. It is a thin pass-through to migrate.NewRegistry, which
// enforces the registry invariants (well-formed, ordered, dependency-consistent
// IDs, complete for both engines).
func Registry() (*migrate.Registry, error) {
	return migrate.NewRegistry(
		migration0001Owners(),
		migration0002Devices(),
		migration0003KeySets(),
	)
}

// migration0001Owners creates the owners root table and the owner-scoped
// handles table. handles.name is globally unique (names are stored already
// normalized to a lowercase slug), and handles are indexed by owner_id for
// owner-scoped lookups. owners.status and handles.state are constrained to their
// domain value sets (OwnerStatus and NameState) by CHECK.
func migration0001Owners() migrate.Migration {
	return migrate.Migration{
		ID:   "0001",
		Name: "owners_and_handles",
		Preconditions: []migrate.Precondition{
			migrate.TableAbsent("owners"),
			migrate.TableAbsent("handles"),
		},
		Up: migrate.Steps{
			SQLite: []string{
				`CREATE TABLE owners (
	id TEXT PRIMARY KEY,
	status TEXT NOT NULL CHECK (status IN ('active', 'suspended', 'deleted')),
	created_at TEXT NOT NULL,
	updated_at TEXT NOT NULL,
	deleted_at TEXT
)`,
				`CREATE TABLE handles (
	id TEXT PRIMARY KEY,
	owner_id TEXT NOT NULL REFERENCES owners(id),
	name TEXT NOT NULL,
	state TEXT NOT NULL CHECK (state IN ('active', 'quarantined', 'retired')),
	quarantine_until TEXT,
	flagged_for_review INTEGER NOT NULL DEFAULT 0 CHECK (flagged_for_review IN (0, 1)),
	quarantine_on_release INTEGER NOT NULL DEFAULT 0 CHECK (quarantine_on_release IN (0, 1)),
	created_at TEXT NOT NULL,
	updated_at TEXT NOT NULL
)`,
				`CREATE UNIQUE INDEX ux_handles_name ON handles (name)`,
				`CREATE INDEX ix_handles_owner_id ON handles (owner_id)`,
			},
			Postgres: []string{
				`CREATE TABLE owners (
	id TEXT PRIMARY KEY,
	status TEXT NOT NULL CHECK (status IN ('active', 'suspended', 'deleted')),
	created_at TEXT NOT NULL,
	updated_at TEXT NOT NULL,
	deleted_at TEXT
)`,
				`CREATE TABLE handles (
	id TEXT PRIMARY KEY,
	owner_id TEXT NOT NULL REFERENCES owners(id),
	name TEXT NOT NULL,
	state TEXT NOT NULL CHECK (state IN ('active', 'quarantined', 'retired')),
	quarantine_until TEXT,
	flagged_for_review BOOLEAN NOT NULL DEFAULT FALSE,
	quarantine_on_release BOOLEAN NOT NULL DEFAULT FALSE,
	created_at TEXT NOT NULL,
	updated_at TEXT NOT NULL
)`,
				`CREATE UNIQUE INDEX ux_handles_name ON handles (name)`,
				`CREATE INDEX ix_handles_owner_id ON handles (owner_id)`,
			},
		},
		Down: migrate.Steps{
			SQLite: []string{
				`DROP TABLE handles`,
				`DROP TABLE owners`,
			},
			Postgres: []string{
				`DROP TABLE handles`,
				`DROP TABLE owners`,
			},
		},
	}
}

// migration0002Devices creates the owner-scoped devices and public_keys tables.
// A public key's fingerprint is unique per owner, and public_keys are indexed by
// owner_id and by device_id (its parent).
//
// devices carries a UNIQUE (id, owner_id) constraint so public_keys can reference
// its parent device by the composite (device_id, owner_id) FOREIGN KEY. That
// composite reference is the DB-level guarantee that a key never attaches to a
// device belonging to a different owner: because public_keys.owner_id must also
// match owners(id), a row can only satisfy both constraints when the key and its
// device share one owner. status columns are constrained to {active, revoked} by
// CHECK.
func migration0002Devices() migrate.Migration {
	return migrate.Migration{
		ID:       "0002",
		Name:     "devices_and_public_keys",
		Requires: []string{"0001"},
		Preconditions: []migrate.Precondition{
			migrate.TableAbsent("devices"),
			migrate.TableAbsent("public_keys"),
		},
		Up: migrate.Steps{
			SQLite: []string{
				`CREATE TABLE devices (
	id TEXT PRIMARY KEY,
	owner_id TEXT NOT NULL REFERENCES owners(id),
	name TEXT NOT NULL,
	status TEXT NOT NULL CHECK (status IN ('active', 'revoked')),
	created_at TEXT NOT NULL,
	updated_at TEXT NOT NULL,
	revoked_at TEXT,
	UNIQUE (id, owner_id)
)`,
				`CREATE INDEX ix_devices_owner_id ON devices (owner_id)`,
				`CREATE TABLE public_keys (
	id TEXT PRIMARY KEY,
	owner_id TEXT NOT NULL REFERENCES owners(id),
	device_id TEXT NOT NULL,
	algorithm TEXT NOT NULL,
	blob BLOB NOT NULL,
	comment TEXT NOT NULL DEFAULT '',
	fingerprint TEXT NOT NULL,
	bit_len INTEGER NOT NULL,
	status TEXT NOT NULL CHECK (status IN ('active', 'revoked')),
	created_at TEXT NOT NULL,
	updated_at TEXT NOT NULL,
	revoked_at TEXT,
	FOREIGN KEY (device_id, owner_id) REFERENCES devices (id, owner_id)
)`,
				`CREATE UNIQUE INDEX ux_public_keys_owner_fingerprint ON public_keys (owner_id, fingerprint)`,
				`CREATE INDEX ix_public_keys_owner_id ON public_keys (owner_id)`,
				`CREATE INDEX ix_public_keys_device_id ON public_keys (device_id)`,
			},
			Postgres: []string{
				`CREATE TABLE devices (
	id TEXT PRIMARY KEY,
	owner_id TEXT NOT NULL REFERENCES owners(id),
	name TEXT NOT NULL,
	status TEXT NOT NULL CHECK (status IN ('active', 'revoked')),
	created_at TEXT NOT NULL,
	updated_at TEXT NOT NULL,
	revoked_at TEXT,
	UNIQUE (id, owner_id)
)`,
				`CREATE INDEX ix_devices_owner_id ON devices (owner_id)`,
				`CREATE TABLE public_keys (
	id TEXT PRIMARY KEY,
	owner_id TEXT NOT NULL REFERENCES owners(id),
	device_id TEXT NOT NULL,
	algorithm TEXT NOT NULL,
	blob BYTEA NOT NULL,
	comment TEXT NOT NULL DEFAULT '',
	fingerprint TEXT NOT NULL,
	bit_len INTEGER NOT NULL,
	status TEXT NOT NULL CHECK (status IN ('active', 'revoked')),
	created_at TEXT NOT NULL,
	updated_at TEXT NOT NULL,
	revoked_at TEXT,
	FOREIGN KEY (device_id, owner_id) REFERENCES devices (id, owner_id)
)`,
				`CREATE UNIQUE INDEX ux_public_keys_owner_fingerprint ON public_keys (owner_id, fingerprint)`,
				`CREATE INDEX ix_public_keys_owner_id ON public_keys (owner_id)`,
				`CREATE INDEX ix_public_keys_device_id ON public_keys (device_id)`,
			},
		},
		Down: migrate.Steps{
			SQLite: []string{
				`DROP TABLE public_keys`,
				`DROP TABLE devices`,
			},
			Postgres: []string{
				`DROP TABLE public_keys`,
				`DROP TABLE devices`,
			},
		},
	}
}

// migration0003KeySets creates the owner-scoped key_sets table and the
// key_set_members join table relating public keys to key sets. A set name is
// unique per owner, and at most one key set per owner may be the default
// (ux_key_sets_owner_default, a partial unique index over is_default).
//
// The key_set_members table matches the domain KeySetMembership, which carries
// no owner_id. Its two foreign keys guarantee only that the referenced key set
// and public key EXIST; they do NOT constrain the two to share an owner, because
// neither reference includes owner_id. Preventing a membership that mixes one
// owner's key set with another owner's key is therefore the repository/service
// layer's responsibility: the "add key to set" path must independently verify
// that both the key set and the public key belong to the acting owner before
// inserting, and is covered by a test that rejects the cross-owner case.
func migration0003KeySets() migrate.Migration {
	return migrate.Migration{
		ID:       "0003",
		Name:     "key_sets_and_memberships",
		Requires: []string{"0001", "0002"},
		Preconditions: []migrate.Precondition{
			migrate.TableAbsent("key_sets"),
			migrate.TableAbsent("key_set_members"),
		},
		Up: migrate.Steps{
			SQLite: []string{
				`CREATE TABLE key_sets (
	id TEXT PRIMARY KEY,
	owner_id TEXT NOT NULL REFERENCES owners(id),
	name TEXT NOT NULL,
	visibility TEXT NOT NULL CHECK (visibility IN ('public', 'protected')),
	is_default INTEGER NOT NULL DEFAULT 0 CHECK (is_default IN (0, 1)),
	state TEXT NOT NULL CHECK (state IN ('active', 'quarantined', 'retired')),
	quarantine_until TEXT,
	flagged_for_review INTEGER NOT NULL DEFAULT 0 CHECK (flagged_for_review IN (0, 1)),
	quarantine_on_release INTEGER NOT NULL DEFAULT 0 CHECK (quarantine_on_release IN (0, 1)),
	created_at TEXT NOT NULL,
	updated_at TEXT NOT NULL
)`,
				`CREATE UNIQUE INDEX ux_key_sets_owner_name ON key_sets (owner_id, name)`,
				`CREATE UNIQUE INDEX ux_key_sets_owner_default ON key_sets (owner_id) WHERE is_default = 1`,
				`CREATE INDEX ix_key_sets_owner_id ON key_sets (owner_id)`,
				`CREATE TABLE key_set_members (
	key_set_id TEXT NOT NULL REFERENCES key_sets(id),
	public_key_id TEXT NOT NULL REFERENCES public_keys(id),
	added_at TEXT NOT NULL,
	PRIMARY KEY (key_set_id, public_key_id)
)`,
				`CREATE INDEX ix_key_set_members_public_key_id ON key_set_members (public_key_id)`,
			},
			Postgres: []string{
				`CREATE TABLE key_sets (
	id TEXT PRIMARY KEY,
	owner_id TEXT NOT NULL REFERENCES owners(id),
	name TEXT NOT NULL,
	visibility TEXT NOT NULL CHECK (visibility IN ('public', 'protected')),
	is_default BOOLEAN NOT NULL DEFAULT FALSE,
	state TEXT NOT NULL CHECK (state IN ('active', 'quarantined', 'retired')),
	quarantine_until TEXT,
	flagged_for_review BOOLEAN NOT NULL DEFAULT FALSE,
	quarantine_on_release BOOLEAN NOT NULL DEFAULT FALSE,
	created_at TEXT NOT NULL,
	updated_at TEXT NOT NULL
)`,
				`CREATE UNIQUE INDEX ux_key_sets_owner_name ON key_sets (owner_id, name)`,
				`CREATE UNIQUE INDEX ux_key_sets_owner_default ON key_sets (owner_id) WHERE is_default = TRUE`,
				`CREATE INDEX ix_key_sets_owner_id ON key_sets (owner_id)`,
				`CREATE TABLE key_set_members (
	key_set_id TEXT NOT NULL REFERENCES key_sets(id),
	public_key_id TEXT NOT NULL REFERENCES public_keys(id),
	added_at TEXT NOT NULL,
	PRIMARY KEY (key_set_id, public_key_id)
)`,
				`CREATE INDEX ix_key_set_members_public_key_id ON key_set_members (public_key_id)`,
			},
		},
		Down: migrate.Steps{
			SQLite: []string{
				`DROP TABLE key_set_members`,
				`DROP TABLE key_sets`,
			},
			Postgres: []string{
				`DROP TABLE key_set_members`,
				`DROP TABLE key_sets`,
			},
		},
	}
}
