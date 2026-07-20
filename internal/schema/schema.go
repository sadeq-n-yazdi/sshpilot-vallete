// Package schema holds the domain database migrations for sshpilot-vallet and
// assembles them into a validated migrate.Registry.
//
// The migrations create the core publish-path schema — owners, handles,
// devices, public keys, key sets, and the key-set membership relation — plus
// the append-only audit log, with
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
//
// Two tables deliberately carry no foreign key to owners. audit_records is the
// cross-owner system record whose rows must outlive the owners they mention, so
// it has neither an owner_id nor an FK. owner_erasure_salts is keyed by owner
// but has no FK either, because its row must be destroyable on a schedule the
// erasure flow controls rather than one the owner row's lifetime dictates. See
// migration0004AuditRecords and migration0005OwnerErasureSalts for the full
// rationale. administrators is a third: it is a system-axis principal table
// with no owner at all, so there is nothing for an owner_id to reference; see
// migration0009Administrators. list_overrides is a fourth, for the same reason:
// the reserved-identifier lists are global service policy rather than any
// owner's data; see migration0011ListOverrides.
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
		migration0004AuditRecords(),
		migration0005OwnerErasureSalts(),
		migration0006RefreshCredentials(),
		migration0007LinkedIdentities(),
		migration0008DevicePairings(),
		migration0009Administrators(),
		migration0011ListOverrides(),
	)
}

// migration0011ListOverrides creates the durable record of runtime edits to the
// reserved-identifier lists (ADR-0017, Fb3).
//
// # Why a removal is a row and not a missing row
//
// The table stores a state per entry, including 'removed', rather than storing
// only the entries that are in force. A removal recorded as an absent row
// cannot outrank anything: the lists are composed at startup by replaying this
// table over an operator-supplied seed, and an absent row leaves the seed's copy
// of the entry standing. An entry an administrator deliberately removed would
// come back on the next restart while the audit log still showed the removal.
//
// For the allowlist that direction is fail-open. Removing an allowlist entry
// re-blocks a term, so a resurrected entry silently re-permits an identifier
// somebody decided to refuse. Storing the tombstone lets replay rank it above
// the seed, so a seed file that later re-adds a removed entry does not
// resurrect it.
//
// # Keyed on the skeleton
//
// The primary key is (list, skeleton), not (list, entry). The skeleton is the
// form the matcher compares on, so two confusable spellings are one rule to the
// engine and must be one row here; keying on the raw spelling would let them
// sit as separate overrides whose winner depended on replay order. The raw
// entry is kept as an ordinary column for the audit and listing surfaces, since
// a skeleton must never be displayed as the thing that was approved.
//
// The key also serves the only read this table has -- fetch every override,
// ordered -- so no secondary index is created: one would duplicate the primary
// key's leading column and earn nothing.
//
// actor_id carries no FOREIGN KEY to administrators, deliberately and for the
// same reason audit_records has none. The policy decision must outlive the
// principal who made it: an administrator's row being removed later must never
// quietly delete the tombstones they set, because that would re-open every hole
// they closed. Both CHECK constraints mirror the domain enums so the database
// refuses a value the domain would not recognize, behind the adapter's own
// validation.
func migration0011ListOverrides() migrate.Migration {
	const ddl = `CREATE TABLE list_overrides (
	list TEXT NOT NULL CHECK (list IN ('allowlist', 'blocklist_term')),
	skeleton TEXT NOT NULL,
	entry TEXT NOT NULL,
	state TEXT NOT NULL CHECK (state IN ('present', 'removed')),
	actor_id TEXT NOT NULL,
	updated_at TEXT NOT NULL,
	PRIMARY KEY (list, skeleton)
)`
	return migrate.Migration{
		ID:   "0011",
		Name: "list_overrides",
		Preconditions: []migrate.Precondition{
			migrate.TableAbsent("list_overrides"),
		},
		Up: migrate.Steps{
			SQLite:   []string{ddl},
			Postgres: []string{ddl},
		},
		Down: migrate.Steps{
			SQLite:   []string{`DROP TABLE list_overrides`},
			Postgres: []string{`DROP TABLE list_overrides`},
		},
	}
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

// migration0004AuditRecords creates the append-only audit log table (ADR-0007).
//
// Unlike every other table in this schema, audit_records carries NO owner_id and
// NO foreign key to owners(id). That is deliberate on two counts. First, the log
// is a cross-owner system record: an actor may be an administrator or the system
// itself, and a target is polymorphic across entity types, so there is no single
// owner to scope a row to. Second, an FK to owners(id) would actively break
// ADR-0024: owner deletion must leave the structural audit trail standing
// (pseudonymized), whereas an FK would force the deletion either to be blocked
// or to cascade the history away. Records therefore outlive the owners they
// mention, which is the entire point of an audit log.
//
// There is deliberately no BEFORE UPDATE / BEFORE DELETE trigger enforcing
// immutability at the database level. Append-only is enforced by the shape of
// the repository port (repository.AuditAppender exposes only Append, and
// repository.AuditRepository adds only reads), and ADR-0024 requires a
// controlled retention purge and pseudonymization path that a hard trigger would
// have to be dropped to permit. Encoding the property as a trigger that the very
// next track must rip out would weaken it, not strengthen it.
//
// The indexes serve the three access patterns the port declares: newest-first
// keyset listing over (occurred_at, id), filtering by actor, and filtering by
// target. occurred_at is fixed-width RFC3339 UTC text, so its index orders
// chronologically under a plain lexical comparison.
func migration0004AuditRecords() migrate.Migration {
	return migrate.Migration{
		ID:   "0004",
		Name: "audit_records",
		Preconditions: []migrate.Precondition{
			migrate.TableAbsent("audit_records"),
		},
		Up: migrate.Steps{
			SQLite: []string{
				`CREATE TABLE audit_records (
	id TEXT PRIMARY KEY,
	actor_type TEXT NOT NULL CHECK (actor_type IN ('owner', 'administrator', 'system')),
	actor_id TEXT NOT NULL,
	action TEXT NOT NULL,
	target_type TEXT NOT NULL CHECK (target_type IN ('owner', 'handle', 'device', 'public_key', 'key_set', 'access_key', 'refresh_credential', 'blocklist_entry', 'allowlist_entry')),
	target_id TEXT NOT NULL,
	occurred_at TEXT NOT NULL,
	metadata TEXT NOT NULL DEFAULT '{}',
	pseudonymized INTEGER NOT NULL DEFAULT 0 CHECK (pseudonymized IN (0, 1))
)`,
				`CREATE INDEX ix_audit_records_occurred_at ON audit_records (occurred_at, id)`,
				`CREATE INDEX ix_audit_records_actor ON audit_records (actor_id)`,
				`CREATE INDEX ix_audit_records_target ON audit_records (target_type, target_id)`,
			},
			Postgres: []string{
				`CREATE TABLE audit_records (
	id TEXT PRIMARY KEY,
	actor_type TEXT NOT NULL CHECK (actor_type IN ('owner', 'administrator', 'system')),
	actor_id TEXT NOT NULL,
	action TEXT NOT NULL,
	target_type TEXT NOT NULL CHECK (target_type IN ('owner', 'handle', 'device', 'public_key', 'key_set', 'access_key', 'refresh_credential', 'blocklist_entry', 'allowlist_entry')),
	target_id TEXT NOT NULL,
	occurred_at TEXT NOT NULL,
	metadata TEXT NOT NULL DEFAULT '{}',
	pseudonymized BOOLEAN NOT NULL DEFAULT FALSE
)`,
				`CREATE INDEX ix_audit_records_occurred_at ON audit_records (occurred_at, id)`,
				`CREATE INDEX ix_audit_records_actor ON audit_records (actor_id)`,
				`CREATE INDEX ix_audit_records_target ON audit_records (target_type, target_id)`,
			},
		},
		Down: migrate.Steps{
			SQLite:   []string{`DROP TABLE audit_records`},
			Postgres: []string{`DROP TABLE audit_records`},
		},
	}
}

// migration0005OwnerErasureSalts creates the per-owner salt table that makes
// audit crypto-erasure possible (ADR-0024).
//
// # The erasure model
//
// An owner's audit trail must survive that owner's deletion — the point of an
// audit log is that the event stays provable — while the owner's identity must
// become unrecoverable. Deleting the records would destroy the evidence;
// blanking the IDs would destroy the ability to tell two subjects apart in the
// surviving trail. The resolution is a tombstone: each of the owner's
// polymorphic IDs is replaced by HMAC-SHA256(salt, id) under a salt held only
// for that owner, and erasure is performed by DESTROYING THE SALT.
//
// This table is where that salt lives, and the row is the entire secret. While
// the row exists the mapping is reproducible: given a candidate ID, recomputing
// the HMAC and comparing to the tombstone confirms or refutes it, which is what
// lets an operator still answer "did this owner do that?" before erasure.
// Once the row is deleted, that check is no longer computable by anyone. The
// tombstone is a 256-bit HMAC output over a 256-bit random key, so recovering
// the subject from the record needs the key; it cannot be brute-forced from the
// ID space the way an unsalted hash of a short identifier could be. Destroying
// the salt is therefore not bookkeeping — it IS the erasure.
//
// Note the honest limit: DELETE removes the row logically, and the bytes may
// persist in freelist pages or a WAL until the database reclaims them. Erasure
// is complete against anyone reading through the database; a forensic reader of
// the raw file needs a VACUUM (or full-disk encryption) to be excluded too.
//
// # Why no foreign key to owners(id)
//
// For the same reason audit_records has none, and one more. An FK would tie the
// salt's lifetime to the owner row, so deleting the owner would either be
// blocked by the salt or silently cascade it away — and a cascade would destroy
// the salt at a moment not chosen by the erasure flow, possibly before the
// records that depend on it have been rewritten. That ordering is exactly what
// must stay under explicit control: pseudonymize first, then destroy the salt.
// The salt is also created for an owner that may already be mid-deletion, so
// requiring a live owner row would make the erasure path fail when it is needed
// most. A salt row for an owner that no longer exists is harmless — it is
// nothing but entropy — whereas a salt destroyed too early is an un-erasable
// audit trail, permanently.
func migration0005OwnerErasureSalts() migrate.Migration {
	return migrate.Migration{
		ID:   "0005",
		Name: "owner_erasure_salts",
		Preconditions: []migrate.Precondition{
			migrate.TableAbsent("owner_erasure_salts"),
		},
		Up: migrate.Steps{
			SQLite: []string{
				`CREATE TABLE owner_erasure_salts (
	owner_id TEXT PRIMARY KEY,
	salt BLOB NOT NULL,
	created_at TEXT NOT NULL
)`,
			},
			Postgres: []string{
				`CREATE TABLE owner_erasure_salts (
	owner_id TEXT PRIMARY KEY,
	salt BYTEA NOT NULL,
	created_at TEXT NOT NULL
)`,
			},
		},
		Down: migrate.Steps{
			SQLite:   []string{`DROP TABLE owner_erasure_salts`},
			Postgres: []string{`DROP TABLE owner_erasure_salts`},
		},
	}
}

// migration0008DevicePairings creates the device_pairings table: the short-lived
// enrollment records a device code and a user code are verified against.
//
// Only digests are stored. device_code_hash and user_code_hash hold the hash of
// each secret, never the secret, so a store dump yields nothing presentable;
// the lookup path hashes first and matches on the digest.
//
// user_code_hash is nullable because a manually minted pairing is approved at
// creation and never needs a user code. The index on it is therefore a plain
// index and not UNIQUE: a UNIQUE index would still permit multiple NULLs on
// both engines, so it would not constrain the manual case, while it would make
// a hash collision between two live pairings an insert failure rather than a
// lookup that the caller resolves. Uniqueness of a user code is a property the
// minting code enforces by drawing fresh codes, not something this table can
// assert about a digest column that is mostly NULL.
//
// status is CHECK-constrained to the PairingStatus set. It is the interlock the
// conditional transitions turn on: approval applies only to a pending row and
// redemption only to an approved one, so a second approval cannot rebind the
// owner and a second redemption cannot spend the same device code twice.
//
// owner_id is nullable and carries no FOREIGN KEY. A pending pairing has no
// owner yet — the owner is established BY the approval — so the column cannot
// be NOT NULL, and a pairing must remain deletable by the expiry sweep on its
// own schedule rather than one an owner row's lifetime dictates.
//
// expires_at is indexed for the expiry sweep, and next_poll_at is stored so a
// client that ignores the polling interval is throttled rather than served.
func migration0008DevicePairings() migrate.Migration {
	const (
		createSQLite = `CREATE TABLE device_pairings (
	id TEXT PRIMARY KEY,
	owner_id TEXT,
	device_code_hash BLOB NOT NULL,
	user_code_hash BLOB,
	client_label TEXT NOT NULL DEFAULT '',
	scopes TEXT NOT NULL DEFAULT '[]',
	status TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'redeemed', 'revoked')),
	lineage_id TEXT NOT NULL DEFAULT '',
	next_poll_at TEXT NOT NULL,
	created_at TEXT NOT NULL,
	expires_at TEXT NOT NULL,
	approved_at TEXT,
	redeemed_at TEXT,
	revoked_at TEXT
)`
		createPostgres = `CREATE TABLE device_pairings (
	id TEXT PRIMARY KEY,
	owner_id TEXT,
	device_code_hash BYTEA NOT NULL,
	user_code_hash BYTEA,
	client_label TEXT NOT NULL DEFAULT '',
	scopes TEXT NOT NULL DEFAULT '[]',
	status TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'redeemed', 'revoked')),
	lineage_id TEXT NOT NULL DEFAULT '',
	next_poll_at TEXT NOT NULL,
	created_at TEXT NOT NULL,
	expires_at TEXT NOT NULL,
	approved_at TEXT,
	redeemed_at TEXT,
	revoked_at TEXT
)`
		indexUserCode  = `CREATE INDEX ix_device_pairings_user_code_hash ON device_pairings (user_code_hash)`
		indexOwner     = `CREATE INDEX ix_device_pairings_owner_id ON device_pairings (owner_id)`
		indexExpiresAt = `CREATE INDEX ix_device_pairings_expires_at ON device_pairings (expires_at)`
	)

	return migrate.Migration{
		ID:       "0008",
		Name:     "device_pairings",
		Requires: []string{"0001"},
		Preconditions: []migrate.Precondition{
			migrate.TableAbsent("device_pairings"),
		},
		Up: migrate.Steps{
			SQLite:   []string{createSQLite, indexUserCode, indexOwner, indexExpiresAt},
			Postgres: []string{createPostgres, indexUserCode, indexOwner, indexExpiresAt},
		},
		Down: migrate.Steps{
			SQLite:   []string{`DROP TABLE device_pairings`},
			Postgres: []string{`DROP TABLE device_pairings`},
		},
	}
}

// migration0007LinkedIdentities creates the linked_identities table, which binds
// an external identity-provider subject to a local owner and carries the
// personal data (email) obtained from that provider.
//
// The (provider, subject) pair is UNIQUE. That index is not merely an
// optimisation for the login-bootstrap lookup: it is the control that prevents
// one external subject from being bound to two owners. Without it a race
// between two concurrent link requests could attach the same provider identity
// to a second owner, and a subsequent login would resolve to whichever row was
// read first — an account-takeover primitive. The uniqueness is enforced by the
// database so it holds regardless of what any adapter or service does.
//
// email is nullable. It is personal data held here, separate from the owner
// row, so it can be crypto-erased independently; NULL is the post-erasure state
// as well as the state for providers that release no address.
//
// The table has an owner_id FOREIGN KEY to owners(id) and is indexed by
// owner_id for the owner-scoped list and the account-deletion sweep.
//
// This migration is numbered 0007 rather than 0006 because 0006
// (refresh_credentials) is developed on a sibling branch; see the pull request
// for the required merge order.
func migration0007LinkedIdentities() migrate.Migration {
	const (
		createSQLite = `CREATE TABLE linked_identities (
	id TEXT PRIMARY KEY,
	owner_id TEXT NOT NULL REFERENCES owners(id),
	provider TEXT NOT NULL,
	subject TEXT NOT NULL,
	email TEXT,
	created_at TEXT NOT NULL,
	updated_at TEXT NOT NULL
)`
		createPostgres = `CREATE TABLE linked_identities (
	id TEXT PRIMARY KEY,
	owner_id TEXT NOT NULL REFERENCES owners(id),
	provider TEXT NOT NULL,
	subject TEXT NOT NULL,
	email TEXT,
	created_at TEXT NOT NULL,
	updated_at TEXT NOT NULL
)`
		uniqueProviderSubject = `CREATE UNIQUE INDEX ux_linked_identities_provider_subject ON linked_identities (provider, subject)`
		indexOwner            = `CREATE INDEX ix_linked_identities_owner_id ON linked_identities (owner_id)`
	)

	return migrate.Migration{
		ID:       "0007",
		Name:     "linked_identities",
		Requires: []string{"0001"},
		Preconditions: []migrate.Precondition{
			migrate.TableAbsent("linked_identities"),
		},
		Up: migrate.Steps{
			SQLite:   []string{createSQLite, uniqueProviderSubject, indexOwner},
			Postgres: []string{createPostgres, uniqueProviderSubject, indexOwner},
		},
		Down: migrate.Steps{
			SQLite:   []string{`DROP TABLE linked_identities`},
			Postgres: []string{`DROP TABLE linked_identities`},
		},
	}
}

// migration0006RefreshCredentials creates the refresh_credentials table: the
// rotatable, single-use credentials from which access tokens are minted
// (ADR-0018).
//
// # Only the digest is stored
//
// secret_hash holds a digest of the refresh secret, never the secret itself.
// The secret exists only in the response that minted it, so a stolen database
// backup yields nothing that can be presented as a credential. The column is
// BLOB/BYTEA rather than TEXT because it holds raw digest bytes, and the
// comparison that consumes it is a constant-time one in internal/auth — the
// repository only ever stores and returns the bytes.
//
// # status is the single-use interlock
//
// A refresh credential is redeemed exactly once. That property is not enforced
// by the application reading the row and deciding it looks unused; it is
// enforced by a conditional UPDATE whose WHERE clause carries
// status = 'active', so that of two concurrent redemptions of the same
// credential exactly one can affect a row. The CHECK constraint here is
// defense-in-depth for the value set; the interlock itself lives in the
// single-statement transition. See refreshCredentialRepo.MarkRotated.
//
// # lineage_id and rotated_from_id
//
// lineage_id groups a rotation chain so that detecting reuse of any credential
// in the chain can revoke the whole chain in one statement — the
// reuse-detection response, which must reach the successor an attacker minted
// as well as the token they replayed. rotated_from_id records the predecessor
// and is nullable because the first credential in a lineage has none. It
// carries no foreign key to refresh_credentials(id) deliberately: DeleteExpired
// sweeps rows out by expiry without regard to chain position, and an FK would
// either block the sweep or cascade it into deleting live successors of an
// expired predecessor.
//
// # rotated_at is write-only for now
//
// MarkRotated is specified to stamp the credential's timestamps with the
// supplied now, but domain.RefreshCredential exposes no rotated-at field to
// carry it back, so the column is written and not read. It is kept rather than
// dropped because the moment a credential was rotated is exactly the datum a
// replay investigation needs: ErrConflict tells an operator a token was
// presented twice, and this column tells them when the legitimate presentation
// happened. The domain type can surface it later without a schema change.
//
// The indexes serve the two owner-scoped access patterns the port declares —
// listing an owner's credentials and listing one lineage — plus the expiry
// sweep, which scans by expires_at across all owners. expires_at is fixed-width
// RFC3339 UTC text, so its index orders chronologically under a plain lexical
// comparison.
func migration0006RefreshCredentials() migrate.Migration {
	return migrate.Migration{
		ID:       "0006",
		Name:     "refresh_credentials",
		Requires: []string{"0001"},
		Preconditions: []migrate.Precondition{
			migrate.TableAbsent("refresh_credentials"),
		},
		Up: migrate.Steps{
			SQLite: []string{
				`CREATE TABLE refresh_credentials (
	id TEXT PRIMARY KEY,
	owner_id TEXT NOT NULL REFERENCES owners(id),
	lineage_id TEXT NOT NULL,
	secret_hash BLOB NOT NULL,
	scopes TEXT NOT NULL DEFAULT '[]',
	client_label TEXT NOT NULL DEFAULT '',
	rotated_from_id TEXT,
	issued_at TEXT NOT NULL,
	expires_at TEXT NOT NULL,
	status TEXT NOT NULL CHECK (status IN ('active', 'rotated', 'revoked', 'expired')),
	rotated_at TEXT,
	revoked_at TEXT
)`,
				`CREATE INDEX ix_refresh_credentials_owner_id ON refresh_credentials (owner_id)`,
				`CREATE INDEX ix_refresh_credentials_lineage ON refresh_credentials (owner_id, lineage_id)`,
				`CREATE INDEX ix_refresh_credentials_expires_at ON refresh_credentials (expires_at)`,
			},
			Postgres: []string{
				`CREATE TABLE refresh_credentials (
	id TEXT PRIMARY KEY,
	owner_id TEXT NOT NULL REFERENCES owners(id),
	lineage_id TEXT NOT NULL,
	secret_hash BYTEA NOT NULL,
	scopes TEXT NOT NULL DEFAULT '[]',
	client_label TEXT NOT NULL DEFAULT '',
	rotated_from_id TEXT,
	issued_at TEXT NOT NULL,
	expires_at TEXT NOT NULL,
	status TEXT NOT NULL CHECK (status IN ('active', 'rotated', 'revoked', 'expired')),
	rotated_at TEXT,
	revoked_at TEXT
)`,
				`CREATE INDEX ix_refresh_credentials_owner_id ON refresh_credentials (owner_id)`,
				`CREATE INDEX ix_refresh_credentials_lineage ON refresh_credentials (owner_id, lineage_id)`,
				`CREATE INDEX ix_refresh_credentials_expires_at ON refresh_credentials (expires_at)`,
			},
		},
		Down: migrate.Steps{
			SQLite:   []string{`DROP TABLE refresh_credentials`},
			Postgres: []string{`DROP TABLE refresh_credentials`},
		},
	}
}

// migration0009Administrators creates the administrators table: the system-axis
// principals authorized to curate the reserved-identifier lists (ADR-0017).
//
// # Why this table has no owner_id and no foreign key
//
// Every other principal in the schema hangs off owners(id), because every other
// principal acts on one owner's data. An administrator does not: the blocklist
// and its allowlist are global (handles are a single global namespace), so the
// authority to edit them cannot be scoped to an owner without making it the
// wrong authority. Giving this table an owner_id would invite exactly the
// confusion the role exists to prevent — an "administrator of one owner" who
// nonetheless edits a list that binds every owner.
//
// # Why status is a CHECK-constrained enum rather than a boolean
//
// The authorization decision reads "is this administrator active?", and a
// disabled administrator must be distinguishable from an absent one. A deleted
// row loses the fact that the principal ever existed, which an incident review
// needs; a boolean invites a future third state to be encoded as NULL. The
// CHECK mirrors domain.AdminStatus so the database refuses a value the domain
// would not recognize, as defense-in-depth behind the adapter's own validation:
// an unrecognized status must never be readable back as authorization.
func migration0009Administrators() migrate.Migration {
	const ddl = `CREATE TABLE administrators (
	id TEXT PRIMARY KEY,
	label TEXT NOT NULL,
	status TEXT NOT NULL CHECK (status IN ('active', 'disabled')),
	created_at TEXT NOT NULL,
	updated_at TEXT NOT NULL
)`
	return migrate.Migration{
		ID:   "0009",
		Name: "administrators",
		Preconditions: []migrate.Precondition{
			migrate.TableAbsent("administrators"),
		},
		Up: migrate.Steps{
			SQLite:   []string{ddl},
			Postgres: []string{ddl},
		},
		Down: migrate.Steps{
			SQLite:   []string{`DROP TABLE administrators`},
			Postgres: []string{`DROP TABLE administrators`},
		},
	}
}
