# 0030. Handle look-alike fold: stored column, fail-closed drift, startup recompute

- **Status:** Accepted (confirmed by owner)
- **Date:** 2026-07-21

## Context

A handle is the public address whose keys land in servers' `authorized_keys`
(ADR-0026). Exact-name uniqueness (`ux_handles_name`, migration 0001) does not
stop an impersonator: `paypa1`, `pay-pal`, and `paypal` are three distinct,
individually valid slugs that a human reads as one name. Confusable-name
uniqueness needs the folded comparison form — `blocklist.Skeleton(name)` — to be
unique across live claims.

`blocklist.Skeleton` is documented as a **one-way, lossy** projection whose
output "MUST NEVER be stored as the user's identifier, displayed back, used as a
database key, or round-tripped." That rule protects *identity*: resolution must
never go through the fold, or a request for `paypa1` would serve `paypal`'s keys
— the very impersonation this guards against. `blocklist.TableVersion`
(currently 6) identifies the folding-table revision; a table change moves which
identifiers fold together and is a deliberate, reviewed, security-relevant act.

Migration 0012 already added a `name_fold` column (storing `Skeleton(name)`), a
`fold_version` column, and a UNIQUE index `ux_handles_name_fold`. It backfills
pre-existing rows with `name_fold = name` (RAW, unfolded) and `fold_version = 0`
— so handles registered before 0012 carry no look-alike protection until a Go
pass recomputes them, and two pre-existing confusables (`paypal` / `paypa1`) can
both survive the index creation because their raw backfills differ as strings.

Two questions were left open and are decided here (owner decisions #45 and #48).

## Decision

### Storing the fold is a ratified, deliberate deviation (owner decision #45)

Storing `Skeleton(name)` in `name_fold` under a UNIQUE index is an **accepted,
deliberate deviation** from the Skeleton "do not store" contract. It is the only
race-free way to enforce confusable-handle uniqueness: an application-level "fold
the name, then look for a matching fold, then insert" check has a TOCTOU window
in which two concurrent registrations both pass the check and both insert. A
UNIQUE index closes that window in the database.

The deviation is bounded by three mitigations, and it is those bounds — not the
raw act of storing — that keep it safe:

- **Write-only.** `name_fold` never appears in a `WHERE`, `JOIN`, or `ORDER BY`
  that resolves a handle. Resolution matches the exact `name` (`GetByName`), so a
  request for a look-alike that was never registered **misses** rather than
  landing on the name it imitates. The identity guarantee the Skeleton contract
  protects is therefore never crossed; only the auxiliary uniqueness layer uses
  the column.
- **Per-row `fold_version`.** Every row records the `TableVersion` its
  `name_fold` was computed under, so a table bump is detectable per row and the
  column can be recomputed.
- **Recompute on bump.** A startup pass (below) brings stale rows current, so the
  stored value is never durably out of step with the live table.

### Fail closed on fold-version drift (owner decision #45)

Handle **create and rename fail closed while any handle row's `fold_version`
differs from `blocklist.TableVersion`**. The enforcement point is the adapter's
`Register` method — the single write choke point that both bootstrap create and
rename-to-a-new-name pass through — because `name_fold`/`fold_version` are
adapter-only concepts (there is deliberately no fold field on `domain.Handle`),
so a service-level guard would have to leak that concept upward and could be
walked past by a second write path. `Register` refuses with the new sentinel
`domain.ErrFoldStale` when any row is stale.

The rationale: while a stale (possibly raw, unfolded) `name_fold` sits in the
table, `ux_handles_name_fold` cannot be trusted to reject a look-alike of that
row, so a new registration could slip a confusable past it. Refusing new
registrations until a recompute has made the index trustworthy is the
fail-closed direction.

This is **not** server-wide downtime. Resolution of existing handles matches the
exact name and is unaffected — a live server keeps serving every handle it
already serves. Only *new registrations and renames* wait, and only until the
startup recompute (which runs before the listener binds) has completed, i.e. in
practice never at runtime.

**Intentional scope:** rename that *reclaims the owner's own quarantined hold*
reactivates an existing row through `Update`, not `Register`, so the guard does
not fire on it. This is deliberate: it is the owner's own name, it establishes no
new confusable relationship, and after the startup recompute no row is ever stale
at runtime, so the case cannot arise on a live server.

### Recompute is an automatic startup Go pass (owner decision #48)

The recompute — set `name_fold = Skeleton(name)`, `fold_version = TableVersion`
for every stale row — runs as a **Go pass integrated into the startup sequence**,
immediately after migrations apply and before the listener binds (fail-closed
ordering), and likewise in the `bootstrap-owner` subcommand after its migrations.
No operator action is required.

It is **not** a migration step. `internal/migrate` is a driver-free runner that
executes only SQL statements; it has no Go/data-migration step, and `Skeleton` is
Go code a SQL statement cannot call. Placing the pass in the composition root,
gated before the listener binds, is what guarantees a live server never serves
with stale folds and the recompute can never be skipped: startup fails closed if
it errors.

The pass runs in **one transaction**. Handle counts are small, and all-or-nothing
is the safe shape: a crash mid-pass rolls back, leaving rows stale, so the
fail-closed guard keeps blocking and the next boot retries. To avoid the ordering
hazard where a not-yet-processed row's raw backfill equals another row's true
skeleton, the pass first rewrites every stale row's `name_fold` to a unique,
non-collidable placeholder (`"!" + row id` — `Skeleton` never emits `!`, and ids
are unique), then writes true skeletons. Collisions are resolved in Go, not by
letting the index discover them.

### Keep the oldest handle; quarantine newer look-alikes (owner decision #48)

Recompute can surface a **pre-existing collision**: two handles registered before
the index that fold to the same skeleton. On collision the pass **keeps the
oldest handle** (by `created_at`, tie-broken by id) and **quarantines the newer
look-alike(s)** through the existing quarantine mechanism (`state = quarantined`,
held indefinitely with a nil `quarantine_until` so the release sweep never frees
it, `flagged_for_review = true`). Each quarantine emits a **loud audit record**
(`handle.quarantined`, system actor, naming the quarantined handle and the
survivor it collides with).

The pass **never aborts on a collision** — that would wedge every upgrade — and
**never silently serves two confusables**: the survivor keeps its true skeleton
in the index, and each newer look-alike is quarantined and recorded.

A quarantined loser keeps its placeholder `name_fold` (not its true skeleton):
its true skeleton belongs to the survivor and cannot be stored twice under the
full UNIQUE index. The placeholder is write-only, never resolved, and occupies no
reachable fold slot, so it collides with and blocks nothing. The full index is
kept deliberately rather than made partial on `state = 'active'`: a partial index
would let a stranger register a confusable of a quarantined name during the hold,
which the owner could then collide with on reclaim.

## Consequences

- Confusable-handle uniqueness is enforced by the database, race-free.
- New registrations/renames wait through a fold-table bump only until the startup
  recompute completes; existing handles resolve throughout.
- A fold-table bump is a code change that must ship with the recompute already in
  the startup path (it is), so an operator upgrade is self-healing.
- Migration 0012's guard, deployed against a database with pre-existing handles,
  fail-closed-blocks all create/rename (every row is `fold_version = 0`) **until**
  the recompute runs; the two must ship together. They do — both land before the
  `develop -> main` deploy in the same change.
- Pre-existing confusables are resolved on first boot after this change, keeping
  the oldest and quarantining the rest, with an audit trail for operators.

## Alternatives considered

- **Application-level fold check instead of a stored column + index.** Rejected:
  TOCTOU window under concurrent registration.
- **Partial `WHERE state = 'active'` fold index** so a quarantined loser can hold
  its true skeleton. Rejected: needs a new migration, changes 0012's documented
  invariant, and relaxes security (confusable of a quarantined name becomes
  registerable during the hold).
- **A migrate Go/data step.** Rejected: the runner is SQL-only by design, and the
  startup-pass placement gives the same guarantee without adding Go-migration
  support.
- **Aborting recompute on a pre-existing collision.** Rejected: it would wedge
  every upgrade of a database that already holds a confusable pair.
