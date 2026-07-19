# 0028. Schema migrations and backup

- **Status:** Accepted (confirmed by owner)
- **Date:** 2026-07-19

## Context

The backend supports both SQLite and PostgreSQL (ADR-0011). Schema evolution must
be safe and reproducible on both, easy for self-hosters yet controlled for
production.

## Decision

- **Versioned, embedded migrations.** Migrations are embedded in the binary, with
  **parallel sets maintained for SQLite and PostgreSQL**; features must not rely
  on engine-specific behavior only one supports.
- **Reversibility is mandatory.** **Every migration ships both a forward (up) and
  a reverse (down) plan.** A migration without a working reverse is not accepted;
  an intentionally destructive/irreversible step requires an explicit, reviewed
  exception documented in the migration itself. Down plans are tested (ADR-0020).
- **Dependency checking.** Each migration **declares its prerequisites**, and the
  runner **verifies dependencies and current schema preconditions before
  applying** — refusing to apply out of order, with a gap, or against an
  unexpected state, rather than corrupting data.
- **Configurable application.** Migrations **auto-apply on startup by default**
  (smooth self-hosting), with a **config toggle** to require an **explicit
  `migrate` command/subcommand** for controlled production rollouts.
- **Fail-closed on mismatch.** On startup the app checks the schema version and
  **refuses to run against an incompatible/newer schema** rather than risk data
  corruption.
- **Backup/restore documented per store** — SQLite (consistent file snapshot /
  online backup) and PostgreSQL (`pg_dump` / PITR) — with restore steps.
- **Migrations are tested on both engines** in CI (ties to ADR-0020).

## Consequences

- Self-hosters get zero-fuss upgrades; operators can gate schema changes in
  production.
- Maintaining two migration sets requires portability discipline and dual-engine
  CI.

## Tooling

Rather than bending a general-purpose library, the project uses a **small
embedded custom runner** over embedded SQL, because the mandatory-down and
dependency/precondition rules above are first-class requirements rather than
add-ons. Each migration is a versioned unit declaring:

- a unique **`id`** (monotonic/orderable),
- **`requires`** — the prerequisite migration id(s) that must already be applied,
- **`preconditions`** — schema/state checks that must hold before apply,
- an **`up`** plan and a **`down`** plan (down mandatory unless a documented,
  reviewed irreversible exception),
- an optional **`destructive`** flag that requires an explicit confirmation to
  apply.

The runner records applied migrations, verifies `requires`/`preconditions`, and
**refuses to apply out of order, with a gap, or against an unexpected state**.
Existing libraries (golang-migrate, goose) were considered; the custom runner was
chosen for full control over the mandatory-down + dependency semantics, with
their SQL-file conventions as prior art.

## Open items

Resolved: **embedded custom runner** with the `id`/`requires`/`preconditions`/
`up`/`down`/`destructive` declaration format above. Remaining as implementation
detail: the concrete on-disk migration file format and the applied-migrations
bookkeeping table layout.
