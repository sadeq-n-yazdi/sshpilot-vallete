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

## Open items

Migration tooling/library choice (must support mandatory down plans and
dependency/precondition declarations); the exact dependency-declaration format;
whether destructive migrations require an explicit confirmation flag.
