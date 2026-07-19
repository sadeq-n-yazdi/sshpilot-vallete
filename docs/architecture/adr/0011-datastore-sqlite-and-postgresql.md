# 0011. Data store: SQLite and PostgreSQL behind a repository interface

- **Status:** Accepted (confirmed by owner)
- **Date:** 2026-07-19

## Context

The phased deployment model (ADR-0008) spans zero-ops personal self-hosting and
multi-tenant SaaS. These have different storage sweet spots: an embedded store
for the former, a networked RDBMS for the latter. ADR-0005 already mandates
accessing storage only through repository interfaces.

## Decision

Support **both SQLite and PostgreSQL** as first-class stores, selected by
configuration, behind the domain's **repository interfaces**:

- **SQLite** — default for single-instance/self-host; no external service.
- **PostgreSQL** — for SaaS, teams, and higher concurrency/HA.

Rules:

- Domain and service layers depend only on repository interfaces, never on a
  concrete driver or SQL dialect.
- Schema/migrations are maintained for both; features must not rely on
  engine-specific behavior that only one supports.
- Choice is a deploy-time config value; no code change to switch.

## Consequences

- Frictionless self-hosting and scalable SaaS from one codebase.
- Cost: two migration paths and a portable-SQL discipline (or a query layer that
  abstracts dialect differences); CI must test against both.
- Concurrency semantics differ (SQLite write serialization); the service layer
  must not assume Postgres-only guarantees.

## Alternatives considered

- **PostgreSQL only:** rejected; imposes an operational dependency on simple
  self-hosters.
- **SQLite only:** rejected; insufficient for SaaS-scale concurrency/HA.
- **Defer entirely:** rejected; supporting both is a design constraint worth
  fixing now so interfaces are shaped correctly.
