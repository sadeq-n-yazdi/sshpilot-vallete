# 0005. REST/HTTP+JSON, OpenAPI, and standard Go layout

- **Status:** Accepted (confirmed by owner)
- **Date:** 2026-07-19

## Context

The backend serves multiple clients: the sshpilot desktop app now, and web/TUI/
CLI later — including AI consumers that benefit from a machine-readable
contract. A layout is needed that stays maintainable as the project grows.

## Decision

- **Transport:** REST over HTTP+JSON, with an **OpenAPI** document as the
  source-of-truth contract.
- **Layout:** standard Go project layout (`cmd/`, `internal/`, `pkg/`) with clean
  layered/hexagonal separation — domain, service, repository, transport — placed
  at the repository root (idiomatic Go).
- **Data store:** not selected yet; accessed only through repository interfaces
  so the concrete store is a late, swappable decision. Docs default to
  PostgreSQL for examples.

## Consequences

- One contract serves human and AI frontend developers; codegen is possible.
- Business logic is transport- and storage-agnostic and unit-testable without a
  database or HTTP server.
- Swapping/choosing the datastore later touches only the repository layer.

## Alternatives considered

- **gRPC / GraphQL:** deferred. REST+OpenAPI is the lowest-friction contract for
  the current and near-term clients, incl. simple `curl` consumption.
- **Flat package layout:** rejected as harder to scale for a security-sensitive,
  growing codebase.
