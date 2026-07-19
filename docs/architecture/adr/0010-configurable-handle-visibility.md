# 0010. Configurable handle visibility

- **Status:** Accepted (confirmed by owner)
- **Date:** 2026-07-19

## Context

Keys are published at `GET /{handle}` and consumed by plain `curl` (ADR-0003).
Public keys are not secret, but the *association* handle→keys is metadata some
owners will want to restrict, while others want a frictionless public URL.

> **Refined by ADR-0016:** with named key sets, visibility is a **per key set**
> setting (each set is independently public or protected, with per-set access
> keys). The rationale and mechanics below are unchanged; read "handle" as "key
> set".

## Decision

Handle/key-set visibility is a **per key set** setting (originally per-owner):

- **Public (default):** anyone with the handle can fetch the keys. Rationale:
  public keys are public by nature, and this preserves the zero-friction
  `curl` workflow.
- **Protected:** fetching requires an **access key**. The exact presentation
  mechanism (so plain `curl` still works) is an open question — candidates:
  `Authorization` header, `?key=` query parameter, or HTTP basic auth — each with
  different caching/logging/leak trade-offs.

Notes:

- This governs only **read/consume** access to published keys. It is orthogonal
  to management authentication (ADR-0009).
- Even public handles serve only canonical, options-free key lines (ADR-0006).
- The instance default for new owners is operator-configurable (ADR-0008).

## Consequences

- Owners choose their own privacy/convenience trade-off.
- Protected mode needs a credential model (issue/rotate/revoke access keys) and a
  curl-friendly transport — to be specified.
- Rate limiting/enumeration protection still matters for public handles,
  especially in SaaS (open question).

## Alternatives considered

- **Always public:** rejected; some owners need to restrict the metadata.
- **Always authenticated:** rejected; breaks the phase-1 clientless `curl` goal
  for the common case.
