# 0007. Append-only audit log

- **Status:** Accepted (confirmed by owner)
- **Date:** 2026-07-19

## Context

Every change to which keys can access an owner's hosts is security-relevant.
Reconstructing "who added/removed which key, when" after the fact is impossible
without a record, and bolting one on later is invasive.

## Decision

Model an **append-only** audit log as a first-class domain concept. Record
access-affecting events (device registered/revoked, key added/revoked, handle
changed) with actor, action, target, timestamp, and non-secret metadata.
Repositories may insert and read audit records but never update or delete them.
Audit records never contain private key material or other secrets.

## Consequences

- Incident investigation and accountability are possible from day one.
- Minor write overhead per mutating operation.
- Retention, purge, and owner-erasure (pseudonymization) policy is specified in
  **ADR-0024**.
