# Architecture Decision Records

An ADR captures one significant decision: its context, the choice, and the
consequences. They are the project's decision memory.

## Status values

- **Accepted** — confirmed by the project owner; the project is committed to it.
- **Proposed** — recommended (often for security) but **not yet confirmed**.
  Treat as an open question until accepted.
- **Superseded by NNNN** — replaced by a later ADR.

## Index

| ADR | Title | Status |
| --- | --- | --- |
| [0001](0001-record-architecture-decisions.md) | Record architecture decisions | Accepted |
| [0002](0002-public-keys-only.md) | Store public keys only | Accepted |
| [0003](0003-clientless-distribution-native-authorized-keys.md) | Phase-1 distribution is clientless via native authorized_keys | Accepted |
| [0004](0004-owner-handle-device-model-and-scoping.md) | Owner / Handle / Device model and owner-scoping | Accepted |
| [0005](0005-rest-http-json-standard-go-layout.md) | REST/HTTP+JSON, OpenAPI, standard Go layout | Accepted |
| [0006](0006-canonical-key-storage-forbid-options.md) | Canonical key storage; forbid authorized_keys options | Proposed |
| [0007](0007-append-only-audit-log.md) | Append-only audit log | Proposed |

New ADRs: copy [`0000-template.md`](0000-template.md), take the next number, add
a row above.
