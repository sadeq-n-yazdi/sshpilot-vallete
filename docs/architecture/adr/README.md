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
| [0006](0006-canonical-key-storage-forbid-options.md) | Canonical key storage; forbid authorized_keys options | Accepted |
| [0007](0007-append-only-audit-log.md) | Append-only audit log | Accepted |
| [0008](0008-deployment-model-multi-tenant-self-hosted-saas-ready.md) | Deployment: multi-tenant, self-hosted first, SaaS-ready | Accepted |
| [0009](0009-pluggable-management-authentication.md) | Pluggable management authentication | Accepted |
| [0010](0010-configurable-handle-visibility.md) | Configurable handle visibility | Accepted |
| [0011](0011-datastore-sqlite-and-postgresql.md) | Data store: SQLite and PostgreSQL behind a repository interface | Accepted |
| [0012](0012-configurable-owner-onboarding.md) | Configurable owner onboarding | Accepted |
| [0013](0013-key-application-methods.md) | Key application methods and managed-block helper | Accepted |
| [0014](0014-ca-signing-deferred.md) | Per-owner CA signing deferred beyond phase 1 | Accepted |
| [0015](0015-https-only-transport-and-certificate-provisioning.md) | HTTPS-only transport with pluggable certificate provisioning | Accepted |
| [0016](0016-named-key-sets.md) | Named key sets per owner | Accepted |
| [0017](0017-reserved-blocklisted-identifiers.md) | Reserved / blocklisted identifiers | Accepted |
| [0018](0018-auth-credentials-enrollment-and-scopes.md) | Auth credentials, enrollment, and authorization scopes | Accepted |
| [0019](0019-publish-and-consume-semantics.md) | Publish/consume semantics | Accepted |
| [0020](0020-testing-strategy.md) | Testing strategy: unit + e2e, happy/fail/gray | Accepted |
| [0021](0021-openapi-docs-endpoints.md) | Self-served OpenAPI spec and docs endpoints | Accepted |
| [0022](0022-configuration-and-secrets.md) | Configuration and secrets management | Accepted |
| [0023](0023-rate-limiting-and-abuse.md) | Rate limiting and abuse protection | Accepted |
| [0024](0024-audit-retention-and-erasure.md) | Audit retention and erasure | Accepted |
| [0025](0025-observability-and-telemetry.md) | Observability and telemetry | Accepted |
| [0026](0026-handle-lifecycle.md) | Handle lifecycle: uniqueness, rename, quarantine | Accepted |

New ADRs: copy [`0000-template.md`](0000-template.md), take the next number, add
a row above.
