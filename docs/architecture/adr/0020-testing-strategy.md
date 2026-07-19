# 0020. Testing strategy: unit + e2e across happy/fail/gray paths

- **Status:** Accepted (confirmed by owner)
- **Date:** 2026-07-19

## Context

Security is the first priority; correctness of the key-ingest, authorization,
isolation, and publish paths is safety-critical. The owner requires **all code**
covered by **unit and e2e** tests spanning **happy, fail, and gray** paths, with
both positive (pass) and negative (fail) tests.

## Decision

### Test kinds and path coverage

- **Unit tests** for all packages, table-driven, covering:
  - **Happy paths** — expected inputs produce expected results.
  - **Fail paths** — invalid input, auth failures, and error branches produce the
    correct errors/refusals. **Negative tests are mandatory.**
  - **Gray paths** — boundaries, malformed/hostile input, empty/limit values,
    unicode/homoglyph cases, and concurrency.
- **End-to-end tests** exercise the running server over HTTPS: enrollment, key &
  set management, publish for **public and protected** sets, the bounded
  revocation window, blocklist enforcement, and TLS modes (incl. refuse-plaintext
  and the self-signed guardrails). E2E runs against **both SQLite and
  PostgreSQL**.

### Security-critical packages (explicit negative/abuse tests, target 100%)

Key ingest (option rejection, weak-key rejection, canonicalization), publisher
line reconstruction, reserved-identifier blocklist incl. confusable/leetspeak,
authorization scopes, cross-tenant isolation, and TLS enforcement. Each must have
tests proving the *unsafe* thing is refused, not just that the safe thing works.

### CI gates

- Unit + e2e must pass to merge.
- Enforce a **coverage gate** (high overall — target ≥ 90%, tunable; **100% for
  designated security-critical packages**) as a required check.
- Run the **race detector** (`-race`); use **fuzz/property tests** for the
  key-ingest and identifier-normalization parsers.
- Matrix over SQLite + PostgreSQL.
- Test fixtures must **never** contain real secrets or private keys.

## Consequences

- High confidence and safe refactoring; regressions in security boundaries fail
  the build.
- Slower CI and real test-writing discipline; thin wiring (e.g. `main`) may be
  covered via e2e rather than unit tests.

## Open items

Exact coverage thresholds, e2e framework/harness choice, and the fuzz corpus are
implementation details to settle when coding starts.
