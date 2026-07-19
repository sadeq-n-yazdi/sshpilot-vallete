# 0021. Self-served OpenAPI spec and docs endpoints

- **Status:** Accepted (confirmed by owner)
- **Date:** 2026-07-19

## Context

ADR-0005 makes an OpenAPI document the source-of-truth API contract. Consumers —
human and AI frontend developers — need to fetch the machine-readable spec and to
browse a rendered version, served by the backend itself.

## Decision

### `/docs/` — content-negotiated

`GET /docs/` returns the OpenAPI document in the **requested representation**:

- **JSON — the default** (`application/json`) when no type is specified.
- **YAML** (`application/yaml`) when requested.
- **Rendered HTML** documentation UI when explicitly requested (e.g. via
  `Accept: text/html` or an explicit selector).

Selection is by `Accept` header and/or an explicit selector (e.g. `?format=` or a
path suffix); when ambiguous or unspecified, **JSON is served**.

### `/docs/spec/` — stable explicit URLs

Provide fixed URLs for tooling that wants a deterministic path, e.g.
`/docs/spec/openapi.json` and `/docs/spec/openapi.yaml`, returning the same
document as `/docs/`.

### Cross-cutting rules

- **Self-contained assets.** The rendered UI bundles all JS/CSS locally (embedded
  in the binary); it makes **no external CDN/network calls** and complies with a
  strict CSP.
- **Version-aligned.** The served spec matches the running server's API version;
  drift is prevented by generating the spec from code and/or contract tests.
- **Exposure is deployer-configurable.** Enabled and public by default (the
  contract is not secret), but the deployer can **disable** the docs endpoints or
  **require authentication** for locked-down/internal deployments.
- `docs` is a reserved routing term (ADR-0017), so no handle can shadow `/docs`.
- HTTPS-only like all endpoints (ADR-0015).

## Consequences

- Human and AI clients get both the raw contract and a browsable UI directly from
  the server, offline-friendly and CDN-free.
- The spec must be kept in sync with the implementation (generate-from-code or
  contract tests) or it will mislead consumers.
- Embedding renderer assets adds to the binary/embedded FS.

## Open items

Renderer choice (e.g. Swagger UI / Redoc / Scalar); spec generated-from-code vs
hand-authored with contract tests; the exact selector syntax and file paths.
