# sshpilot-vallet — Phase-1 Spec Overview (review snapshot)

> **A readable roll-up for review.** The authoritative sources remain the
> [requirements outline](requirements/phase-1.md), the
> [ADR log](architecture/adr/README.md), and the
> [threat model](security/threat-model.md). This page summarizes all decisions to
> date (#1–34, ADR-0002–0028) grouped by theme. Nothing here is implemented yet —
> this is the design, still pre-implementation, phase 1 **not yet finalized**.

## What it is

An **"SSH ID"-style backend**: an owner registers their SSH **public** keys from
their devices, organizes them into named **key sets**, and publishes each set at
`GET /{handle}/{set}` in native `authorized_keys` format. Servers consume it with
plain `curl` or `AuthorizedKeysCommand` — no client required. Companion backend
to the **sshpilot** desktop app; future clients: web/TUI/CLI. Security is the
first priority throughout.

---

## A. Product & architecture

- **Go**; **REST over HTTP+JSON** with an **OpenAPI** contract (#1, #2 · ADR-0005).
- **Standard Go layout** + clean layered/hexagonal separation (#3 · ADR-0005).
- **Data store: SQLite _and_ PostgreSQL** behind repository interfaces — SQLite
  for zero-ops self-host, Postgres for SaaS/teams (#4 · ADR-0011).
- **Deployment: multi-tenant-capable, self-hosted first, SaaS-ready** (both,
  phased) (#7 · ADR-0008).
- **License GPL-3.0**; module `github.com/mfat/sshpilot-vallet` (assumed) (#8, #9).

## B. Identity, tenancy & namespace

- **Owner / Handle / Device** model; **owner-scoping enforced at the data layer**
  (multi-tenant isolation) (ADR-0004).
- **Named key sets** per owner (many-to-many key membership); `/{handle}/{set}`,
  bare `/{handle}` = owner-designated **default set** (#20 · ADR-0016).
- **Handle lifecycle:** globally unique; **rename allowed with quarantine** so a
  freed handle never serves another owner's keys (old URL 404/410) (#32 · ADR-0026).
- **Reserved-identifier blocklist** (system/impersonation/offensive +
  confusable/leetspeak matching); default + deploy-seed + **runtime-editable by a
  system administrator** (audited). New **administrator** role (#21 · ADR-0017).
- **Onboarding: deployer-configurable** — open self-signup or invite/admin (#14 ·
  ADR-0012).

## C. Keys & publishing

- **Public keys only** — private keys never touch the backend (#5 · ADR-0002).
- **Canonical storage; forbid `authorized_keys` options; reject weak keys**
  (DSA, RSA<3072). Publisher reconstructs lines, never echoes input (#12 · ADR-0006).
- **Clientless distribution** via native `authorized_keys` (#6 · ADR-0003), applied
  by **`curl` + managed-block helper** or **`AuthorizedKeysCommand`** (#15 · ADR-0013).
- **Publish semantics:** deterministic output, **short bounded TTL (~60s) + ETag**;
  protected sets never shared-cached; documented revocation window (#24 · ADR-0019).
- **Per-set visibility:** public by default or **access-key protected**, presented
  as **`Authorization: Bearer`** (#11, #28 · ADR-0010).
- **Per-owner CA signing: deferred** beyond phase 1; model stays forward-compatible
  (#16 · ADR-0014).

## D. Authentication & authorization

- **Pluggable management-auth providers** — passkeys/WebAuthn (incl. **hardware
  security keys: YubiKey / FIDO2**), OIDC, API-token/device-pairing — **deployer
  selects** which are enabled; email+password excluded (#10 · ADR-0009).
- **Credentials:** revocable **refresh** (rotates on use, reuse-theft detection,
  90-day absolute cap) + **short-lived access** tokens (**15m TTL**); revocation
  **hybrid** (TTL + small live denylist); **enrollment** via device-authorization
  grant, manual paste, or in-client login (#22 · ADR-0018).
- **Scoped authorization:** default **full owner authority**; mintable narrower
  scopes (read-only / single-set / single-device, each bound to one resource).
  Admin authority is a separate axis (#23 · ADR-0018).
- **OIDC:** provider-agnostic (`.well-known` discovery + configurable claim
  mapping); documented/tested for Keycloak/Authentik, Google, Microsoft Entra,
  Auth0, GitHub (#23 · ADR-0018).

## E. Transport & TLS

- **HTTPS-only** — no plaintext listener; plaintext **refused** (not redirected);
  HSTS; TLS ≥ 1.2 (#17 · ADR-0015).
- **Cert modes (deployer picks):** automatic **ACME**, operator-provided cert+key,
  **CSR for external signing**, **TLS terminated upstream**, or **ephemeral
  self-signed** for dev/install-bootstrap (≤ ~6h, production-refused w/o override)
  (#18 · ADR-0015).
- **ACME challenges: TLS-ALPN-01 and DNS-01** (pluggable DNS providers, e.g.
  Cloudflare); no HTTP-01 (#19 · ADR-0015).

## F. Security controls (cross-cutting)

- **Append-only audit log** of access-affecting changes (#13 · ADR-0007), with
  **retention purge + pseudonymize-on-erasure** (#30 · ADR-0024).
- **Rate limiting & abuse protection** — built-in tiered, configurable,
  external-friendly; brute-force backoff (#29 · ADR-0023).

## G. Configuration & secrets

- **Config:** structured file (YAML/TOML) + env overrides (env > file > defaults),
  **validated fail-closed** at startup. **Secrets** never in the file — env/file
  refs behind a **pluggable secret-provider** interface (Vault/KMS later), never
  logged (#27 · ADR-0022).

## H. Operations

- **Observability:** OpenTelemetry (OTLP) core + Prometheus `/metrics`; supports
  Grafana/New Relic/Datadog/etc. by config; `/healthz`+`/readyz` reflect DB & cert
  readiness; no secrets/PII in telemetry (#31 · ADR-0025).
- **Migrations/backup:** embedded, versioned, **dual-engine**; **mandatory
  forward + reverse plans**; **declared dependencies verified before apply**;
  auto-apply default w/ explicit-command toggle; fail-closed on mismatch;
  per-store backup/restore (#34 · ADR-0028).
- **Supply chain:** pinned deps + CI vuln scanning + SBOM + **signed/reproducible**
  artifacts & images (SLSA-style provenance) (#33 · ADR-0027).

## I. Quality & developer surface

- **Testing:** all code under **unit + e2e** tests across **happy/fail/gray**;
  mandatory negative tests; CI coverage gate (100% for security-critical pkgs);
  run on SQLite + Postgres (#25 · ADR-0020).
- **Self-served API docs:** `GET /docs/` content-negotiated OpenAPI (**default
  JSON**) + rendered UI; `/docs/spec/` stable URLs; bundled CDN-free assets;
  exposure configurable (#26 · ADR-0021).

---

## Deferred beyond phase 1

Per-owner CA signing (ADR-0014); web/TUI/CLI management clients; teams/orgs/RBAC
(owner abstraction already leaves room); pull-agent distribution mode.

## Open items (tuning/detail, not open decisions)

- ~~**Auth detail:**~~ **resolved (ADR-0018):** scope catalog (4 owner scopes,
  single-resource binding), access TTL 15m, rotating refresh + 90-day cap, hybrid
  revocation, OIDC discovery + claim mapping (Keycloak/Authentik, Google, Entra,
  Auth0, GitHub). Remaining: **WebAuthn RP config** (with library choice).
- **Key-set detail:** set-name rules/reserved names, max sets, delete-default/
  non-empty rules, per-set access-key lifecycle; whether set names quarantine.
- **Blocklist detail:** confusable/leetspeak folding tables, per-category match
  mode, false-positive allowlist, treatment of already-existing-now-blocked names.
- **TLS detail:** EAB for ZeroSSL, first DNS-01 providers, cert/key/cred storage,
  renewal scheduling/alerting, min TLS/cipher defaults, fail-closed vs last-good.
- **Ops detail:** default rate limits + multi-instance counter store; audit
  retention duration + pseudonymization technique; metric/span catalog; migration
  tooling + dependency-declaration format; quarantine duration.
- **Implementation artifacts (produced when coding starts):** field-level data
  model & constraints; full OpenAPI endpoint enumeration; package layout.

## Not-yet-written docs

Top-level `LICENSE` (GPL-3.0), `SECURITY.md` (disclosure policy), `CONTRIBUTING.md`,
and the developer / frontend-&-AI / operator / user guides.
