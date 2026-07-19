# Requirements — Phase 1 (DRAFT / LIVING)

> **This document is not final.** Features are being described one at a time.
> It will not be treated as complete until the project owner explicitly says
> "phase 1 is finalized." Until then, expect additions and changes.

## 1. Product vision

`sshpilot-vallet` is a backend "vallet" for a user's SSH **public** keys. It
lets a user publish the public keys generated on their various devices and keep
the `authorized_keys` on their machines consistent — without manually copying
keys between hosts. It is modelled on the "SSH ID" concept: keys are generated
**on each device** (private keys never leave the device), only **public** keys
are synced, and an owner's active public keys are published at a stable
**handle**.

Primary consumer of the backend: the **sshpilot** desktop client
(`io.github.mfat.sshpilot`). Future consumers: a web UI, a TUI, and/or a simple
CLI for managing keys.

## 2. Glossary

- **Owner** — the entity that owns devices and keys. Today a single user; the
  abstraction is designed to become a team/org later without a rewrite.
- **Handle** — an owner's URL-safe, globally-unique identifier. Key sets publish
  under it at `GET /{handle}/{set}`; `GET /{handle}` serves the default set.
- **Key set** — a named, owner-scoped subset of the owner's keys with its own
  publish address and its own visibility. Keys may belong to several sets.
- **Device** — a machine that generated one or more key pairs. Keys are grouped
  by device so a lost/retired device can be revoked as a unit.
- **Public key** — an SSH public key (incl. hardware/passkey-backed
  `sk-ssh-ed25519`, `sk-ecdsa-...`, plus `ed25519`, `ecdsa`, `rsa`).
- **Consuming server** — a host whose `authorized_keys` is populated from a
  handle.
- **Deployer / operator** — whoever runs an instance; chooses which auth
  providers are enabled and other instance policy (deploy-time config).
- **System administrator** — an authenticated role (distinct from an owner) that
  manages system-wide policy at runtime, e.g. editing the reserved-identifier
  blocklist. Actions are audited.
- **Reserved-identifier blocklist** — the system-wide list of words/patterns that
  may not be used as handles or key-set names (ADR-0017).

## 3. Confirmed decisions (see ADRs for detail)

| # | Decision | ADR |
| --- | --- | --- |
| 1 | Implementation language: **Go**. | — |
| 2 | API style: **REST over HTTP+JSON**, OpenAPI as the contract. | 0005 |
| 3 | Architecture: **standard Go layout** + clean layered/hexagonal separation. | 0005 |
| 4 | Data store: **SQLite and PostgreSQL** behind a repository interface (SQLite for zero-ops self-host, Postgres for SaaS/teams). | 0005, 0011 |
| 5 | Key material: **public keys only** — private keys never touch the backend. | 0002 |
| 6 | Phase-1 distribution: **clientless** — a server populates `authorized_keys` via stock `curl`/`AuthorizedKeysCommand`, no agent required. | 0003 |
| 7 | Tenancy: **owner abstraction now**; **multi-tenant-capable, self-hosted first, SaaS-ready later** (both, phased). | 0004, 0008 |
| 8 | License: **GPL-3.0** (matches the sshpilot family). | — |
| 9 | Module path (assumed): `github.com/mfat/sshpilot-vallet` — trivially renamable. | — |
| 10 | Management auth: **pluggable providers** — passkeys/WebAuthn (incl. **hardware security keys: YubiKey / FIDO2 roaming authenticators** as first-class), OAuth/OIDC, and API-token/device-pairing; the **deployer configures which are enabled**. Email+password excluded. | 0009 |
| 11 | Publish access: **per-owner configurable** — public by default; optionally requires an access key. | 0010 |
| 12 | Ingest security: **forbid `authorized_keys` options**; **canonical storage**; **reject weak keys** (DSA, RSA < 3072). | 0006 |
| 13 | **Append-only audit log** of every access-affecting change. | 0007 |
| 14 | Owner onboarding: **deployer-configurable** — open self-signup or invite/admin-provisioned. | 0012 |
| 15 | Key application: support **`curl`** and **`AuthorizedKeysCommand`**; ship a **managed-block helper** for the curl path. | 0013 |
| 16 | Per-owner **CA signing**: **deferred** beyond phase 1. | 0014 |
| 17 | Transport is **HTTPS-only**: no plaintext listener, plaintext **refused** (not redirected), HSTS, TLS ≥ 1.2. | 0015 |
| 18 | **Certificate modes** (deployer selects): automatic ACME, operator-provided cert+key, generate CSR for external signing, TLS terminated upstream, or **ephemeral self-signed** (dev/install-bootstrap only; ≤ ~6h validity; refused in production without explicit override). | 0015 |
| 19 | **ACME challenges**: TLS-ALPN-01 and DNS-01 (pluggable DNS providers, e.g. Cloudflare); HTTP-01 not used. | 0015 |
| 20 | **Multiple named key sets** per owner (many-to-many key membership), addressed at `/{handle}/{set}`; bare `/{handle}` serves an owner-designated **default set**; **visibility is per set** (access keys per set). **Set names:** lowercase `a–z`/`0–9`/hyphen, 1–64 chars, blocklist applies. **Max sets default 100** (configurable). **Default set not deletable** (reassign first); **non-empty delete needs confirmation**; **freed set names quarantine**. | 0016, 0010 |
| 21 | **Reserved-identifier blocklist** for handles & key-set names (system/impersonation/offensive terms + confusable/leetspeak matching); built-in default, deployer-seedable, and **runtime-editable by a system administrator** (audited). Introduces an **administrator** role. | 0017 |
| 22 | Management credentials: **refresh + short-lived access tokens** (individually revocable). **Access TTL 15m**; **refresh rotates on use** (reuse-theft detection) with a **90-day absolute cap**; revocation **hybrid** (TTL + small live denylist for immediate effect). Enrollment via **device-authorization grant, manual token paste, or in-client login** (deployer/owner choice). | 0009, 0018 |
| 23 | Authorization: tokens carry **scopes** — default **full owner authority**, with mintable narrower scopes (**read-only, single-set, single-device**, each bound to exactly one resource). Admin authority is a separate axis. **OIDC** provider-agnostic via discovery + configurable claim mapping; documented/tested for Keycloak/Authentik, Google, Microsoft Entra, Auth0, GitHub. | 0018 |
| 24 | Publish semantics: native `authorized_keys`, canonical/options-free, deterministic order; **short bounded TTL (~60s default) + ETag**; protected sets not shared-cached; revocation window bounded by TTL (AuthorizedKeysCommand is live). | 0019 |
| 25 | **Testing**: all code covered by **unit + e2e** tests spanning **happy, fail, and gray** paths; positive *and* negative tests mandatory; CI-enforced coverage gate; run against SQLite and Postgres. | 0020 |
| 26 | **Self-served API docs**: `GET /docs/` returns the OpenAPI document by requested type (rendered HTML / YAML / JSON), **default JSON**; `/docs/spec/` gives stable JSON/YAML URLs; assets bundled (no CDN); exposure deployer-configurable. | 0021 |
| 27 | **Config**: structured file (YAML/TOML) + env overrides (env > file > defaults), validated fail-closed at startup. **Secrets** never in the file — via env/file refs behind a pluggable secret-provider interface (Vault/KMS later); never logged. | 0022 |
| 28 | **Protected-set access** presented as an **`Authorization: Bearer`** header (never query string). Per-set access keys: **multiple named, independently revocable**, **rotate-with-grace**, **stored hashed**, **shown in plaintext once** at creation. | 0010 |
| 29 | **Rate limiting**: built-in, tiered, configurable (auth/signup/publish/admin), `429`+`Retry-After`, trusted-IP keying; coexists with external limiters. | 0023 |
| 30 | **Audit retention/erasure**: append-only + configurable retention purge; **pseudonymize** owner data on deletion/erasure while keeping the structural record. | 0024 |
| 31 | **Observability**: OpenTelemetry (OTLP) core + Prometheus `/metrics`; supports Grafana/New Relic/Datadog/etc. by config; `/healthz`+`/readyz` (readiness reflects DB & cert); `/metrics` exposure configurable; no secrets/PII in telemetry. | 0025 |
| 32 | **Handle lifecycle**: globally unique; **rename allowed with quarantine** (old handle held, never serves another owner's keys — 404/410). | 0026 |
| 33 | **Supply chain**: pinned deps + CI vuln scanning + SBOM + signed/reproducible artifacts & images (SLSA-style provenance). | 0027 |
| 34 | **Migrations/backup**: embedded, versioned, dual-engine migrations; **every migration has mandatory forward + reverse plans** and **declared dependencies verified before apply**; auto-apply by default with explicit-command toggle; fail-closed on schema mismatch; per-store backup/restore documented. | 0028 |

## 4. Phase-1 scope (as described so far)

Captured from the requirements given to date. **Incomplete — will grow.**

- **Publish public keys via key sets.** Store an owner's public keys, let the
  owner organize them into named **key sets**, and expose each set's active keys
  at `/{handle}/{set}` (and the default set at `/{handle}`) in native
  `authorized_keys` format. (ADR-0016)
- **Clientless consumption.** `curl https://<host>/<handle> >> ~/.ssh/authorized_keys`
  (or via `AuthorizedKeysCommand`) works with no proprietary client on the
  consuming server.
- **Idempotent application helper.** Ship a small **managed-block helper** so the
  curl path can update keys inside marked BEGIN/END blocks without duplicating or
  clobbering unmanaged lines; document `AuthorizedKeysCommand` as the recommended
  always-current option. (ADR-0013)
- **Sync across machines.** The same published set can be applied to all of the
  owner's machines, keeping them consistent.
- **Configurable onboarding.** The deployer chooses how owners are created —
  open self-signup or invite/admin-provisioned. (ADR-0012)
- **Reserved-identifier blocklist.** Enforce a system-wide blocklist on handles
  and key-set names (with confusable/leetspeak-aware matching); ship a default,
  allow deploy-time seeding, and let a **system administrator** edit it at
  runtime (audited). (ADR-0017)
- **Self-served API docs.** Serve the OpenAPI contract at `GET /docs/` by
  requested type (rendered HTML / YAML / JSON, default JSON) plus stable
  `/docs/spec/` URLs, with bundled (CDN-free) assets and deployer-configurable
  exposure. (ADR-0021)
- **HTTPS-only transport with certificate provisioning.** Serve only over TLS
  (no plaintext listener); obtain certs via automatic ACME (TLS-ALPN-01 / DNS-01,
  incl. Let's Encrypt / ZeroSSL / Cloudflare-DNS), or use an operator-provided
  cert, or generate a CSR for external signing, or run behind an upstream TLS
  terminator, or use an **ephemeral self-signed** cert for development / install
  bootstrap (≤ ~6h, refused in production without explicit override). (ADR-0015)
- **Key management surface.** The backend exposes management operations (register
  device, add/list/revoke keys, set handle, set handle visibility) for a
  separate client (sshpilot desktop first; web/TUI/CLI later). *Management client
  UX is out of scope for the backend.*
- **Configurable authentication.** The deployer enables any combination of the
  supported management-auth providers (§ decision 10).
- **Configurable handle visibility.** Each owner can make their handle public or
  require an access key (§ decision 11).

## 5. Confirmed security controls (phase 1)

- **Public keys only** — the backend never receives/stores private keys.
  (ADR-0002)
- **Canonical key storage; forbid options** — parse and store only structured
  fields (algorithm, normalized blob, fingerprint, sanitized comment); reject
  any option-bearing line (`command=`, `from=`, `environment=`, `no-pty`, ...);
  the publisher reconstructs lines and never echoes raw input. (ADR-0006)
- **Reject weak keys** — refuse DSA and RSA < 3072 bits at ingest. (ADR-0006)
- **Append-only audit log** — immutable record of every access-affecting change.
  (ADR-0007)
- **Owner-scoping at the data layer** — every query scoped by `OwnerID`.
  (ADR-0004)

## 6. Deferred / future (noted, not phase 1)

- **Per-owner CA signing** of published keys for third-party verifiability
  (Termius "SSH ID" parity). **Confirmed out of phase 1** (ADR-0014); the data
  model must not preclude adding it later.
- **Web UI / TUI / CLI** management clients.
- **Teams / orgs / RBAC** (owner abstraction already leaves room).
- **Pull-agent** distribution mode (superseded for phase 1 by clientless curl).

## 7. Cross-cutting requirements (apply to every feature)

- **Security is priority #1** at every step; no feature ships that weakens the
  controls in §5.
- **Test coverage is mandatory.** Every feature ships with unit + e2e tests
  covering happy, fail, and gray paths (positive and negative), meeting the
  CI-enforced coverage gate. Security boundaries require explicit negative tests.
  (ADR-0020)
- **Multi-tenant isolation:** one owner can never read or affect another owner's
  data; enforced at the repository layer.
- **Instance-level configuration:** auth providers, default handle visibility,
  and similar policy are set by the deployer via config (mechanism TBD).

## 8. Open questions (resolve before finalizing phase 1)

Resolved in round 1: management-auth model (→ pluggable, decision 10), handle
exposure (→ per-owner configurable, decision 11), key-options & audit policy
(→ decisions 12–13). Resolved in round 2: onboarding (→ configurable, decision
14), key application (→ curl + AuthorizedKeysCommand + helper, decision 15), data
store (→ SQLite + Postgres, decision 4), CA signing (→ deferred, decision 16).

Still open:

1. ~~Protected-set access mechanism~~ — **resolved:** `Authorization: Bearer`
   header (ADR-0010); access-key issuance/rotation/revocation lifecycle resolved
   in §5a (multiple named keys, rotate-with-grace, hashed, shown once).
2. ~~Auth fine detail~~ — **resolved (ADR-0018):** access TTL **15m**; refresh
   **rotates on use** with reuse-theft detection and **90-day absolute cap**;
   revocation is **hybrid** (TTL + small live denylist for immediate effect).
   Scope catalog fixed at four owner scopes (full-owner / read-only / single-set
   / single-device), each narrow scope bound to exactly one resource.
3. **OIDC & WebAuthn specifics** — OIDC **resolved (ADR-0018):** provider-agnostic
   via `.well-known` discovery + configurable claim mapping; documented/tested
   setups for self-hosted (Keycloak/Authentik), Google, Microsoft Entra, Auth0,
   GitHub. Still open: **WebAuthn RP config** (settled with library choice at
   implementation).
4. ~~Instance config mechanism~~ — **resolved:** file + env overrides, secrets
   via env/file refs behind a pluggable provider (ADR-0022). Exact schema/field
   names and YAML-vs-TOML remain implementation detail.
5. ~~Handle claiming & uniqueness / rename rules~~ — **resolved:** globally
   unique; rename allowed with quarantine (ADR-0026). Quarantine **duration**
   remains open (§Ops detail); set-name quarantine now resolved (§5a).
5a. ~~Key-set details~~ — **resolved (ADR-0016):** set-name rules = lowercase
   `a–z`/`0–9`/hyphen, 1–64 chars, blocklist applies; **max sets default 100**
   (configurable); **default set not deletable** (reassign first); **non-empty
   delete needs confirmation**; **freed set names quarantine**. Per-set access
   keys: **multiple named, independently revocable, rotate-with-grace, stored
   hashed, shown once** (ADR-0010).
5b. **Blocklist details:** confusable/leetspeak folding tables and per-category
   match mode; false-positive handling / allowlist; treatment of existing
   identifiers that later become blocked; whether device names are covered.
6. ~~Rate limiting / abuse~~ — **resolved:** built-in tiered + external-friendly
   (ADR-0023). Default values and the multi-instance shared counter store remain
   open.
7. **Managed-block helper form:** shell script shipped with releases vs an
   endpoint that serves the script vs both.
8. **TLS specifics:** EAB handling for ZeroSSL-style CAs; which DNS-01 providers
   ship first; storage location/format for cert, key, and DNS credentials;
   renewal scheduling and failure alerting; min TLS version / cipher defaults;
   fail-closed vs serve-last-good when a cert expires and renewal fails.

## 9. Change log

- 2026-07-19 (b809bbb) — Initial capture: vision, confirmed decisions, phase-1
  scope, open questions.
- 2026-07-19 (round 1 answers) — Added deployment model (both, phased),
  pluggable management auth, per-owner handle visibility; promoted key-ingest
  controls and audit log from Proposed to Confirmed; refreshed open questions.
- 2026-07-19 (round 2 answers) — Data store = SQLite + PostgreSQL; onboarding
  deployer-configurable; key application via curl + AuthorizedKeysCommand with a
  managed-block helper; CA signing confirmed deferred. Refreshed open questions.
- 2026-07-19 (feature: TLS) — HTTPS-only transport (refuse plaintext), four
  deployer-selectable certificate modes (ACME / provided / CSR / upstream),
  ACME via TLS-ALPN-01 and DNS-01 (no HTTP-01). Added ADR-0015 and TLS open
  items.
- 2026-07-19 (feature: dev/bootstrap TLS) — Added an ephemeral self-signed
  certificate mode for development and install bootstrap: ≤ ~6h validity ceiling,
  explicit/first-run activation, production start-refusal without override, loud
  warnings + audit event.
- 2026-07-19 (gap: key sets) — Owners can define multiple named key sets
  (many-to-many key membership), addressed at `/{handle}/{set}` with a default
  set at `/{handle}`; visibility and access keys are per set. Added ADR-0016;
  refined ADR-0004 and ADR-0010.
- 2026-07-19 (gap: auth) — Consolidated the auth model in ADR-0018: refresh +
  short-lived access tokens (individually revocable), enrollment via
  device-grant / manual paste / in-client login, and scoped authorization
  (default full owner authority; mintable read-only / single-set / single-device
  scopes). Admin authority is a separate axis (decisions #22, #23).
- 2026-07-19 (gap: publish semantics) — ADR-0019: native/canonical output,
  deterministic order, short bounded TTL (~60s) + ETag, protected sets not
  shared-cached, documented revocation window (decision #24).
- 2026-07-19 (feature: testing) — ADR-0020: all code under unit + e2e tests
  across happy/fail/gray with mandatory negative tests, CI coverage gate, run on
  SQLite + Postgres (decision #25).
- 2026-07-19 (feature: API docs endpoints) — ADR-0021: `/docs/` content-
  negotiated OpenAPI (default JSON) + rendered UI, `/docs/spec/` stable URLs,
  bundled assets, deployer-configurable exposure (decision #26).
- 2026-07-19 (gaps: access mechanism, config) — Protected-set access via
  `Authorization: Bearer` (ADR-0010, decision #28); configuration = file + env
  overrides with pluggable, never-logged secret providers (ADR-0022, #27).
- 2026-07-19 (gaps: rate limiting, audit lifecycle) — Built-in tiered,
  external-friendly rate limiting (ADR-0023, #29); audit append-only with
  retention purge and pseudonymize-on-erasure (ADR-0024, #30).
- 2026-07-19 (gaps: observability, handle lifecycle) — OTLP + Prometheus
  telemetry supporting Grafana/New Relic/Datadog/etc. (ADR-0025, #31); globally
  unique handles with rename-and-quarantine to prevent hijack (ADR-0026, #32).
- 2026-07-19 (gaps: supply chain, migrations) — Comprehensive supply-chain
  security (pinned deps, scanning, SBOM, signed/reproducible artifacts;
  ADR-0027, #33); embedded dual-engine versioned migrations with configurable
  apply and documented backup/restore (ADR-0028, #34).
- 2026-07-19 (migrations refinement) — Mandatory reverse (down) plan for every
  migration and dependency/precondition checking before apply (ADR-0028, #34).
- 2026-07-19 (feature: reserved identifiers) — System-wide blocklist for handles
  and key-set names across four categories with confusable/leetspeak-aware
  matching; default + deploy-time seed + runtime-editable by a new **system
  administrator** role (audited). Added ADR-0017.
- 2026-07-19 (open items: key-set detail) — Fixed key-set tuning in ADR-0016 /
  ADR-0010: set-name rules (lowercase/`0-9`/hyphen, 1–64, blocklist applies),
  **max sets default 100** (configurable), **default set not deletable**,
  **non-empty delete needs confirmation**, **freed set names quarantine**; per-set
  access keys are **multiple named, independently revocable, rotate-with-grace,
  hashed, shown once** (decisions #20, #28).
- 2026-07-19 (open items: auth detail) — Fixed concrete auth tuning in ADR-0018:
  **access TTL 15m**, **rotating refresh** with reuse-theft detection and a
  **90-day absolute cap**, and **hybrid revocation** (TTL + small live denylist).
  Scope catalog fixed at four owner scopes, each narrow scope bound to exactly
  one resource. **OIDC** made provider-agnostic (discovery + configurable claim
  mapping) with documented/tested setups for Keycloak/Authentik, Google,
  Microsoft Entra, Auth0, and GitHub (decisions #22, #23).
