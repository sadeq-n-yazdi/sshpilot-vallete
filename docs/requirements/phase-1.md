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
- **Handle** — an owner's URL-safe identifier. An owner's active public keys are
  published at `GET /{handle}`. Visibility is per-owner configurable (§5).
- **Device** — a machine that generated one or more key pairs. Keys are grouped
  by device so a lost/retired device can be revoked as a unit.
- **Public key** — an SSH public key (incl. hardware/passkey-backed
  `sk-ssh-ed25519`, `sk-ecdsa-...`, plus `ed25519`, `ecdsa`, `rsa`).
- **Consuming server** — a host whose `authorized_keys` is populated from a
  handle.
- **Deployer / operator** — whoever runs an instance; chooses which auth
  providers are enabled and other instance policy.

## 3. Confirmed decisions (see ADRs for detail)

| # | Decision | ADR |
| --- | --- | --- |
| 1 | Implementation language: **Go**. | — |
| 2 | API style: **REST over HTTP+JSON**, OpenAPI as the contract. | 0005 |
| 3 | Architecture: **standard Go layout** + clean layered/hexagonal separation. | 0005 |
| 4 | Data store: **not chosen yet**; abstracted behind repository interfaces; docs default to PostgreSQL. | 0005 |
| 5 | Key material: **public keys only** — private keys never touch the backend. | 0002 |
| 6 | Phase-1 distribution: **clientless** — a server populates `authorized_keys` via stock `curl`/`AuthorizedKeysCommand`, no agent required. | 0003 |
| 7 | Tenancy: **owner abstraction now**; **multi-tenant-capable, self-hosted first, SaaS-ready later** (both, phased). | 0004, 0008 |
| 8 | License: **GPL-3.0** (matches the sshpilot family). | — |
| 9 | Module path (assumed): `github.com/mfat/sshpilot-vallet` — trivially renamable. | — |
| 10 | Management auth: **pluggable providers** — passkeys/WebAuthn, OAuth/OIDC, and API-token/device-pairing; the **deployer configures which are enabled**. Email+password excluded. | 0009 |
| 11 | Publish access: **per-owner configurable** — public by default; optionally requires an access key. | 0010 |
| 12 | Ingest security: **forbid `authorized_keys` options**; **canonical storage**; **reject weak keys** (DSA, RSA < 3072). | 0006 |
| 13 | **Append-only audit log** of every access-affecting change. | 0007 |

## 4. Phase-1 scope (as described so far)

Captured from the requirements given to date. **Incomplete — will grow.**

- **Publish public keys.** Store an owner's public keys and expose the active
  set at a handle in native `authorized_keys` format.
- **Clientless consumption.** `curl https://<host>/<handle> >> ~/.ssh/authorized_keys`
  (or via `AuthorizedKeysCommand`) works with no proprietary client on the
  consuming server.
- **Sync across machines.** The same published set can be applied to all of the
  owner's machines, keeping them consistent.
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
  (Termius "SSH ID" parity). *(in/out of phase 1 still to confirm — see §8)*
- **Web UI / TUI / CLI** management clients.
- **Teams / orgs / RBAC** (owner abstraction already leaves room).
- **Pull-agent** distribution mode (superseded for phase 1 by clientless curl).

## 7. Cross-cutting requirements (apply to every feature)

- **Security is priority #1** at every step; no feature ships that weakens the
  controls in §5.
- **Multi-tenant isolation:** one owner can never read or affect another owner's
  data; enforced at the repository layer.
- **Instance-level configuration:** auth providers, default handle visibility,
  and similar policy are set by the deployer via config (mechanism TBD).

## 8. Open questions (resolve before finalizing phase 1)

Resolved since round 1: management-auth model (→ pluggable, decision 10), handle
exposure (→ per-owner configurable, decision 11), key-options & audit policy
(→ decisions 12–13).

Still open:

1. **Protected-handle access mechanism:** when a handle requires a key, how is it
   presented so plain `curl` still works? (`Authorization` header, `?key=` query,
   basic-auth?) Each has caching/logging/leak trade-offs.
2. **Token model:** scope, lifetime, rotation, and revocation for API tokens and
   device-pairing credentials.
3. **Owner onboarding/registration** per deployment: self-signup vs
   admin-provisioned, and how it differs by enabled auth provider and by
   self-hosted vs SaaS.
4. **OIDC specifics:** which providers, discovery/config, claim→owner mapping.
5. **Instance config mechanism:** file/env schema for enabling auth providers and
   setting defaults.
6. **Idempotent application:** plain `>> authorized_keys` duplicates on re-run
   and can clobber unmanaged lines. Recommend `AuthorizedKeysCommand`? Ship a
   managed-block helper?
7. **Handle claiming & uniqueness**, reservation, and change/rename rules
   (esp. across tenants).
8. **Rate limiting / abuse** on the public endpoint (more pressing for SaaS).
9. **Data store selection** and when to commit to it.
10. **CA signing** — in or out of phase 1?

## 9. Change log

- 2026-07-19 (b809bbb) — Initial capture: vision, confirmed decisions, phase-1
  scope, open questions.
- 2026-07-19 (round 1 answers) — Added deployment model (both, phased),
  pluggable management auth, per-owner handle visibility; promoted key-ingest
  controls and audit log from Proposed to Confirmed; refreshed open questions.
