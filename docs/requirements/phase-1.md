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
are synced, and an owner's active public keys are published at a stable public
**handle**.

Primary consumer of the backend: the **sshpilot** desktop client
(`io.github.mfat.sshpilot`). Future consumers: a web UI, a TUI, and/or a simple
CLI for managing keys.

## 2. Glossary

- **Owner** — the entity that owns devices and keys. Today a single user; the
  abstraction is designed to become a team/org later without a rewrite.
- **Handle** — an owner's public, URL-safe identifier. An owner's active public
  keys are published at `GET /{handle}`.
- **Device** — a machine that generated one or more key pairs. Keys are grouped
  by device so a lost/retired device can be revoked as a unit.
- **Public key** — an SSH public key (incl. hardware/passkey-backed
  `sk-ssh-ed25519`, `sk-ecdsa-...`, plus `ed25519`, `ecdsa`, `rsa`).
- **Consuming server** — a host whose `authorized_keys` is populated from a
  handle.

## 3. Confirmed decisions (see ADRs for detail)

| # | Decision | ADR |
| --- | --- | --- |
| 1 | Implementation language: **Go**. | — |
| 2 | API style: **REST over HTTP+JSON**, OpenAPI as the contract. | 0005 |
| 3 | Architecture: **standard Go layout** + clean layered/hexagonal separation. | 0005 |
| 4 | Data store: **not chosen yet**; abstracted behind repository interfaces; docs default to PostgreSQL. | 0005 |
| 5 | Key material: **public keys only** — private keys never touch the backend. | 0002 |
| 6 | Phase-1 distribution: **clientless** — a server populates `authorized_keys` via stock `curl`/`AuthorizedKeysCommand`, no agent required. | 0003 |
| 7 | Tenancy: **owner abstraction now** (single user + devices); teams/orgs later. | 0004 |
| 8 | License: **GPL-3.0** (matches the sshpilot family). | — |
| 9 | Module path (assumed): `github.com/mfat/sshpilot-vallet` — trivially renamable. | — |

## 4. Phase-1 scope (as described so far)

Captured from the requirements given to date. **Incomplete — will grow.**

- **Publish public keys.** Store an owner's public keys and expose the active
  set at a public handle in native `authorized_keys` format.
- **Clientless consumption.** `curl https://<host>/<handle> >> ~/.ssh/authorized_keys`
  (or via `AuthorizedKeysCommand`) works with no proprietary client on the
  consuming server.
- **Sync across machines.** The same published set can be applied to all of the
  owner's machines, keeping them consistent.
- **Key management surface.** The backend must expose management operations
  (register device, add/list/revoke keys, set handle) for a separate client
  (sshpilot desktop first; web/TUI/CLI later). *Management client UX is out of
  scope for the backend.*

## 5. Proposed (security-driven, pending your confirmation)

- **Canonical key storage; forbid `authorized_keys` options.** Store only parsed
  fields (algorithm, normalized blob, fingerprint, sanitized comment); reject
  option-bearing lines (`command=`, `from=`, `environment=`, ...); reject DSA and
  undersized RSA. (ADR-0006)
- **Append-only audit log** of every access-affecting change. (ADR-0007)

## 6. Deferred / future (noted, not phase 1)

- **Per-owner CA signing** of published keys for third-party verifiability
  (Termius "SSH ID" parity).
- **Web UI / TUI / CLI** management clients.
- **Teams / orgs / RBAC.**
- **Pull-agent** distribution mode (superseded for phase 1 by clientless curl).

## 7. Open questions (resolve before finalizing phase 1)

1. **Management authN/authZ:** how does a client (sshpilot) authenticate an
   owner to add/revoke keys? (API tokens, OAuth/OIDC, device pairing?)
2. **Handle endpoint exposure:** is `GET /{handle}` public/unauthenticated?
   Implications: handle enumeration, and that publishing reveals *which* public
   keys grant access (public keys are not secret, but the association is
   metadata).
3. **Idempotent application:** plain `>> authorized_keys` duplicates on re-run
   and can clobber unmanaged lines. Do we recommend `AuthorizedKeysCommand`, and
   do we ship a managed-block helper?
4. **Handle claiming & uniqueness**, reservation, and change/rename rules.
5. **Rate limiting / abuse** on the public endpoint.
6. **Data store selection** and when to commit to it.
7. **Key options policy** and **audit log** — confirm the proposed items above.
8. **CA signing** — in or out of phase 1?

## 8. Change log

- _(pending first commit)_ — Initial capture: vision, confirmed decisions,
  phase-1 scope as described, open questions.
