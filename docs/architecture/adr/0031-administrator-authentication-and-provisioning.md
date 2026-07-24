# 0031. Administrator authentication and provisioning

- **Status:** Proposed
- **Date:** 2026-07-23

## Context

ADR-0017 introduced the **system administrator** role (governs system-wide policy:
the reserved-identifier blocklist, allowlist, and audited runtime list edits).
ADR-0018 fixed the **owner** credential/enrollment/scope model and drew the
architectural line this ADR must respect:

> The system administrator role (ADR-0017) governs system-wide policy … and is
> **not** an owner scope. **Owner tokens can never grant administrator authority.**

Today the administrator role is *defined but unauthenticatable and unprovisionable*:

- `domain.Administrator` carries only `{ID, Label, Status(active|disabled),
  timestamps}` — **no credential, secret, handle, or scope**. Lookup is by
  `AdministratorID` only (`AdministratorRepository.Get`); there is no
  `GetByHandle`/`GetByCredential`.
- **Nothing creates an administrator.** No `bootstrap-admin` subcommand, no seed,
  no migration insert — only tests call `Admins.Create`. A deployment cannot
  produce a single admin.
- The admin list-edit HTTP surface (`internal/transport/http/adminlists.go`) is
  built and mounted but wired to `denyAllAdminIdentifier`, which returns `""` →
  every admin request is `403`. `listadmin.authorize` already requires a
  non-empty actor, calls `Admins.Get`, maps `ErrNotFound → 403` and
  `status != Active → 403`, and audits.

So the administrator axis needs two things it does not have: **a way to
authenticate** and **a way to provision the first admin**. Both must be a
separate axis from owners — an owner-key or owner-token leak must not yield admin
authority.

This ADR is deliberately scoped to **not** depend on the owner
enrollment/token-issuance HTTP surface (that work is tracked separately and is
not yet built); the administrator scheme must stand alone.

## Decision

### Credential: a signed administrator bearer token, on its own signing key

An administrator authenticates by presenting a **bearer token** whose payload
names an `AdministratorID` and which is **signed with a dedicated administrator
signing key that is distinct from the owner access-token signing key**.

- The **separate signing key** enforces ADR-0018's axis separation
  *cryptographically*: an owner-token signing-key compromise cannot forge an
  administrator token, and an owner access token is structurally never an
  administrator token (different key, different payload shape, different
  verifier). Admin authority is never expressible on the owner token.
- **Existence and revocation come from the `administrators` table, for free.**
  The token asserts *who*; the signature proves the assertion is authentic; the
  `Admins.Get → status == Active` check that `listadmin.authorize` **already**
  performs on every request is what actually authorizes. A validly-signed token
  for a `disabled` or deleted administrator is refused with no extra code.
- Therefore this scheme adds **no credential column, no credential table, and no
  migration.** No secret is stored on the backend to verify the token — only the
  signing key (an operator secret, resolved via the existing `secrets.Provider`,
  never persisted).

A new `AdminIdentifier` implementation verifies the bearer token (signature +
validity window) and returns the embedded `AdministratorID`; on any failure it
returns `""` (fail-closed → `403`), exactly as `denyAllAdminIdentifier` does.

### Provisioning: a `bootstrap-admin` subcommand

Provisioning is **in scope for this ADR**, not a follow-up: without it the scheme
authenticates nobody. A `bootstrap-admin` subcommand mirrors `bootstrap-owner`:
runs migrations idempotently, then `Admins.Create` a first administrator row
(`AdminStatusActive`), then **mints and prints, once, an administrator token**
for that ID. Only public facts and the token are printed; the token is shown
exactly once (like an access key), and re-running mints an additional token for
a (possibly new) admin rather than echoing an old one.

### Fail-closed wiring (mirrors the owner-management mount, ADR-0022/#112)

- Config gains an `admin_token_signing_key_ref` (a `secrets.Ref`, value ends in
  `_ref`, never inline). It resolves through the existing provider chain with the
  **same fail-closed rules** as the owner token signing key: unset in production
  is a hard error *when the admin API is enabled*; unset in dev leaves the admin
  API disabled (all `403`); set-but-unresolvable is always an error; **no
  generated default key is ever synthesized.**
- The `WithAdminIdentifier` option is mounted **all-or-nothing**: an adequate key
  builds the verifier and mounts it; an absent key logs a loud warning and mounts
  nothing, so the admin routes stay `403` for everyone. This is the exact shape
  of the owner-management mount.
- The signing key MUST meet the same minimum length floor as the owner signing
  key (`MinSigningKeyLen`).

## Consequences

- The administrator axis becomes usable end-to-end (provision → authenticate →
  edit lists) **without** any owner-enrollment machinery, keeping it independent
  of the separately-tracked token-issuance surface.
- ADR-0018's "owner tokens can never grant administrator authority" is upheld
  *by construction* (distinct signing key + distinct verifier + distinct payload).
- **Revocation granularity (note forward):** an administrator token is a stateless
  signed bearer credential; before its validity window closes, the only way to
  revoke it is to **disable the administrator row**, which revokes *all* of that
  admin's tokens at once — there is no per-token revocation in v1. This is
  adequate for the initial admin surface and mirrors the interim posture already
  accepted for the owner denylist (#112). Per-token revocation, if it proves
  necessary, would add an admin-credential table + a denylist and is deferred to
  a future ADR — explicitly out of scope here to keep this change small.
- The administrator token TTL is configurable and validated fail-closed; a short
  default bounds the blast radius of a leaked token, at the cost of re-minting
  (re-running the mint path) when it expires.

## Alternatives considered

1. **Reuse the owner access token with an added admin scope. — Rejected.**
   Directly forbidden by ADR-0018; the owner token/scope stack yields an
   `OwnerID`, never an `AdministratorID`, and putting admin authority on an
   owner-signed token collapses the two axes a single key compromise is supposed
   to keep apart.
2. **mTLS administrator client certificates. — Deferred.** Operationally strong
   (no bearer secret in transit; revocation via CRL/short-lived certs), and it
   would still resolve to an `AdministratorID` via a cert→admin mapping. But the
   server does not request client certificates today (`ClientAuth`/`ClientCAs`
   are unset), so it needs real TLS surgery plus a trust-store and mapping layer —
   materially more than the signed-token path. It remains the natural upgrade if a
   no-bearer-secret posture is later required, and this ADR does not preclude it.
3. **No HTTP administrator surface; edits only via a local CLI writing overrides
   directly. — Rejected.** The admin list-edit endpoints are already built and
   mounted; abandoning the runtime API to avoid building auth discards working
   code and pushes every policy edit to shell access on the host.
