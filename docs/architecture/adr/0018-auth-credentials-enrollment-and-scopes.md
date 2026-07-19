# 0018. Authentication credentials, enrollment, and authorization scopes

- **Status:** Accepted (confirmed by owner)
- **Date:** 2026-07-19

## Context

ADR-0009 chose *pluggable* management-auth providers (passkeys/WebAuthn, OIDC,
API-token/device-pairing) selected by the deployer. This ADR fixes the concrete
credential lifecycle and authorization model that sit on top of any provider.

## Decision

### Credential model

- Authenticating via any enabled provider yields a **long-lived, revocable
  refresh credential** bound to a specific client/device.
- The client exchanges the refresh credential for **short-lived access tokens**
  with a **15-minute TTL** (config-tunable, default 15m), presented as bearer
  credentials on API calls. Short TTLs bound the damage of a leaked access token.
- **Refresh credentials rotate on use.** Each refresh exchange issues a new
  refresh credential and invalidates the presented one. **Reuse of an already-
  rotated refresh credential is treated as a theft signal** and revokes the whole
  lineage (and is audited). Refresh credentials carry an **absolute lifetime cap
  (default 90 days)**, after which full re-authentication is required.
- Refresh credentials are **individually revocable** and enumerable by the owner
  ("your devices/sessions"), so losing one device does not require rotating
  everything.

Defaults (`15m` access TTL, `90d` refresh absolute cap) are configurable
(ADR-0022) and validated fail-closed.

### Enrollment (obtaining the first refresh credential)

Support all three, deployer/owner's choice:

1. **Device-authorization grant** — client shows a code; owner approves from an
   authenticated session.
2. **Manual token paste** — owner mints a pairing token and pastes it once.
3. **In-client interactive login** — client runs the provider flow directly.

### Authorization scopes

- A token carries **scopes**. The default for a paired **management client** is
  **full owner authority**: manage all of that owner's keys, key sets, devices,
  defaults, and per-set visibility.
- **Phase-1 scope catalog (owner axis):**
  1. **full-owner** — default; all of the owner's resources.
  2. **read-only** — read any of the owner's resources, mutate nothing.
  3. **single-set** — bound to **exactly one** named key set.
  4. **single-device** — bound to **exactly one** device.
- **Single-resource binding.** `single-set` and `single-device` bind to exactly
  one resource each; managing several resources with least privilege means
  minting several narrow tokens. (A resource *list* per token was considered and
  rejected for phase 1 — harder to reason about and audit; revisit if demand
  appears.)
- Scopes may be combined where meaningful (e.g. read-only + single-set).
- Every request is **owner-scoped** first (ADR-0004); scopes restrict *within*
  the owner. Scopes can only narrow, never widen, owner authority.

### Administrator authority (separate axis)

The **system administrator** role (ADR-0017) governs system-wide policy (e.g. the
reserved-identifier blocklist) and is **not** an owner scope. Owner tokens can
never grant administrator authority.

### OIDC providers (claim mapping)

Authentication against OIDC is **provider-agnostic via `.well-known` discovery**
with a **configurable claim mapping** (`sub` as the stable subject; configurable
`email`/`groups`/etc.), so any spec-compliant IdP works with no lock-in.

We **document and test** concrete setups for: **generic self-hosted OpenID
providers (Keycloak, Authentik)**, **Google**, **Microsoft (Entra ID)**,
**Auth0**, and **GitHub** (OAuth2, not full OIDC — via a small adapter). The
operator guide will include per-provider setup walkthroughs (self-hosted first,
then Google/Microsoft/Auth0/GitHub).

### Revocation

Revocation is **hybrid**:

- **Access tokens** normally expire by their 15-minute TTL (stateless fast path).
- Additionally, a **small live revocation denylist** is consulted so that
  high-value events — logout, device/credential removal, scope change, and
  refresh-reuse theft detection — take effect **immediately**, not after the TTL.
- Revoking a refresh credential invalidates its whole rotation lineage.

The denylist holds only not-yet-expired revoked identifiers, so it stays small
(entries age out with the access TTL). This gives immediate revocation without a
full-store lookup on every request.

## Consequences

- Leaked **access** token → short exposure window; leaked **refresh** credential
  → revocable, and if scoped, limited blast radius.
- Requires endpoints to list/revoke credentials and to mint scoped tokens; all
  such actions are audited (ADR-0007).
- The live revocation denylist is a small, fast store (in-memory with a shared
  backing for multi-instance, aligned with the rate-limit counter store, ADR-0023).
- WebAuthn covers both platform passkeys and **hardware security keys (YubiKey /
  FIDO2 roaming authenticators)** as first-class authenticators (ADR-0009);
  policy may require user verification (PIN/biometric).
- Remaining open item: **WebAuthn RP configuration** (relying-party ID/origin,
  attestation policy, resident-key/UV requirements) — to be settled with the
  WebAuthn library choice at implementation time. Account linking across providers for one owner is a
  documented implementation detail (match on verified email or explicit link).

## Alternatives considered

- **All tokens = full owner authority:** rejected; no least-privilege option and
  any leak is full account compromise.
- **Strict per-device least privilege by default:** rejected; too much friction
  for the primary desktop manager (sshpilot), which is expected to manage the
  whole account.
