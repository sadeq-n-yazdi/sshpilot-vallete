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
- The client exchanges the refresh credential for **short-lived access tokens**,
  presented as bearer credentials on API calls. Short TTLs bound the damage of a
  leaked access token.
- Refresh credentials are **individually revocable** and enumerable by the owner
  ("your devices/sessions"), so losing one device does not require rotating
  everything.

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
- Tokens may be minted with **narrower scopes** — e.g. **read-only**,
  **single-set**, **single-device** (and combinations) — for servers/CI or
  limited clients.
- Every request is **owner-scoped** first (ADR-0004); scopes restrict *within*
  the owner. Scopes can only narrow, never widen, owner authority.

### Administrator authority (separate axis)

The **system administrator** role (ADR-0017) governs system-wide policy (e.g. the
reserved-identifier blocklist) and is **not** an owner scope. Owner tokens can
never grant administrator authority.

### Revocation

Revoking a refresh credential invalidates its lineage; the access-token TTL
bounds the residual window. The exact propagation mechanism (e.g. short TTL vs a
revocation check) is an open design item.

## Consequences

- Leaked **access** token → short exposure window; leaked **refresh** credential
  → revocable, and if scoped, limited blast radius.
- Requires endpoints to list/revoke credentials and to mint scoped tokens; all
  such actions are audited (ADR-0007).
- Open design items: WebAuthn RP configuration, OIDC claim→owner mapping and
  account linking, the exact **scope catalog**, and token TTLs.

## Alternatives considered

- **All tokens = full owner authority:** rejected; no least-privilege option and
  any leak is full account compromise.
- **Strict per-device least privilege by default:** rejected; too much friction
  for the primary desktop manager (sshpilot), which is expected to manage the
  whole account.
