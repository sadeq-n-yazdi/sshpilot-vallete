# 0033. Admin-provisioned owner onboarding

- **Status:** Proposed
- **Date:** 2026-07-24

## Context

ADR-0012 made owner onboarding **deployer-configurable** with two modes — open
self-signup (SaaS) and invite / admin-provisioned (default-safe for self-host
and teams) — and named the default as the safe one. `config.OnboardingConfig`
carries the `mode` knob (`invite` | `open`, default `invite`, validated in
`config.Validate`), but nothing consumed it: no path created an owner at
runtime, so both modes behaved identically (there was no onboarding at all).

The pieces an admin-provisioned path needs already existed, unconnected:

- **Owner-creation invariants.** `bootstrap.Seed` creates an owner, its handle
  name-claim, and a public default key set in ONE transaction, running each
  user-chosen name through the composed name guard (ADR-0017). It exists for
  bring-up, seeds a device/key, and is a subcommand, not an authenticated
  surface.
- **Administrator authority.** ADR-0031 gave administrators a signed bearer
  token on a **dedicated** signing key and an `AdminIdentifier` transport seam,
  with the real authorization being the `Admins.Get → status == Active` check
  (a validly-signed token for a disabled admin is refused). Owner tokens can
  never carry admin authority (ADR-0018).
- **First-credential issuance.** ADR-0032 wired the enrollment/token surface.
  `auth.EnrollmentService.Mint(ownerID, label, scopes)` creates a **pre-approved**
  device pairing bound to an owner and returns a `Grant` whose `DeviceCode` is a
  one-time secret redeemed at `POST /api/v1/enroll/redeem` for the owner's own
  refresh + access tokens.
- **Insert-only audit.** ADR-0007's `audit.Emitter` appends allowlisted,
  non-secret records; `AuditActionOwnerCreated` ("owner.created") was defined
  but never emitted.

What was missing was the one composition tying **owner-creation** →
**first-credential**, behind the **administrator** role. Open self-signup —
which pulls in identity verification, abuse handling, and unauthenticated
rate-limiting (ADR-0012's open questions) — remains **deferred**; this ADR does
not build an unauthenticated signup route.

## Decision

### An administrator provisions an owner and receives a one-time enrollment code

A new service, `internal/service/onboarding`, exposes
`ProvisionOwner(ctx, actor AdministratorID, req)`. It is mounted at
`POST /api/v1/admin/owners`, gated by the same `AdminIdentifier` seam as the
reserved-identifier list routes (ADR-0031), and it:

1. **Re-authorizes the administrator against the store**, replicating
   `listadmin.authorize`: empty/unknown → `ErrUnauthorized`, disabled →
   `ErrForbidden`, store fault → wrapped (fail-closed). The transport verifies
   the token's *signature*; a signature is not authority, so the active-admin
   check lives in the service, where any future caller inherits it. Transport
   renders `ErrUnauthorized` and `ErrForbidden` **identically as 403**, so a
   disabled admin cannot be distinguished from an unknown one.
2. **Creates the owner atomically**, mirroring `bootstrap.Seed`'s invariants
   through the **composed** name guard (`policy.Guard`, not
   `nameguard.Default()`, so the operator's seed and runtime overrides apply):
   owner (active) → handle (active) → **public default** key set (active), in
   one `WithTx`. Unlike bootstrap it creates **no device and no key** — an
   admin-provisioned owner adds their own keys after they enroll. A partial seed
   (a claimed handle with no default set) is the dangerous outcome the single
   transaction rules out.
3. **Emits `owner.created` inside that transaction** via `Emitter.EmitTo(r.Audit,
   …)`: actor `administrator`/`<actor id>`, target `owner`/`<new owner id>`,
   details `handle` and `key_set_name` only. The owner and its audit record
   commit together or not at all. **No credential value is ever recorded** — the
   enrollment code is a secret and appears in no detail.
4. **Mints a one-time enrollment code** for the new owner via
   `EnrollmentService.Mint(ownerID, clientLabel, [full-owner])` and returns
   `{owner_id, handle, set_name, enrollment_code, expires_at, pairing_id}`. The
   code is the `Grant.DeviceCode`; the owner redeems it at the existing
   `POST /api/v1/enroll/redeem` to mint their **own** tokens. **The operator
   never holds the owner's long-lived credential** — only the short-lived,
   single-use code.

### The enrollment code IS a `Mint` device code — no new invite entity

Credential handoff reuses the device-pairing machinery (ADR-0032) rather than
inventing an invite entity. `Mint` already produces a pre-approved pairing whose
device code redeems for tokens; the provisioning route simply surfaces that
code. There is no new redeem path, no new revocation surface, and the owner's
first credential is minted by the same code the owner ultimately controls.

### Mint runs after the owner-create transaction commits

The owner-create writes + audit are one transaction; `Mint` runs in the
enrollment service's **own** transaction afterward. A mint failure leaves a real
owner with no issued code — the administrator sees the error and re-issues —
rather than the provision silently half-succeeding. This is the same
deliberately-separate posture `Redeem` takes; owner existence and code issuance
are not one atomic unit and are not pretended to be.

### Rate limiting: the ADMIN tier, keyed per administrator

The route carries the **ADMIN** rate-limit tier (ADR-0023): an ordinary
fixed-window `Tier` (not the failure-counting AUTH tier — the surface
authenticates a MAC-signed bearer, so there is no guessable secret for backoff
to defend), failing **closed** on a counter-store outage. It is keyed by the
resolved administrator; a request resolving to no administrator lands in one
shared empty-id bucket that only ever holds requests the service refuses anyway,
so a legitimate admin's own bucket is never touched. This is the **first admin
route wired to the ADMIN tier**; the reserved-identifier list routes are not
changed here.

### `onboarding.mode` is consumed at startup

`run()` warns loudly when `onboarding.mode == "open"`: public self-signup is
configured but not implemented, and only admin-provisioned onboarding is active.
`invite` (the default) stays quiet. This turns the deferred mode from a silent
no-op into a visible one, so an operator who expected a public signup route
learns it is absent from the log rather than from a 404.

## Consequences

- A deployment can create its first owners the moment it has one administrator
  (ADR-0031's `bootstrap-admin`), with the owner minting their own credentials —
  no operator-held owner secret, no client, no private key on the backend.
- **No new repository method, table, or migration.** Provisioning reuses
  `Owners.Create` / `Handles.Register` / `KeySets.Create`, the enrollment
  `Mint`, and the existing `owner.created` action and detail-key allowlist.
- **Fail-closed in every direction it can be:** no admin identity → 403 (empty
  actor refused); disabled/unknown admin → 403; nil onboarding service (owner
  signing key absent) → 500; nil guard refuses; reserved or invalid handle →
  400 with no hint which rule fired; taken handle → 409.
- Open self-signup remains future work and still owes verification, abuse
  handling, and unauthenticated rate-limiting before it is safe to enable
  (ADR-0012). Nothing here is superseded.

## Alternatives considered

- **A new invite entity (token, table, redeem route).** Rejected: `Mint`
  already yields a one-time, owner-bound, redeemable secret with a revocation
  story (ADR-0032). A parallel invite mechanism would be a second credential
  path to keep in agreement.
- **Authorizing only at the transport (trust the signed token).** Rejected: a
  signature proves authenticity, not active authority. The `Admins.Get → Active`
  check in the service is what revokes a disabled admin's still-valid token, and
  placing it in the service makes it a property of the operation (ADR-0031).
- **Provisioning the owner and minting the code in one transaction.** Rejected:
  `Mint` uses its own unit of work and the enrollment surface already treats
  issuance as separate from the state it reads; forcing atomicity would entangle
  two services' transaction boundaries for no safety gain.
- **Building open self-signup now.** Out of scope by ADR-0012; it requires
  controls not yet designed, and shipping it behind the same route would be an
  unauthenticated owner-creation surface.
