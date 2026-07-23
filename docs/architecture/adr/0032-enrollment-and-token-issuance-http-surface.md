# 0032. Enrollment and token-issuance HTTP surface

- **Status:** Accepted
- **Date:** 2026-07-19
- **Decider(s):** valletd maintainers

## Context

ADR-0018 defines the credential model — refresh credentials, single-use rotation,
device-pairing enrollment, and the three enrollment modes — and the service layer
that implements it (`internal/auth`: `EnrollmentService`, `TokenService`,
`Authenticator`, `Denylist`) is complete on both engines. What has been missing is
the HTTP surface that lets a clientless management tool actually *obtain* its first
refresh credential and *exchange* it for access tokens. Until those routes land,
enrollment is a set of tested service methods no caller can reach.

This surface is the authentication **entry point**. Every route here is reachable by
an unauthenticated network peer, and two of them (redeem, exchange) take a bearer
secret and hand back a freshly minted credential on success. That makes them the
highest-value brute-force and enumeration targets in the system. The forces:

- **No enumeration oracle.** A wrong credential, an expired one, a revoked one, and
  a never-existed one must be indistinguishable on the wire (status, body, and
  timing class). ADR-0018's uniform-rejection rule and `domain.ErrNotFound`'s
  deliberate conflation of "missing" and "someone else's" extend to this surface.
- **Brute-force bounding.** The device code is 256-bit (not guessable), but the
  human-typed **user code** is short (~40 bits) and is checked during owner
  approval. The token endpoints mint credentials and so must be metered even though
  their inputs are strong, because an unmetered mint endpoint is a credential-
  spraying amplifier. ADR-0023 already provides the AUTH rate-limit tier
  (failure-counting exponential backoff, fail-closed) for exactly this.
- **Revocation must be durable and shared.** ADR-0018's reuse-theft detection
  revokes a whole credential lineage the moment a rotated refresh token is replayed.
  That revocation is only meaningful if the component that *checks* tokens on the
  owner surface sees the same denylist the component that *revokes* them writes to.

## Decision

Mount an enrollment + token-issuance HTTP surface in `internal/transport/http`,
wired from the composition root, covering **modes 1 and 2 only**:

- **Mode 1 — device-authorization grant** (RFC 8628 in shape, not error vocabulary):
  `POST /api/v1/enroll/device` starts a grant (no owner; returns device code, user
  code, expiry, poll interval); the owner approves out-of-band via
  `POST /api/v1/enroll/approve` (guarded, owner from the verified token);
  `POST /api/v1/enroll/poll` reports pending/approved/failed against the device code;
  `POST /api/v1/enroll/redeem` exchanges an approved device code for the first
  credential.
- **Mode 2 — manual token mint:** `POST /api/v1/enroll/mint` (guarded) mints a grant
  the owner copies to the client, redeemed through the same `redeem` route.
- **Token exchange:** `POST /api/v1/token` exchanges a refresh token for an access
  token, rotating the refresh token single-use (ADR-0018); a replayed token revokes
  the lineage.

**Mode 3 (in-client interactive / OIDC login) is deferred.** ADR-0018 lists three
modes; the interactive mode needs an identity-provider round trip and a browser
redirect surface that this PR does not build. No route, option, or field for it is
added here; it will arrive under its own ADR.

### AUTH-tier rate limiting, keyed at the point of the credential check

The AUTH tier (ADR-0023) is driven **inside the handlers**, wrapping the credential
check, not as blanket middleware — the key depends on what the endpoint verifies:

- **Redeem, Exchange** — the credential-minting checks — are keyed by the
  **trusted-proxy-aware client IP** (`clientIP`). `Check` runs before the service
  call; a genuine credential failure calls `RecordFailure`; success calls
  `RecordSuccess`. A limiter error or a deny is fail-closed: `429` with `Retry-After`.
- **Approve** is keyed by the **verified owner**, not IP, so short-user-code guessing
  is bounded independently of IP rotation and behind the owner's authenticated
  identity. This is a distinct limiter namespace from the service's own per-owner
  approval-attempt cap (`checkApprovalLimit`): the service enforces a flat attempt
  ceiling per pairing lifetime; the transport tier adds failure-counting backoff.
  The two are complementary, not duplicative — inner flat cap, outer backoff.
- **Poll and StartDeviceGrant** run `Check` (so an IP already locked out for spraying
  redeem/exchange cannot use them either) but do **not** `RecordFailure`. Poll takes
  the 256-bit device code (no guessing oracle) and the service already throttles poll
  cadence per device code; the "polled too soon" and "wrong code" outcomes are
  deliberately indistinguishable at the service boundary, so counting them as auth
  failures would penalize an honest, slightly-eager client. StartDeviceGrant presents
  no credential at all, so there is nothing to count. Their abuse bound is the shared
  IP lockout plus short pairing expiry; a dedicated per-IP volume limit for the
  unauthenticated start/poll pair is noted as follow-up.

### One shared denylist instance

The composition root builds **exactly one** `*auth.Denylist` and threads it into the
owner `Guard`, the `TokenService`, and the `EnrollmentService`. It is backed by the
**shared counter store** (`rate_limit.store`) so a revocation survives a restart and
is visible across replicas; when no shared store is configured it falls back to the
in-memory store, exactly as the owner path does today. Building a second denylist
for the new services would let a lineage revoked during exchange stay honored by the
owner Guard — the precise failure this decision forecloses.

## Consequences

- The management client has a complete, native enrollment path with no private key
  or agent on the backend, closing the last gap between the service layer and a
  usable "SSH ID" onboarding flow.
- The AUTH tier's failure-counting is now exercised by real routes; its keying is
  explicit and testable (removing a `RecordFailure`, or flipping a `Check` deny to
  allow, breaks a negative test).
- Revocation is durable and consistent across the token, enrollment, and owner
  surfaces because one denylist instance is shared.
- Handlers embed no service secret types in their response structs: each response is
  a purpose-built struct whose fields are filled by explicit `Reveal()` at the single
  one-time-disclosure point, so the `MarshalJSON` `[REDACTED]` guard on `Grant`/
  `Issued` cannot be bypassed by accidental embedding.
- Mode 3 remains unreachable; a deployment needing interactive login must wait for
  its ADR. This is the intended fail-closed interim state.

## Alternatives considered

- **AUTH limiting as blanket middleware keyed on IP.** Rejected: it cannot key
  Approve on the owner, cannot distinguish a credential failure from a well-formed
  request, and would meter reads that present no secret. Keying at the check is the
  only way the failure count means "someone is guessing."
- **Per-user-code throttle keyed on the submitted code.** Rejected: each wrong guess
  carries a different code, so the key is unique per attempt and bounds nothing.
  Owner-keying is what makes the throttle IP-rotation-proof.
- **A second denylist for the new services.** Rejected: revocation would not be seen
  by the owner Guard, reopening the reuse-theft window ADR-0018 closes.
- **Building mode 3 now.** Deferred: it needs an IdP integration and redirect surface
  out of scope for the enrollment/token entry point, and folding it in would couple
  this security-critical surface to an unfinished design.
