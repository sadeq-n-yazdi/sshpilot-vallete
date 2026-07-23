# Possible upgrades and changes

A living catalogue of features and changes deliberately deferred out of the
current phase, kept so the rationale and the concrete "how" are not lost between
the moment a decision is made and the moment someone picks the work up.

Each entry has the same four parts:

- **Description** — what it is and why it is wanted.
- **How-to** — the concrete implementation sketch: the seams to touch, the
  order of work, and the constraints that must hold.
- **Notes** — decisions already made, tradeoffs, dependencies, and links to the
  relevant ADRs or tasks.

This is not a commitment or a schedule; it is a durable place to record work
that is understood but not yet scheduled. Add to it whenever a decision defers
something with a real design behind it. Keep entries in rough priority order and
mark an entry done (or delete it) once the work lands.

---

## mTLS administrator authentication

### Header
Authenticate administrators with a mutual-TLS client certificate instead of (or
in addition to) the signed administrator bearer token chosen for v1.

### Description
ADR-0031 selected a **signed administrator bearer token** as the first
administrator authentication scheme because it is self-contained, adds no
storage, and enforces the owner/administrator axis separation cryptographically
via a dedicated signing key. mTLS was **deferred, not rejected**: it is the
natural upgrade when a no-bearer-secret posture is wanted. With mTLS the
administrator presents a client certificate during the TLS handshake; there is
no bearer secret to leak in a header, log, or proxy, and revocation can ride on
short-lived certificates or a CRL/OCSP rather than on disabling a row.

### How-to
1. **Request and verify client certificates at the TLS layer.** The server does
   not ask for client certificates today (`tls.Config.ClientAuth` /
   `ClientCAs` are unset in `internal/transport/http`). Add a mode that sets
   `ClientAuth` (start at `tls.VerifyClientCertIfGiven` so owner/publish traffic
   is unaffected, and require a valid cert only on the admin routes) and
   `ClientCAs` to an administrator trust store. This must compose with the
   existing per-handshake `certGuard` and the `CertProvider` selection
   (ADR-0015) without weakening leaf validation for server certs.
2. **Add an administrator trust store to config.** A CA bundle (or an explicit
   allowlist of pinned client-cert fingerprints) resolved through the existing
   `secrets.Provider` / config surface, fail-closed: no trust store configured
   ⇒ the mTLS admin path stays disabled, exactly as an absent admin signing key
   leaves the bearer path disabled.
3. **Map a verified client certificate to a `domain.AdministratorID`.** Provide
   a new implementation of the existing `httpserver.AdminIdentifier` seam
   (`AdministratorID(r *http.Request) domain.AdministratorID`) that reads the
   verified peer certificate from `r.TLS.VerifiedChains` / `PeerCertificates`
   and resolves it to an administrator ID (e.g. by a stored cert
   fingerprint→admin mapping, or by a certificate subject the provisioning step
   recorded). On any failure return the empty ID — `listadmin.authorize` then
   refuses via its existing `Get → active` check. Do **not** duplicate the
   existence/status check in the identifier.
4. **Provisioning.** Extend `bootstrap-admin` (or add a sibling command) to
   register the administrator together with the fingerprint/subject of the
   client certificate that will authenticate as it, so a fresh deployment can
   mint the first mTLS administrator in one step.
5. **Tests.** Handshake-level tests proving: a valid admin client cert resolves
   to the right ID and edits succeed; no cert / untrusted cert / expired cert ⇒
   403; an owner or publish request without a client cert is unaffected; a
   disabled administrator is refused even with a valid cert.

### Notes
- Tracked as task **#74**. Alternative **#2** in **ADR-0031**; that ADR
  explicitly does not preclude this upgrade.
- Must remain a **separate authorization axis** from owners (ADR-0018: "owner
  tokens can never grant administrator authority"). A client cert must never
  resolve to an `OwnerID`, and an owner credential must never satisfy the admin
  path.
- Fail-closed throughout (ADR-0015 posture): an unconfigured or unverifiable
  trust store denies rather than allows.
- Advantage over the bearer token: revocation without a per-token denylist
  (short-lived certs or CRL/OCSP), and no bearer secret in transit. Cost: real
  TLS surgery plus certificate lifecycle/operational overhead.
- The `AdminIdentifier` seam already exists, so this is additive — a second
  identifier implementation selected by configuration, not a rewrite.

---

## Per-token administrator token revocation

### Header
Allow revoking an individual administrator bearer token before it expires,
without disabling the whole administrator.

### Description
The v1 administrator bearer token (ADR-0031) is a stateless signed credential:
before its validity window closes, the only way to revoke it is to disable the
administrator row, which revokes **all** of that administrator's tokens at once.
This mirrors the interim posture accepted for the owner access-token path. Finer
granularity — revoke one leaked token while the administrator keeps working — is
a plausible future need.

### How-to
1. Persist a minimal record per issued admin token keyed by its `jti` (the admin
   token payload already carries a `jti` for exactly this reason), or add an
   admin-credential table.
2. Add a denylist check to the administrator verification path (mirror the owner
   `auth.Denylist` built on the shared `counter.Store`), consulted after
   signature/validity but before returning the `AdministratorID`.
3. Provide an admin-facing (or CLI) operation to revoke a `jti`, audited.

### Notes
- Explicit note-forward in **ADR-0031** ("Revocation granularity"). Deliberately
  out of scope for v1 to keep the first admin surface small.
- The `jti` claim already exists in the v1 token, so adding this later does not
  require a token format bump.
- Reuses the owner denylist pattern (`internal/auth/denylist.go` +
  `internal/counter`); do not invent a second mechanism.

---

## Additional DNS-01 ACME providers

### Header
Add the long tail of DNS-01 challenge providers behind the existing provider
interface.

### Description
ACME DNS-01 issuance is built with a provider interface plus reference
implementations (manual, Cloudflare, and others already landed). The remaining
providers each land as their own small, self-contained PR so no single change
carries a large surface.

### How-to
1. Implement the existing DNS-01 provider interface for the target
   (e.g. Route 53, Google Cloud DNS, Azure DNS, DigitalOcean, DNSimple, GoDaddy,
   Namecheap, OVH, RFC2136, and any others still missing).
2. Resolve provider credentials through the existing central secret seam — note
   that some providers need **several** credential fields (e.g. Route 53 packs
   two), which the seam already accommodates; do not re-resolve per provider.
3. Reject a whitespace-only or empty credential at startup, not at first API
   call (a hardening rule already established for existing providers).
4. Table-driven tests with a faked provider API; no live network in CI.

### Notes
- Track E tail (plan items E6–E16); tracked as task **#116** and related. Some
  providers (Gandi, ArvanCloud, Cloudflare, and more) already merged.
- Each provider is one PR — keep them independent and small.
- Follow ADR-0015 for TLS/cert posture and the established per-provider
  credential-validation shape.

---

## WebAuthn / passkey management-authentication provider

### Header
Add a WebAuthn (passkey) provider for owner management authentication.

### Description
Management authentication is pluggable (ADR-0009): the deployer selects the
provider, and API-token/device-pairing shipped first (ADR-0018). WebAuthn is a
planned additional provider on the same interface, giving owners phishing-
resistant hardware-backed login.

### How-to
1. Implement the existing `AuthProvider` interface (the same one the API-token
   provider satisfies) so a WebAuthn credential resolves to a
   `LinkedIdentity` (principal → `OwnerID`) and then into the standard
   refresh/access-token machinery (ADR-0018) — nothing downstream of enrollment
   changes.
2. Add the WebAuthn RP (relying-party) configuration surface (the one deferred
   config item noted in the phase-1 plan): RP ID, origin, and attestation
   policy, validated fail-closed.
3. Enrollment reuses the existing paths (device-authorization grant / manual
   paste / in-client interactive) where applicable.
4. Negative tests for spoofed origin, wrong RP ID, and replayed assertions.

### Notes
- Lands on the same interface as API-token auth (ADR-0009, ADR-0018); do not
  fork the credential/scope model.
- Scopes and owner-scoping are unchanged — WebAuthn only changes how the first
  refresh credential is obtained.
- The WebAuthn RP config is the single deferred open config item from the
  phase-1 plan.

---

## OIDC management-authentication provider

### Header
Add an OIDC provider for owner management authentication.

### Description
A second planned provider on the pluggable management-auth interface (ADR-0009),
letting a deployer federate owner login to an existing identity provider.

### How-to
1. Implement the `AuthProvider` interface: an OIDC authorization-code flow whose
   verified subject maps to a `LinkedIdentity` (principal → `OwnerID`), then into
   the standard refresh/access-token machinery (ADR-0018).
2. Add IdP configuration (issuer, client credentials via the secret seam,
   redirect URIs, allowed audiences), validated fail-closed; verify `iss`,
   `aud`, `nonce`, and signature strictly.
3. Ship one reference IdP integration first; additional IdPs each land as their
   own small follow-up (same pattern as the DNS-01 providers).

### Notes
- Same interface and credential/scope model as the other providers (ADR-0009,
  ADR-0018); owner-scoping unchanged.
- Long-tail IdPs are separate small PRs, not one large change.
