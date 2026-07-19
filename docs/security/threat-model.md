# Threat model (LIVING / DRAFT)

> Evolves with requirements. Captures assets, trust boundaries, and the risks
> that most shape the design. Security is the first priority at every step.

## Assets

- **Integrity of published public keys.** The keys served at a handle decide who
  can SSH into consuming hosts. Corrupting/adding a key = unauthorized access.
- **Integrity of `authorized_keys` output.** Phase-1 output is appended straight
  into host files (ADR-0003), so its exact bytes are security-critical.
- **Owner account / management access.** Whoever can mutate an owner's keys
  controls access to that owner's hosts.
- **Audit trail** (ADR-0007).
- **Owner isolation.** In a multi-tenant instance, one owner reading/altering
  another's data is a critical breach (ADR-0004, 0008).
- **Server TLS private key** and, when DNS-01 is used, **DNS-provider API
  credentials.** The server's own secrets (distinct from users' SSH keys); their
  compromise enables impersonation or unauthorized cert issuance (ADR-0015).

## Explicitly NOT assets

- **Private keys.** The backend never holds them (ADR-0002). Confidentiality of
  *public* keys is not a security property (they are public by nature), though
  the *association* handle→keys is metadata worth minimizing.

## Trust boundaries

1. **Untrusted key submission → backend.** Any submitted key is hostile input.
   Mitigation: strict canonical parsing, forbid options, reject weak algorithms
   (ADR-0006).
2. **Backend → consuming server (HTTP).** Output must be reconstructed, never
   echoed. Consuming servers must fetch over TLS. Handle may be public or
   access-key protected per owner (ADR-0010).
3. **Management client → backend.** Authenticated via pluggable providers
   (passkeys/OIDC/API-tokens, ADR-0009) and strictly owner-scoped (ADR-0004).
4. **Owner ↔ owner (multi-tenant).** Isolation enforced at the repository layer
   (ADR-0004, 0008).
5. **Upstream TLS terminator → backend.** When TLS is terminated by a proxy/CDN,
   the app-facing hop is trusted only if explicitly configured; forwarded headers
   from unknown sources must not be trusted (ADR-0015).

## Top risks (current view)

| Risk | Vector | Mitigation | Status |
| --- | --- | --- | --- |
| `authorized_keys` directive injection | Option-bearing "public key" is stored and re-emitted | Canonical storage, forbid options | Confirmed (0006) |
| Unauthorized key addition | Weak/absent management authN | Pluggable authN + owner-scoped authZ | Confirmed (0009, 0004); token model TBD |
| Weak-key acceptance | DSA / short RSA | Algorithm + size floors at ingest | Confirmed (0006) |
| Cross-tenant access | Missing owner scoping | Owner-scoping enforced in repository | Confirmed (0004, 0008) |
| Duplicate/clobbered host files | Non-idempotent `>>` append | Managed-block helper (atomic, 0600, marked block) / AuthorizedKeysCommand | Confirmed (0013); helper form TBD |
| Identifier impersonation | Claiming `admin`/`root`/homoglyph handles | Reserved-identifier blocklist w/ confusable-aware matching | Confirmed (0017); folding tables TBD |
| Handle/set enumeration / metadata leak | Public endpoint | Per-set visibility + access key; rate limiting | Partly (0010, 0016); limiting TBD |
| Access-key leakage (protected sets) | Key in URL/logs/caches | Presentation mechanism choice; per-set keys | Open question |
| MITM / tampering on key fetch | Plaintext or downgraded transport | HTTPS-only, refuse plaintext, HSTS, TLS ≥ 1.2 | Confirmed (0015) |
| Forwarded-header spoofing | Trusting `X-Forwarded-*` from any source | Trust proxy headers only when explicitly configured | Confirmed (0015) |
| TLS key / DNS-credential leakage | Weak storage, logging | Restrictive perms, never logged, least-privilege DNS creds | Confirmed (0015); storage form TBD |
| Cert expiry outage | Renewal failure | Renewal scheduling + expiry alerting; fail-closed vs last-good | Open question (0015) |
| Self-signed cert used in production | Dev/bootstrap mode left on | ~6h validity ceiling, production start-refusal, loud warnings + audit event | Confirmed (0015) |
| Tampering without trace | No audit | Append-only audit log | Confirmed (0007) |

## Deferred defense-in-depth

- Per-owner **CA signing** of published keys for third-party verification
  (ADR-0014, deferred).
