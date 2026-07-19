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
| Unauthorized key addition | Weak/absent management authN | Pluggable authN + owner-scoped authZ + token scopes | Confirmed (0009, 0004, 0018) |
| Leaked management token | Bearer token stolen | 15m access tokens + rotating revocable refresh (reuse-theft detection, 90d cap) + hybrid revocation denylist + optional narrow scopes | Confirmed (0018) |
| Weak-key acceptance | DSA / short RSA | Algorithm + size floors at ingest | Confirmed (0006) |
| Cross-tenant access | Missing owner scoping | Owner-scoping enforced in repository | Confirmed (0004, 0008) |
| Duplicate/clobbered host files | Non-idempotent `>>` append | Managed-block helper (atomic, 0600, marked block) / AuthorizedKeysCommand; delivered as signed release + served endpoint w/ pinned-hash install | Confirmed (0013) |
| Identifier impersonation | Claiming `admin`/`root`/homoglyph handles | Skeleton match (whole-token system/impersonation, substring offensive) + admin allowlist | Confirmed (0017); word lists/folding tables are curated data |
| Handle-hijack after rename | Reclaiming a freed handle still in servers' URLs | Rename quarantine (default 30d, handles + set names); old handle 404s, never serves other keys | Confirmed (0026) |
| Handle/set enumeration / metadata leak | Public endpoint | Per-set visibility + access key; unauthenticated protected set → uniform `404` (no existence leak); rate limiting | Confirmed (0010, 0016, 0019, 0023) |
| Credential brute force | Repeated login/enrollment attempts | Tiered rate limits (~5/min auth) + exponential failed-auth backoff/lockout | Confirmed (0023) |
| Signup flood / scraping | Automated abuse of open surfaces | Built-in tiered rate limiting (per-IP/owner) w/ starting defaults; pluggable shared counter store | Confirmed (0023) |
| Access-key leakage (protected sets) | Key in URL/logs/caches | `Authorization: Bearer` (never query string); per-set keys stored hashed, shown once, rotate-with-grace, independently revocable | Confirmed (0010, 0016) |
| MITM / tampering on key fetch | Plaintext or downgraded transport | HTTPS-only, refuse plaintext, HSTS, TLS 1.2+ strong-AEAD allowlist (1.3 preferred) | Confirmed (0015) |
| Forwarded-header spoofing | Trusting `X-Forwarded-*` from any source | Trust proxy headers only when explicitly configured | Confirmed (0015) |
| TLS key / provider-credential leakage | Weak storage, logging | Cert/key as `0600` files; DNS/Origin-CA/EAB creds via secret provider, never in config/DB/logs; least-privilege DNS creds | Confirmed (0015, 0022) |
| Cert expiry outage | Renewal failure | Renew-ahead + backoff + expiry alerting; **fail-closed on expiry** (never serve expired) | Confirmed (0015) |
| Self-signed cert used in production | Dev/bootstrap mode left on | ~6h validity ceiling, production start-refusal, loud warnings + audit event | Confirmed (0015) |
| Stale key after revocation | Cached publish response within TTL | Small bounded TTL (~60s, tunable); AuthorizedKeysCommand is live | Accepted trade-off (0019) |
| API schema exposure | Public `/docs/` reveals API surface | Contract is not secret; exposure is deployer-configurable (disable/authenticate) | Confirmed (0021) |
| Tampering without trace | No audit | Append-only audit log | Confirmed (0007) |

## Deferred defense-in-depth

- Per-owner **CA signing** of published keys for third-party verification
  (ADR-0014, deferred).
