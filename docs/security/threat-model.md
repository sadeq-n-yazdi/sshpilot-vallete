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
- **Audit trail** (proposed, ADR-0007).

## Explicitly NOT assets

- **Private keys.** The backend never holds them (ADR-0002). Confidentiality of
  *public* keys is not a security property (they are public by nature), though
  the *association* handle→keys is metadata worth minimizing.

## Trust boundaries

1. **Untrusted key submission → backend.** Any submitted key is hostile input.
   Mitigation: strict canonical parsing, forbid options, reject weak algorithms
   (ADR-0006, proposed).
2. **Backend → consuming server (public HTTP).** Output must be reconstructed,
   never echoed. Consuming servers must fetch over TLS.
3. **Management client → backend.** Requires authN/authZ (OPEN QUESTION) and
   strict owner-scoping (ADR-0004).

## Top risks (current view)

| Risk | Vector | Mitigation | Status |
| --- | --- | --- | --- |
| `authorized_keys` directive injection | Option-bearing "public key" is stored and re-emitted | Canonical storage, forbid options | Proposed (0006) |
| Unauthorized key addition | Weak/absent management authN | Owner-scoped authZ; auth mechanism TBD | Open question |
| Weak-key acceptance | DSA / short RSA | Algorithm + size floors at ingest | Proposed (0006) |
| Duplicate/clobbered host files | Non-idempotent `>>` append | Managed-block helper / AuthorizedKeysCommand | Open question |
| Handle enumeration / metadata leak | Public unauthenticated endpoint | Endpoint exposure policy, rate limiting | Open question |
| MITM on key fetch | Plaintext HTTP | Require TLS; document HTTPS-only | To document |
| Tampering without trace | No audit | Append-only audit log | Proposed (0007) |

## Deferred defense-in-depth

- Per-owner **CA signing** of published keys for third-party verification.
- Host-side write safety (atomic write, `0600`, managed-block markers).
