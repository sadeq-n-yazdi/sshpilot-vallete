# 0015. HTTPS-only transport with pluggable certificate provisioning

- **Status:** Accepted (confirmed by owner)
- **Date:** 2026-07-19

## Context

The backend serves the management API and the public key-publish endpoints
(consumed by `curl`, `AuthorizedKeysCommand`, and clients). All traffic must be
confidential and integrity-protected in transit — a MITM that alters published
keys is unauthorized-access risk (see threat model). Deployments vary widely:
self-host with a public domain, behind a reverse proxy / Cloudflare, or with an
internal/BYO CA.

Note the boundary vs ADR-0002: the **server's own TLS private key** is a
legitimate secret the server must hold. ADR-0002 forbids storing **users' SSH**
private keys; it is unaffected by TLS key custody.

## Decision

### 1. HTTPS-only, refuse plaintext

The app serves content **only over TLS**. When the app terminates TLS it opens
**no plaintext HTTP listener** (port 80 is not bound). Plaintext requests are
**refused, not redirected**. Enforce **TLS ≥ 1.2** (prefer 1.3) and send
**HSTS**. A valid domain (FQDN + SANs) is required for the ACME and CSR modes;
its absence is a hard configuration error.

### 2. Certificate provisioning modes (deployer selects one)

- **Automatic ACME** — obtain and auto-renew from any ACME CA via directory URL
  (Let's Encrypt, ZeroSSL, others). Challenges: **TLS-ALPN-01** (port 443) or
  **DNS-01** via **pluggable DNS providers** (e.g. Cloudflare; enables
  wildcards, works behind firewalls). **HTTP-01 is not used** (no port-80
  listener). Some CAs (e.g. ZeroSSL) require **EAB** credentials.
- **Operator-provided cert + key** — load a supplied certificate and private
  key; the operator owns renewal.
- **Generate CSR for external signing** — the app generates a private key and a
  CSR from the configured subject/SANs; the operator gets it signed by any
  CA/provider and installs the returned certificate. Renewal is manual.
- **TLS terminated upstream** — a trusted reverse proxy / CDN
  (nginx/Caddy/Cloudflare) terminates TLS; the app runs behind it and enforces
  HTTPS by requiring a trusted `X-Forwarded-Proto: https`. Proxy trust is
  **explicit opt-in** (never trust forwarded headers from arbitrary sources).

### 3. Secrets handling

The TLS private key and any DNS-provider API credentials are sensitive: stored
with restrictive permissions, never logged, and treated as the server's own
secrets. DNS-01 credentials should be least-privilege (scoped to the ACME TXT
records where the provider allows it).

## Consequences

- Strong default posture; no accidental plaintext exposure. The MITM risk on the
  key-fetch path is mitigated.
- Users who type `http://` get a connection refused (no redirect) — intentional.
- ACME without port 80 depends on TLS-ALPN-01 / DNS-01; DNS-01 needs provider
  credentials and unlocks wildcard certs.
- Upstream-termination mode requires careful proxy-trust configuration to avoid
  `X-Forwarded-*` spoofing.
- CSR and operator-provided modes shift renewal responsibility to the operator;
  the app should surface expiry/renewal status.

## Alternatives considered

- **Allow plaintext with 80→443 redirect:** rejected; owner requires HTTPS-only
  and refusing plaintext.
- **HTTP-01 challenge:** rejected; needs a port-80 listener the strict posture
  forbids.
- **A single fixed certificate source:** rejected; deployments are too varied.

## Open items (tracked in requirements §8)

EAB handling for ZeroSSL and similar CAs; which DNS-01 providers ship first;
storage location/format for cert, key, and DNS credentials; renewal scheduling
and failure alerting; minimum TLS version / cipher defaults; and fail-closed vs
serve-last-good behavior when a cert is expired and renewal fails.
