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
**refused, not redirected**. A valid domain (FQDN + SANs) is required for the
ACME and CSR modes; its absence is a hard configuration error.

**TLS policy (defaults):** minimum **TLS 1.2**, **TLS 1.3 preferred**; cipher
suites restricted to a **strong AEAD allowlist** (no CBC/RC4/3DES/export), with
forward secrecy required for the 1.2 suites. **HSTS** is sent. The floor at 1.2
(not 1.3-only) preserves compatibility with older `curl`/server clients on the
publish path while remaining strong; the policy is config-tunable upward.

### 2. Certificate provisioning modes (deployer selects one)

- **Automatic ACME (Let's Encrypt)** — obtain and auto-renew via the ACME
  protocol. **Phase 1 ships and tests Let's Encrypt** as the ACME CA (no EAB),
  and **supports both challenge solvers**: **TLS-ALPN-01** (port 443) and
  **DNS-01**. **HTTP-01 is not used** (no port-80 listener). The ACME directory
  URL is configurable so other ACME CAs *can* be pointed at, but additional
  supported/tested ACME CAs (e.g. ZeroSSL, which needs **EAB**) are **deferred
  to a later phase**.
  - **DNS-01 solving has two modes:**
    - **Manual** — the app emits the required `_acme-challenge` TXT record(s)
      and waits for the operator to publish them (with a verification poll),
      then completes. Works for any DNS host and air-gapped/no-API setups.
    - **Provider API (automated)** — the app creates/removes the TXT records
      itself via a **pluggable DNS-provider interface**. **Phase 1 ships at
      least the top-10 DNS providers plus the ArvanCloud DNS API** (see list
      below). Credentials come from the secret provider (§3), least-privilege.
- **Cloudflare Origin CA** — obtain an origin certificate from Cloudflare via its
  API (long-lived origin cert), for deployments whose origin sits **behind the
  Cloudflare proxy**. This is a **first-class, selectable alternative to Let's
  Encrypt in phase 1** (the deployer picks Let's Encrypt *or* Cloudflare). The
  Cloudflare API token is a secret (§3). Note: an Origin CA cert is trusted by
  the Cloudflare edge, **not** by public clients connecting directly — it is for
  the Cloudflare-fronted topology.
- **Operator-provided cert + key** — load a supplied certificate and private
  key; the operator owns renewal.
- **Generate CSR for external signing** — the app generates a private key and a
  CSR from the configured subject/SANs; the operator gets it signed by any
  CA/provider and installs the returned certificate. Renewal is manual.
- **TLS terminated upstream** — a trusted reverse proxy / CDN
  (nginx/Caddy/Cloudflare) terminates TLS; the app runs behind it and enforces
  HTTPS by requiring a trusted `X-Forwarded-Proto: https`. Proxy trust is
  **explicit opt-in** (never trust forwarded headers from arbitrary sources).
- **Ephemeral self-signed (development / install bootstrap only).** The app
  generates a **short-lived self-signed** certificate so it can serve over HTTPS
  before a real cert exists — for local development and for the first-run/install
  phase (letting an admin connect to configure a real cert). It preserves the
  HTTPS-only invariant (never plaintext). Guardrails below make it unusable as a
  production posture.

### Guardrails for the ephemeral self-signed mode

- **Short hard ceiling on validity:** certificates are valid for **at most ~6
  hours** and are regenerated on expiry/restart. The ceiling is fixed low on
  purpose so the mode cannot quietly become a steady-state posture; it is not
  configurable to a long-lived value.
- **Activation:** used only when the deployer explicitly selects this mode, or
  automatically during the defined first-run/install bootstrap phase — never as a
  silent fallback in normal operation.
- **Production refusal:** if the instance is marked production, the app
  **refuses to start** with a self-signed cert unless a separate, explicit
  override is set. Whenever the mode is active it emits **loud warnings** and
  records an **audit event**.
- **Client expectations:** peers will see certificate-validation failures
  (self-signed). This is acceptable only for development/bootstrap; it must never
  serve real users. Docs will note the dev-only `curl -k` / trust-exception
  caveat and that consumers must not disable verification against real
  deployments.

### 3. Secrets handling

The TLS private key and any provider credentials are sensitive. **Cert and key
are stored as files with `0600` permissions**; provider credentials — the
**configured DNS-provider API credentials** (Cloudflare, Route 53, ArvanCloud,
…), the **Cloudflare Origin CA API token**, and (in later phases) ACME **EAB**
credentials — come from the **pluggable secret provider** (ADR-0022), **never
written to the config file, the database, or telemetry/logs**. DNS-01 credentials should be least-privilege (scoped to the
ACME TXT records where the provider allows it). Storing cert/key/creds in the
database was considered (for easy multi-instance sharing) and rejected for phase
1: it puts private keys in the data store; instances that need shared material
use the secret provider.

### 4. Renewal scheduling and failure handling

- **Renew ahead of expiry** — attempt renewal well before the certificate
  expires (order of ~1/3 of remaining lifetime / ~30 days for 90-day certs),
  with **retry and backoff** on transient ACME/DNS failures.
- **Alert on repeated failure** — renewal failures surface via telemetry
  (ADR-0025) and mark readiness accordingly, so operators are warned **before**
  expiry.
- **Fail closed on expiry.** If a cert actually expires with renewal unresolved,
  the listener **stops serving** (readiness goes false, loud alert/audit event)
  rather than serve an expired/invalid certificate. Serving a "last-good" expired
  cert was rejected as inconsistent with the HTTPS-only, no-compromise posture.
- **Operator-owned modes** (operator-provided cert, CSR) still surface
  expiry/renewal status so operators can act; the fail-closed-on-expiry rule
  applies to them too.

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

## Phasing of certificate providers

- **Phase 1 (shipped & tested):**
  - Automatic cert providers: **Let's Encrypt via ACME** (TLS-ALPN-01 **and**
    DNS-01 solvers) and **Cloudflare Origin CA** — deployer-selectable.
  - **DNS-01 solving:** **manual mode** + automated **DNS-provider APIs** for
    **at least the top-10 providers plus ArvanCloud**.
  - Always-available modes: operator-provided cert+key, CSR for external
    signing, upstream TLS termination, ephemeral self-signed (dev/bootstrap).
- **Later phases:** additional ACME CAs including **ZeroSSL (EAB)**, and DNS-01
  providers beyond the phase-1 set. The provider interfaces are designed now so
  these drop in without redesign.

### Phase-1 DNS-01 provider set (proposed top-10 + Arvan + generic)

Concretely: **Cloudflare, AWS Route 53, Google Cloud DNS, Azure DNS,
DigitalOcean, DNSimple, GoDaddy, Namecheap, Gandi, OVH**, plus **ArvanCloud** and
the generic **RFC 2136** dynamic-update provider, and the **manual** solver.
This list is the phase-1 target and can be adjusted; the pluggable interface
makes adding/removing a provider a small, isolated change.

## Open items

All phase-1 TLS tuning is resolved: providers above, cert/key as `0600` files
with creds via the secret provider, renew-ahead + backoff + alert, TLS 1.2+
strong-AEAD allowlist (1.3 preferred), and **fail-closed on expiry**. Remaining
as implementation detail: the specific ACME/DNS/Cloudflare client libraries and
the exact renewal thresholds/cipher list (config defaults, not design decisions).
