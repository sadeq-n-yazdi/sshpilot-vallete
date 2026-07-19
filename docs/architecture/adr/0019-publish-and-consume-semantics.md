# 0019. Publish/consume semantics

- **Status:** Accepted (confirmed by owner)
- **Date:** 2026-07-19

## Context

The published endpoint is the product's core read path: its bytes are appended
into hosts' `authorized_keys` (ADR-0003) or read by `AuthorizedKeysCommand`. It
must be precise, deterministic, safe, and have predictable freshness on
revocation.

## Decision

### Endpoint & output

- `GET /{handle}/{set}` returns a key set; `GET /{handle}` returns the owner's
  designated **default set** (ADR-0016). `HEAD` is supported; other methods are
  rejected. HTTPS-only (ADR-0015).
- Body is **native `authorized_keys`**: one **canonical, options-free** line per
  key (reconstructed from stored fields, ADR-0006), `Content-Type: text/plain;
  charset=utf-8`, trailing newline.
- Only **active** keys **assigned to that set** are emitted; revoked/removed keys
  are excluded.
- **Deterministic ordering** (e.g. by fingerprint) so identical content yields a
  stable `ETag`.

### Freshness & caching

- **Short, bounded TTL.** Responses carry a small `max-age` (deploy-configurable,
  **default ~60s**, with a low ceiling) plus a strong **`ETag`**; conditional
  `If-None-Match` returns `304`.
- **Public sets** may use shared caching (`Cache-Control: public, max-age=...`).
- **Protected sets** (access-key required, ADR-0010/0016) must be
  **`Cache-Control: private`** (or `no-store`) so shared caches never hold
  access-gated content, and must vary on the access credential.
- **Revocation window:** on the `curl`/cached path a revoked key can persist up
  to the TTL; the `AuthorizedKeysCommand` path is evaluated per authentication
  and is effectively live. This bound is documented for operators.

### Not-found & enumeration

- Unknown handle or set → `404`. Existing but empty **public** set → `200` with
  an empty body.
- **Enumeration hardening (resolved):** existence of a protected set is revealed
  **only to a valid credential**. Anything short of a valid access key — no
  `Authorization` header, or a **malformed/invalid/expired/revoked** token —
  returns a **uniform `404`**, identical to a genuinely nonexistent set. This is
  the GitHub-private-repo pattern: an attacker cannot probe with a garbage Bearer
  token and read existence off a `401`-vs-`404` difference.
  - **Only a syntactically valid, authenticated token produces a non-`404`
    response:** the correct key → **`200`**; a valid token for a *different*
    set/scope (authenticated but not authorized for this set) → **`403`**.
  - Consequence: a legitimate consumer with a **mistyped or stale** key sees
    `404`, not a diagnostic `401`. That reduced troubleshooting signal is
    **accepted** in exchange for leaking no existence to unauthenticated probes.
  - Combined with rate limiting (ADR-0023), this blunts enumeration of protected
    set names.

## Consequences

- Efficient and CDN-friendly, with a **known, bounded** staleness window on
  revocation that operators can tune down.
- Deterministic ordering + ETag make conditional fetches cheap.
- Protected-set caching rules prevent access-gated keys leaking via shared
  caches.

## Alternatives considered

- **Always-live, no-store + ETag:** fastest revocation, rejected in favor of a
  small TTL for cache/CDN efficiency (revocation window accepted and documented).
- **Long CDN caching + purge-on-change:** rejected; purge failures could serve
  stale keys, with more moving parts.
