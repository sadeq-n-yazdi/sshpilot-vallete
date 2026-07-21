# 0019. Publish/consume semantics

- **Status:** Accepted (confirmed by owner); amended 2026-07-21 (see Amendment)
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
  - **Only the correct access key for the requested set produces a non-`404`
    response** → **`200`**. Every other outcome is the uniform `404`, including a
    valid access key minted for a *different* one of the same owner's sets. An
    access key is bound to a single key set and carries no scope dimension beyond
    that binding, so "authenticated but not authorized for this set" is not a
    distinct verdict — it is just another refused credential, indistinguishable
    from an absent set. **The publish path therefore never returns `403`.** (See
    the 2026-07-21 amendment below, which removed an earlier `403` clause.)
  - Consequence: a legitimate consumer with a **mistyped or stale** key sees
    `404`, not a diagnostic `401`. That reduced troubleshooting signal is
    **accepted** in exchange for leaking no existence to unauthenticated probes.
  - Combined with rate limiting (ADR-0023), this blunts enumeration of protected
    set names.

## Amendment (2026-07-21)

The original Decision above returned `403` for "a valid token for a different
set/scope (authenticated but not authorized for this set)". That clause is
**dropped**: the publish path now returns the **uniform `404`** for *every*
not-authorized case — unknown handle or set, no token, a
malformed/invalid/expired/revoked token, **and** a valid access key minted for a
different one of
the owner's sets.

Rationale: the dropped `403` was itself an existence oracle. A consumer holding
any one of an owner's access keys is not the owner and must not learn the owner's
other set names; a `403` that distinguished "that set exists but this token is
for another set" from the `404` an absent set returns would leak exactly that.
Access keys carry no scope dimension beyond their single-set binding, so no
"authenticated but unauthorized" verdict exists on this path for a `403` to
describe, and "insufficient scope" is not separately representable.

`403` is retained **only** on the owner-authenticated management API, which is
out of scope here. The enumeration-hardening bullet in the Decision above has
been updated in place to state the uniform-`404` rule and to point here; this
amendment records what changed and why, so the history reads intact.

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
