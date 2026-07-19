# 0023. Rate limiting and abuse protection

- **Status:** Accepted (confirmed by owner)
- **Date:** 2026-07-19

## Context

Public and unauthenticated surfaces (publish fetch, signup, login/enrollment) and
sensitive admin operations can be abused: credential brute force, signup floods,
scraping, and DoS. This matters more for SaaS but must not leave bare
self-hosted instances unprotected.

## Decision

- **Built-in, configurable rate limiting** with sane defaults, and **designed to
  coexist with an external limiter** (proxy/CDN/WAF).
- **Tiered limits** by surface, keyed appropriately (starting **defaults**, all
  config-tunable):
  - **Auth/login/enrollment** and **onboarding/signup** — strict; keyed per-IP
    (and per-account where known): **~5 attempts/min** with **exponential
    failed-auth backoff/lockout** to resist brute force.
  - **Publish fetch** (`/{handle}/{set}`) — per-IP, sized for legitimate
    `curl`/`AuthorizedKeysCommand` polling: **~60 requests/min per IP** (output
    is TTL-cached anyway, ADR-0019).
  - **Management** operations — **~120 requests/min per credential**;
    **admin** operations — **~60 requests/min per admin**.
- Over-limit responses return **`429`** with **`Retry-After`**.
- **Trusted client IP only.** The client IP used for keying is derived from
  forwarded headers **only** when a trusted proxy is configured (ADR-0015);
  otherwise the socket peer. Limits can be **disabled/relaxed** when a trusted
  external limiter is in front.

## Consequences

- Bare deployments get baseline protection; fronted deployments avoid double
  enforcement.
- Correct keying depends on correct proxy-trust configuration.
- **Multi-instance** deployments use a **pluggable shared counter store behind a
  single interface**: **in-process counters for single-node**, a **Redis/Valkey-
  style backend for multi-node**. No hard Redis dependency is imposed on
  self-hosters. **The same store backs the auth revocation denylist** (ADR-0018),
  so multi-instance coordination has one moving part, not two.

## Open items

Resolved: **starting default limits per tier** (above), and the **pluggable
in-memory/shared-store** design for distributed counters (shared with the
ADR-0018 denylist). Remaining as tuning/implementation: exact backoff curve
constants and optional allow/deny lists (config, not design).
