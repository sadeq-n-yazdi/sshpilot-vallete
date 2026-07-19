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
- **Tiered limits** by surface, keyed appropriately:
  - **Auth/login/enrollment** and **onboarding/signup** — strict; keyed per-IP
    (and per-account where known). Include **failed-auth backoff/lockout** to
    resist brute force.
  - **Publish fetch** (`/{handle}/{set}`) — per-IP limits sized for legitimate
    `curl`/`AuthorizedKeysCommand` polling.
  - **Management & admin** operations — per-credential/per-owner limits.
- Over-limit responses return **`429`** with **`Retry-After`**.
- **Trusted client IP only.** The client IP used for keying is derived from
  forwarded headers **only** when a trusted proxy is configured (ADR-0015);
  otherwise the socket peer. Limits can be **disabled/relaxed** when a trusted
  external limiter is in front.

## Consequences

- Bare deployments get baseline protection; fronted deployments avoid double
  enforcement.
- Correct keying depends on correct proxy-trust configuration.
- **Multi-instance** deployments need a **shared counter store** (e.g. Redis) for
  accurate distributed limits; in-memory suffices for single-instance. The shared
  backend is an open item.

## Open items

Default limit values per tier; counter storage for multi-instance/SaaS
(distributed rate limiting); lockout/backoff parameters; allow/deny lists.
