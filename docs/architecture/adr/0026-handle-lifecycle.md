# 0026. Handle lifecycle: uniqueness, rename, quarantine

- **Status:** Accepted (confirmed by owner)
- **Date:** 2026-07-19

## Context

A handle is the public address whose keys land in servers' `authorized_keys`.
If a handle could be renamed and immediately reclaimed, whoever grabbed the old
name would start serving keys to every server still pointed at the old URL — an
access-hijack. Handles are also the global namespace subject to the blocklist
(ADR-0017).

## Decision

- **Globally unique**, compared on the normalized form (ADR-0017 normalization),
  and validated against the reserved-identifier blocklist.
- **Rename is allowed.** On rename, the previous handle enters a
  **quarantine/hold** for a configurable cooling-off period during which **no
  other owner can claim it**; the original owner may reclaim it. After the period
  it returns to the pool.
- **A renamed/quarantined handle never serves another party's keys.**
  `GET /{old-handle}` returns **`404`/`410`** (not a redirect), so servers still
  pointed at the old URL simply stop updating rather than silently receiving a
  different owner's keys.
- **Key-set renames** carry an analogous but **within-owner** footgun (only the
  same owner can reuse the name under their handle): the old `/{handle}/{set}`
  path 404s, and reusing the name later would serve different keys. Documented as
  a caution; whether set names are also quarantined is an open item.

## Consequences

- Eliminates cross-owner handle hijack while still letting users rename.
- Adds a quarantine state and a configurable duration; quarantined names are
  briefly unavailable to everyone but the original owner.
- Old URLs fail closed (404), which operators should monitor after a rename.

## Open items

Default quarantine duration; whether an old handle is ever permanently retired vs
released; whether key-set names get the same quarantine; grace/notification on
rename.
