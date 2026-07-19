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
  **quarantine/hold** for a cooling-off period — **default 30 days
  (configurable)** — during which **no other owner can claim it**; the original
  owner may reclaim it. After the period it returns to the pool. 30 days lets
  cached consumers / `AuthorizedKeysCommand` pollers stop trusting the old URL
  before anyone else can claim the name.
- **A renamed/quarantined handle never serves another party's keys.**
  `GET /{old-handle}` returns **`404`/`410`** (not a redirect), so servers still
  pointed at the old URL simply stop updating rather than silently receiving a
  different owner's keys.
- **Key-set renames** carry an analogous but **within-owner** footgun (only the
  same owner can reuse the name under their handle): the old `/{handle}/{set}`
  path 404s, and reusing the name later would serve different keys. **Freed set
  names are quarantined too** (ADR-0016), on the **same default 30-day** window,
  so a name cannot be silently reused for different keys while consumers still
  poll the old path.

## Consequences

- Eliminates cross-owner handle hijack while still letting users rename.
- Adds a quarantine state and a configurable duration; quarantined names are
  briefly unavailable to everyone but the original owner.
- Old URLs fail closed (404), which operators should monitor after a rename.

## Open items

Resolved: **default quarantine 30 days (configurable)**, applied to **both
handles and set names** (ADR-0016). Remaining as implementation detail:
grace/notification UX on rename, and whether an operator may permanently retire
(never release) a specific name — a small admin affordance, not a phase-1
blocker.
