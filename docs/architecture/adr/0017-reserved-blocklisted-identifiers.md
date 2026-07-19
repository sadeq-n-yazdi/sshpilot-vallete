# 0017. Reserved / blocklisted identifiers

- **Status:** Accepted (confirmed by owner)
- **Date:** 2026-07-19

## Context

User-chosen public identifiers — **handles** (global namespace) and **key-set
names** (`/{handle}/{set}` routing) — must not allow impersonation of the service
or privileged roles, must not collide with the app's own routes, and should not
be abusive. The set of forbidden words changes over time, so operators and
administrators need to curate it.

## Decision

Maintain a **blocklist** enforced on user-chosen identifiers (at least handles
and key-set names; extendable to device names).

### Default coverage (four categories)

1. **Routing/system terms** — `api`, `admin`, `healthz`, `readyz`, `.well-known`,
   `static`, `assets`, `login`, ... (prevents route collisions).
2. **Authority/impersonation terms** — `root`, `administrator`, `support`,
   `security`, `official`, `staff`, `help`, `billing`, `moderator`, ...
3. **Offensive/abusive terms** — profanity/slurs (matters most for public SaaS).
4. **Confusable & leetspeak variants** — evasions of the above such as `adm1n`,
   `ad-min`, and Unicode homoglyphs (e.g. Cyrillic `аdmin`).

### Normalization-based matching

Blocking is done on a **normalized form**, not raw string equality: case-fold,
trim, NFKC Unicode normalization, homoglyph/confusable folding, leetspeak
folding (e.g. `1→i`, `0→o`, `3→e`, `$→s`, `@→a`), and separator stripping,
producing a **skeleton** that is matched against the equally-skeletonized
blocklist entries. This is what catches category 4.

**Per-category match mode:**

- **Routing/system** and **authority/impersonation** terms match as
  **whole-token** on the skeleton (so `root` blocks `root`/`r00t` but not
  `roots`), preventing route collisions and impersonation without over-blocking.
- **Offensive/abusive** terms match as **substring** on the skeleton (profanity
  hidden inside a longer name is still caught).

The confusable/leetspeak **folding tables are data**, versioned alongside the
default word lists, so they can be extended without code changes; the folding is
deterministic and shared with identifier validation (see Consequences).

### Management (two levels)

- **Deployer/config:** seed and override the list at deploy time.
- **System administrator at runtime:** an authenticated **administrator** can
  add/remove entries via an admin operation. All changes are **audited**
  (ADR-0007).
- **Admin-editable allowlist (false-positive override).** Because folding can
  over-block legitimate names (the "Scunthorpe problem"), an administrator can
  add specific normalized names to an **allowlist** that takes precedence over
  the blocklist. Allowlist edits are audited exactly like blocklist edits.

The **system administrator** is a new actor/role, distinct from an owner; its
authorization is part of the auth model (see ADR-0009 and the forthcoming auth
ADR). The blocklist is **system-wide/global** (handles are global).

### Enforcement points

Checked at identifier **creation and rename**, applied to **handles, key-set
names, and device names** (device names too, for consistency, even though they
are private labels — only length/charset validation is otherwise applied there).

### Existing identifiers newly blocked

When an administrator adds an entry that would block an **already-existing**
identifier, that identifier **keeps working** — it is not yanked out from under
the owner. Instead it is **flagged for admin review** and marked
**quarantine-on-release**: the owner may keep using it, but once the identifier
is freed (rename/delete) it **cannot be re-claimed** and enters the normal
quarantine (ADR-0026). Administrators get a report of currently-flagged
identifiers. (Immediate suspension and permanent grandfathering were both
rejected — the former breaks live URLs without warning; the latter lets
offensive/impersonation names persist forever.)

## Consequences

- Reduces impersonation and route-collision risk on the public namespace.
- Confusable/leetspeak matching can cause **false positives** (legitimate names
  blocked); admins need an allow/remove path and tunable aggressiveness.
- Requires an administrator role and an audited admin API.
- Normalization must be deterministic and **shared** with identifier validation
  so "valid" and "not blocked" agree.

## Open items

Resolved: per-category match mode (whole-token for system/impersonation,
substring for offensive), admin-editable allowlist, existing-name handling
(flag + quarantine-on-release), and device-name coverage (included). Remaining
as **data to curate at implementation:** the exact default word lists and the
initial confusable/leetspeak folding tables (versioned data, not a design
decision).

## Alternatives considered

- **Hard-coded list only:** rejected; operators/admins must curate over time.
- **Raw case-insensitive equality:** rejected; trivially bypassed by
  homoglyphs/leetspeak.
