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
folding, and separator stripping, then match against normalized blocklist
entries. This is what catches category 4. Per-category match mode (exact vs
substring) is a tunable detail.

### Management (two levels)

- **Deployer/config:** seed and override the list at deploy time.
- **System administrator at runtime:** an authenticated **administrator** can
  add/remove entries via an admin operation. All changes are **audited**
  (ADR-0007).

The **system administrator** is a new actor/role, distinct from an owner; its
authorization is part of the auth model (see ADR-0009 and the forthcoming auth
ADR). The blocklist is **system-wide/global** (handles are global).

### Enforcement points

Checked at identifier **creation and rename**. Policy for an existing identifier
that later becomes blocked (grandfather vs force-rename) is an open item.

## Consequences

- Reduces impersonation and route-collision risk on the public namespace.
- Confusable/leetspeak matching can cause **false positives** (legitimate names
  blocked); admins need an allow/remove path and tunable aggressiveness.
- Requires an administrator role and an audited admin API.
- Normalization must be deterministic and **shared** with identifier validation
  so "valid" and "not blocked" agree.

## Open items (tracked in requirements §8)

Confusable/leetspeak folding tables and per-category match mode; false-positive
handling / allowlist; behavior for already-existing identifiers that become
blocked; whether device names are also covered; exact default word lists.

## Alternatives considered

- **Hard-coded list only:** rejected; operators/admins must curate over time.
- **Raw case-insensitive equality:** rejected; trivially bypassed by
  homoglyphs/leetspeak.
