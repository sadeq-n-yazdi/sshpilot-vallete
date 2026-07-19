# 0016. Named key sets per owner

- **Status:** Accepted (confirmed by owner)
- **Date:** 2026-07-19

## Context

A single flat list of an owner's keys (Termius-style) is not enough: owners want
different `authorized_keys` for different groups of servers — e.g. a `personal`
set that is public and a `prod` set that is access-key protected. This requires a
first-class grouping with its own publish address and its own visibility.

## Decision

Introduce **`KeySet`** — a named subset of an owner's public keys — as a
first-class, owner-scoped entity.

- **Membership is many-to-many.** A `PublicKey` may belong to several key sets; a
  key set contains zero or more of the owner's keys. A key in no set is simply
  not published.
- **Addressing:** a set is published at **`GET /{handle}/{set}`**. The bare
  **`GET /{handle}`** serves an **owner-designated default set**.
- **Visibility is per key set** (refines ADR-0010): each set is independently
  public or access-key protected, and **access keys are per-set**.
- **Every owner has at least one set.** A `default` set is created with the owner
  and is the initial default; the owner may designate a different default.
- **Set names** are URL-safe slugs, **unique per owner** (not globally — unlike
  handles), with reserved names avoided to prevent route conflicts.
- The publisher still emits only canonical, options-free lines (ADR-0006) for the
  set's **active** keys; owner-scoping (ADR-0004) extends to set-scoping.

## Model (conceptual)

```
Owner 1─* KeySet          Owner 1─* Device 1─* PublicKey
KeySet *─* PublicKey      (a key belongs to one device and to zero+ sets)
```

## Consequences

- Owners can mix public and protected sets and publish tailored subsets per
  server group.
- More endpoints and management operations (create/rename/delete sets, assign/
  unassign keys, set default, per-set visibility & access keys).
- Revoking a key removes it from every set's output (governed by key status).
- Per-set access keys expand the credential surface (issue/rotate/revoke).

## Open sub-items (tracked in requirements §8)

Finalize set-name rules and reserved names; max sets per owner; whether deleting
a non-empty or default set is allowed; per-set access-key lifecycle.

## Alternatives considered

- **One flat set per owner:** rejected by the owner; cannot serve different
  server groups differently.
- **Opaque per-set token URLs / subdomains:** rejected in favor of the readable
  `/{handle}/{set}` scheme (see the addressing decision).
