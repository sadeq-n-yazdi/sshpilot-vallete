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
- **Set-name rules:** lowercase `a–z`, `0–9`, and hyphen; **1–64 characters**;
  case-insensitive; no leading/trailing hyphen. The reserved-identifier blocklist
  (ADR-0017) also applies to set names.
- **Max sets per owner:** **configurable cap, default 100**, to prevent
  enumeration bloat and abuse while covering realistic use.
- **Deletion rules:**
  - The **designated default set cannot be deleted**; the owner must first make
    another set the default (or explicitly clear the default), so bare
    `GET /{handle}` never dangles.
  - Deleting a **non-empty** set **requires an explicit confirmation flag**.
    Removing keys from a set does not delete the underlying `PublicKey` records
    (they may belong to other sets / their device).
  - A **freed set name enters quarantine** (aligned with handle lifecycle,
    ADR-0026) so re-creating the same name cannot silently serve keys to
    consumers still polling the old `/{handle}/{set}` URL.
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

## Per-set access-key lifecycle

For access-key-protected sets (ADR-0010), the Bearer credential a consuming
server presents is managed as follows:

- **Multiple named access keys per set** — e.g. one per server or CI pipeline —
  each **independently revocable**, so retiring one server never disrupts others.
- **Rotation with a grace window:** creating a new access key does not instantly
  invalidate the old one; old and new are both valid for a bounded overlap so
  servers polling `/{handle}/{set}` are not locked out mid-rotation.
- **Stored hashed; shown in plaintext exactly once at creation.** If lost, the
  owner mints a new one; the server never holds recoverable access-key material.
- Issue/rotate/revoke actions are audited (ADR-0007).

## Open sub-items

All phase-1 key-set sub-items are now resolved (see set-name rules, max sets,
deletion rules, and the access-key lifecycle above). Field-level constraints are
an implementation artifact.

## Alternatives considered

- **One flat set per owner:** rejected by the owner; cannot serve different
  server groups differently.
- **Opaque per-set token URLs / subdomains:** rejected in favor of the readable
  `/{handle}/{set}` scheme (see the addressing decision).
