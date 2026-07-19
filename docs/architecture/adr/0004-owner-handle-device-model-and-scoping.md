# 0004. Owner / Handle / Device model and owner-scoping

- **Status:** Accepted (confirmed by owner)
- **Date:** 2026-07-19

## Context

The product needs identities for (a) whoever owns keys, (b) the public address
their keys are published under, and (c) the devices that generate keys. The
owner confirmed a single-user model now, with teams/orgs later and no rewrite.

## Decision

Three core concepts:

- **Owner** — internal identity (`OwnerID`, non-guessable) that owns everything.
  A single user today; the abstraction is the seam where teams/orgs attach
  later.
- **Handle** — the owner's *public*, URL-safe identifier; keys publish at
  `GET /{handle}`. Separate from `OwnerID` so the public name can change without
  breaking internal references.
- **Device** — belongs to an owner; groups the keys it generated so a
  lost/retired device can be revoked as a unit.

**Owner-scoping is enforced at the data layer:** every query is scoped by
`OwnerID`, not just checked in handlers. Authorization is a property of the
repository, which is what makes "teams later" additive rather than a rewrite.

## Consequences

- Clean path to multi-user/teams: introduce membership between a principal and
  an owner; scoping code already assumes an owner boundary.
- Public handle can be renamed/rotated independently of stable internal IDs.
- Reserved/handle-format rules are needed to avoid route collisions and
  impersonation.

## Alternatives considered

- **Keys embedded in a machine/device record only:** rejected. Authorization
  should be explicit and owner-scoped, not implied by object nesting.
- **Handle == primary key:** rejected. Public identifiers should not be internal
  references; they must be able to change.
