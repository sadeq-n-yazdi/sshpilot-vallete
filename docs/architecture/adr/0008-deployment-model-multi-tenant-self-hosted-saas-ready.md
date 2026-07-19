# 0008. Deployment model: multi-tenant, self-hosted first, SaaS-ready

- **Status:** Accepted (confirmed by owner)
- **Date:** 2026-07-19

## Context

The service could be a personal single-owner instance, a shared self-hosted
instance, or a central hosted SaaS. The owner chose "both, phased": build for
self-hosting now while keeping the path to a hosted service open.

## Decision

Design the backend as **multi-tenant-capable** from day one and ship it as a
**self-hostable** instance first, with nothing that blocks running it as a
**hosted SaaS** later.

- Every owner's data is isolated; a single instance can serve one or many
  owners. Single-owner is just multi-tenant with one owner.
- No design choice assumes a trusted, single-user environment. Isolation,
  authentication, and abuse controls are present even when only one owner exists.
- SaaS-only concerns (global handle namespace policy, aggressive abuse
  protection, billing) are deferred but must not be precluded.

## Consequences

- Owner-scoping (ADR-0004) and real authentication (ADR-0009) are mandatory even
  for a personal instance — slightly more up-front work, no later rewrite.
- Config must distinguish instance-level policy (operator) from owner-level
  settings (user).
- Handle uniqueness/reservation rules must be defined with multi-tenancy in mind
  (open question).

## Alternatives considered

- **Single-owner only:** rejected; would bake in single-user assumptions and
  block the SaaS path.
- **SaaS-first:** rejected; premature operational burden before the core exists.
