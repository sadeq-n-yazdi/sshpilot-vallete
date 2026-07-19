# 0001. Record architecture decisions

- **Status:** Accepted
- **Date:** 2026-07-19

## Context

This is a security-critical, long-lived project built incrementally as
requirements are described. Decisions must be traceable so future contributors
(human and AI) understand *why*, not just *what*.

## Decision

Use lightweight ADRs (this format) for every significant decision. Distinguish
**Accepted** (owner-confirmed) from **Proposed** (recommended, unconfirmed) so
the difference between a commitment and a recommendation is never ambiguous.

## Consequences

- Decisions and their rationale are durable and reviewable.
- Reversals are explicit (an ADR superseding another), not silent drift.
