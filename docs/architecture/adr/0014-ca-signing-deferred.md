# 0014. Per-owner CA signing deferred beyond phase 1

- **Status:** Accepted (confirmed by owner)
- **Date:** 2026-07-19

## Context

The "SSH ID" model can sign each published key with a per-owner CA so third
parties verify the keys were genuinely issued by the owner. It adds real value
but also significant scope and a new critical secret (the CA private key).

## Decision

**CA signing is out of scope for phase 1.** Phase 1 delivers store + publish +
manage. However, the data model and API must be designed so signing can be added
later **without a breaking change** (e.g. leave room for per-key signature
material and per-owner signing identities).

## Consequences

- Phase 1 stays lean and avoids introducing a high-value signing secret before
  the core is proven.
- A future ADR will specify the CA lifecycle (generation, storage, rotation,
  revocation, verification format) when signing is picked up.

## Alternatives considered

- **Implement in phase 1:** rejected as premature scope and added key-management
  risk.
- **Ignore entirely:** rejected; the model should not preclude it, hence the
  forward-compatibility requirement above.
