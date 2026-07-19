# 0024. Audit retention and erasure

- **Status:** Accepted (confirmed by owner)
- **Date:** 2026-07-19

## Context

The audit log is append-only (ADR-0007), but owners can be deleted and may
request erasure of personal data. Immutable audit and right-to-erasure appear to
conflict; this ADR reconciles them.

## Decision

- **Append-only in normal operation.** No updates or deletes of audit records via
  ordinary application paths (ADR-0007 stands).
- **Configurable retention window.** Records older than the retention period are
  **purged** by a controlled, system-level process — the only routine deletion
  path — and the purge itself is documented/observable.
- **Pseudonymization on owner deletion / erasure.** Rather than deleting an
  owner's history, replace their identity and personal fields with a
  **non-reversible pseudonym** and drop personal data, while **preserving the
  structural record** (which action happened, when, on what target type). This
  keeps accountability/forensics without retaining PII.
- Pseudonymization/erasure is a **controlled, audited operation**, not an
  arbitrary record edit.
- Audit records **never contain secrets or key material** (reaffirms ADR-0007).

## Consequences

- Satisfies erasure expectations while retaining a usable security history.
- Retention duration and pseudonymization scope become policy/config, with legal
  basis a deployer responsibility.
- The pseudonym mapping must be truly non-reversible (e.g. destroyed salt /
  crypto-erasure), or the "erasure" is only nominal.

## Open items

Default retention duration; exact pseudonymization technique (salted-hash with
destroyed salt vs crypto-erasure); which fields count as personal; interaction
with external SIEM/log export.
