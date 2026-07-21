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
- **Configurable retention window, default 365 days.** Records older than the
  retention period are **purged** by a controlled, system-level process — the
  only routine deletion path — and the purge itself is documented/observable.
- **Pseudonymization on owner deletion / erasure.** Rather than deleting an
  owner's history, replace their identity and personal fields with a
  **non-reversible pseudonym** and drop personal data, while **preserving the
  structural record** (which action happened, when, on what target type). This
  keeps accountability/forensics without retaining PII.
- **Technique: salted-hash tombstone with per-owner salt destroyed on erasure**
  (crypto-erasure). Each owner's identifying audit fields are pseudonymized to an
  **irreversible salted hash**; erasure **destroys the salt**, so the pseudonym
  can no longer be linked back to the person, yet event counts and lineage remain
  consistent.
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

Resolved: **default retention 365 days (configurable)** and the
**salted-hash-with-destroyed-salt** pseudonymization technique.

**Resolved — the exact field list classed as personal.** Erasure covers the
whole audit record: the two identity columns (`actor_id`, `target_id`) and the
identifying values in record metadata. Each allowlisted detail key is classified
once, authoritatively, enforced in code by `internal/audit.IsErasableDetail` (a
fail-closed inversion of a KEEP set, so an unclassified or newly-added key
defaults to erasable) and pinned by `TestDetailErasureClassification`:

- **Pseudonymize** (rewrite the value to a salted-hash tombstone under the same
  per-owner salt as the columns, so equal values collapse to equal tombstones
  and counts/lineage stay consistent, and destroying the salt makes it
  irreversible): `fingerprint`, `handle`, `device_name`, `key_set_name`,
  `client_label`, `from`, `to`. (`from`/`to` carry the old/new handle-or-name in
  a rename and are therefore identifying; `fingerprint` names a specific key and
  so its owner.)
- **Keep** (structural, non-identifying, preserved byte-for-byte so the record
  still proves what happened): `algorithm`, `visibility`, `scope`, `reason`,
  `result`, `request_id`, `count`.

The whole-record erasure runs in the `internal/erasure` service: it reads the
owner's records, rewrites their identifying metadata via the audit port's
`ScrubMetadata`, pseudonymizes the identity columns, then destroys the salt —
one controlled, audited operation, not an arbitrary record edit.

Reserved-identifier list edits (`internal/service/listadmin`) are **not** owner
personal data and are deliberately out of erasure scope: their actor is a
system-axis administrator (explicitly excluded from an owner's graph) and their
target is a reserved *term* — an administrator policy decision about which words
may be registered, which must outlive any owner for accountability.

Remaining as implementation detail: interaction with external SIEM/log export
(exported copies are outside the app's erasure reach — documented as a deployer
responsibility).
