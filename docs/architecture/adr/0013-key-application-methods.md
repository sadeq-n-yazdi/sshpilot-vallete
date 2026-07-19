# 0013. Key application methods and managed-block helper

- **Status:** Accepted (confirmed by owner)
- **Date:** 2026-07-19

## Context

Published keys must land in a host's `authorized_keys` (ADR-0003) with no
proprietary client. Plain `curl >> authorized_keys` is convenient but not
idempotent: re-running duplicates lines, and a naive overwrite could clobber
unmanaged (local) keys or lock the owner out.

## Decision

Support and document **two application methods** for phase 1:

1. **`curl` + managed-block helper (quick path).** Document the one-liner, and
   ship a small **managed-block helper** that writes fetched keys between marked
   delimiters, e.g.:

   ```
   # >>> sshpilot-vallet:<handle> (managed) >>>
   ...keys...
   # <<< sshpilot-vallet:<handle> (managed) <<<
   ```

   Re-runs replace only the managed block; unmanaged lines are never touched.
   The helper must write atomically (temp file + rename) and preserve `0600`.

2. **`AuthorizedKeysCommand` (recommended).** Document wiring sshd's
   `AuthorizedKeysCommand` to fetch keys on each auth, so hosts are always
   current without a cron/pull and without editing the file at all.

## Consequences

- Users pick convenience (`curl`) or always-current correctness
  (`AuthorizedKeysCommand`).
- The helper's safety properties (atomicity, permissions, block markers, never
  removing unmanaged lines) are security-relevant and must be tested.
- Helper delivery form (bundled script vs served script vs both) is an open
  question.

## Alternatives considered

- **Plain `curl` only:** rejected; non-idempotent and unsafe on re-run.
- **Push/agent application:** out of scope for phase 1 (ADR-0003).
