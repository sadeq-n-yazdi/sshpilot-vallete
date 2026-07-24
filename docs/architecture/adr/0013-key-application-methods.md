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

   An existing but empty published set returns `200` with an empty body
   (ADR-0019), which would render an empty managed block and drop every managed
   key. Because a single accidental set-emptying would otherwise lock out every
   host, the helper **refuses** a non-empty → empty transition of the managed
   block unless `--allow-empty` is passed. The refusal is **fail-loud** (non-zero
   exit, including under `--dry-run`/`--check`), never a silent no-op: an empty
   render can be a genuine full revocation, so the operator is made aware and
   opts in with `--allow-empty` rather than a revocation being quietly held back.

2. **`AuthorizedKeysCommand` (recommended).** Document wiring sshd's
   `AuthorizedKeysCommand` to fetch keys on each auth, so hosts are always
   current without a cron/pull and without editing the file at all.

### Helper delivery

The managed-block helper is delivered **both ways**:

- **Shipped with releases** — the audited script is a release artifact, covered
  by the supply-chain controls (signed / SBOM / reproducible, ADR-0027), for
  offline and version-pinned installs.
- **Served from an endpoint** — the same script is available from the app for a
  one-liner `curl` bootstrap.

Because `curl | sh` is a trust decision, the docs show a **pinned-hash install**
(download, verify the published checksum/signature, then run) rather than piping
an unverified stream to a shell; the served copy and the release artifact are the
same audited bytes.

## Consequences

- Users pick convenience (`curl`) or always-current correctness
  (`AuthorizedKeysCommand`).
- The helper's safety properties (atomicity, permissions, block markers, never
  removing unmanaged lines, and the fail-loud empty-block refusal) are
  security-relevant and must be tested.
- Helper delivery form is **resolved: both** (release artifact + served
  endpoint), with a pinned-hash verified install documented.

## Alternatives considered

- **Plain `curl` only:** rejected; non-idempotent and unsafe on re-run.
- **Push/agent application:** out of scope for phase 1 (ADR-0003).
