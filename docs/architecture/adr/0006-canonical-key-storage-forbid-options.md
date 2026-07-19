# 0006. Canonical key storage; forbid authorized_keys options

- **Status:** Accepted (confirmed by owner)
- **Date:** 2026-07-19

## Context

An `authorized_keys` line is `[options] type base64 [comment]`. Options such as
`command=`, `environment=`, `from=`, `permitopen=`, `no-pty` are
code-execution / access-control primitives. Because phase-1 distribution appends
the published output directly into servers' `authorized_keys` (ADR-0003), any
byte the publisher emits is security-relevant. If the service stored and
re-emitted whatever a user pasted, a submitted "public key" could smuggle a
forced command or restriction into every consuming host.

## Decision

Never store or re-emit raw `authorized_keys` lines. On ingest:

1. Parse with a real SSH parser; **reject any line that carries options**.
2. Store only structured fields: algorithm, normalized key blob, sanitized
   comment (no control chars/newlines, length-capped), and a computed SHA256
   fingerprint.
3. Reject disallowed algorithms (**DSA**) and **undersized RSA** (e.g. < 3072
   bits). Accept `ed25519`, `ecdsa`, hardware `sk-ssh-ed25519`/`sk-ecdsa-...`,
   and adequately-sized `rsa`.
4. The publisher **reconstructs** each line from stored structured data; options
   are server-decided and forbidden in v1.

## Consequences

- A malicious or careless submission cannot inject directives into any host.
- Deduplication and revocation key off the fingerprint.
- Slightly stricter ingest (some exotic-but-legitimate keys refused in v1).

## Status note

This is the security crux of the product. Confirmed by the owner: options are
forbidden and weak keys (DSA, RSA < 3072) are rejected. The exact accepted
algorithm set and RSA floor are implementation constants captured here and may
be tightened, never loosened, without a superseding ADR.
