# 0003. Phase-1 distribution is clientless via native authorized_keys

- **Status:** Accepted (confirmed by owner)
- **Date:** 2026-07-19

## Context

Consuming servers need the owner's public keys in `~/.ssh/authorized_keys`. The
owner requires that **phase 1 not depend on any custom client on the consuming
server**. The "SSH ID" model publishes keys at a URL consumed by plain `curl`.

## Decision

In phase 1 the backend is a **public HTTP publisher of native
`authorized_keys`**. A server operator applies keys with stock tooling:

```
curl https://<host>/<handle> >> ~/.ssh/authorized_keys
# or, preferred, via sshd AuthorizedKeysCommand
```

No agent, SDK, or proprietary client is required to *consume* keys. (Managing
keys is a separate concern with its own client; see the requirements doc.)

## Consequences

- Zero install friction on consuming servers; works with any stock sshd.
- The public endpoint's output is security-critical: it is appended directly
  into `authorized_keys`. It MUST be reconstructed from validated structured
  data and never echo raw input (see ADR-0006).
- Plain `>>` is not idempotent and can clobber unmanaged lines; a managed-block
  helper and/or `AuthorizedKeysCommand` guidance is an open question.
- The backend never holds outbound access to any host (contrast with a
  push-over-SSH model, which was rejected as too high-value a target).

## Alternatives considered

- **Pull-agent on each host:** deferred. Good for later features (per-host
  policy, idempotent writes) but violates the phase-1 clientless requirement.
- **Backend pushes over SSH:** rejected. Would make the backend hold access to
  every host — an unacceptable single point of compromise.
