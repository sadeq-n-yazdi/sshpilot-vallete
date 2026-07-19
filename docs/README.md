# sshpilot-vallet — Documentation

> **Status: pre-implementation.** Requirements for phase 1 are still being
> gathered. These documents are *living*: they capture decisions as they are
> made so nothing is lost, and they will change as requirements evolve. No
> backend implementation exists yet — by design.

`sshpilot-vallet` is the backend for an **"SSH ID"**-style service: an owner
registers their SSH **public** keys from their devices, and those keys are
published at a stable public handle so any server can trust them without
copying keys around by hand. It is the companion backend to the
[`sshpilot`](../../sshpilot/) desktop SSH manager and is inspired by the model
described in Termius's "SSH ID / passkeys for SSH".

## Who each document is for

| Audience | Start here |
| --- | --- |
| **Everyone (quick review)** | [Spec Overview](spec-overview.md) — a one-page roll-up of all decisions grouped by theme. |
| **Everyone (detail)** | [Requirements — Phase 1](requirements/phase-1.md) — the single source of truth for scope, decisions, and open questions. |
| **Architects / reviewers** | [Architecture Decision Records](architecture/adr/README.md) — every significant decision, with status. |
| **Security reviewers** | [Threat model](security/threat-model.md) — assets, trust boundaries, and the core risks. |
| **Backend developers** | Requirements + ADRs today; a developer guide will be added when implementation starts. |
| **Frontend / client developers (human + AI)** | Requirements today; an API contract (OpenAPI) and client guide will be added once the API surface is agreed. |
| **Contributors** | The ADR process below, plus a CONTRIBUTING guide (to be added). |

## How decisions are recorded

Significant choices are captured as **ADRs** under
[`architecture/adr/`](architecture/adr/). Each ADR is marked:

- **Accepted** — confirmed by the project owner.
- **Proposed** — recommended (often on security grounds) but **not yet
  confirmed**. Proposed ADRs are open questions, not commitments.

## Security posture (non-negotiable)

Security is the first priority at every step. Two principles are already locked:

1. **Public keys only.** The backend never receives, stores, or transmits
   private key material. (ADR-0002)
2. **The publisher never emits raw user input.** Anything served into a
   server's `authorized_keys` is reconstructed from validated, structured data
   — never echoed back verbatim. (ADR-0006, proposed)
