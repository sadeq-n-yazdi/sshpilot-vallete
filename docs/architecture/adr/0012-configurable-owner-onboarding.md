# 0012. Configurable owner onboarding

- **Status:** Accepted (confirmed by owner)
- **Date:** 2026-07-19

## Context

Owners must be created somehow. A public SaaS wants open self-signup; a
self-hosted/team instance often wants only operator-created or invited owners.
This mirrors the pluggable-auth philosophy (ADR-0009).

## Decision

Onboarding mode is **deployer-configurable** per instance:

- **Open self-signup** — anyone can register an owner (needs verification and
  abuse controls; primarily for SaaS).
- **Invite / admin-provisioned** — only the operator creates owners or issues
  invites (default-safe for self-host/teams).

Implications:

- The instance config selects the mode; the default should be the safe one
  (invite/admin) unless the operator opts into open signup.
- Onboarding composes with the enabled auth providers (ADR-0009): e.g. an invited
  owner still authenticates via a passkey/OIDC/API-token as configured.
- Every created owner gets an isolated tenant boundary (ADR-0004, 0008).

## Consequences

- One codebase serves locked-down self-host and open SaaS.
- Open signup pulls in verification, rate limiting, and abuse handling (open
  questions) before it is safe to enable.

## Alternatives considered

- **Open signup only / admin-only only:** each rejected as too narrow for the
  phased deployment model.
