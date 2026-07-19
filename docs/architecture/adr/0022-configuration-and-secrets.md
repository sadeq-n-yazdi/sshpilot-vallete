# 0022. Configuration and secrets management

- **Status:** Accepted (confirmed by owner)
- **Date:** 2026-07-19

## Context

A deployer must configure many things — enabled auth providers, certificate mode
and ACME/DNS settings, data store, onboarding mode, token TTLs, publish TTL,
blocklist seed, docs exposure. Some of these involve **secrets** (TLS key, DNS
API credentials, DB credentials, token-signing keys) that must never sit in a
plain config file.

## Decision

### Configuration

- A **structured config file** (YAML or TOML) is the base; **environment
  variables override** individual values. Precedence: **env > file > built-in
  defaults**.
- Config is **validated at startup**; invalid or inconsistent config is a
  **hard, fail-closed** error with a clear message (e.g. DNS-01 selected but no
  provider credentials; production + self-signed without override).
- Three configuration planes are kept distinct:
  - **Instance/operator** config (this file + env).
  - **Runtime admin-managed** policy — e.g. the reserved-identifier blocklist a
    system administrator edits at runtime (ADR-0017).
  - **Owner-level** settings — e.g. per-set visibility (ADR-0010/0016).

### Secrets

- Secrets are **never stored in the plain config file**. They are supplied via
  **environment variables** or **file-path references** (mounted secrets, Docker/
  Kubernetes secrets); the config file may hold *references/paths*, not values.
- A **pluggable secret-provider interface** lets external managers (HashiCorp
  Vault, cloud KMS / Secrets Manager) be added later without code churn; env/file
  is the built-in provider.
- Secrets are **never logged**; logging redacts known-sensitive fields. Required
  secrets for the selected modes are checked at startup (fail-closed).

## Consequences

- Readable base config with container-friendly overrides and safe secret
  injection from day one; external secret managers are an additive change.
- The startup validator becomes a security control (misconfig fails closed).

## Open items

Exact config schema and field names; YAML vs TOML choice; which external secret
managers to support first; documented precedence/override matrix.
