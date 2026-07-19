# 0027. Supply-chain and build security

- **Status:** Accepted (confirmed by owner)
- **Date:** 2026-07-19

## Context

Security is the first priority. A compromised dependency, build, or release
artifact undermines every other control. The project therefore adopts a
comprehensive supply-chain posture.

## Decision

- **Pinned dependencies.** `go.sum` committed; a small, vetted dependency set;
  pinned Go toolchain version.
- **Automated vulnerability scanning in CI** — `govulncheck` plus an automated
  dependency-update mechanism (Dependabot/Renovate). Known-vuln findings block
  release.
- **SBOM** (CycloneDX or SPDX) generated for every release.
- **Signed, provenance-bearing artifacts.** Release binaries and container images
  are **signed** (e.g. cosign) with **SLSA-style build provenance**; builds are
  **reproducible** where feasible.
- **Hardened CI.** Least-privilege tokens, no secrets in logs, pinned action/tool
  versions.

## Consequences

- Strong assurance of what shipped and from what sources; tampering is
  detectable.
- More release tooling and CI maintenance; contributors must keep deps current.

## Open items

Concrete tool choices and pipeline wiring (signing key custody, SBOM format,
provenance level) are implementation details for when CI is built.
