# 0009. Pluggable management authentication

- **Status:** Accepted (confirmed by owner)
- **Date:** 2026-07-19

## Context

Owners manage keys (register devices, add/revoke keys, change handle/visibility)
through a client — sshpilot desktop first, later web/TUI/CLI, including AI
clients. Different deployments have different needs: a self-hoster may want
zero-dependency API tokens; a team may want SSO; a security-focused user may want
passkeys. The owner asked for several mechanisms, deployer-selectable.

## Decision

Authentication for the **management** surface is provided by **pluggable
providers**, and the **deployer configures which are enabled** (any combination):

1. **Passkeys / WebAuthn** — account secured by FIDO2 credentials;
   phishing-resistant; on-theme with the product.
2. **OAuth / OIDC** — delegate human login to an external IdP (e.g. Google,
   GitHub, self-hosted OIDC).
3. **API tokens / device pairing** — an owner mints scoped, revocable tokens; a
   client pairs once and holds a long-lived credential. No web login required.

**Email + password is intentionally excluded** as a primary mechanism.

Design implications:

- An **`AuthProvider` abstraction** behind a common interface; providers are
  registered/enabled via instance config.
- An **owner may have multiple linked identities** (a passkey credential, an OIDC
  subject, one or more API tokens) mapped to one internal `OwnerID`.
- Providers authenticate a **principal**; authorization is always owner-scoped
  (ADR-0004) regardless of provider.
- The **publish/consume path (curl) is separate** and governed by ADR-0010, not
  by these providers.

## Consequences

- Deployments range from "API token only" (simplest self-host) to full SSO
  without code changes.
- Token lifetime/scope/rotation/revocation and OIDC claim→owner mapping are
  follow-up decisions (open questions).
- Onboarding/registration differs per provider and per deployment (open
  question).

## Alternatives considered

- **Single fixed auth method:** rejected; cannot satisfy the range of self-host
  and SaaS needs.
- **Email + password as primary:** rejected by the owner; weaker and higher
  maintenance (reset flows, breach risk) than the chosen mechanisms.
