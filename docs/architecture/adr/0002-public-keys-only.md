# 0002. Store public keys only

- **Status:** Accepted (confirmed by owner)
- **Date:** 2026-07-19

## Context

The service manages SSH keys. The single largest security decision is whether it
ever holds private key material. In the "SSH ID" model, keys are generated on
each device and private keys never leave it.

## Decision

The backend handles **public keys only**. It must never receive, store,
transmit, or log private key material. The storage layer has a hard boundary and
does not accept secrets. Private-key custody is out of scope, permanently, for
this component.

## Consequences

- Dramatically smaller blast radius: a full breach exposes only public keys,
  which are not secret.
- No KMS/HSM/envelope-encryption needed for key custody in this service.
- If encrypted-secret storage is ever needed, it must live behind a separate,
  explicitly-designed boundary and its own ADR — not by relaxing this one.

## Alternatives considered

- **Also store private keys (encrypted):** rejected. Turns the service into a
  high-value secret store with a far larger attack surface, for no benefit the
  device-local model doesn't already provide.
