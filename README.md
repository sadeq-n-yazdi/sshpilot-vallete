# sshpilot-vallet

> **Status: phase 1 implemented.** `valletd` builds and runs: the publish read
> path, the owner management API, enrollment and token issuance, and instance
> administration are all live. The design documents remain *living* — they capture
> decisions as they're made.
>
> **Writing a client?** Start with the
> [Frontend & API Guide](docs/api-guide/README.md).

A clientless **"SSH ID"** backend. An owner registers their SSH **public** keys
from their devices, organizes them into named **key sets**, and publishes each set
at `GET /{handle}/{set}` in native `authorized_keys` format. Any server consumes it
with plain `curl` or `AuthorizedKeysCommand` — **no client, agent, or private key**
ever required on the backend.

It is the companion backend to the **sshpilot** desktop SSH manager, inspired by
the model behind Termius's "SSH ID / passkeys for SSH".

## How it works

```
device ──register public key──▶  sshpilot-vallet  ──GET /{handle}/{set}──▶  any host
   (owner authenticates)            (public keys,        (curl / AuthorizedKeysCommand,
                                      grouped in sets)     native authorized_keys)
```

- **Public keys only** — private keys never touch the backend.
- **Clientless consumption** — hosts fetch over HTTPS; no proprietary agent.
- **Security first** — HTTPS-only, pluggable auth (passkeys/WebAuthn incl.
  YubiKey/FIDO2, OIDC, API tokens), owner isolation, append-only audit log,
  reserved-identifier blocklist, rate limiting, and fail-closed TLS.

## Documentation

| You want… | Read |
| --- | --- |
| **To build a client — quick start, config, every endpoint** | **[docs/api-guide/README.md](docs/api-guide/README.md)** |
| The machine-readable API contract | [api/openapi/openapi.yaml](api/openapi/openapi.yaml), or `GET /docs/` on a running server |
| A one-page roll-up of every decision | [docs/spec-overview.md](docs/spec-overview.md) |
| The authoritative scope & requirements | [docs/requirements/phase-1.md](docs/requirements/phase-1.md) |
| The decision log (ADRs) | [docs/architecture/adr/README.md](docs/architecture/adr/README.md) |
| The threat model | [docs/security/threat-model.md](docs/security/threat-model.md) |
| The full docs index | [docs/README.md](docs/README.md) |

## Roadmap

- **Phase 1 (current):** single-owner vallet — registration, key sets, clientless
  publishing, pluggable auth, TLS, and the security/ops controls above.
- **Phase 2:** group / organization accounts (multi-user, roles/RBAC).
- **Phase 3:** scaling (horizontal scale-out, higher throughput).

## Contributing & security

- Contributions: see [CONTRIBUTING.md](CONTRIBUTING.md) and the
  [Code of Conduct](CODE_OF_CONDUCT.md).
- **Security issues:** do **not** open a public issue — follow
  [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE) © 2026 Sadeq N. Yazdi
