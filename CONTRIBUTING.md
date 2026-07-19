# Contributing to sshpilot-vallet

Thanks for your interest! **sshpilot-vallet** is an open, clientless "SSH ID"
backend: owners register SSH **public** keys, group them into named key sets, and
publish each set at `GET /{handle}/{set}` in native `authorized_keys` format so any
host can consume it with plain `curl` or `AuthorizedKeysCommand`.

> **Status:** the project is in **phase-1 design**. The authoritative sources are
> the [requirements outline](docs/requirements/phase-1.md), the
> [ADR log](docs/architecture/adr/README.md), and the
> [threat model](docs/security/threat-model.md). Read those before proposing
> changes — most "why is it this way?" questions are already answered there.

## Ground rules

- **Security is the first priority.** Any change that touches auth, owner
  isolation, key ingest/output, TLS, secrets, or the audit log must state its
  security impact in the PR and add negative tests. When in doubt, open an issue or
  a security report (see [SECURITY.md](SECURITY.md)) before writing code.
- **Public keys only.** The backend must never accept, store, or transit private
  key material. Reject any design that would.
- **Decisions are recorded, not re-litigated in code.** Significant architectural
  changes need an ADR (see below), not just a diff.
- Be respectful and constructive; see [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## How to contribute

1. **Search first** — check existing issues and the docs to avoid duplicates.
2. **Open an issue** describing the bug or proposal. For anything non-trivial,
   agree on the approach in the issue before you start.
3. **Fork and branch** from the default branch. Use a short, descriptive branch
   name (`fix/…`, `feat/…`, `docs/…`).
4. **Make focused commits.** One logical change per commit; keep unrelated changes
   out.
5. **Open a pull request** using the PR template. Link the issue it resolves.

## Architecture Decision Records (ADRs)

Design decisions live in `docs/architecture/adr/` as numbered records. If your
change alters or adds a decision:

- Add a new ADR (copy the format of an existing one: Status, Date, Context,
  Decision, Consequences, Alternatives considered).
- Mark superseded decisions as such rather than deleting them.
- Reference the ADR number in your PR.

## Commit messages

- Use the imperative mood and a concise summary line (≤ ~72 chars), e.g.
  `docs: clarify enumeration rule for protected sets`.
- Explain the *why* in the body when it isn't obvious.
- **Do not** reference AI assistants or automated tooling in commit messages.
- Sign your commits (`git commit -S`) where possible.

## Code contributions (once implementation begins)

Implementation has not started yet. When it does, the following will apply:

- **Language:** Go, standard layout, clean layered/hexagonal separation.
- **Tests are mandatory** across happy / failure / gray paths, including negative
  tests; security-critical packages target 100% coverage, and the suite runs on
  both SQLite and PostgreSQL.
- Run `gofmt`/`go vet` (and the project linter) before pushing.
- Keep the OpenAPI contract in sync with any endpoint change.

Until then, contributions are **documentation, design review, threat-model input,
and ADR discussion** — all of which are very welcome.

## Reporting security issues

Do **not** open a public issue for vulnerabilities. Follow
[SECURITY.md](SECURITY.md).

## License

By contributing, you agree that your contributions are licensed under the
project's [MIT License](LICENSE).
