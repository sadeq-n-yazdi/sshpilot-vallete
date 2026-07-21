# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`sshpilot-vallet` is a security-first, clientless **"SSH ID"** backend (`valletd`).
Owners register SSH **public** keys, group them into named **key sets**, and each
set is published at `GET /{handle}/{set}` in native `authorized_keys` format so any
host consumes it with `curl` or `AuthorizedKeysCommand` — no client, agent, or
private key on the backend. Module: `github.com/sadeq-n-yazdi/sshpilot-vallete`.

> The README/CONTRIBUTING still say "pre-implementation." Ignore that — the server
> is under active phased implementation. Design rationale lives in
> `docs/architecture/adr/` (ADR-0000–0029); code comments cite ADRs by number and
> treat them as the source of truth for *why*. Read the relevant ADR before
> changing auth, owner isolation, key ingest/output, TLS, secrets, or the audit log.

## Commands

Go is pinned to **1.26.5** (go.mod `toolchain` + CI); do not float it.

| Task | Command |
| --- | --- |
| Build | `make build` (`go build -ldflags "-s -w" ./...`) |
| Full test (race + coverage) | `make test` (`go test ./... -race -coverprofile=coverage.out`) |
| Single test | `go test ./internal/transport/http/ -run TestName -race -count=1 -v` |
| Coverage report | `make cover` |
| Lint | `make lint` (golangci-lint v2) · `make vet` |
| Vuln scan (hard gate) | `make vuln` (govulncheck, version pinned + mirrored in CI) |
| Reproducible release binary | `make dist` (delegates to `scripts/build.sh`) |
| Verify reproducibility | `make repro` (builds twice, byte-compares) |
| SBOM (CycloneDX) | `make sbom` |
| Install git hooks (once per clone) | `make hooks` (sets `core.hooksPath=.githooks`) |

- **Pre-commit hook** runs only when `.go` files are staged: `gofmt -l`, `go vet`,
  and `golangci-lint` if installed. Bypass with `VALLET_SKIP_HOOKS=1 git commit`.
- **CI** (`.github/workflows/ci.yml`) gates: build+test over a `[sqlite, postgres]`
  matrix, golangci-lint, govulncheck, and reproducible-build + SBOM. Third-party
  actions are SHA-pinned (ADR-0027).

## Dual-engine testing

Tests run against **both SQLite and PostgreSQL**. Postgres tests are integration
tests that **skip when `VALLET_TEST_POSTGRES_DSN` is unset** — so plain
`go test ./...` stays green with no database, and SQLite always runs (in-memory,
CGO-free `modernc.org/sqlite`). To exercise Postgres locally, start Postgres 17 and
export e.g. `VALLET_TEST_POSTGRES_DSN=postgres://vallet:vallet@localhost:5432/vallet_test?sslmode=disable`
before `make test`. (`VALLET_TEST_ENGINE` is set in CI but read by no Go code.)
Postgres test helpers create a fresh random schema per test.

Conventions (ADR-0020): table-driven; **negative/abuse tests are mandatory** for
security-critical packages (prove the unsafe thing is refused); target 100%
coverage for security-critical packages (key ingest, publisher line
reconstruction, blocklist, authz scopes, cross-tenant isolation, TLS enforcement) —
a review policy, **not** a mechanical CI threshold. Hand-written fakes live in
`*fakes_test.go`; thin wiring is covered via `internal/transport/http/e2e_test.go`.

## Architecture — layered / hexagonal

Dependency arrow points strictly inward:
`transport → service → repository (port) ← storage (adapter)`, with `domain` at the
center depending only on the standard library.

- **`internal/domain`** — pure entities, enums, the sentinel-error vocabulary, and
  format validators. No business logic, storage, normalization, blocklist, or crypto.
- **`internal/repository`** — the persistence **port**: interfaces + value types only,
  no implementations. `Store` is the unit-of-work root: `Repos()` (auto-commit) and
  `WithTx(ctx, fn)` (atomic multi-entity). Read `internal/repository/repository.go`
  package doc — it *is* the cross-engine contract.
- **`internal/storage/sqlite`, `internal/storage/postgres`** — the two adapters,
  file-per-entity mirroring the port, each with a compile-time
  `var _ repository.XRepository = (*xRepo)(nil)` assertion.
- **`internal/service/*`** (`publish`, `keyset`, `device`, `publickey`, `accesskey`,
  `bootstrap`, `listadmin`) — application logic. Depends on the `repository` port,
  **never** on a `storage/*` package. Collaborator ports (e.g. `publish.Verifier`,
  `keyset.Auditor`) are declared **at the point of use** in the consumer, satisfied
  by concrete services — so the arrow stays inward.
- **`internal/transport/http`** (package `httpserver`) — outermost adapter: HTTPS-only
  server, router + middleware, handlers taking service interfaces via `HandlerOption`s,
  cert providers, rate-limit and authz middleware, docs/install endpoints.

### Adding a repository method (dual-engine — the core rule)

1. Add the method to the entity interface in `internal/repository/<entity>.go`
   (context first; explicit `ownerID` for owner-scoped data; error contract).
2. Implement it in **both** `internal/storage/sqlite/<entity>.go` **and**
   `internal/storage/postgres/<entity>.go` (the `var _ Port = ...` assertion breaks
   the build if either is missing).
3. New columns/tables → add a `migrationNNNN...()` in `internal/schema/schema.go`
   supplying **both** `SQLite` and `Postgres` SQL for `Up` and `Down`. The runner
   (`internal/migrate`) rejects a migration with empty steps for either engine.
4. Add parallel tests in both adapter test suites (Postgres ones gated on the DSN).

`internal/migrate` is a driver-free dual-engine runner (never imports
`database/sql`); it works through `DB`/`Tx`/`Executor` ports the adapters implement
in `migratedb.go`. Migrations carry `id`/`requires`/`preconditions`/`up`/`down`.

## Composition root

- **`cmd/valletd/main.go`** `run()` is the wiring: `config.Load` + `Validate` →
  logger → `openDatabase` → `sqlite.NewStore` → `publish.New` → retention scheduler →
  telemetry → `httpserver.New` → `serve`. Startup is **fail-closed and ordered**:
  config validated before anything opens, DB pinged before the listener binds, TLS
  policy set before any connection is accepted. (Postgres driver is defined but
  `openDatabase` still only opens SQLite.)
- **SEAM comments** in `main.go` mark surfaces that are *mounted but intentionally
  not yet wired*: without `httpserver.WithAuthorizer`/`With*Service` the management
  routes answer 401 to everyone; without `publish.WithVerifier` every protected set
  answers 404. This is the intended fail-closed interim state, pinned by
  `TestManagementRoutesFailClosedWithoutAnAuthorizer`. When completing wiring, add
  the option — "nothing else here changes."
- **`bootstrap-owner`** subcommand (`cmd/valletd/bootstrap.go`) seeds the first
  owner; runs migrations idempotently first.
- **`cmd/vallet-helper`** is a *separate client binary* for a managed host: fetches a
  published key set over HTTPS (TLS verification cannot be disabled) and syncs it into
  the managed block of `~/.ssh/authorized_keys` via `internal/managedblock`. It never
  touches the DB or services.

## Conventions (enforced by review, cite ADRs)

- **Errors:** wrap domain sentinels with `fmt.Errorf("ctx: %w", domain.ErrX)`; test
  with `errors.Is`, never `==` or message text. `domain.ErrNotFound` **deliberately
  conflates** "missing row" and "another owner's row" (never leak cross-owner
  existence). Adapters translate storage faults to sentinels in `errors.go`.
- **Owner scoping (ADR-0004):** the owner comes from the verified token in transport
  and is **passed as a parameter** down through services to repository methods —
  services never derive it. Every owner-scoped repo method takes an explicit
  `ownerID` and MUST filter by it; the only unscoped methods carry an inline
  `// UNSCOPED:` justification.
- **Fail-closed everywhere:** a nil guard/verifier/authorizer refuses rather than
  allows; nameguard/auth/publish/rate-limit all default to denial.
- **No IDs/timestamps/hashes/normalization in repositories** — the service supplies
  fully-populated, already-normalized entities; repositories persist exactly what
  they are given (keeps the two engines identical). Time is RFC3339 UTC text in
  storage; time-dependent queries take an explicit `now` (adapters hold no clock).
- **Reserved-identifier blocklist (ADR-0017):** every user-chosen handle / set name /
  device name passes through the single `internal/nameguard` choke point (syntax then
  blocklist, fail-closed). Callers get error-or-nil, never which term fired; a nil
  guard refuses everything and services refuse to construct without one.
- **Public keys only (ADR-0002):** `internal/keys.Parse` rejects private-key material,
  authorized_keys options, weak algorithms; errors never echo input bytes. The
  publisher reconstructs each line from stored fields (`AuthorizedKeyLineFrom`) so a
  stored comment can never forge an extra line.
- **Secrets (ADR-0022):** never in the config file — config holds typed `secrets.Ref`
  values (`"scheme:opaque"`, fields end in `_ref`) resolved via a pluggable
  `secrets.Provider` (`env`, `file` built in). Resolved values are `secrets.Redacted`
  and render `[REDACTED]` through every fmt/log/json path. `config → secrets`; secrets
  must never import config.
- **Config:** `config.Load` = env > file > defaults; unknown YAML keys are a hard
  error; `Validate` is separate and fail-closed (production requires https base URL +
  token signing key, rejects self-signed TLS). `vallet.example.yaml` is the annotated
  reference.
- **TLS (ADR-0015):** cert modes are `CertProvider` implementations
  (`certselfsigned`/manual/`certcsr`/`certacme`/`certcloudflare`) selected in
  `newCertProvider`, asked **per handshake**. A single `certGuard` validates every
  handshake (leaf re-parse, key/leaf match, validity window) with `Certificates` left
  nil (no unvalidated fallback). Each case returns through the generic
  `asCertProvider[T]` **typed-nil guard** so a nil concrete pointer never boxes into a
  non-nil interface — the `cloudflare_origin` case must not skip it (the exact
  regression that guard prevents; see recent commits).
- **Audit (ADR-0007):** `internal/audit.Emitter` is insert-only (mint id, stamp time,
  validate, append; cannot read/rewrite/delete). Details come from an allowlisted key
  set; credential-shaped or redacted values are rejected.

## Do / don't

- Do keep the OpenAPI contract (`api/openapi/openapi.yaml`) in sync with endpoint changes.
- Do add a new ADR for significant design changes; mark superseded ones, don't delete.
- **Don't** reference AI/automated tooling in commit messages (project rule).
- **Don't** add a private-key path, a plaintext HTTP listener, or a new command/auth
  builder — the single native/HTTPS/fail-closed paths are deliberate.
