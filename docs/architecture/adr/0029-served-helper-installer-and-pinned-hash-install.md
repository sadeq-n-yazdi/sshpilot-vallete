# 0029. Served helper installer and pinned-hash install

- **Status:** Accepted
- **Date:** 2026-07-20
- **Amends:** ADR-0013 (key application methods and managed-block helper)

## Context

ADR-0013 decided the managed-block helper would be delivered two ways: shipped
with releases, and **served from an endpoint** for a one-liner `curl` bootstrap,
with the docs showing a pinned-hash install rather than a pipe to a shell.

That decision was written assuming the helper *was* a shell script — it says
"the audited script" and "the served copy and the release artifact are the same
audited bytes". The helper that was actually built (L1, PR #32) is a **Go
program**, `cmd/vallet-helper`. Two consequences follow, and neither is
negotiable:

- **A binary cannot be the served artifact.** `//go:embed` requires the file to
  exist in the source tree at compile time. A binary produced by the same build
  does not. Embedding it is not merely awkward; it does not compile.
- **A binary is per-platform.** Serving the right one to an anonymous requester
  needs platform selection, which means a request parameter choosing a file —
  the traversal surface this design exists to avoid.

So the served artifact and the helper cannot be the same bytes. Something has to
give.

A second constraint decides the installer's contents. The release pipeline
(`.github/workflows/release.yml`) builds, signs, and publishes **`valletd`
only**. There is no released `vallet-helper` binary and, at the time of writing,
no tags or releases at all. An installer that downloaded a signed helper binary
would be pointing at URLs that do not exist.

## Decision

**The served artifact is an installer script, not the helper.**

`/install/vallet-helper.sh` serves a POSIX shell script that installs
`vallet-helper`; `/install/vallet-helper.sh.sha256` serves its digest. ADR-0013's
"served from an endpoint" is satisfied; its "same bytes as the release artifact"
clause is superseded by this ADR.

**The installer installs via `go install` at an operator-supplied version.**
That resolves through the Go module proxy and is verified against the public
checksum database — an integrity anchor that already exists, that requires no
new release infrastructure, and that the script forces on for its own
invocation so a caller's `GOFLAGS`/`GOPRIVATE`/`GOSUMDB` cannot silently
disable it. There is no floating default version and `latest` is rejected by
name: an unpinned install is not a verifiable one.

**The helper is not reimplemented in shell.** That would be a second
security-critical implementation of HTTPS fetching, key validation, and atomic
`0600` marker-block writing, free to drift from the audited Go one. A drifting
duplicate of the code that decides which keys may log into a host is a worse
outcome than requiring a Go toolchain.

**The digest is derived from the embedded bytes at initialization**, never
hand-maintained. A hand-copied hash goes stale on the first edit, and a stale
hash teaches operators that verification failures are noise to be skipped —
which is the habit that makes a supply-chain attack land. A test recomputes the
digest independently from the served body and fails if the two can disagree.

**The endpoints are unauthenticated and enabled by default.** The installer is a
bootstrap path for a host that has nothing from this project yet, so a
credential requirement would make it useless for its only job. The script is
byte-identical for every requester and carries no keys, host names, or
information about who uses the deployment. Deployers who do not accept an
anonymous route set `install.enabled: false`; both routes then answer exactly as
an unrouted path does, so a probe cannot learn the feature exists to be
disabled.

**Serving is static and embedded.** Two hard-coded literal routes, no
`/install/{name}`, no disk access on the request path — enforced by a test that
parses the handler source and rejects filesystem imports and calls, because a
byte-comparison test passes whether the bytes came from `embed` or from disk and
therefore does not test the mechanism.

### On the checksum endpoint's honesty

The `.sha256` endpoint is **not a trust anchor** and the documentation says so
in those words. A server compromised into serving a hostile script serves that
script's hash too; verifying against a hash from the same origin proves the
transfer was intact, not that the origin is honest. The endpoint exists so the
published digest cannot go stale and so the documented install has something to
fail closed against. `docs/install-helper.md` therefore leads with two methods
anchored outside the server (build from a signed tag; verify against a digest
from the release notes) and presents the same-origin one-liner last, labelled
with what it does not defend against.

No install instruction anywhere pipes a fetched script into a shell. Every one
writes to a file, verifies, and chains with `&&` so a mismatch aborts before
execution.

## Consequences

- ADR-0013's helper-delivery clause is amended: served copy and release artifact
  are deliberately different artifacts, with different integrity anchors.
- Installing via the served script requires a Go toolchain on the target host.
  This is a real limitation, documented, with a build-machine workaround.
- **Follow-up:** the release pipeline should build, sign, and publish
  `vallet-helper` alongside `valletd`. When it does, the installer can gain a
  signed-binary path and the toolchain requirement goes away. That is release
  infrastructure work and out of scope here.
- Two more unauthenticated routes exist by default. They are static, embedded,
  parameterless, and individually disableable.

## Alternatives considered

- **Reimplement the helper as a POSIX script and serve that** (ADR-0013's
  original assumption): rejected. Duplicates security-critical logic in a
  second language with no shared tests.
- **Serve the helper binary**: rejected. Does not compile (`//go:embed` of a
  build output) and needs a platform parameter.
- **Serve the helper's Go source**: rejected. Not an install path; the operator
  still needs a toolchain and now also needs to know what to do with it.
- **An installer that downloads a signed release binary**: rejected *for now*.
  No such artifact is published; shipping a script pointing at URLs that 404
  would be worse than shipping none. Revisit per the follow-up above.
- **Hard-code the digest in the docs**: rejected. It goes stale silently, and a
  stale hash trains operators to skip verification.
