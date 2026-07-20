# Installing the managed-block helper

`vallet-helper` syncs a published key set into the managed block of a host's
`authorized_keys`. This page is about getting it onto a host **verifiably**.

The server serves an installation script at:

| Path | What it is |
| --- | --- |
| `/install/vallet-helper.sh` | The installation script |
| `/install/vallet-helper.sh.sha256` | Its SHA-256, in `sha256sum -c` format |

Both are HTTPS-only — this server does not speak plaintext HTTP at all
(ADR-0015) — and both are embedded in the binary at build time, so the bytes
served are the bytes reviewed.

## Read this before you copy a command

Fetching a script from a server and running it is a trust decision, and it is
worth being precise about what each step below actually buys you.

- **TLS** proves you reached the server you named and that nothing on the
  network altered the bytes in transit.
- **The `.sha256` endpoint** proves the copy you downloaded is intact and that
  it matches what the server intends to serve. It is derived from the embedded
  script at process start, so it cannot go stale and cannot disagree with the
  script endpoint.
- **The `.sha256` endpoint is not a trust anchor.** A server that has been
  compromised into serving a hostile script will serve that script's hash just
  as cheerfully. Verifying a download against a hash from the *same origin*
  cannot detect a dishonest origin. Anyone who tells you otherwise is selling
  you a checksum as if it were a signature.

The anchor that does defend against a dishonest server is a digest you obtained
**somewhere other than that server** — from the release notes, from a source
checkout, or from a colleague. Method 1 and Method 2 below use one. Method 3
does not, and says so.

## Method 1 — build from source (strongest)

No server is involved, and the integrity anchor is the git tag itself.

```sh
git clone https://github.com/sadeq-n-yazdi/sshpilot-vallete
cd sshpilot-vallete
git checkout v1.2.3          # the release you intend to run
git verify-tag v1.2.3        # fails closed if the tag is not signed by the maintainer
go build -o ~/.local/bin/vallet-helper ./cmd/vallet-helper
```

## Method 2 — served script, verified against an out-of-band digest

Use this when you have the expected digest from the release notes. Paste it in
place of `EXPECTED` — do **not** fetch it from the server you are installing
from, or you are doing Method 3 with extra steps.

```sh
EXPECTED=0000000000000000000000000000000000000000000000000000000000000000

curl -fsSL --proto '=https' --tlsv1.2 \
  https://vallet.example/install/vallet-helper.sh \
  -o install-vallet-helper.sh

printf '%s  install-vallet-helper.sh\n' "$EXPECTED" | sha256sum -c - \
  && sh ./install-vallet-helper.sh --version v1.2.3
```

The `&&` is what makes this fail closed: `sha256sum -c` exits non-zero on a
mismatch, so the shell never reaches the `sh` that would run the script. Note
also that the script is written to a file and run from it. There is no pipe
into a shell anywhere on this page, and that is deliberate: a piped script is
executed as it arrives, so a truncated or swapped stream has already run part
of itself by the time anything could have checked it.

To derive `EXPECTED` yourself from a source checkout:

```sh
sha256sum internal/helperinstall/install-vallet-helper.sh
```

## Method 3 — served script and served digest (convenience)

```sh
curl -fsSL --proto '=https' --tlsv1.2 \
  https://vallet.example/install/vallet-helper.sh \
  -o install-vallet-helper.sh

curl -fsSL --proto '=https' --tlsv1.2 \
  https://vallet.example/install/vallet-helper.sh.sha256 \
  | sha256sum -c - \
  && sh ./install-vallet-helper.sh --version v1.2.3
```

This fails closed on a corrupted transfer, a truncated download, and any drift
between the two endpoints. It does **not** defend against a compromised server,
because both halves come from that server. Use Method 1 or 2 for a host you
care about.

`--proto '=https'` refuses to follow a redirect down to plaintext; `-f` makes
curl exit non-zero on an HTTP error instead of saving an error page as if it
were the script.

## What the script does, and what it refuses to do

```
sh install-vallet-helper.sh --version VERSION [--bin-dir DIR] [--dry-run]
```

It runs `go install github.com/sadeq-n-yazdi/sshpilot-vallete/cmd/vallet-helper@VERSION`,
which resolves through the Go module proxy and is verified against the public
checksum database (`sum.golang.org`). That database is the integrity anchor for
the binary itself, and it is one the script cannot weaken: it clears `GOFLAGS`,
`GOPRIVATE`, `GONOSUMDB`, `GONOSUMCHECK`, and `GOINSECURE` and forces `GOSUMDB`
on for its own invocation, so a caller's environment cannot turn verification
off without editing the script — which would change its digest.

It refuses to:

- run without `--version`. There is no floating default and `latest` is
  rejected by name, because an unpinned install cannot be pinned, audited, or
  reproduced.
- continue past any failed step (`set -eu`).
- download an executable from a URL, disable TLS verification, or pipe anything
  into a shell.
- touch `authorized_keys`. Installing the helper and running it are separate
  acts.

Run it with `--dry-run` first if you want to see the exact `go install` it
would perform.

### It needs a Go toolchain

`go install` is the only install path that has a verifiable integrity anchor
today. The release pipeline currently signs and publishes `valletd` only, not
`vallet-helper`, so there is no signed helper binary for the script to download
and check. Until there is, a host without Go should use Method 1 on a build
machine and copy the resulting binary across.

## Turning the endpoints off

```yaml
install:
  enabled: false
```

or `VALLET_INSTALL_ENABLED=false`. Both routes then answer exactly as any
unrouted path does, so a scanner cannot tell the feature exists to be disabled.
Enabled is the default: the script is a bootstrap path for hosts that have
nothing from this project yet, it is byte-identical for every requester, and it
contains no keys, host names, or information about who uses the deployment.

## Related

- ADR-0013 — key application methods and managed-block helper
- ADR-0029 — served helper installer and pinned-hash install
- ADR-0027 — supply-chain and build security
