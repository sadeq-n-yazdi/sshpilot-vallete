#!/usr/bin/env bash
#
# Reproducible build of the valletd binary.
#
# This script is the single source of truth for release build flags. The
# Makefile, CI, and the reproducibility test in internal/build all shell out to
# it, so a "reproducible build" cannot drift between a developer's machine and
# the release pipeline -- there is only one place the flags are written down.
#
# Determinism rules enforced here:
#   * CGO_ENABLED=0        -- no host toolchain, headers, or libc leak into the
#                             output; the module is pure Go (modernc.org/sqlite).
#   * -trimpath            -- strips absolute workspace paths from the binary.
#   * -buildvcs=false      -- VCS stamping embeds the commit hash, commit time,
#                             and a dirty flag, which makes the bytes depend on
#                             the presence and state of .git rather than on the
#                             source. Provenance is established by signing the
#                             artifact, not by stamping it.
#   * deterministic ldflags -- only the version string is injected. No build
#                             timestamp is ever baked in, so the output depends
#                             on the source and the requested version and on
#                             nothing else. There is deliberately no clock in
#                             this build: SOURCE_DATE_EPOCH is unnecessary
#                             because nothing here reads the time.
#
# Environment overrides:
#   OUT_DIR   output directory                      (default: ./dist)
#   BIN_NAME  output file name                      (default: valletd)
#   VERSION   version string injected via -ldflags  (default: git describe)
#   GOOS      target OS                             (default: host)
#   GOARCH    target architecture                   (default: host)

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

readonly MODULE="github.com/sadeq-n-yazdi/sshpilot-vallete"
readonly PKG="./cmd/valletd"

OUT_DIR="${OUT_DIR:-dist}"
BIN_NAME="${BIN_NAME:-valletd}"

# Resolve the version without ever failing the build: an exported source tree
# has no .git, and that must still produce a byte-identical binary given the
# same VERSION. Callers that need strict reproducibility pass VERSION in.
if [[ -z "${VERSION:-}" ]]; then
	if git rev-parse --git-dir >/dev/null 2>&1; then
		VERSION="$(git describe --tags --always --dirty 2>/dev/null || echo "0.0.0-dev")"
	else
		VERSION="0.0.0-dev"
	fi
fi

GOOS="${GOOS:-$(go env GOHOSTOS)}"
GOARCH="${GOARCH:-$(go env GOHOSTARCH)}"

mkdir -p "$OUT_DIR"

# -s -w drop the symbol and DWARF tables. They shrink the artifact and, more
# usefully here, remove a class of absolute-path and toolchain-detail leakage.
ldflags="-s -w -X ${MODULE}/internal/version.Version=${VERSION}"

echo "building ${BIN_NAME} version=${VERSION} os=${GOOS} arch=${GOARCH}" >&2

CGO_ENABLED=0 GOOS="$GOOS" GOARCH="$GOARCH" \
	go build \
	-trimpath \
	-buildvcs=false \
	-ldflags "$ldflags" \
	-o "${OUT_DIR}/${BIN_NAME}" \
	"$PKG"

echo "wrote ${OUT_DIR}/${BIN_NAME}" >&2
