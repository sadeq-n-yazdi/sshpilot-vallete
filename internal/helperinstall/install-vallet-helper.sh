#!/bin/sh
#
# install-vallet-helper.sh -- install the sshpilot-vallet managed-block helper
# (vallet-helper) onto a host whose authorized_keys this server maintains.
#
# This script is served by the vallet server itself and is meant to be fetched,
# CHECKED AGAINST ITS PUBLISHED SHA-256, and only then run. It is deliberately
# not something you should pipe straight into a shell; see docs/install-helper.md
# for the verified one-liner, which fails closed on a hash mismatch.
#
# What it does NOT do, on purpose:
#
#   * It never downloads an unverified executable. There is no `curl | sh` and
#     no fetch of a binary from a URL. The one install path it offers is
#     `go install` at an operator-supplied version, which resolves through the
#     Go module proxy and is verified against the public checksum database --
#     an integrity anchor that already exists and that this script cannot
#     weaken (see the exports below).
#   * It never guesses a version. There is no floating default and no "latest":
#     an unpinned install is not a verifiable one, so omitting --version is an
#     error rather than a silent best effort.
#   * It never touches authorized_keys. Installing the helper and running it
#     are separate acts; this script only puts the binary in place.
#
# Usage:
#   sh install-vallet-helper.sh --version v1.2.3 [--bin-dir DIR] [--dry-run]

set -eu

MODULE="github.com/sadeq-n-yazdi/sshpilot-vallete"
PKG="${MODULE}/cmd/vallet-helper"

version=""
# Empty rather than a guess when HOME is unset. "${HOME:-}/.local/bin" would
# collapse to /.local/bin, which a non-root operator cannot create, and any
# relative fallback such as ./bin would drop an executable into whatever
# directory the caller happened to be standing in -- not on PATH, and in a
# container possibly a mount other processes read. The check further down
# refuses instead; see the die() there.
bin_dir="${HOME:+${HOME}/.local/bin}"
dry_run=0

die() {
	printf 'install-vallet-helper: %s\n' "$*" >&2
	exit 1
}

usage() {
	cat >&2 <<'EOF'
usage: install-vallet-helper.sh --version VERSION [--bin-dir DIR] [--dry-run]

  --version VERSION  release tag or commit to install (required; no default)
  --bin-dir DIR      where to place the binary (default ~/.local/bin;
                     required when HOME is unset -- nothing is guessed)
  --dry-run          print what would happen and install nothing
EOF
	exit 2
}

while [ "$#" -gt 0 ]; do
	case "$1" in
	--version)
		[ "$#" -ge 2 ] || die "--version needs a value"
		version="$2"
		shift 2
		;;
	--bin-dir)
		[ "$#" -ge 2 ] || die "--bin-dir needs a value"
		[ -n "$2" ] || die "--bin-dir must not be empty"
		bin_dir="$2"
		shift 2
		;;
	--dry-run)
		dry_run=1
		shift
		;;
	-h | --help) usage ;;
	*) die "unknown argument: $1" ;;
	esac
done

# No default version. A floating install cannot be pinned, audited, or
# reproduced, so refusing here is the whole point rather than an inconvenience.
[ -n "$version" ] || die "--version is required; pass the release tag you intend to install"

# "latest" resolves to whatever the proxy serves at this moment, which is
# exactly the unpinned install the line above refuses. Rejecting the spelling
# stops it sneaking back in as an explicit-looking argument.
case "$version" in
latest | @latest | "") die "refusing to install an unpinned version" ;;
esac

command -v go >/dev/null 2>&1 || die "go toolchain not found on PATH; install Go, or fetch a signed release binary instead"

[ -n "${bin_dir}" ] || die "cannot determine an install directory: HOME is unset, so pass --bin-dir DIR explicitly"

# A dry run must not touch the filesystem, so it exits before the directory is
# created and before anything is resolved against it.
if [ "$dry_run" -eq 1 ]; then
	printf 'dry run: would install %s@%s into %s\n' "$PKG" "$version" "$bin_dir"
	printf 'dry run: would run: go install %s@%s\n' "$PKG" "$version"
	exit 0
fi

# `go install` rejects a relative GOBIN, and it does so from deep inside the
# toolchain with a message that does not mention --bin-dir. Resolve to an
# absolute path here instead. The directory has to exist before it can be
# resolved, which is why it is created first rather than just before the
# install.
# CDPATH is cleared first: with it set, `cd bin` can silently land in a
# completely different directory, which would send the binary somewhere the
# operator never named.
CDPATH=''
mkdir -p -- "$bin_dir" || die "cannot create --bin-dir: $bin_dir"
bin_dir=$(CDPATH='' cd -P -- "$bin_dir" && pwd) || die "cannot resolve --bin-dir to an absolute path: $bin_dir"

# Force module verification on for this invocation regardless of how the
# calling environment is configured. An operator with GOFLAGS=-insecure,
# GONOSUMDB, or GOPRIVATE covering this module would otherwise install
# unverified bytes without any visible difference in the output. These exports
# are scoped to this process; the caller's environment is not modified.
GOFLAGS=""
GOPRIVATE=""
GONOSUMDB=""
GONOSUMCHECK=""
GOINSECURE=""
GONOSUMVERIFY=""
GOSUMDB="sum.golang.org"
GOBIN="$bin_dir"
export GOFLAGS GOPRIVATE GONOSUMDB GONOSUMCHECK GOINSECURE GONOSUMVERIFY GOSUMDB GOBIN

printf 'installing %s@%s into %s\n' "$PKG" "$version" "$bin_dir"
printf 'module integrity is verified against %s\n' "$GOSUMDB"

# No `|| true`, and `set -e` is still in force: a failed or unverifiable
# download aborts here rather than leaving a half-installed helper behind.
go install "${PKG}@${version}"

printf 'installed: %s/vallet-helper\n' "$bin_dir"
printf 'next: %s/vallet-helper -url https://<this-server>/<handle>/<set> -dry-run\n' "$bin_dir"
