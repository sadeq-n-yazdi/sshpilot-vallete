// Package helperinstall embeds the helper installation script into the binary
// and publishes its SHA-256 digest.
//
// The script is embedded rather than read from disk at request time, for the
// same two reasons the API contract is (see api/openapi): a request-time disk
// read is a path-traversal surface waiting for its first parameter, and bytes
// read from a disk are whatever is on that disk rather than what was reviewed.
// An installer script is the worst possible artifact to get that wrong on — it
// is fetched by strangers and run as a shell.
//
// The digest lives here, beside the embed, and is computed FROM the embedded
// bytes. It is not a constant anyone maintains. A hand-copied hash goes stale
// the first time the script changes, and a stale hash is worse than none: it
// teaches operators that verification failures are noise to be skipped, which
// is precisely the habit that makes a supply-chain attack land.
//
// The embed lives in its own package because a //go:embed pattern may not
// contain "..", so the file must sit beside the directive. That constraint is
// useful: there is exactly one copy of the script in the tree.
package helperinstall

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
)

// ScriptName is the file name the script is published under.
//
// It appears in the digest line and in Content-Disposition, so a downloader
// that follows the documented instructions writes the file under the name the
// checksum line refers to and `sha256sum -c` finds it.
const ScriptName = "install-vallet-helper.sh"

// scriptFS holds the script. It is an embed.FS rather than a []byte so the
// exported accessor below can hand out a copy: a shared []byte is mutable by
// any caller, and the digest is computed once, so a caller that scribbled on
// the backing array would make the served bytes and the served hash disagree
// without either side being obviously wrong.
//
//go:embed install-vallet-helper.sh
var scriptFS embed.FS

// script and digest are derived once at package initialization, in that order,
// so the digest is by construction the digest of these exact bytes. There is no
// code path that produces one without the other.
var script, digest = func() ([]byte, string) {
	b, err := scriptFS.ReadFile(ScriptName)
	if err != nil {
		// Unreachable: the embed directive above guarantees the file is
		// present, and a missing one is a compile error. Panicking rather than
		// serving nothing is right for an initialization-time impossibility --
		// a process that cannot produce its own installer should not start and
		// pretend the endpoint works.
		panic("helperinstall: embedded script missing: " + err.Error())
	}
	sum := sha256.Sum256(b)
	return b, hex.EncodeToString(sum[:])
}()

// Script returns the installer script exactly as authored.
//
// It returns a fresh copy on every call. That costs a few kilobytes per request
// and buys the guarantee that no handler, middleware, or test can mutate the
// bytes the digest was taken over.
func Script() []byte {
	out := make([]byte, len(script))
	copy(out, script)
	return out
}

// Digest returns the lowercase hex SHA-256 of the bytes Script returns.
func Digest() string { return digest }

// DigestLine returns the digest in the format `sha256sum -c` reads: the hex
// digest, two spaces, the file name.
//
// Serving this shape rather than a bare hex string is what lets the documented
// install pipe into `sha256sum -c -` and fail closed on a mismatch, with no
// shell arithmetic on the operator's part for a comparison to get subtly wrong.
func DigestLine() string { return digest + "  " + ScriptName + "\n" }
