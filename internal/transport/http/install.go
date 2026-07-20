package httpserver

import (
	"bytes"
	"net/http"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/config"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/helperinstall"
)

// installCacheControl lets shared caches hold the installer briefly. The script
// is fixed at build time and cannot change within the life of a process, so the
// only reason for a ceiling at all is that a deployment which ships a new
// script should not stay shadowed by caches for long. Revalidation is cheap:
// every response carries a strong ETag.
//
// The window is deliberately short for an artifact of this kind. A long-lived
// cached installer is a stale installer, and a stale installer whose digest no
// longer matches the published one trains operators to skip verification.
const installCacheControl = "public, max-age=300"

// The media types the install endpoints produce. Both are text/plain: the
// script is served as plain text rather than an executable type so that no
// browser or intermediary is invited to treat it as something to run, and
// nosniff on every response stops one deciding otherwise.
const (
	mediaInstallScript = "text/plain; charset=utf-8"
	mediaInstallDigest = "text/plain; charset=utf-8"
)

// writeInstallAsset writes one of the two static install artifacts.
//
// http.ServeContent does the conditional-request and HEAD handling, so
// If-None-Match, 304, and a bodiless HEAD cannot be got subtly wrong here, and
// a HEAD can never describe a GET it disagrees with because the same call
// produces both.
//
// filename drives Content-Disposition: attachment. A browser that reaches
// either URL must download the file, not render it -- an installer script
// displayed inline in a page is one click away from being copied out of a
// context that dropped the verification step.
//
// etag arrives already quoted, in the form entityTag produces, so there is one
// spelling of an entity tag in this package rather than two that could drift.
func writeInstallAsset(w http.ResponseWriter, r *http.Request, mediaType, filename, etag string, body []byte) {
	header := w.Header()
	header.Set("Content-Type", mediaType)
	header.Set("X-Content-Type-Options", "nosniff")
	header.Set("Cache-Control", installCacheControl)
	header.Set("Content-Disposition", `attachment; filename="`+filename+`"`)
	header.Set("ETag", etag)
	http.ServeContent(w, r, "", time.Time{}, bytes.NewReader(body))
}

// installScriptHandler serves the helper installation script.
//
// There is exactly one document and no parameter selects it. That is the reason
// there is no /install/{name} route: the moment a path segment names the file,
// the endpoint has a traversal surface and an enumeration oracle, and this is
// the one endpoint on the server whose output an operator is expected to
// execute. A hard-coded route has neither.
//
// The ETag is the script's own SHA-256 -- the same digest the sibling endpoint
// publishes. Reusing it means a client that has already verified a copy can
// revalidate against the very value it verified.
func installScriptHandler(enabled bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !enabled {
			http.NotFound(w, r)
			return
		}
		body := helperinstall.Script()
		// The entity tag is computed from the bytes about to be written, not
		// from helperinstall.Digest(). The two are equal -- a test asserts it
		// -- and deriving the tag from the response body means a serving path
		// that ever wrote something other than the embedded script would
		// announce a tag that no longer matched the published digest, instead
		// of silently labeling different bytes with the trusted hash.
		writeInstallAsset(w, r, mediaInstallScript, helperinstall.ScriptName,
			entityTag(body), body)
	})
}

// installDigestHandler serves the script's SHA-256 in `sha256sum -c` format.
//
// The digest is derived from the embedded script bytes at initialization, never
// written down by hand, so this endpoint and the script endpoint cannot
// disagree about what is being served.
//
// What this endpoint is NOT: a trust anchor. A server that has been compromised
// into serving a hostile script will happily serve that script's digest too.
// Verifying a download against a hash fetched from the same origin proves the
// transfer was intact and that the two endpoints agree -- it proves nothing
// about the origin. The anchor an operator should pin is the digest published
// out-of-band in the release notes and docs. This endpoint exists so that
// published value can be checked for staleness, and so the documented install
// has something to fail closed against. docs/install-helper.md says so plainly
// rather than leaving an operator to assume otherwise.
func installDigestHandler(enabled bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !enabled {
			http.NotFound(w, r)
			return
		}
		body := []byte(helperinstall.DigestLine())
		writeInstallAsset(w, r, mediaInstallDigest, helperinstall.ScriptName+".sha256",
			entityTag(body), body)
	})
}

// installEnabled reports whether the install endpoints should answer.
//
// A nil config means no configuration was supplied, which resolves to the
// product default: enabled and unauthenticated. That is ADR-0013's decision,
// not a convenience -- the whole point of a served installer is that a stranger
// bootstrapping a host can fetch it, and an installer behind a credential the
// host does not yet have is an installer nobody can use. The script is not
// secret: it contains no keys, no host names, and no information about who uses
// this deployment, and it is byte-identical for every requester.
//
// Deployers who do not accept an unauthenticated route -- internal-only
// installations, or anyone minimizing anonymous attack surface -- set
// enabled: false, and both routes stop existing as far as a probe can tell.
func installEnabled(cfg *config.Config) bool {
	if cfg == nil {
		return true
	}
	return cfg.Install.Enabled
}
