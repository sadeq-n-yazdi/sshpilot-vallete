package httpserver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/service/publish"
)

// Publisher is the publish dependency, declared at the point of use so the
// transport depends on a method set rather than on a concrete service type.
// *publish.Service satisfies it.
type Publisher interface {
	// Resolve returns the authorized_keys body for a handle and set name. An
	// empty setName selects the owner's default set. It reports
	// publish.ErrNotFound for every negative verdict.
	Resolve(ctx context.Context, handle, setName string) ([]byte, error)
}

// publishMaxAge is how long a client or shared cache may reuse a published
// authorized_keys body without revalidating.
//
// It is a deliberate compromise. Longer would blunt key revocation, which is
// the operation that most needs to take effect quickly; shorter would push a
// fleet of AuthorizedKeysCommand callers into revalidating on almost every SSH
// login. A minute bounds the revocation lag while letting the common case be
// answered from cache, and conditional requests make even the revalidation
// cheap.
const publishMaxAge = 60

// publishContentType is the media type of an authorized_keys body: it is a
// plain text file consumed by sshd, not a structured document.
const publishContentType = "text/plain; charset=utf-8"

// publishHandler serves the unauthenticated publish endpoint for both
// /{handle} and /{handle}/{set}.
//
// The two routes share one handler; the set name is simply absent from the
// first, which the service reads as "the owner's default set". Keeping them in
// one function is what guarantees their success, 404, and error responses are
// produced by identical code rather than by two implementations that could
// drift apart into a distinguishable pair.
func publishHandler(p Publisher, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// A nil publisher is a wiring fault, not a client error. It must not
		// degrade into a 404, which would be indistinguishable from a genuine
		// miss and would hide a broken deployment behind a plausible answer.
		if p == nil {
			logger.LogAttrs(r.Context(), slog.LevelError, "publish handler misconfigured",
				slog.String("request_id", RequestIDFromContext(r.Context())),
				slog.String("error", ErrNilPublisher.Error()),
			)
			writePublishError(w)
			return
		}

		body, err := p.Resolve(r.Context(), r.PathValue("handle"), r.PathValue("set"))
		if err != nil {
			if errors.Is(err, publish.ErrNotFound) {
				writePublishNotFound(w)
				return
			}
			// The reason is logged, never returned. Resolve's non-404 errors
			// name internal state (key IDs, storage failures) that an
			// unauthenticated caller has no business learning.
			logger.LogAttrs(r.Context(), slog.LevelError, "publish resolution failed",
				slog.String("request_id", RequestIDFromContext(r.Context())),
				slog.String("error", err.Error()),
			)
			writePublishError(w)
			return
		}

		writePublishBody(w, r, body)
	}
}

// writePublishBody sends a resolved authorized_keys body, honoring conditional
// requests and HEAD.
//
// Header order matters: the validators (ETag, Cache-Control) are set BEFORE the
// If-None-Match check so that a 304 carries them too — a conditional response
// that dropped its ETag would leave the client with nothing to revalidate
// against next time, silently degrading every subsequent request to a full
// fetch.
//
// HEAD needs no special casing beyond that: net/http discards the body of a
// HEAD response by itself, and because Content-Length is set explicitly rather
// than inferred from what was written, a HEAD response carries exactly the same
// headers as the GET it stands in for.
func writePublishBody(w http.ResponseWriter, r *http.Request, body []byte) {
	etag := entityTag(body)
	h := w.Header()
	h.Set("ETag", etag)
	h.Set("Cache-Control", "public, max-age="+strconv.Itoa(publishMaxAge))

	if matchesETag(r.Header.Get("If-None-Match"), etag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}

	h.Set("Content-Type", publishContentType)
	// The body is attacker-influenced only through validated key comments, but
	// nosniff is set anyway: it costs nothing and removes any chance of a
	// browser deciding this text is something more interesting.
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write(body)
}

// entityTag returns a strong entity tag derived from the body.
//
// The tag is a hash of the content, not a random or time-based token, so it is
// identical across restarts, replicas, and rebuilds: any instance can validate
// a tag any other instance issued. SHA-256 is used because it is already a
// dependency and because a collision here would mean serving a stale key list
// to a client that asked whether its copy was current.
func entityTag(body []byte) string {
	sum := sha256.Sum256(body)
	return `"` + hex.EncodeToString(sum[:]) + `"`
}

// matchesETag reports whether an If-None-Match header value matches the current
// tag, per the weak comparison RFC 9110 prescribes for this header.
//
// "*" matches any existing representation. Otherwise the header is a
// comma-separated list of tags, each of which may carry a "W/" prefix that is
// ignored for the comparison. Anything that does not parse simply fails to
// match, which yields a full 200 — the safe direction, since a wrongly matched
// tag would answer 304 and leave a client using a key list it should have
// replaced.
func matchesETag(header, etag string) bool {
	header = strings.TrimSpace(header)
	if header == "" {
		return false
	}
	if header == "*" {
		return true
	}

	want := strings.TrimPrefix(etag, "W/")
	for candidate := range strings.SplitSeq(header, ",") {
		if strings.TrimPrefix(strings.TrimSpace(candidate), "W/") == want {
			return true
		}
	}
	return false
}

// writePublishNotFound writes THE 404 of the publish path.
//
// Every negative verdict — unknown handle, unknown set, a set belonging to
// another owner, an inactive or non-public set, a malformed name — reaches this
// one function, so all of them produce a byte-identical status, body, and
// header set. Any divergence would be an existence oracle: a stranger could
// otherwise tell "no such handle" from "that handle exists but the set is
// private", and enumerate another owner's namespace from the outside.
//
// The body is a fixed string that reflects nothing about the request. It
// deliberately carries no ETag and no cacheability: a cached negative would
// keep answering 404 after the owner published the set.
func writePublishNotFound(w http.ResponseWriter) {
	writePublishStatus(w, http.StatusNotFound, "not found\n")
}

// writePublishError writes the generic 500 for an internal fault. Like the 404
// it is fixed text: the cause is in the log, never on the wire.
func writePublishError(w http.ResponseWriter) {
	writePublishStatus(w, http.StatusInternalServerError, "internal server error\n")
}

// writePublishStatus writes a fixed-text response with no cache validators, the
// single writer shared by the failure paths.
func writePublishStatus(w http.ResponseWriter, status int, body string) {
	h := w.Header()
	h.Set("Content-Type", publishContentType)
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(status)
	// net/http suppresses this for HEAD, so a HEAD failure response matches its
	// GET counterpart header-for-header without a method check here.
	_, _ = w.Write([]byte(body))
}
