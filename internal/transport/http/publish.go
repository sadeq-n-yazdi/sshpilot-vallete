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

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/secrets"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/service/publish"
)

// Publisher is the publish dependency, declared at the point of use so the
// transport depends on a method set rather than on a concrete service type.
// *publish.Service satisfies it.
type Publisher interface {
	// Resolve returns the authorized_keys body for a handle and set name. An
	// empty setName selects the owner's default set. presented is the bearer
	// token the caller supplied, empty when it supplied none; it is consulted
	// only for an access-gated set.
	//
	// It reports publish.ErrNotFound for every negative verdict, INCLUDING
	// every refused credential. There is deliberately no second error value
	// for "protected but not authorized": this signature is what makes it
	// impossible for this package to answer a protected miss with anything
	// other than the response it gives an absent set (ADR-0019).
	Resolve(ctx context.Context, handle, setName string, presented secrets.Redacted) (publish.Result, error)
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

// publishHandler serves the publish endpoint for both /{handle} and
// /{handle}/{set}.
//
// The two routes share one handler; the set name is simply absent from the
// first, which the service reads as "the owner's default set". Keeping them in
// one function is what guarantees their success, 404, and error responses are
// produced by identical code rather than by two implementations that could
// drift apart into a distinguishable pair.
//
// # Access-gated sets
//
// The endpoint is unauthenticated in the sense that it never REQUIRES a
// credential to be reached: a missing Authorization header is not an error
// here, it is simply an empty token that no protected set accepts. The handler
// does not decide that, and does not know which sets are protected — it hands
// whatever bearer token arrived to the service and acts on the same two
// verdicts it has always acted on.
//
// That is the point. A refused credential and a nonexistent set are one value
// by the time they reach this function, so both leave through
// writePublishNotFound and are byte-identical on the wire; there is no branch
// here that could be written to tell them apart, because there is nothing here
// to branch on (ADR-0019).
//
// The token is taken from the Authorization header ONLY. A query parameter or
// cookie is never consulted: those are logged by proxies, kept in browser
// history, and sent cross-site by the client without the caller's intent, and a
// credential that unlocks a key set must not travel that way.
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
			writePublishError(w, r)
			return
		}

		// A malformed or absent Authorization header yields the empty token
		// rather than an early refusal. Rejecting it here would answer before
		// the service had looked anything up, and the response would then
		// depend on the header alone — harmless for a protected set, but a
		// public set would start refusing callers that sent a stray header,
		// and the two refusals would not be the same one.
		token, _ := bearerToken(r)

		res, err := p.Resolve(r.Context(), r.PathValue("handle"), r.PathValue("set"), token)
		if err != nil {
			if errors.Is(err, publish.ErrNotFound) {
				writePublishNotFound(w, r)
				return
			}
			// The reason is logged, never returned. Resolve's non-404 errors
			// name internal state (key IDs, storage failures) that an
			// unauthenticated caller has no business learning.
			logger.LogAttrs(r.Context(), slog.LevelError, "publish resolution failed",
				slog.String("request_id", RequestIDFromContext(r.Context())),
				slog.String("error", err.Error()),
			)
			writePublishError(w, r)
			return
		}

		writePublishBody(w, r, res)
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
// HEAD parity comes from two things. Content-Length is set explicitly rather
// than inferred from what was written, so it survives a response with no body;
// and the body write is skipped by an explicit method check rather than left to
// net/http's own HEAD handling, so the parity holds under any writer this
// handler is composed with, not only under the standard server.
//
// # Caching, and why a protected body may not be shared
//
// A public body is shared-cacheable: any cache may hold it and hand it to any
// client, because any client could have fetched it directly.
//
// An access-gated body may not. It gets "private", which forbids a shared cache
// from storing it at all, plus "Vary: Authorization" so that a cache which
// stores it anyway — a client's own, or an intermediary that ignores the
// directive — is at least keyed by the credential rather than by the URL, and
// cannot serve one consumer's copy to a request bearing a different token or
// none. ADR-0019 requires both. They are set BEFORE the If-None-Match branch,
// alongside the ETag and for the same reason: a 304 that dropped them would
// answer "your copy is current" with no restriction on who may reuse that copy.
//
// The ETag stays a content hash on both paths. It is not a shared-cache key
// here — "private" and the Vary have already removed sharing — and two owners
// whose sets happen to hold identical keys getting identical tags leaks
// nothing, since a matching tag can only be produced by a caller that already
// holds the body. Making it credential-derived instead would break the
// cross-replica stability the tag exists for and would put a value derived from
// a secret on the wire.
func writePublishBody(w http.ResponseWriter, r *http.Request, res publish.Result) {
	etag := entityTag(res.Body)
	h := w.Header()
	h.Set("ETag", etag)
	if res.Protected {
		h.Set("Cache-Control", "private, max-age="+strconv.Itoa(publishMaxAge))
		h.Set("Vary", "Authorization")
	} else {
		h.Set("Cache-Control", "public, max-age="+strconv.Itoa(publishMaxAge))
	}

	if matchesETag(r.Header.Get("If-None-Match"), etag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}

	h.Set("Content-Type", publishContentType)
	// The body is attacker-influenced only through validated key comments, but
	// nosniff is set anyway: it costs nothing and removes any chance of a
	// browser deciding this text is something more interesting.
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Content-Length", strconv.Itoa(len(res.Body)))
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write(res.Body)
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
// another owner, an inactive set, a malformed name, and every refused access
// key: absent, malformed, revoked, or minted for one of the owner's OTHER sets
// — reaches this one function, so all of them produce a byte-identical status,
// body, and header set. Any divergence would be an existence oracle: a stranger
// could otherwise tell "no such handle" from "that handle exists but the set is
// protected", and enumerate another owner's namespace from the outside. A
// consumer holding one set's token is not the owner, and must not be able to
// read the owner's other protected set names off a 403.
//
// It takes no argument describing the request, and that is deliberate: there is
// nothing here it could condition on. In particular NO Vary header is set. Vary
// belongs to the protected success path only; emitting it here for a protected
// miss and not for an absent set would be precisely the distinguishable pair
// this function exists to prevent, restated in a header nobody reads.
//
// The body is a fixed string that reflects nothing about the request. It
// deliberately carries no ETag and no cacheability: a cached negative would
// keep answering 404 after the owner published the set.
func writePublishNotFound(w http.ResponseWriter, r *http.Request) {
	writePublishStatus(w, r, http.StatusNotFound, "not found\n")
}

// writePublishError writes the generic 500 for an internal fault. Like the 404
// it is fixed text: the cause is in the log, never on the wire.
func writePublishError(w http.ResponseWriter, r *http.Request) {
	writePublishStatus(w, r, http.StatusInternalServerError, "internal server error\n")
}

// writePublishStatus writes a fixed-text response with no cache validators, the
// single writer shared by the failure paths.
func writePublishStatus(w http.ResponseWriter, r *http.Request, status int, body string) {
	h := w.Header()
	h.Set("Content-Type", publishContentType)
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(status)
	// The HEAD check is explicit rather than left to net/http, which drops a
	// HEAD body itself. Relying on that would make correctness a property of
	// who happens to be serving this handler: under any other writer — a test
	// recorder, an in-process wrapper, a future embedding — the body would
	// escape. The failure paths suppress it here for the same reason the
	// success path does, so the two behave alike wherever they run.
	if r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write([]byte(body))
}
