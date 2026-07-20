package httpserver

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/auth"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/secrets"
)

// bearerScheme is the only Authorization scheme this server accepts.
const bearerScheme = "bearer"

// maxBearerLen bounds the credential this server will even attempt to verify.
//
// An access token is a few hundred bytes; nothing legitimate approaches this.
// The bound exists so an unauthenticated caller cannot make the server do
// base64 decoding and HMAC work proportional to a header it chose -- the header
// is read before anything has authenticated, so its size is entirely the
// caller's to pick.
const maxBearerLen = 4096

// DenialStyle selects what an unauthenticated caller is told.
//
// It exists because this codebase has two surfaces with genuinely different
// answers, and the difference is a decision an operator of a route must make
// deliberately rather than inherit.
type DenialStyle int

const (
	// DenyNotFound answers every unauthenticated request with 404, identical to
	// a genuinely nonexistent resource. It is the zero value, so a route that
	// says nothing gets the style that leaks least.
	//
	// This is what ADR-0019 requires of any surface where the mere existence of
	// a resource is itself protected: "an attacker cannot probe with a garbage
	// Bearer token and read existence off a 401-vs-404 difference". The cost is
	// named in the ADR and accepted: a legitimate client with a stale token
	// sees 404 rather than a diagnostic 401.
	DenyNotFound DenialStyle = iota

	// DenyUnauthorized answers with 401 and a WWW-Authenticate challenge.
	//
	// It is correct only where existence is not a secret -- the owner-facing
	// management API, whose resources are addressed by non-guessable internal
	// identifiers and whose caller is by definition already an account holder.
	// There a 401 tells the client to refresh its token, which is the whole
	// difference between a client that recovers and one that presents an
	// expired token forever. Choosing it on an existence-sensitive surface
	// reintroduces exactly the oracle DenyNotFound closes, so it must be
	// written down at the route rather than defaulted into.
	DenyUnauthorized
)

// Authorizer is the authorization dependency, declared at the point of use so
// the transport depends on a method set rather than a concrete type.
// *auth.Guard satisfies it.
type Authorizer interface {
	// Authorize verifies the presented bearer token and reports whether it
	// permits acc. It returns auth.ErrAuthFailed for anything short of a valid,
	// unrevoked token and auth.ErrForbidden for a valid token whose grant does
	// not cover the request.
	Authorize(ctx context.Context, presented secrets.Redacted, acc auth.Access, now time.Time) (*auth.Authorization, error)
}

// ScopedHandler is what a protected route implements.
//
// The *auth.Authorization is a parameter rather than something the handler goes
// and fetches, and that is the design decision this file exists to make. Every
// repository port in this codebase is owner-scoped by an explicit ownerID
// argument, so every handler has to produce a domain.OwnerID from somewhere;
// the only question is where. A handler that reaches for r.PathValue, a body
// field or a header has made the owner boundary a suggestion, because those are
// attacker-chosen.
//
// Handing the verified Authorization in as an argument means the correct owner
// is already in the handler's hand before its first line runs. Forgetting to
// scope a query is then not an omission -- it requires ignoring an argument and
// going to fetch an owner from somewhere else instead, which reads as a
// deliberate act in review rather than as nothing at all. The Authorization is
// also placed in the request context, for service code further down that cannot
// take it as a parameter; the two are the same value.
type ScopedHandler func(w http.ResponseWriter, r *http.Request, a *auth.Authorization)

// AccessFunc describes what a request is trying to do, for the route it is
// registered on. It is where a route names the resource it addresses -- the key
// set id out of the path, say -- so that a resource-bound token can be checked
// against it.
//
// It returns an error when the request does not name a coherent target at all
// (an unparsable identifier). That is a refusal, not a 400: the caller is
// unauthenticated at the point this runs and must learn nothing about which
// identifiers are well formed.
//
// It must NOT report who is asking. Nothing it returns is trusted as identity;
// auth.Access.Owner means "whose resources this request names", which is
// precisely the value the Guard checks against the token rather than believes.
type AccessFunc func(*http.Request) (auth.Access, error)

// AccountAccess is the AccessFunc for a route that addresses no single
// resource: the owner's own account-wide views. It names no owner, because the
// management API takes the owner from the token (ADR-0004), and no resource, so
// a resource-bound token cannot reach it.
func AccountAccess(*http.Request) (auth.Access, error) { return auth.Access{}, nil }

// Guardian mounts protected routes. It is immutable after construction and safe
// for concurrent use.
type Guardian struct {
	authz  Authorizer
	style  DenialStyle
	now    func() time.Time
	logger *slog.Logger
}

// NewGuardian builds a Guardian.
//
// A nil Authorizer is refused. Tolerating one would produce a Guardian whose
// Protect returned handlers that serve every request unauthorized, while the
// route table still read as guarded -- the same failure NewDenylist refuses a
// nil store to prevent, restated at the layer that mounts routes.
//
// now may be nil, in which case time.Now is used; a clock is behavior a test
// needs to control, not a security control. A nil logger is replaced with a
// discarding one: losing logs must never be why a request fails.
func NewGuardian(authz Authorizer, style DenialStyle, now func() time.Time, logger *slog.Logger) (*Guardian, error) {
	if authz == nil {
		return nil, ErrNilAuthorizer
	}
	if now == nil {
		now = time.Now
	}
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &Guardian{authz: authz, style: style, now: now, logger: logger}, nil
}

// Protect wraps a ScopedHandler in the authorization check, returning the
// http.Handler to register on the mux.
//
// This is the only way to obtain a handler that receives an *auth.Authorization,
// and there is no variant that skips a step: every handler built here runs
// Authorize, and Authorize has no branch that skips the owner boundary. A route
// therefore cannot bypass the owner check by being registered differently --
// the alternative registration does not exist.
//
// A nil access or handler panics, at registration time rather than on the first
// request. A route table is built once at startup, so a wiring fault there
// should stop the process while an operator is watching, not turn into a 500
// under load. This mirrors how the server's construction-time errors already
// fail closed rather than serve.
func (g *Guardian) Protect(access AccessFunc, h ScopedHandler) http.Handler {
	if access == nil {
		panic("httpserver: Protect called with a nil AccessFunc")
	}
	if h == nil {
		panic("httpserver: Protect called with a nil ScopedHandler")
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Vary is set here, before anything branches, so it covers the success
		// path as well as every refusal. The success path is where a
		// cross-owner cache leak would actually live: two owners issue the same
		// GET for a resource they each may see, and a shared cache without this
		// header would serve the first one's body to the second. Setting it at
		// the choke point rather than in each handler means a route cannot omit
		// it, and ADR-0019 requires access-gated responses to vary on the
		// credential.
		w.Header().Set("Vary", "Authorization")

		token, ok := bearerToken(r)
		if !ok {
			g.deny(w, r, auth.ErrAuthFailed)
			return
		}
		acc, err := access(r)
		if err != nil {
			g.deny(w, r, auth.ErrAuthFailed)
			return
		}
		// Mutation is derived from the method here, once, rather than declared
		// per route. A route cannot forget to set it and thereby become
		// writable to a read-only token, and a route cannot claim to be a read
		// while serving a DELETE.
		acc.Mutating = isMutating(r.Method)

		a, err := g.authz.Authorize(r.Context(), token, acc, g.now())
		if err != nil {
			g.deny(w, r, err)
			return
		}
		if a == nil {
			// A nil Authorization with a nil error is a contract violation by
			// the Authorizer. Reading it as "authorized as nobody" would hand
			// the handler an empty owner; denying is the only safe reading.
			g.deny(w, r, auth.ErrAuthFailed)
			return
		}

		h(w, r.WithContext(auth.ContextWithAuthorization(r.Context(), a)), a)
	})
}

// isMutating reports whether a method changes state.
//
// The safe methods are listed explicitly and everything else mutates, rather
// than the reverse. A method this code has never heard of is then a write, so a
// caller cannot slip a mutation past a read-only token by naming a verb the
// list did not anticipate.
func isMutating(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return false
	default:
		return true
	}
}

// bearerToken extracts the credential from the Authorization header.
//
// Three rules, each of which is a refusal rather than a repair:
//
//   - Exactly one Authorization header. Two is a request-smuggling shape --
//     which header an intermediary acted on and which this server reads need
//     not agree -- and there is no correct way to pick one.
//   - The scheme must be "Bearer", matched case-insensitively per RFC 9110,
//     which defines auth schemes as case-insensitive.
//   - The credential must be non-empty and within maxBearerLen.
//
// The returned value is a secrets.Redacted from the moment it exists, so it
// cannot reach a log or an error message by accident.
func bearerToken(r *http.Request) (secrets.Redacted, bool) {
	values := r.Header.Values("Authorization")
	if len(values) != 1 {
		return "", false
	}
	scheme, credential, ok := strings.Cut(values[0], " ")
	if !ok || !strings.EqualFold(scheme, bearerScheme) {
		return "", false
	}
	// Leading spaces are tolerated because RFC 9110 allows whitespace between
	// the scheme and the credential; the credential itself is then taken
	// verbatim, since a token is a single unpadded base64url word and trimming
	// its tail would mean verifying something other than what arrived.
	credential = strings.TrimLeft(credential, " \t")
	if credential == "" || len(credential) > maxBearerLen {
		return "", false
	}
	return secrets.NewRedacted(credential), true
}

// deny writes the refusal for err.
//
// # Which status, and why none of them is an existence oracle
//
// auth.ErrForbidden -> 403. It is reached only by a caller holding a valid,
// unrevoked token, and the verdict was computed from that token's own claims
// against the request the caller just composed. No storage was read and no
// resource was looked up, so the response is a function of the caller's two
// own inputs and of nothing in the system. It cannot report on what exists
// because nothing asked.
//
// Anything else -> 404 or 401 by the route's DenialStyle. Under DenyNotFound
// the answer is identical to a genuinely absent resource, which is what
// ADR-0019 requires where existence is protected. Under DenyUnauthorized the
// answer names an authentication problem, which is safe only because that style
// belongs to routes whose resources are addressed by non-guessable internal
// identifiers -- and even there the status depends solely on the presented
// token, never on whether the target exists, because this layer refuses before
// any handler runs and no lookup has happened yet.
//
// The invariant behind all three: authorization never consults storage other
// than the denylist, whose answer is about a credential the caller already
// holds. So no status this function writes can vary with the system's contents.
//
// The reason is logged and never returned. The body is a fixed string that
// reflects nothing about the request.
func (g *Guardian) deny(w http.ResponseWriter, r *http.Request, err error) {
	status := http.StatusNotFound
	switch {
	case errorIsForbidden(err):
		status = http.StatusForbidden
	case g.style == DenyUnauthorized:
		status = http.StatusUnauthorized
	}

	g.logger.LogAttrs(r.Context(), slog.LevelInfo, "request refused",
		slog.String("request_id", RequestIDFromContext(r.Context())),
		slog.String("method", r.Method),
		slog.String("path", sanitizeLogPath(r.URL.Path)),
		slog.Int("status", status),
	)

	if status == http.StatusUnauthorized {
		// The challenge carries no realm and no error parameter. RFC 6750's
		// error codes ("invalid_token", "insufficient_scope") are exactly the
		// distinctions ErrAuthFailed exists to erase, so the challenge says
		// only which scheme to use.
		w.Header().Set("WWW-Authenticate", "Bearer")
	}
	// Protect has already set this for every request it dispatches, success or
	// refusal. It is repeated here so that deny remains correct on its own if a
	// later entry point calls it directly; Set is idempotent.
	w.Header().Set("Vary", "Authorization")
	writeJSON(w, status, statusResponse{Status: "error"})
}

// errorIsForbidden reports whether err is the authorization sentinel.
//
// It is a helper rather than an inline errors.Is so there is exactly one place
// that decides a 403, and so the ordering in deny cannot be rearranged into one
// where a forbidden verdict falls through to the unauthenticated style and back
// into being indistinguishable from a missing token.
func errorIsForbidden(err error) bool {
	return errors.Is(err, auth.ErrForbidden)
}
