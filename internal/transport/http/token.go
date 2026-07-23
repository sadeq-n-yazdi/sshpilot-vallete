package httpserver

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/auth"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/ratelimit"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/secrets"
)

// TokenIssuer is the token-exchange dependency, declared at the point of use so
// the transport depends on a method set rather than the concrete
// *auth.TokenService. Exchange rotates a refresh token single-use and mints a
// fresh access token; a replayed refresh token revokes the whole lineage
// (ADR-0018 reuse-theft detection).
//
// Exchange takes an explicit now so the clock is the composition root's to
// choose and a test's to control -- the service holds none of its own for this
// call.
type TokenIssuer interface {
	Exchange(ctx context.Context, presented secrets.Redacted, now time.Time) (*auth.Issued, error)
}

// exchangeRequest carries the refresh token to rotate. Its single field is the
// secret, and the strict decoder's DisallowUnknownFields refuses any companion
// field -- there is nothing else a caller may assert here.
type exchangeRequest struct {
	RefreshToken string `json:"refresh_token"`
}

// exchangeHandler rotates a refresh token for a fresh credential pair.
//
// It is a credential-minting endpoint on the unauthenticated edge, so it carries
// the full AUTH-tier pattern keyed by client IP: Check before the service call,
// RecordFailure on a genuine rejection, RecordSuccess on a correct rotation.
// This is the sibling of redeemHandler; the two share the IP key space so a
// campaign that sprays one is throttled on the other.
func exchangeHandler(svc TokenIssuer, lim *ratelimit.AuthLimiter, proxies trustedPeers, now func() time.Time, logger *slog.Logger) http.Handler {
	if now == nil {
		now = time.Now
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if svc == nil || lim == nil {
			writeTokenMisconfigured(w, r, logger)
			return
		}
		// The key is resolved once and reused for Check and Record.
		key := clientIP(r, proxies)
		if !authPrecheck(w, r, lim, key, logger) {
			return
		}
		var body exchangeRequest
		if err := decodeStrictJSON(w, r, &body, maxEnrollRequestBody); err != nil {
			// A malformed body is a 400 and is NOT counted: it is not a credential
			// guess and must not climb the backoff curve.
			writeTokenStatus(w, http.StatusBadRequest)
			return
		}
		issued, err := svc.Exchange(r.Context(), secrets.NewRedacted(body.RefreshToken), now())
		if err != nil {
			recordAuthFailure(r, lim, key, logger)
			// Uniform 401: an unknown, expired, revoked, or already-rotated token
			// is one answer. A replayed token additionally revokes its lineage
			// inside Exchange, but the wire response is identical either way, so a
			// replayer cannot tell a live lineage it just burned from a dead one.
			writeTokenStatus(w, http.StatusUnauthorized)
			return
		}
		recordAuthSuccess(r, lim, key, logger)
		writeJSON(w, http.StatusOK, toIssuedResponse(*issued))
	})
}

// writeTokenMisconfigured answers a request that reached the handler with no
// service (or no limiter) behind it. A wiring fault is a 500, never a 404, for
// the same reason as the enrollment surface.
func writeTokenMisconfigured(w http.ResponseWriter, r *http.Request, logger *slog.Logger) {
	if logger != nil {
		logger.LogAttrs(r.Context(), slog.LevelError, "token handler misconfigured",
			slog.String("request_id", RequestIDFromContext(r.Context())),
			slog.String("error", ErrNilTokenService.Error()))
	}
	writeTokenStatus(w, http.StatusInternalServerError)
}

// writeTokenStatus writes the uniform error body.
func writeTokenStatus(w http.ResponseWriter, status int) {
	writeJSON(w, status, statusResponse{Status: "error"})
}
