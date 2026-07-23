package httpserver

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/auth"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/ratelimit"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/secrets"
)

// EnrollmentService is the enrollment dependency, declared at the point of use
// so the transport depends on a method set rather than the concrete
// *auth.EnrollmentService. It covers ADR-0018 modes 1 (device-authorization
// grant: start -> approve -> poll -> redeem) and 2 (manual mint -> redeem);
// mode 3 (interactive/OIDC) is deferred by ADR-0032 and has no method here.
//
// Note which methods take an owner and which do not. StartDeviceGrant, Poll and
// Redeem take none: the caller has not authenticated as anybody, and the pairing
// is unusable until an owner approves it. Mint and Approve take an owner, and
// the only owner a guarded handler holds is the one the Guardian handed it
// (ADR-0004) -- nothing from the request body reaches those arguments.
type EnrollmentService interface {
	StartDeviceGrant(ctx context.Context, clientLabel string, scopes []domain.Scope) (*auth.Grant, error)
	Mint(ctx context.Context, ownerID domain.OwnerID, clientLabel string, scopes []domain.Scope) (*auth.Grant, error)
	Approve(ctx context.Context, ownerID domain.OwnerID, userCode string) error
	Poll(ctx context.Context, deviceCode secrets.Redacted) error
	Redeem(ctx context.Context, deviceCode secrets.Redacted) (*auth.Issued, error)
}

// maxEnrollRequestBody bounds the JSON an enrollment endpoint will read.
//
// The un-guarded endpoints read this BEFORE any credential is verified, so it is
// an anonymous-DoS control, not merely a bound on an authenticated client: a
// device grant carries a short label and a handful of scopes and nothing else.
const maxEnrollRequestBody = 8 << 10

// wireScope is the JSON form of a domain.Scope, used in both directions. The
// field names are the domain's own kind/resource-id vocabulary so the wire
// contract cannot drift from the model it serializes.
type wireScope struct {
	Kind       string `json:"kind"`
	ResourceID string `json:"resource_id,omitempty"`
}

// startDeviceGrantRequest / mintRequest carry a client label and the scopes the
// pairing asks for. They deliberately carry no owner: on the mint path the owner
// is the verified token's, and on the start path there is no owner yet. An owner
// field here would be the single change that turned the owner boundary into a
// client-supplied value, so its absence -- enforced by the strict decoder's
// DisallowUnknownFields -- is the control.
type startDeviceGrantRequest struct {
	ClientLabel string      `json:"client_label"`
	Scopes      []wireScope `json:"scopes"`
}

type mintRequest struct {
	ClientLabel string      `json:"client_label"`
	Scopes      []wireScope `json:"scopes"`
}

// approveRequest carries the short user code the owner transcribed. pollRequest
// and redeemRequest carry the 256-bit device code the pairing client holds.
type approveRequest struct {
	UserCode string `json:"user_code"`
}

type pollRequest struct {
	DeviceCode string `json:"device_code"`
}

type redeemRequest struct {
	DeviceCode string `json:"device_code"`
}

// grantResponse is the one-time disclosure of a pairing's codes. It is a
// purpose-built struct rather than an embedding of auth.Grant: Grant.MarshalJSON
// emits [REDACTED] for its secret fields, so embedding it would silently ship
// the marker in place of the code. Each secret is instead revealed explicitly in
// toGrantResponse, at the single point disclosure is intended.
type grantResponse struct {
	PairingID           string    `json:"pairing_id"`
	DeviceCode          string    `json:"device_code"`
	UserCode            string    `json:"user_code,omitempty"`
	ExpiresAt           time.Time `json:"expires_at"`
	PollIntervalSeconds int64     `json:"poll_interval_seconds"`
}

// issuedResponse is the one-time disclosure of a freshly issued credential pair,
// built the same deliberate way as grantResponse and for the same reason.
type issuedResponse struct {
	RefreshToken     string      `json:"refresh_token"`
	RefreshExpiresAt time.Time   `json:"refresh_expires_at"`
	AccessToken      string      `json:"access_token"`
	AccessExpiresAt  time.Time   `json:"access_expires_at"`
	OwnerID          string      `json:"owner_id"`
	Scopes           []wireScope `json:"scopes"`
}

// startDeviceGrantHandler opens a pending pairing for an unauthenticated client.
func startDeviceGrantHandler(svc EnrollmentService, lim *ratelimit.AuthLimiter, proxies trustedPeers, logger *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if svc == nil || lim == nil {
			writeEnrollMisconfigured(w, r, logger)
			return
		}
		// Check only. A device-grant start presents no credential, so there is
		// nothing to count as a failed guess -- but an IP already locked out for
		// spraying redeem must not be able to open fresh pairings from here
		// either, so it shares the IP key space. RecordFailure is deliberately
		// absent: a successful start is not a failure, and counting it would
		// climb an honest new client up the backoff curve.
		if !authPrecheck(w, r, lim, clientIP(r, proxies), logger) {
			return
		}
		var body startDeviceGrantRequest
		if err := decodeEnrollJSON(w, r, &body); err != nil {
			// The decode error is not returned: it can quote the bytes that
			// failed to parse, which tells a client nothing useful and hands a
			// shared log a copy.
			writeEnrollStatus(w, http.StatusBadRequest)
			return
		}
		grant, err := svc.StartDeviceGrant(r.Context(), body.ClientLabel, toDomainScopes(body.Scopes))
		if err != nil {
			writeEnrollError(w, r, logger, err, "device grant start failed")
			return
		}
		writeJSON(w, http.StatusCreated, toGrantResponse(*grant))
	})
}

// pollHandler reports whether a pairing has been approved yet.
//
// It preserves the service's three-way answer -- approved / pending / refused --
// because the caller has already presented the pairing's own 256-bit device
// code, so telling it "keep waiting" from "give up" reveals nothing it does not
// already hold, and a device-authorization client cannot function without the
// distinction (ADR-0032, ADR-0018 errPollPending rationale).
func pollHandler(svc EnrollmentService, lim *ratelimit.AuthLimiter, proxies trustedPeers, logger *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if svc == nil || lim == nil {
			writeEnrollMisconfigured(w, r, logger)
			return
		}
		// Check only, keyed by IP: the device code is 256-bit (no guessing
		// oracle) and the service already throttles poll cadence per code, and a
		// "polled too soon" outcome is indistinguishable here from "wrong code",
		// so RecordFailure would penalize an honest but eager client. The Check
		// still applies the shared IP lockout earned on the minting endpoints.
		if !authPrecheck(w, r, lim, clientIP(r, proxies), logger) {
			return
		}
		var body pollRequest
		if err := decodeEnrollJSON(w, r, &body); err != nil {
			writeEnrollStatus(w, http.StatusBadRequest)
			return
		}
		err := svc.Poll(r.Context(), secrets.NewRedacted(body.DeviceCode))
		switch {
		case err == nil:
			writeJSON(w, http.StatusOK, statusResponse{Status: "approved"})
		case auth.PollPending(err):
			writeJSON(w, http.StatusAccepted, statusResponse{Status: "pending"})
		default:
			// ErrAuthFailed collapses unknown/expired/revoked/too-soon into one
			// answer; the transport keeps it one answer.
			writeEnrollStatus(w, http.StatusUnauthorized)
		}
	})
}

// redeemHandler exchanges an approved device code for the first credential pair.
//
// This is a credential-minting endpoint, so it carries the full AUTH-tier
// pattern keyed by client IP: Check before the service call, RecordFailure on a
// genuine rejection so a guessing campaign climbs the backoff curve, and
// RecordSuccess to clear the count after a correct redemption.
func redeemHandler(svc EnrollmentService, lim *ratelimit.AuthLimiter, proxies trustedPeers, logger *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if svc == nil || lim == nil {
			writeEnrollMisconfigured(w, r, logger)
			return
		}
		// The key is resolved once and reused for Check and Record, so the count
		// a failure lands on is the same bucket the check consulted.
		key := clientIP(r, proxies)
		if !authPrecheck(w, r, lim, key, logger) {
			return
		}
		var body redeemRequest
		if err := decodeEnrollJSON(w, r, &body); err != nil {
			// A malformed body is a 400 and is NOT counted: it is not a credential
			// guess, so it must not climb the backoff curve.
			writeEnrollStatus(w, http.StatusBadRequest)
			return
		}
		issued, err := svc.Redeem(r.Context(), secrets.NewRedacted(body.DeviceCode))
		if err != nil {
			recordAuthFailure(r, lim, key, logger)
			// Uniform 401: an unknown, expired, unapproved, or already-redeemed
			// code is one answer, so a redeemer learns nothing about which.
			writeEnrollStatus(w, http.StatusUnauthorized)
			return
		}
		recordAuthSuccess(r, lim, key, logger)
		writeJSON(w, http.StatusOK, toIssuedResponse(*issued))
	})
}

// mintHandler mints an already-approved pairing for the token's owner (mode 2).
//
// It carries no AUTH-tier limiter of its own: it verifies no guessable secret --
// the owner is authenticated by the Guardian and the mint IS the approval -- and
// it already runs behind the management tier's per-credential limit. Adding a
// failure counter here would meter a legitimate provisioning action as if it
// were a guess.
func mintHandler(svc EnrollmentService, logger *slog.Logger) ScopedHandler {
	return func(w http.ResponseWriter, r *http.Request, a *auth.Authorization) {
		if svc == nil {
			writeEnrollMisconfigured(w, r, logger)
			return
		}
		var body mintRequest
		if err := decodeEnrollJSON(w, r, &body); err != nil {
			writeEnrollStatus(w, http.StatusBadRequest)
			return
		}
		// a.Owner() is the only owner in this function and comes from the verified
		// token; nothing from r reaches it.
		grant, err := svc.Mint(r.Context(), a.Owner(), body.ClientLabel, toDomainScopes(body.Scopes))
		if err != nil {
			writeEnrollError(w, r, logger, err, "credential mint failed")
			return
		}
		writeJSON(w, http.StatusCreated, toGrantResponse(*grant))
	}
}

// approveHandler binds a pending pairing to the token's owner on the strength of
// a transcribed user code.
//
// The AUTH tier here is keyed by the VERIFIED OWNER, not the client IP. The user
// code is the ~40-bit secret this surface must protect, and owner-keying bounds
// guessing independently of IP rotation and behind an authenticated identity. It
// is a distinct key space from the service's own per-owner approval cap
// (checkApprovalLimit): the service enforces a flat attempt ceiling per pairing
// lifetime, and this adds exponential backoff over it -- inner flat cap, outer
// backoff, documented so the two responsibilities do not read as duplication.
func approveHandler(svc EnrollmentService, lim *ratelimit.AuthLimiter, logger *slog.Logger) ScopedHandler {
	return func(w http.ResponseWriter, r *http.Request, a *auth.Authorization) {
		if svc == nil || lim == nil {
			writeEnrollMisconfigured(w, r, logger)
			return
		}
		key := string(a.Owner())
		if !authPrecheck(w, r, lim, key, logger) {
			return
		}
		var body approveRequest
		if err := decodeEnrollJSON(w, r, &body); err != nil {
			writeEnrollStatus(w, http.StatusBadRequest)
			return
		}
		if err := svc.Approve(r.Context(), a.Owner(), body.UserCode); err != nil {
			recordAuthFailure(r, lim, key, logger)
			// Uniform 403: unknown code, expired pairing, already-approved, and
			// exhausted budget are one answer, so an owner guessing another
			// pairing's code cannot confirm a hit. The bearer already passed the
			// Guardian, so this is a 403 (the action is refused) rather than a 401
			// (which would wrongly invite a token refresh).
			writeEnrollStatus(w, http.StatusForbidden)
			return
		}
		recordAuthSuccess(r, lim, key, logger)
		w.WriteHeader(http.StatusNoContent)
	}
}

// recordAuthFailure and recordAuthSuccess drive the failure counter after a
// credential check, logging a store error without changing the response.
//
// They are kept as one call each at the handler so removing a RecordFailure is a
// single, visible edit that a negative test kills -- the outcome coupling is the
// whole point of the AUTH tier, so it lives where the outcome is known.
func recordAuthFailure(r *http.Request, lim *ratelimit.AuthLimiter, key string, logger *slog.Logger) {
	if _, err := lim.RecordFailure(r.Context(), key); err != nil {
		logAuthRecordErr(r, logger, err, "recording an auth failure")
	}
}

func recordAuthSuccess(r *http.Request, lim *ratelimit.AuthLimiter, key string, logger *slog.Logger) {
	if err := lim.RecordSuccess(r.Context(), key); err != nil {
		logAuthRecordErr(r, logger, err, "clearing the auth failure count")
	}
}

func logAuthRecordErr(r *http.Request, logger *slog.Logger, err error, what string) {
	if logger == nil {
		return
	}
	// The key is not logged, for the same reason authPrecheck does not log it.
	logger.LogAttrs(r.Context(), slog.LevelError, "auth rate limit: "+what,
		slog.String("request_id", RequestIDFromContext(r.Context())),
		slog.String("error", err.Error()))
}

// decodeEnrollJSON reads a bounded, strict JSON body, sharing the one strict
// decoder every management handler uses so an enrollment endpoint cannot acquire
// a laxer body policy.
func decodeEnrollJSON(w http.ResponseWriter, r *http.Request, into any) error {
	return decodeStrictJSON(w, r, into, maxEnrollRequestBody)
}

// toDomainScopes converts the wire scopes to domain scopes without validating
// them: the service's ValidateScopes is the single validation boundary, and
// duplicating its rules here would be a second place for them to drift. A nil
// input stays nil so the service sees exactly what the client sent.
func toDomainScopes(in []wireScope) []domain.Scope {
	if in == nil {
		return nil
	}
	out := make([]domain.Scope, 0, len(in))
	for _, s := range in {
		out = append(out, domain.Scope{Kind: domain.ScopeKind(s.Kind), ResourceID: s.ResourceID})
	}
	return out
}

func fromDomainScopes(in []domain.Scope) []wireScope {
	out := make([]wireScope, 0, len(in))
	for _, s := range in {
		out = append(out, wireScope{Kind: string(s.Kind), ResourceID: s.ResourceID})
	}
	return out
}

// toGrantResponse reveals a grant's secrets at the single intended disclosure
// point. UserCode is empty for a mint and omitted from the JSON.
func toGrantResponse(g auth.Grant) grantResponse {
	return grantResponse{
		PairingID:           string(g.PairingID),
		DeviceCode:          g.DeviceCode.Reveal(),
		UserCode:            g.UserCode.Reveal(),
		ExpiresAt:           g.ExpiresAt,
		PollIntervalSeconds: int64(g.PollInterval / time.Second),
	}
}

// toIssuedResponse reveals a credential pair's tokens at the single intended
// disclosure point.
func toIssuedResponse(i auth.Issued) issuedResponse {
	return issuedResponse{
		RefreshToken:     i.RefreshToken.Reveal(),
		RefreshExpiresAt: i.RefreshExpiresAt,
		AccessToken:      i.AccessToken.Reveal(),
		AccessExpiresAt:  i.AccessExpiresAt,
		OwnerID:          string(i.OwnerID),
		Scopes:           fromDomainScopes(i.Scopes),
	}
}

// writeEnrollError maps a service error from the non-credential paths (start,
// mint) to a response. The credential paths do not use it: they map the service's
// bare ErrAuthFailed to a single uniform status inline, so there is no branch
// here that could grow a second, distinguishable answer for a rejected code.
//
// domain.ErrInvalidInput -> 400: it reports only on the caller's own request
// content (a bad scope or label). Everything else -> 500, logged and never
// returned.
func writeEnrollError(w http.ResponseWriter, r *http.Request, logger *slog.Logger, err error, msg string) {
	switch {
	case errors.Is(err, domain.ErrInvalidInput):
		writeEnrollStatus(w, http.StatusBadRequest)
	default:
		if logger != nil {
			logger.LogAttrs(r.Context(), slog.LevelError, msg,
				slog.String("request_id", RequestIDFromContext(r.Context())),
				slog.String("error", err.Error()))
		}
		writeEnrollStatus(w, http.StatusInternalServerError)
	}
}

// writeEnrollMisconfigured answers a request that reached a handler with no
// service (or no limiter) behind it. A wiring fault is a 500, never a 404:
// degrading into "not found" would be indistinguishable from a genuine miss and
// would hide a broken deployment behind a plausible answer.
func writeEnrollMisconfigured(w http.ResponseWriter, r *http.Request, logger *slog.Logger) {
	if logger != nil {
		logger.LogAttrs(r.Context(), slog.LevelError, "enrollment handler misconfigured",
			slog.String("request_id", RequestIDFromContext(r.Context())),
			slog.String("error", ErrNilEnrollmentService.Error()))
	}
	writeEnrollStatus(w, http.StatusInternalServerError)
}

// writeEnrollStatus writes the uniform error body, the same shape every other
// refusal on the server uses.
func writeEnrollStatus(w http.ResponseWriter, status int) {
	writeJSON(w, status, statusResponse{Status: "error"})
}
