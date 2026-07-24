package httpserver

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/service/onboarding"
)

// OwnerOnboardingService provisions a new owner on an administrator's authority
// and returns a one-time enrollment credential the owner redeems to bootstrap
// their own tokens. It is declared at the point of use so the transport depends
// on a method set rather than the concrete *onboarding.Service.
//
// The provision takes the acting administrator first, exactly as every admin
// list edit does. The handler does not authorize; it hands the identity it
// extracted to this service, which authorizes (active administrator required),
// audits, and persists before the owner is created (ADR-0033, ADR-0031,
// ADR-0007). An empty AdministratorID is the fail-closed default: the service
// refuses it.
type OwnerOnboardingService interface {
	ProvisionOwner(ctx context.Context, actor domain.AdministratorID, req onboarding.Request) (onboarding.Result, error)
}

// maxOwnerProvisionBody bounds the JSON the provision handler will read. The
// body carries a handle, an optional set name, and an optional client label,
// all short identifiers, so this is generous and exists only to bound what one
// request can make the server allocate before the service rejects an
// over-length name.
const maxOwnerProvisionBody = 4 << 10

// ownerProvisionRequest is the body of a provision request: the handle to claim
// and, optionally, the default set name and a label for the minted credential.
type ownerProvisionRequest struct {
	Handle      string `json:"handle"`
	SetName     string `json:"set_name,omitempty"`
	ClientLabel string `json:"client_label,omitempty"`
}

// ownerProvisionResponse reports what was provisioned and reveals the one-time
// enrollment code. This struct is the single disclosure point for the code:
// the service carries it as a secrets.Redacted so it cannot land in a log by
// accident, and it is turned back into a plain string exactly here, in the
// response body the administrator asked for.
type ownerProvisionResponse struct {
	OwnerID        string    `json:"owner_id"`
	Handle         string    `json:"handle"`
	SetName        string    `json:"set_name"`
	EnrollmentCode string    `json:"enrollment_code"`
	ExpiresAt      time.Time `json:"expires_at"`
	PairingID      string    `json:"pairing_id"`
}

// adminCreateOwnerHandler provisions an owner on an administrator's authority.
//
// The order is rate-limit, decode, delegate. Authorization is NOT performed
// here: the service authorizes the extracted identity, and doing it twice would
// be two places to keep in agreement. The identity is handed straight through;
// an empty one is refused by the service, which is why a missing AdminIdentifier
// fails closed rather than open. The rate limiter runs first and is keyed by the
// resolved administrator, so a refused caller costs nothing past the counter.
func adminCreateOwnerHandler(svc OwnerOnboardingService, id AdminIdentifier, logger *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if svc == nil {
			writeOwnerProvisionMisconfigured(w, r, logger)
			return
		}
		// A nil identifier is a caller contract violation (NewHandler coerces it
		// to denyAllAdminIdentifier). Coerce it again here rather than trusting
		// that: an authorization path must never depend on a value nobody
		// promised, and calling AdministratorID on a nil interface would panic.
		if id == nil {
			id = denyAllAdminIdentifier{}
		}

		var body ownerProvisionRequest
		if err := decodeStrictJSON(w, r, &body, maxOwnerProvisionBody); err != nil {
			// The decode error text can quote the bytes that failed to parse, so
			// it is logged by decodeStrictJSON, never returned.
			writeAdminListStatus(w, http.StatusBadRequest)
			return
		}

		actor := id.AdministratorID(r)
		res, err := svc.ProvisionOwner(r.Context(), actor, onboarding.Request{
			Handle:      body.Handle,
			SetName:     body.SetName,
			ClientLabel: body.ClientLabel,
		})
		if err != nil {
			writeOwnerProvisionError(w, r, logger, err)
			return
		}

		// The audit log already holds the owner id and handle; the log line
		// carries only the request id and never the enrollment code, which is a
		// credential and appears solely in the response body below.
		logger.LogAttrs(r.Context(), slog.LevelInfo, "owner provisioned",
			slog.String("request_id", RequestIDFromContext(r.Context())),
			slog.String("owner_id", string(res.OwnerID)),
		)
		writeJSON(w, http.StatusCreated, ownerProvisionResponse{
			OwnerID:        string(res.OwnerID),
			Handle:         res.Handle,
			SetName:        res.SetName,
			EnrollmentCode: res.EnrollmentCode.Reveal(),
			ExpiresAt:      res.ExpiresAt,
			PairingID:      string(res.PairingID),
		})
	})
}

// writeOwnerProvisionError maps a service error to a response.
//
// # Authorization refusals render identically
//
// domain.ErrUnauthorized (no or unknown administrator) and domain.ErrForbidden
// (a disabled one) both answer 403 with the same body, the same BOUNDARY
// OBLIGATION the admin list surface takes: distinguishing them would let a
// caller tell "no such administrator" from "disabled administrator" and
// enumerate admin IDs.
//
// # The rest report only on the caller's own request
//
// ErrInvalidInput and ErrBlockedName both -> 400 (a malformed or reserved
// name), rendered the same so nothing reveals WHICH rule fired -- a curated
// blocklist hit must not be distinguishable from a syntax error. ErrConflict ->
// 409 (the handle is taken). None carries the error text, so nothing here can
// echo which term a name resembled or which bytes failed to parse.
func writeOwnerProvisionError(w http.ResponseWriter, r *http.Request, logger *slog.Logger, err error) {
	switch {
	case errors.Is(err, domain.ErrUnauthorized), errors.Is(err, domain.ErrForbidden):
		writeAdminListStatus(w, http.StatusForbidden)
	case errors.Is(err, domain.ErrInvalidInput), errors.Is(err, domain.ErrBlockedName):
		writeAdminListStatus(w, http.StatusBadRequest)
	case errors.Is(err, domain.ErrConflict):
		writeAdminListStatus(w, http.StatusConflict)
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		// The caller has gone away, so nothing reads the status; it is left 500
		// and logged at Info, the posture the other admin surfaces take for a
		// client that hung up.
		logger.LogAttrs(r.Context(), slog.LevelInfo, "owner provisioning failed",
			slog.String("request_id", RequestIDFromContext(r.Context())),
			slog.String("error", err.Error()),
		)
		writeAdminListStatus(w, http.StatusInternalServerError)
	default:
		logger.LogAttrs(r.Context(), slog.LevelError, "owner provisioning failed",
			slog.String("request_id", RequestIDFromContext(r.Context())),
			slog.String("error", err.Error()),
		)
		writeAdminListStatus(w, http.StatusInternalServerError)
	}
}

// writeOwnerProvisionMisconfigured answers a request that reached the handler
// with no service behind it. A wiring fault is a 500, never a refusal that reads
// as "denied": degrading it would hide a broken deployment behind a plausible
// answer.
func writeOwnerProvisionMisconfigured(w http.ResponseWriter, r *http.Request, logger *slog.Logger) {
	logger.LogAttrs(r.Context(), slog.LevelError, "owner onboarding handler misconfigured",
		slog.String("request_id", RequestIDFromContext(r.Context())),
		slog.String("error", ErrNilOwnerOnboardingService.Error()),
	)
	writeAdminListStatus(w, http.StatusInternalServerError)
}
