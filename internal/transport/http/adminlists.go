package httpserver

import (
	"context"
	"errors"
	"log/slog"
	"net/http"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
)

// ListAdminService is the reserved-identifier list editing dependency, declared
// at the point of use so the transport depends on a method set rather than the
// concrete *listadmin.Service.
//
// Every edit takes the acting administrator first, exactly as every key set
// method takes an owner first. The handler does not authorize; it hands the
// identity it extracted to this service, which authorizes, audits, and persists
// before the edit takes effect (ADR-0017, ADR-0007). Passing an empty
// AdministratorID is the fail-closed default: the service refuses it.
type ListAdminService interface {
	AddAllowlistEntry(ctx context.Context, actor domain.AdministratorID, entry string) error
	RemoveAllowlistEntry(ctx context.Context, actor domain.AdministratorID, entry string) error
	AddBlocklistTerm(ctx context.Context, actor domain.AdministratorID, entry string) error
	RemoveBlocklistTerm(ctx context.Context, actor domain.AdministratorID, entry string) error
}

// AdminIdentifier resolves the administrator a request is authenticated as, or
// the empty ID when it carries no valid admin identity.
//
// It is a seam, not an authenticator: how an administrator proves who they are
// is a separate security decision with its own ADR (there is no admin token
// scheme in this codebase yet), so the transport takes the answer through this
// interface rather than inventing one. The contract is deliberately minimal --
// return the authenticated ID or empty -- and the empty return is the whole
// fail-closed story: ListAdminService refuses an empty actor, so a deployment
// that has not wired a real identifier refuses every edit rather than applying
// one on nobody's authority.
type AdminIdentifier interface {
	AdministratorID(r *http.Request) domain.AdministratorID
}

// denyAllAdminIdentifier is the fail-closed stand-in used when no
// AdminIdentifier was supplied. It authenticates nobody, so every admin edit is
// attributed to the empty ID and refused by the service. It mirrors
// denyAllAuthorizer on the owner surface.
type denyAllAdminIdentifier struct{}

// AdministratorID always returns the empty ID: with no identifier wired, no
// request is the act of any administrator.
func (denyAllAdminIdentifier) AdministratorID(*http.Request) domain.AdministratorID { return "" }

// maxAdminEntryBody bounds the JSON an admin edit will read. An entry is at most
// blocklist.MaxInputBytes (256), so this is generous and exists only to bound
// what one request can make the server allocate before the service rejects an
// over-length entry.
const maxAdminEntryBody = 4 << 10

// adminEntryRequest is the body of every list edit: the single entry to add or
// remove, in the administrator's own spelling. A skeleton is never sent or
// stored as the decided value.
type adminEntryRequest struct {
	Entry string `json:"entry"`
}

// adminListEdit is the shared body of all four edit handlers. Having exactly
// one means the decode, the identity extraction, the delegation order, and the
// error mapping cannot drift between add and remove or between the two lists.
//
// The order is decode, then delegate. Authorization is NOT performed here: the
// service authorizes, and doing it twice -- once here, once there -- would be
// two places to keep in agreement, which is the drift ADR-0017 concentrates the
// decision to avoid. The identity extracted is handed straight through; an empty
// one is refused by the service, which is why a missing AdminIdentifier fails
// closed rather than open.
func adminListEdit(
	svc ListAdminService, id AdminIdentifier, logger *slog.Logger, action string,
	edit func(context.Context, domain.AdministratorID, string) error,
) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if svc == nil {
			writeAdminListMisconfigured(w, r, logger)
			return
		}
		// A nil identifier is a caller contract violation (NewHandler coerces it
		// to denyAllAdminIdentifier). Coerce it again here rather than trusting
		// that: an authorization path must never depend on a value nobody
		// promised, and calling AdministratorID on a nil interface would panic.
		// The stand-in resolves the empty ID, so the request takes the SAME
		// uniform refusal an unknown administrator gets -- no new status, no
		// enumeration oracle.
		if id == nil {
			id = denyAllAdminIdentifier{}
		}

		var body adminEntryRequest
		if err := decodeStrictJSON(w, r, &body, maxAdminEntryBody); err != nil {
			// The decode error text can quote the bytes that failed to parse, so
			// it is logged, never returned.
			writeAdminListStatus(w, http.StatusBadRequest)
			return
		}

		actor := id.AdministratorID(r)
		if err := edit(r.Context(), actor, body.Entry); err != nil {
			writeAdminListError(w, r, logger, err, "reserved-identifier list edit failed")
			return
		}

		// The entry is not echoed. It is the administrator's own input and the
		// audit log already holds it; a 204 says the edit was applied and adds
		// nothing an attacker could read.
		logger.LogAttrs(r.Context(), slog.LevelInfo, "reserved-identifier list edited",
			slog.String("request_id", RequestIDFromContext(r.Context())),
			slog.String("action", action),
		)
		w.WriteHeader(http.StatusNoContent)
	})
}

// addAllowlistEntryHandler exempts an entry from the blocklist.
func addAllowlistEntryHandler(svc ListAdminService, id AdminIdentifier, logger *slog.Logger) http.Handler {
	edit := func(ctx context.Context, actor domain.AdministratorID, entry string) error {
		return svc.AddAllowlistEntry(ctx, actor, entry)
	}
	return adminListEdit(svc, id, logger, "allowlist_add", edit)
}

// removeAllowlistEntryHandler withdraws an exemption.
func removeAllowlistEntryHandler(svc ListAdminService, id AdminIdentifier, logger *slog.Logger) http.Handler {
	edit := func(ctx context.Context, actor domain.AdministratorID, entry string) error {
		return svc.RemoveAllowlistEntry(ctx, actor, entry)
	}
	return adminListEdit(svc, id, logger, "allowlist_remove", edit)
}

// addBlocklistTermHandler adds an administrator-chosen reserved term.
func addBlocklistTermHandler(svc ListAdminService, id AdminIdentifier, logger *slog.Logger) http.Handler {
	edit := func(ctx context.Context, actor domain.AdministratorID, entry string) error {
		return svc.AddBlocklistTerm(ctx, actor, entry)
	}
	return adminListEdit(svc, id, logger, "blocklist_add", edit)
}

// removeBlocklistTermHandler withdraws an administrator-added term.
func removeBlocklistTermHandler(svc ListAdminService, id AdminIdentifier, logger *slog.Logger) http.Handler {
	edit := func(ctx context.Context, actor domain.AdministratorID, entry string) error {
		return svc.RemoveBlocklistTerm(ctx, actor, entry)
	}
	return adminListEdit(svc, id, logger, "blocklist_remove", edit)
}

// writeAdminListError maps a service error to a response.
//
// # Authorization refusals render identically
//
// domain.ErrUnauthorized (no or unknown administrator) and domain.ErrForbidden
// (a disabled one) both answer 403 with the same body. This is listadmin's
// BOUNDARY OBLIGATION, not a stylistic choice: distinguishing them would let an
// unauthenticated caller tell "no such administrator" from "disabled
// administrator" and enumerate which admin IDs exist. One status, one body.
//
// # The rest report only on the caller's own request
//
// ErrInvalidInput -> 400 (a malformed entry), ErrConflict -> 409 (an entry
// already present), ErrNotFound -> 404 (an entry not present). None of these is
// reachable by an unauthenticated caller: the service authorizes before it ever
// computes the next set, so a 409 or 404 is only ever seen by an administrator
// who could read the same fact from the list. None carries the error text, so
// nothing here can echo which curated term a name resembled.
func writeAdminListError(w http.ResponseWriter, r *http.Request, logger *slog.Logger, err error, msg string) {
	switch {
	case errors.Is(err, domain.ErrUnauthorized), errors.Is(err, domain.ErrForbidden):
		writeAdminListStatus(w, http.StatusForbidden)
	case errors.Is(err, domain.ErrInvalidInput):
		writeAdminListStatus(w, http.StatusBadRequest)
	case errors.Is(err, domain.ErrConflict):
		writeAdminListStatus(w, http.StatusConflict)
	case errors.Is(err, domain.ErrNotFound):
		writeAdminListStatus(w, http.StatusNotFound)
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		// The caller has gone away, so nothing reads the status; it is left 500
		// and logged at Info rather than Error, the same posture the key set
		// surface takes for a client that hung up.
		logger.LogAttrs(r.Context(), slog.LevelInfo, msg,
			slog.String("request_id", RequestIDFromContext(r.Context())),
			slog.String("error", err.Error()),
		)
		writeAdminListStatus(w, http.StatusInternalServerError)
	default:
		logger.LogAttrs(r.Context(), slog.LevelError, msg,
			slog.String("request_id", RequestIDFromContext(r.Context())),
			slog.String("error", err.Error()),
		)
		writeAdminListStatus(w, http.StatusInternalServerError)
	}
}

// writeAdminListMisconfigured answers a request that reached a handler with no
// service behind it. A wiring fault is a 500, never a refusal that reads as
// "denied": degrading it would hide a broken deployment behind a plausible
// answer, exactly as the key set surface refuses to do.
func writeAdminListMisconfigured(w http.ResponseWriter, r *http.Request, logger *slog.Logger) {
	logger.LogAttrs(r.Context(), slog.LevelError, "reserved-identifier list handler misconfigured",
		slog.String("request_id", RequestIDFromContext(r.Context())),
		slog.String("error", ErrNilListAdminService.Error()),
	)
	writeAdminListStatus(w, http.StatusInternalServerError)
}

// writeAdminListStatus writes the uniform error body. It carries no diagnostics
// for the same reason the health and key set surfaces carry none: the detail is
// in the log, and the response reflects nothing about the request.
func writeAdminListStatus(w http.ResponseWriter, status int) {
	writeJSON(w, status, statusResponse{Status: "error"})
}
