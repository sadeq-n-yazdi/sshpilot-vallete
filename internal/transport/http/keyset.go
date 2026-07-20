package httpserver

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/auth"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/service/keyset"
)

// KeySetService is the key set management dependency, declared at the point of
// use so the transport depends on a method set rather than a concrete service
// type. *keyset.Service satisfies it.
//
// Note what every method takes first: a domain.OwnerID. There is no method here
// that finds its own owner, so a handler must supply one, and the only owner a
// protected handler holds is the one the Guardian handed it.
type KeySetService interface {
	Create(ctx context.Context, ownerID domain.OwnerID, name, requestID string) (*domain.KeySet, error)
	List(ctx context.Context, ownerID domain.OwnerID) ([]domain.KeySet, error)
	Rename(ctx context.Context, ownerID domain.OwnerID, id domain.KeySetID, name, requestID string) (*domain.KeySet, error)
	Delete(ctx context.Context, ownerID domain.OwnerID, id domain.KeySetID, confirm bool, requestID string) error
	SetDefault(ctx context.Context, ownerID domain.OwnerID, id domain.KeySetID, requestID string) (*domain.KeySet, error)
	SetVisibility(ctx context.Context, ownerID domain.OwnerID, id domain.KeySetID, v domain.Visibility, requestID string) (*domain.KeySet, error)
}

// keySetPathValue is the wildcard segment naming a key set in the route
// pattern. It is a constant so KeySetAccess cannot read a different segment
// than the handler acts on — the confused-deputy shape the device slice names.
const keySetPathValue = "keySetID"

// maxKeySetRequestBody bounds the JSON these endpoints will read. A set name is
// at most 64 bytes, so this is generous by three orders of magnitude and exists
// only to bound what an authenticated but hostile client can make one request
// allocate.
const maxKeySetRequestBody = 4 << 10

// createKeySetRequest is the body of a key set creation.
//
// Name is the only field. There is deliberately no visibility and no
// is_default: both are C4's decisions with their own endpoints, and accepting
// them here would let a create smuggle in a publish-visibility change that no
// separate authorization step ever saw. With DisallowUnknownFields, a request
// that sends either is refused rather than silently stripped — which is also
// what makes the absence of an owner field a control rather than a convention.
type createKeySetRequest struct {
	Name string `json:"name"`
}

// renameKeySetRequest is the body of a rename. Name is the destination name;
// the source is the set addressed by the path.
type renameKeySetRequest struct {
	Name string `json:"name"`
}

// deleteKeySetRequest is the body of a delete.
//
// Confirm is the explicit acknowledgement ADR-0016 requires before a NON-EMPTY
// set is removed. It is a required positive assertion, and every way of not
// making it refuses: an absent body, an absent field, false, and a body that
// will not decode all leave confirm false, and the service then refuses the
// delete of a non-empty set. There is no shape of malformed request that
// deletes more than a well-formed one would.
type deleteKeySetRequest struct {
	Confirm bool `json:"confirm"`
}

// setVisibilityRequest is the body of a visibility change.
//
// Visibility is a required positive assertion, and every way of not making it
// refuses. An absent body, an absent field, an empty string, and a value
// outside the closed {public, protected} set all fail domain.Visibility.IsValid
// in the service and are answered 400; a body that will not decode, or that
// carries an unrecognized field, is refused here. The zero value is not a
// visibility, so there is no shape of malformed request that publishes a set —
// the same fail-closed shape the delete confirmation uses.
type setVisibilityRequest struct {
	Visibility string `json:"visibility"`
}

// keySetResponse is the wire form of a key set.
//
// OwnerID is absent, for the reason the device and key slices give: a caller
// can only ever see its own sets, so it would be redundant, and echoing it back
// invites a client to start sending it.
//
// State is absent too. Only live sets are ever returned — the service filters
// quarantined tombstones out of List and collapses them into 404 everywhere
// else — so the field would be the constant "active" on every response it could
// appear in.
type keySetResponse struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	Visibility string    `json:"visibility"`
	IsDefault  bool      `json:"is_default"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// listKeySetsResponse wraps the collection in an object rather than returning a
// bare JSON array, so the response can gain fields later without breaking
// clients.
type listKeySetsResponse struct {
	KeySets []keySetResponse `json:"key_sets"`
}

// Conflict reasons. Each is a fixed constant chosen by the server from this
// closed set; none is derived from, or contains any part of, the request.
//
// Returning a reason is safe on a 409 and nowhere else. Every one of these is
// reached only after an owner-scoped read or write has already matched a row of
// the CALLER'S OWN — a stranger's set id produces the reasonless 404 below long
// before any of them — so each reports a fact the caller can already read out of
// its own List. The 404 carries no reason at all, which is what keeps it
// byte-identical to the Guardian's refusal.
const (
	reasonNameTaken            = "name_taken"
	reasonLimitReached         = "limit_reached"
	reasonDefaultSet           = "default_set"
	reasonConfirmationRequired = "confirmation_required"
)

// keySetConflictResponse is the body of a 409. It is a distinct type rather
// than a field added to the shared statusResponse so that no other error site
// can start populating a reason by accident.
type keySetConflictResponse struct {
	Status string `json:"status"`
	Reason string `json:"reason"`
}

// KeySetAccess is the AccessFunc for the routes that address one key set.
//
// It names the set from the path so that a set-bound token is confined to the
// set it was issued for: auth.Guard compares this ResourceID against the
// token's bound scope and refuses a mismatch before any handler runs and before
// any storage is touched. It does NOT name an owner — the management API takes
// the owner from the token (ADR-0004) — so there is no request field here that
// authorization could be made to believe.
//
// This is where the key set routes diverge from the public key routes, and the
// divergence is the point. Those declare AccountAccess on every route because
// auth.ResourceKind has no kind for a key, so there is no resource-bound scope
// they could be checked against. Key sets DO have auth.ResourceKeySet, so
// declaring AccountAccess here would silently let a set-bound token reach every
// one of the owner's sets.
//
// An empty segment is an error rather than an unbound Access. Returning
// auth.Access{} for a missing id would produce an account-wide check, which a
// resource-bound token passes — widening a route meant to address one set into
// one that addresses none.
func KeySetAccess(r *http.Request) (auth.Access, error) {
	id := r.PathValue(keySetPathValue)
	if id == "" {
		return auth.Access{}, domain.ErrInvalidInput
	}
	return auth.Access{Resource: auth.ResourceKeySet, ResourceID: id}, nil
}

// createKeySetHandler creates a key set for the token's owner.
//
// The route it is mounted on declares AccountAccess: a create names no existing
// set, so it addresses the account. A set-bound token is therefore refused here,
// which is correct — a token scoped to one set must not be able to mint another.
func createKeySetHandler(svc KeySetService, logger *slog.Logger) ScopedHandler {
	return func(w http.ResponseWriter, r *http.Request, a *auth.Authorization) {
		if svc == nil {
			writeKeySetMisconfigured(w, r, logger)
			return
		}

		var body createKeySetRequest
		if err := decodeKeySetJSON(w, r, &body); err != nil {
			// The decode failure text is not returned. It can quote the bytes
			// that failed to parse, and a client that can see its own input
			// echoed learns nothing useful while a shared log gains a copy.
			writeKeySetStatus(w, http.StatusBadRequest)
			return
		}

		// a.Owner() is the only owner in this function, and it comes from the
		// verified token. Nothing from r reaches the owner argument.
		set, err := svc.Create(r.Context(), a.Owner(), body.Name, RequestIDFromContext(r.Context()))
		if err != nil {
			writeKeySetError(w, r, logger, err, "key set creation failed")
			return
		}

		logger.LogAttrs(r.Context(), slog.LevelInfo, "key set created",
			slog.String("request_id", RequestIDFromContext(r.Context())),
			slog.String("key_set_id", string(set.ID)),
		)
		writeJSON(w, http.StatusCreated, toKeySetResponse(*set))
	}
}

// listKeySetsHandler returns the token owner's live key sets.
func listKeySetsHandler(svc KeySetService, logger *slog.Logger) ScopedHandler {
	return func(w http.ResponseWriter, r *http.Request, a *auth.Authorization) {
		if svc == nil {
			writeKeySetMisconfigured(w, r, logger)
			return
		}

		found, err := svc.List(r.Context(), a.Owner())
		if err != nil {
			writeKeySetError(w, r, logger, err, "key set list failed")
			return
		}

		// The service passes the repository's nil-for-empty slice through
		// untouched; the wire form is decided here, and it is an empty array so
		// a client need not special-case "no sets yet". A nil slice would
		// marshal to null.
		out := make([]keySetResponse, 0, len(found))
		for _, set := range found {
			out = append(out, toKeySetResponse(set))
		}
		writeJSON(w, http.StatusOK, listKeySetsResponse{KeySets: out})
	}
}

// renameKeySetHandler renames one of the token owner's key sets.
//
// The response carries a NEW id. A key_sets row's name is immutable, so a
// rename is a new row plus a quarantined tombstone holding the freed name; see
// the service. A client holding the old id must re-read the set, and will get
// the same 404 a stranger's id gets if it does not.
func renameKeySetHandler(svc KeySetService, logger *slog.Logger) ScopedHandler {
	return func(w http.ResponseWriter, r *http.Request, a *auth.Authorization) {
		if svc == nil {
			writeKeySetMisconfigured(w, r, logger)
			return
		}

		var body renameKeySetRequest
		if err := decodeKeySetJSON(w, r, &body); err != nil {
			writeKeySetStatus(w, http.StatusBadRequest)
			return
		}

		// The id comes from the path and from nowhere else, read through the
		// same keySetPathValue constant KeySetAccess uses. That shared constant
		// is what keeps the authorized set and the acted-on set the same one: if
		// they could diverge, this handler would mutate a set the scope check
		// never approved while the scope check passed honestly.
		id := domain.KeySetID(r.PathValue(keySetPathValue))
		set, err := svc.Rename(r.Context(), a.Owner(), id, body.Name, RequestIDFromContext(r.Context()))
		if err != nil {
			writeKeySetError(w, r, logger, err, "key set rename failed")
			return
		}

		// The names are not logged. They are recorded in the audit log, which is
		// access-controlled and retention-governed; the request log is neither.
		logger.LogAttrs(r.Context(), slog.LevelInfo, "key set renamed",
			slog.String("request_id", RequestIDFromContext(r.Context())),
			slog.String("key_set_id", string(set.ID)),
		)
		writeJSON(w, http.StatusOK, toKeySetResponse(*set))
	}
}

// deleteKeySetHandler deletes one of the token owner's key sets.
//
// A body is optional; when present it must decode strictly. An absent body
// leaves confirm false, which is the fail-closed default: a non-empty set is
// then refused rather than removed.
func deleteKeySetHandler(svc KeySetService, logger *slog.Logger) ScopedHandler {
	return func(w http.ResponseWriter, r *http.Request, a *auth.Authorization) {
		if svc == nil {
			writeKeySetMisconfigured(w, r, logger)
			return
		}

		var body deleteKeySetRequest
		if err := decodeKeySetJSON(w, r, &body); err != nil && !errors.Is(err, io.EOF) {
			// Only a completely absent body is tolerated. A body that is
			// present but malformed is refused outright rather than read as "no
			// confirmation": a caller whose confirmation failed to parse must
			// not be told its delete was declined for a different reason, and
			// tolerating garbage here is how a future edit that defaults the
			// flag to true would go unnoticed.
			writeKeySetStatus(w, http.StatusBadRequest)
			return
		}

		id := domain.KeySetID(r.PathValue(keySetPathValue))
		if err := svc.Delete(r.Context(), a.Owner(), id, body.Confirm, RequestIDFromContext(r.Context())); err != nil {
			writeKeySetError(w, r, logger, err, "key set deletion failed")
			return
		}

		logger.LogAttrs(r.Context(), slog.LevelInfo, "key set deleted",
			slog.String("request_id", RequestIDFromContext(r.Context())),
			slog.String("key_set_id", string(id)),
		)
		w.WriteHeader(http.StatusNoContent)
	}
}

// setDefaultKeySetHandler designates one of the token owner's sets as the
// default that bare GET /{handle} resolves to.
//
// The route it is mounted on declares AccountAccess, NOT KeySetAccess, and the
// divergence from rename and delete is the security decision on this handler.
// Designating a default writes the PREVIOUS default's row as well — the
// repository clears is_default on it in the same transaction — so a set-bound
// token reaching this route would mutate a set it was never scoped to. It also
// repoints the account's bare handle, which is account-wide state rather than
// anything belonging to the addressed set. A token confined to one set must be
// able to do neither, so this route addresses the account and a resource-bound
// token is refused before the handler runs.
//
// There is no request body. The set is named by the path, and the operation has
// no other input, so there is no field a client could send that this handler
// would have to decide whether to trust.
func setDefaultKeySetHandler(svc KeySetService, logger *slog.Logger) ScopedHandler {
	return func(w http.ResponseWriter, r *http.Request, a *auth.Authorization) {
		if svc == nil {
			writeKeySetMisconfigured(w, r, logger)
			return
		}

		// Read through the same keySetPathValue constant the access functions
		// use, so the authorized set and the acted-on set cannot diverge.
		id := domain.KeySetID(r.PathValue(keySetPathValue))
		set, err := svc.SetDefault(r.Context(), a.Owner(), id, RequestIDFromContext(r.Context()))
		if err != nil {
			writeKeySetError(w, r, logger, err, "key set default designation failed")
			return
		}

		logger.LogAttrs(r.Context(), slog.LevelInfo, "key set default changed",
			slog.String("request_id", RequestIDFromContext(r.Context())),
			slog.String("key_set_id", string(set.ID)),
		)
		writeJSON(w, http.StatusOK, toKeySetResponse(*set))
	}
}

// setVisibilityKeySetHandler moves one of the token owner's sets between public
// and protected.
//
// This one DOES declare KeySetAccess, unlike the default designation above. The
// repository's Update is scoped to the addressed row and touches nothing else,
// so the blast radius is exactly the set the token names — the same shape
// rename has, and the reason a set-bound token may perform it.
//
// The value is validated by the service against the closed domain.Visibility
// set, not here. A second place that decides which visibilities exist is a
// second place that can be made to disagree with the first.
func setVisibilityKeySetHandler(svc KeySetService, logger *slog.Logger) ScopedHandler {
	return func(w http.ResponseWriter, r *http.Request, a *auth.Authorization) {
		if svc == nil {
			writeKeySetMisconfigured(w, r, logger)
			return
		}

		// The body is required, and an absent one is an error rather than a
		// tolerated empty request: unlike the delete confirmation, there is no
		// safe default visibility this handler could fall back to — protected
		// would silently narrow and public would silently publish.
		var body setVisibilityRequest
		if err := decodeKeySetJSON(w, r, &body); err != nil {
			writeKeySetStatus(w, http.StatusBadRequest)
			return
		}

		id := domain.KeySetID(r.PathValue(keySetPathValue))
		set, err := svc.SetVisibility(r.Context(), a.Owner(), id,
			domain.Visibility(body.Visibility), RequestIDFromContext(r.Context()))
		if err != nil {
			writeKeySetError(w, r, logger, err, "key set visibility change failed")
			return
		}

		logger.LogAttrs(r.Context(), slog.LevelInfo, "key set visibility changed",
			slog.String("request_id", RequestIDFromContext(r.Context())),
			slog.String("key_set_id", string(set.ID)),
			slog.String("visibility", string(set.Visibility)),
		)
		writeJSON(w, http.StatusOK, toKeySetResponse(*set))
	}
}

// decodeKeySetJSON reads a bounded, strict JSON body. It mirrors
// decodeDeviceJSON and decodeKeyJSON and differs only in the byte bound.
func decodeKeySetJSON(w http.ResponseWriter, r *http.Request, into any) error {
	return decodeStrictJSON(w, r, into, maxKeySetRequestBody)
}

// writeKeySetError maps a service error to a response.
//
// keyset.ErrNotFound -> 404, identical for a set that never existed, one that
// belongs to another owner, and a quarantined tombstone. The service has
// already collapsed them into one error; this function's job is not to undo
// that, which is why there is exactly one branch for all three and no place to
// add a fourth. It carries no reason.
//
// The four conflicts -> 409 with a fixed reason. Each is safe to distinguish;
// see the reason constants for why.
//
// domain.ErrInvalidInput and domain.ErrBlockedName -> 400. Both are reachable
// only from a caller's own request content — a malformed or blocked set name —
// never from a lookup, so they report on nothing but what the caller just sent.
// Neither returns the error text: a blocked name's message is deliberately
// vague (nameguard never renders which curated term fired) and there is no
// reason for the transport to widen it.
//
// Everything else -> 500 with the reason logged and never returned.
func writeKeySetError(w http.ResponseWriter, r *http.Request, logger *slog.Logger, err error, msg string) {
	switch {
	case errors.Is(err, keyset.ErrNotFound):
		writeKeySetStatus(w, http.StatusNotFound)
	case errors.Is(err, keyset.ErrDuplicate):
		writeKeySetConflict(w, reasonNameTaken)
	case errors.Is(err, keyset.ErrLimitExceeded):
		writeKeySetConflict(w, reasonLimitReached)
	case errors.Is(err, keyset.ErrDefaultSet):
		writeKeySetConflict(w, reasonDefaultSet)
	case errors.Is(err, keyset.ErrConfirmationRequired):
		writeKeySetConflict(w, reasonConfirmationRequired)
	case errors.Is(err, domain.ErrBlockedName), errors.Is(err, domain.ErrInvalidInput):
		writeKeySetStatus(w, http.StatusBadRequest)
	default:
		logger.LogAttrs(r.Context(), slog.LevelError, msg,
			slog.String("request_id", RequestIDFromContext(r.Context())),
			slog.String("error", err.Error()),
		)
		writeKeySetStatus(w, http.StatusInternalServerError)
	}
}

// writeKeySetMisconfigured answers a request that reached a handler with no
// service behind it. A wiring fault is a 500, never a 404: degrading into "not
// found" would be indistinguishable from a genuine miss and would hide a broken
// deployment behind a plausible answer.
func writeKeySetMisconfigured(w http.ResponseWriter, r *http.Request, logger *slog.Logger) {
	logger.LogAttrs(r.Context(), slog.LevelError, "key set handler misconfigured",
		slog.String("request_id", RequestIDFromContext(r.Context())),
		slog.String("error", ErrNilKeySetService.Error()),
	)
	writeKeySetStatus(w, http.StatusInternalServerError)
}

// writeKeySetStatus writes the uniform, reasonless error body. It is the same
// shape the Guardian's refusals use, so a 404 from an unauthorized caller and a
// 404 from an authorized one addressing a stranger's set are byte-identical.
func writeKeySetStatus(w http.ResponseWriter, status int) {
	writeJSON(w, status, statusResponse{Status: "error"})
}

// writeKeySetConflict writes a 409 carrying one of the fixed reason constants.
// It takes a reason rather than a status so this is the only function in the
// package that can produce a body with a reason field, and it can only produce
// it at 409.
func writeKeySetConflict(w http.ResponseWriter, reason string) {
	writeJSON(w, http.StatusConflict, keySetConflictResponse{Status: "error", Reason: reason})
}

// toKeySetResponse converts a domain key set to its wire form.
func toKeySetResponse(set domain.KeySet) keySetResponse {
	return keySetResponse{
		ID:         string(set.ID),
		Name:       set.Name,
		Visibility: string(set.Visibility),
		IsDefault:  set.IsDefault,
		CreatedAt:  set.CreatedAt,
		UpdatedAt:  set.UpdatedAt,
	}
}
