package httpserver

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/auth"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/service/publickey"
)

// PublicKeyService is the key management dependency, declared at the point of
// use so the transport depends on a method set rather than a concrete service
// type. *publickey.Service satisfies it.
//
// Note what every method takes first: a domain.OwnerID. There is no method here
// that finds its own owner, so a handler must supply one, and the only owner a
// protected handler holds is the one the Guardian handed it.
type PublicKeyService interface {
	Add(ctx context.Context, ownerID domain.OwnerID, deviceID domain.DeviceID, raw []byte, requestID string) (*domain.PublicKey, error)
	List(ctx context.Context, ownerID domain.OwnerID) ([]domain.PublicKey, error)
	Revoke(ctx context.Context, ownerID domain.OwnerID, id domain.PublicKeyID, requestID string) error
}

// keyPathValue is the wildcard segment naming a key in the route pattern. It is
// a constant so nothing can read a different segment than the handler acts on.
const keyPathValue = "keyID"

// maxKeyRequestBody bounds the JSON this endpoint will read.
//
// It is sized from keys.MaxLineBytes (16 KiB, the largest submission the ingest
// layer will consider) plus room for the JSON envelope and escaping, so a key
// the parser would accept is never truncated into a parse error by the
// transport. The body is read after authorization, so this is not an
// anonymous-DoS control; it is a bound on what an authenticated but hostile
// client can make one request allocate.
const maxKeyRequestBody = 64 << 10

// addKeyRequest is the body of a key enrollment.
//
// PublicKey is the submission verbatim: a single authorized_keys-style line.
// The server does not accept a pre-parsed algorithm, blob, or fingerprint,
// because doing so would let a client assert facts about a key that the ingest
// layer is supposed to derive — and a client-asserted fingerprint is a
// client-asserted identity for the key.
//
// There is no owner field, and its absence is the control (see the device
// slice): with DisallowUnknownFields below, a request that tries to assert one
// is refused rather than silently stripped.
type addKeyRequest struct {
	DeviceID  string `json:"device_id"`
	PublicKey string `json:"public_key"`
}

// publicKeyResponse is the wire form of a public key.
//
// OwnerID is absent, for the reason the device slice gives: a caller can only
// ever see its own keys, so it would be redundant, and echoing it back invites
// a client to start sending it.
//
// The key BLOB is absent too, and that is a separate decision. The fingerprint
// identifies a key unambiguously and is what an owner recognizes it by; the
// blob is the material the publish path exists to serve, and there is no
// management question it answers that the fingerprint does not. Keeping it out
// means this response cannot become a second, authenticated distribution
// channel for key material that ADR-0006 requires be reconstructed canonically.
type publicKeyResponse struct {
	ID          string     `json:"id"`
	DeviceID    string     `json:"device_id"`
	Algorithm   string     `json:"algorithm"`
	Comment     string     `json:"comment"`
	Fingerprint string     `json:"fingerprint"`
	BitLen      int        `json:"bit_len"`
	Status      string     `json:"status"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
	RevokedAt   *time.Time `json:"revoked_at,omitempty"`
}

// keyRejectedResponse is the body of a 400 from the ingest layer. It is the
// only error body in this package that carries a reason, and it is a distinct
// type rather than a field added to the shared statusResponse so that no other
// error site can start populating one by accident.
//
// Carrying a reason is safe here and nowhere else: this status is reached only
// from internal/keys, whose sentinels are fixed strings that never reflect
// input, and it reports on the submission the caller just made rather than on
// anything the system holds. It is also necessary — the private-key refusal's
// message exists to tell a user to submit the .pub file instead, and a bare 400
// would leave someone who pasted the wrong file with no idea why.
type keyRejectedResponse struct {
	Status string `json:"status"`
	Reason string `json:"reason"`
}

// listKeysResponse wraps the collection in an object rather than returning a
// bare JSON array, so the response can gain fields later without breaking
// clients.
type listKeysResponse struct {
	Keys []publicKeyResponse `json:"keys"`
}

// addKeyHandler enrolls a public key for the token's owner.
//
// The route it is mounted on declares AccountAccess: a key names no resource
// the authorization model knows about (auth.ResourceKind has kinds for key sets
// and devices only), so this addresses the account. That is the conservative
// reading, not a gap — a resource-bound token is refused here, and a read-only
// token is refused by the Mutating check the Guardian derives from the method.
func addKeyHandler(svc PublicKeyService, logger *slog.Logger) ScopedHandler {
	return func(w http.ResponseWriter, r *http.Request, a *auth.Authorization) {
		if svc == nil {
			writeKeyMisconfigured(w, r, logger)
			return
		}

		var body addKeyRequest
		if err := decodeKeyJSON(w, r, &body); err != nil {
			// The decode failure text is not returned, and here that is not
			// merely tidy: a JSON error can quote the bytes it choked on, and
			// the field it would be quoting is the one a user pastes a private
			// key into by mistake. Returning it would echo that material back
			// and, worse, invite it into a log.
			writeKeyStatus(w, http.StatusBadRequest)
			return
		}

		// a.Owner() is the only owner in this function, and it comes from the
		// verified token. Nothing from r reaches the owner argument.
		k, err := svc.Add(r.Context(), a.Owner(), domain.DeviceID(body.DeviceID),
			[]byte(body.PublicKey), RequestIDFromContext(r.Context()))
		if err != nil {
			writeKeyError(w, r, logger, err, "public key enrollment failed")
			return
		}

		// The submission is not logged, and neither is the comment. The key id
		// and fingerprint are enough to correlate this line with the audit
		// record that carries the rest, and the request log is neither
		// access-controlled nor retention-governed the way that record is.
		logger.LogAttrs(r.Context(), slog.LevelInfo, "public key added",
			slog.String("request_id", RequestIDFromContext(r.Context())),
			slog.String("key_id", string(k.ID)),
		)
		writeJSON(w, http.StatusCreated, toPublicKeyResponse(*k))
	}
}

// listKeysHandler returns the token owner's public keys.
func listKeysHandler(svc PublicKeyService, logger *slog.Logger) ScopedHandler {
	return func(w http.ResponseWriter, r *http.Request, a *auth.Authorization) {
		if svc == nil {
			writeKeyMisconfigured(w, r, logger)
			return
		}

		found, err := svc.List(r.Context(), a.Owner())
		if err != nil {
			writeKeyError(w, r, logger, err, "public key list failed")
			return
		}

		// The service passes the repository's nil-for-empty slice through
		// untouched; the wire form is decided here, and it is an empty array so
		// a client need not special-case "no keys yet". A nil slice would
		// marshal to null.
		out := make([]publicKeyResponse, 0, len(found))
		for _, k := range found {
			out = append(out, toPublicKeyResponse(k))
		}
		writeJSON(w, http.StatusOK, listKeysResponse{Keys: out})
	}
}

// revokeKeyHandler revokes one of the token owner's public keys.
//
// It answers 204 only for the transition from active to revoked. Every other
// outcome -- unknown id, another owner's id, already revoked -- is the service's
// single ErrNotFound and becomes one 404 written by one line, so the three
// cannot drift into distinguishable responses.
func revokeKeyHandler(svc PublicKeyService, logger *slog.Logger) ScopedHandler {
	return func(w http.ResponseWriter, r *http.Request, a *auth.Authorization) {
		if svc == nil {
			writeKeyMisconfigured(w, r, logger)
			return
		}

		// The id comes from the path and from nowhere else. As on the device
		// route, this is a convention rather than an enforced invariant, and
		// "where does the id come from?" is the question a reviewer of this
		// handler should ask first -- a future edit that took it from a header
		// or a query parameter would still pass every test here.
		id := domain.PublicKeyID(r.PathValue(keyPathValue))
		if err := svc.Revoke(r.Context(), a.Owner(), id, RequestIDFromContext(r.Context())); err != nil {
			writeKeyError(w, r, logger, err, "public key revocation failed")
			return
		}

		logger.LogAttrs(r.Context(), slog.LevelInfo, "public key revoked",
			slog.String("request_id", RequestIDFromContext(r.Context())),
			slog.String("key_id", string(id)),
		)
		w.WriteHeader(http.StatusNoContent)
	}
}

// decodeKeyJSON reads a bounded, strict JSON body.
//
// It mirrors decodeDeviceJSON and differs only in the byte bound, which must
// accommodate a full-size key line. DisallowUnknownFields is what makes the
// absence of an owner field in addKeyRequest enforceable rather than
// decorative.
func decodeKeyJSON(w http.ResponseWriter, r *http.Request, into any) error {
	return decodeStrictJSON(w, r, into, maxKeyRequestBody)
}

// writeKeyError maps a service error to a response.
//
// publickey.ErrNotFound -> 404, identical for a key that never existed, one
// that belongs to another owner, one already revoked, and a device on Add that
// is any of those three. The service has already collapsed them into one error;
// this function's job is not to undo that.
//
// publickey.ErrDuplicate -> 409. It reports only on a key the caller already
// owns, so it is safe to distinguish; see the sentinel's own documentation.
//
// domain.ErrInvalidInput -> 400. Every rejection from the ingest layer arrives
// here, including the private-key refusal, and this branch deliberately does
// NOT log err.Error(). That is the load-bearing property of this switch: the
// keys package's sentinels are fixed strings, but routing an ingest failure
// into the default branch below would put a key-submission error into the
// request log, and a change to the ingest layer that ever made an error carry
// input would then leak it. The rejection reason IS returned to the caller,
// because it is a statement about the bytes that caller just sent -- and only
// those bytes -- and it is what lets a client fix its request.
//
// Everything else -> 500 with the reason logged and never returned.
func writeKeyError(w http.ResponseWriter, r *http.Request, logger *slog.Logger, err error, msg string) {
	switch {
	// Matched on the DOMAIN sentinel rather than publickey.ErrNotFound, which
	// wraps it. Both are caught either way, and an unmapped domain.ErrNotFound
	// reaching here answers 404 instead of falling through to 500. That
	// fallthrough was the real hazard: this surface answers a uniform 404 so a
	// stranger's row is indistinguishable from a missing one, and a 500 on one
	// of those paths would be the difference an observer needs.
	case errors.Is(err, domain.ErrNotFound):
		writeKeyStatus(w, http.StatusNotFound)
	case errors.Is(err, publickey.ErrDuplicate):
		writeKeyStatus(w, http.StatusConflict)
	case errors.Is(err, domain.ErrInvalidInput):
		writeJSON(w, http.StatusBadRequest, keyRejectedResponse{Status: "error", Reason: err.Error()})
	default:
		logger.LogAttrs(r.Context(), slog.LevelError, msg,
			slog.String("request_id", RequestIDFromContext(r.Context())),
			slog.String("error", err.Error()),
		)
		writeKeyStatus(w, http.StatusInternalServerError)
	}
}

// writeKeyMisconfigured answers a request that reached a handler with no
// service behind it. A wiring fault is a 500, never a 404: degrading into "not
// found" would be indistinguishable from a genuine miss and would hide a broken
// deployment behind a plausible answer.
func writeKeyMisconfigured(w http.ResponseWriter, r *http.Request, logger *slog.Logger) {
	logger.LogAttrs(r.Context(), slog.LevelError, "public key handler misconfigured",
		slog.String("request_id", RequestIDFromContext(r.Context())),
		slog.String("error", ErrNilPublicKeyService.Error()),
	)
	writeKeyStatus(w, http.StatusInternalServerError)
}

// writeKeyStatus writes the uniform error body. It is the same shape the
// Guardian's refusals use, so a 404 from an unauthorized caller and a 404 from
// an authorized one addressing a stranger's key are byte-identical.
func writeKeyStatus(w http.ResponseWriter, status int) {
	writeJSON(w, status, statusResponse{Status: "error"})
}

// toPublicKeyResponse converts a domain public key to its wire form.
func toPublicKeyResponse(k domain.PublicKey) publicKeyResponse {
	return publicKeyResponse{
		ID:          string(k.ID),
		DeviceID:    string(k.DeviceID),
		Algorithm:   string(k.Algorithm),
		Comment:     k.Comment,
		Fingerprint: k.Fingerprint,
		BitLen:      k.BitLen,
		Status:      string(k.Status),
		CreatedAt:   k.CreatedAt,
		UpdatedAt:   k.UpdatedAt,
		RevokedAt:   k.RevokedAt,
	}
}
