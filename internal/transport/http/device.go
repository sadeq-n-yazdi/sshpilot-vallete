package httpserver

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/auth"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/service/device"
)

// DeviceService is the device management dependency, declared at the point of
// use so the transport depends on a method set rather than a concrete service
// type. *device.Service satisfies it.
//
// Note what every method takes first: a domain.OwnerID. There is no method here
// that finds its own owner, so a handler must supply one, and the only owner a
// protected handler holds is the one the Guardian handed it.
type DeviceService interface {
	Register(ctx context.Context, ownerID domain.OwnerID, name, requestID string) (*domain.Device, error)
	List(ctx context.Context, ownerID domain.OwnerID) ([]domain.Device, error)
	Revoke(ctx context.Context, ownerID domain.OwnerID, id domain.DeviceID, requestID string) error
}

// devicePathValue is the wildcard segment naming a device in the route
// patterns. It is a constant so the AccessFunc and the handler cannot read
// different segments -- a mismatch there would authorize one device and act on
// another, which is the sharpest bug this surface can have.
const devicePathValue = "deviceID"

// maxDeviceRequestBody bounds the JSON this endpoint will read.
//
// The body is read after authorization, so this is not an anonymous-DoS
// control; it is a bound on what an authenticated but hostile client can make
// one request allocate. A device registration is a short name and nothing else.
const maxDeviceRequestBody = 4 << 10

// registerDeviceRequest is the body of a device registration. It carries a name
// and deliberately nothing else -- in particular no owner. Adding an owner
// field here would be the single change that turns the owner boundary into a
// client-supplied value, so its absence is the control.
type registerDeviceRequest struct {
	Name string `json:"name"`
}

// deviceResponse is the wire form of a device.
//
// OwnerID is absent. It would be redundant -- a caller can only ever see its
// own devices -- and echoing it back would invite a client to start sending it,
// which is the shape the previous type exists to prevent.
type deviceResponse struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	Status    string     `json:"status"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
}

// listDevicesResponse wraps the collection in an object rather than returning a
// bare JSON array, so the response can gain fields later without breaking
// clients.
type listDevicesResponse struct {
	Devices []deviceResponse `json:"devices"`
}

// DeviceAccess is the AccessFunc for the routes that address one device.
//
// It names the device from the path so that a single-device token is confined
// to the device it was issued for: auth.Guard compares this ResourceID against
// the token's bound scope and refuses a mismatch before any handler runs and
// before any storage is touched. It does NOT name an owner -- the management
// API takes the owner from the token (ADR-0004) -- so there is no request field
// here that authorization could be made to believe.
//
// An empty segment is an error rather than an unbound Access. Returning
// auth.Access{} for a missing id would produce an account-wide check, which a
// resource-bound token passes -- silently widening a route meant to address one
// device into one that addresses none.
func DeviceAccess(r *http.Request) (auth.Access, error) {
	id := r.PathValue(devicePathValue)
	if id == "" {
		return auth.Access{}, domain.ErrInvalidInput
	}
	return auth.Access{Resource: auth.ResourceDevice, ResourceID: id}, nil
}

// registerDeviceHandler creates a device for the token's owner.
func registerDeviceHandler(svc DeviceService, logger *slog.Logger) ScopedHandler {
	return func(w http.ResponseWriter, r *http.Request, a *auth.Authorization) {
		if svc == nil {
			writeDeviceMisconfigured(w, r, logger)
			return
		}

		var body registerDeviceRequest
		if err := decodeDeviceJSON(w, r, &body); err != nil {
			// The decode failure text is not returned. It can quote the bytes
			// that failed to parse, and a client that can see its own input
			// echoed learns nothing useful while a shared log gains a copy.
			writeDeviceStatus(w, http.StatusBadRequest)
			return
		}

		// a.Owner() is the only owner in this function, and it comes from the
		// verified token. Nothing from r reaches the owner argument.
		d, err := svc.Register(r.Context(), a.Owner(), body.Name, RequestIDFromContext(r.Context()))
		if err != nil {
			writeDeviceError(w, r, logger, err, "device registration failed")
			return
		}

		// The name is not logged. It is owner-identifying free text, and the
		// request log is neither access-controlled nor retention-governed the
		// way the audit record that DOES carry it is.
		logger.LogAttrs(r.Context(), slog.LevelInfo, "device registered",
			slog.String("request_id", RequestIDFromContext(r.Context())),
			slog.String("device_id", string(d.ID)),
		)
		writeJSON(w, http.StatusCreated, toDeviceResponse(*d))
	}
}

// listDevicesHandler returns the token owner's devices.
func listDevicesHandler(svc DeviceService, logger *slog.Logger) ScopedHandler {
	return func(w http.ResponseWriter, r *http.Request, a *auth.Authorization) {
		if svc == nil {
			writeDeviceMisconfigured(w, r, logger)
			return
		}

		devices, err := svc.List(r.Context(), a.Owner())
		if err != nil {
			writeDeviceError(w, r, logger, err, "device list failed")
			return
		}

		// A nil slice would marshal to null; an empty list is an empty array,
		// so a client need not special-case "no devices yet".
		out := make([]deviceResponse, 0, len(devices))
		for _, d := range devices {
			out = append(out, toDeviceResponse(d))
		}
		writeJSON(w, http.StatusOK, listDevicesResponse{Devices: out})
	}
}

// revokeDeviceHandler revokes one of the token owner's devices.
//
// It answers 204 only for the transition from active to revoked. Every other
// outcome -- unknown id, another owner's id, already revoked -- is the service's
// single ErrNotFound and becomes one 404 written by one line, so the three
// cannot drift into distinguishable responses.
func revokeDeviceHandler(svc DeviceService, logger *slog.Logger) ScopedHandler {
	return func(w http.ResponseWriter, r *http.Request, a *auth.Authorization) {
		if svc == nil {
			writeDeviceMisconfigured(w, r, logger)
			return
		}

		// The id is read from the path, through the same devicePathValue
		// constant DeviceAccess uses. That shared constant is what keeps the
		// authorized device and the acted-on device the same one: if they could
		// diverge, this handler would mutate a device the scope check never
		// approved while the scope check passed honestly -- the confused-deputy
		// shape.
		//
		// This is a convention, not an enforced invariant. Nothing structurally
		// prevents a future edit here from taking the id from a header or a
		// query parameter instead, and mutation testing confirms it: mutants
		// that inject a new steering channel survive, because no test can
		// exercise a channel it does not know the name of. Reviewers of this
		// handler should treat "where does the id come from?" as the question
		// that matters.
		id := domain.DeviceID(r.PathValue(devicePathValue))
		if err := svc.Revoke(r.Context(), a.Owner(), id, RequestIDFromContext(r.Context())); err != nil {
			writeDeviceError(w, r, logger, err, "device revocation failed")
			return
		}

		logger.LogAttrs(r.Context(), slog.LevelInfo, "device revoked",
			slog.String("request_id", RequestIDFromContext(r.Context())),
			slog.String("device_id", string(id)),
		)
		w.WriteHeader(http.StatusNoContent)
	}
}

// decodeDeviceJSON reads a bounded, strict JSON body.
//
// DisallowUnknownFields is what makes the absence of an owner field in
// registerDeviceRequest enforceable rather than decorative: a client that sends
// {"name":"x","owner_id":"victim"} is refused outright instead of having the
// extra field silently dropped, so a request that tried to assert an owner
// never looks like it succeeded.
func decodeDeviceJSON(w http.ResponseWriter, r *http.Request, into any) error {
	return decodeStrictJSON(w, r, into, maxDeviceRequestBody)
}

// decodeStrictJSON is the shared strict-decode used by every management
// handler. It is one function rather than one per slice so a new endpoint
// cannot acquire a laxer body policy by writing its own: the byte bound is the
// only thing a caller chooses.
func decodeStrictJSON(w http.ResponseWriter, r *http.Request, into any, limit int64) error {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, limit))
	dec.DisallowUnknownFields()
	if err := dec.Decode(into); err != nil {
		return err
	}
	// A second JSON value in the same body is refused. Accepting it would mean
	// the request the server acted on is not the whole request the client sent,
	// which is the request-smuggling shape at the body layer.
	if dec.More() {
		return errors.New("httpserver: trailing data after JSON body")
	}
	return nil
}

// writeDeviceError maps a service error to a response.
//
// device.ErrNotFound -> 404, identical for a device that never existed, one
// that belongs to another owner, and one already revoked. The service has
// already collapsed those into one error; this function's job is not to undo
// that, which is why there is exactly one branch for all three and no place to
// add a fourth.
//
// domain.ErrInvalidInput -> 400. It is reachable only from a caller's own
// request content (a malformed device name), never from a lookup, so it reports
// on nothing but what the caller just sent.
//
// Everything else -> 500 with the reason logged and never returned.
func writeDeviceError(w http.ResponseWriter, r *http.Request, logger *slog.Logger, err error, msg string) {
	switch {
	case errors.Is(err, device.ErrNotFound):
		writeDeviceStatus(w, http.StatusNotFound)
	case errors.Is(err, domain.ErrInvalidInput):
		writeDeviceStatus(w, http.StatusBadRequest)
	default:
		logger.LogAttrs(r.Context(), slog.LevelError, msg,
			slog.String("request_id", RequestIDFromContext(r.Context())),
			slog.String("error", err.Error()),
		)
		writeDeviceStatus(w, http.StatusInternalServerError)
	}
}

// writeDeviceMisconfigured answers a request that reached a handler with no
// service behind it. A wiring fault is a 500, never a 404: degrading into "not
// found" would be indistinguishable from a genuine miss and would hide a broken
// deployment behind a plausible answer.
func writeDeviceMisconfigured(w http.ResponseWriter, r *http.Request, logger *slog.Logger) {
	logger.LogAttrs(r.Context(), slog.LevelError, "device handler misconfigured",
		slog.String("request_id", RequestIDFromContext(r.Context())),
		slog.String("error", ErrNilDeviceService.Error()),
	)
	writeDeviceStatus(w, http.StatusInternalServerError)
}

// writeDeviceStatus writes the uniform error body. It is the same shape the
// Guardian's refusals use, so a 404 from an unauthorized caller and a 404 from
// an authorized one addressing a stranger's device are byte-identical.
func writeDeviceStatus(w http.ResponseWriter, status int) {
	writeJSON(w, status, statusResponse{Status: "error"})
}

// toDeviceResponse converts a domain device to its wire form.
func toDeviceResponse(d domain.Device) deviceResponse {
	return deviceResponse{
		ID:        string(d.ID),
		Name:      d.Name,
		Status:    string(d.Status),
		CreatedAt: d.CreatedAt,
		UpdatedAt: d.UpdatedAt,
		RevokedAt: d.RevokedAt,
	}
}
