package httpserver

import (
	"context"
	"log/slog"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/auth"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/secrets"
)

// handlerOptions are the optional dependencies of the route table: the
// authenticated management surface, which an embedder serving only the publish
// path does not need.
type handlerOptions struct {
	authorizer Authorizer
	devices    DeviceService
}

// HandlerOption configures NewHandler.
type HandlerOption func(*handlerOptions)

// WithAuthorizer supplies the authorization dependency for the management
// routes. Without it those routes are mounted behind a Guardian that refuses
// everything; see managementGuardian for why that is the failure mode rather
// than leaving them unmounted.
func WithAuthorizer(a Authorizer) HandlerOption {
	return func(o *handlerOptions) { o.authorizer = a }
}

// WithDeviceService supplies the device management service.
func WithDeviceService(s DeviceService) HandlerOption {
	return func(o *handlerOptions) { o.devices = s }
}

// managementGuardian builds the Guardian for the management routes.
//
// # Why the routes are mounted even with no Authorizer
//
// The alternative -- registering them only when an Authorizer is supplied --
// makes the route table's shape depend on wiring. A deployment that forgot to
// wire authorization would then serve 404 on the management API, which is
// indistinguishable from "this build has no management API" and is exactly the
// kind of quiet difference that gets diagnosed as a client bug. Worse, it makes
// the presence of a security control something a reader has to infer from
// runtime state rather than read off the table.
//
// So the routes always exist, and when there is no Authorizer they are guarded
// by one that refuses every credential. The surface is then constant and the
// failure is loud in the right direction: every management call is refused,
// which is the safe answer, and no request is ever served unauthenticated.
//
// This is a fallback, not a default anybody should reach in production. Prod
// wiring MUST pass WithAuthorizer; see the note in cmd/valletd.
func managementGuardian(a Authorizer, logger *slog.Logger) *Guardian {
	if a == nil {
		a = denyAllAuthorizer{}
	}
	// DenyUnauthorized is correct for this surface and is chosen deliberately
	// rather than inherited. Devices are addressed by non-guessable internal
	// identifiers and the caller is by definition an account holder, so
	// existence is not the secret here -- and a 401 is what lets a client with
	// an expired token know to refresh rather than present it forever. The
	// existence question that DOES matter on this surface, "is this device
	// someone else's", is answered by the handler's 404 and never by this
	// layer, which refuses before any lookup happens.
	//
	// The error is discarded because it has exactly one cause, a nil
	// Authorizer, which the line above has just made impossible.
	g, err := NewGuardian(a, DenyUnauthorized, nil, logger)
	if err != nil {
		// Unreachable: NewGuardian fails only on a nil Authorizer. Panicking
		// rather than returning a nil Guardian means a future change that
		// introduces a second failure mode stops the process at startup instead
		// of nil-panicking on the first management request.
		panic("httpserver: management guardian: " + err.Error())
	}
	return g
}

// denyAllAuthorizer refuses every credential. It is the fail-closed stand-in
// used when no Authorizer was supplied.
type denyAllAuthorizer struct{}

// Authorize always fails. It returns ErrAuthFailed rather than ErrForbidden so
// the refusal is indistinguishable from a bad token: a 403 would tell a caller
// its credential was valid and merely insufficient, which is a claim this type
// is in no position to make.
func (denyAllAuthorizer) Authorize(context.Context, secrets.Redacted, auth.Access, time.Time) (*auth.Authorization, error) {
	return nil, auth.ErrAuthFailed
}
