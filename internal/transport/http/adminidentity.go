package httpserver

import (
	"net/http"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/secrets"
)

// AdminTokenVerifier verifies a presented administrator bearer token and
// returns the AdministratorID it names, or an error for anything short of a
// valid one. It is declared here, at the point of use, so the transport depends
// on this one method rather than on the concrete *auth.AdminTokenSigner, which
// satisfies it.
//
// The contract is exactly auth.AdminTokenSigner.Verify's: it returns the id on
// success and a single opaque error on every failure, and it never reads the
// clock -- the caller supplies now.
type AdminTokenVerifier interface {
	Verify(presented secrets.Redacted, now time.Time) (domain.AdministratorID, error)
}

// signedAdminIdentifier resolves the administrator a request is authenticated
// as by verifying its bearer token (ADR-0031). It is the real AdminIdentifier
// that replaces denyAllAdminIdentifier once an administrator signing key is
// configured.
//
// It verifies ONLY. It does not decide whether that administrator is active or
// even exists -- that authority check is listadmin.authorize's, run on every
// edit (Admins.Get -> status == Active). Splitting the two is deliberate: this
// type answers "whose signed token is this", and a validly-signed token for a
// disabled administrator still resolves to that id here and is then refused one
// layer down, so there is exactly one place that consults administrator status.
type signedAdminIdentifier struct {
	verifier AdminTokenVerifier
	now      func() time.Time
}

// NewSignedAdminIdentifier builds the token-verifying AdminIdentifier.
//
// A nil verifier or nil clock is a wiring fault, and it panics at construction
// rather than returning an identifier that fails some other way later -- the
// same fail-at-startup posture Protect and managementGuardian take for a nil
// dependency. A route table is built once at startup, so a wiring fault there
// should stop the process while an operator is watching, not degrade into a
// per-request nil dereference. The composition root always passes a real signer
// and time.Now, so neither branch is reachable in production.
func NewSignedAdminIdentifier(v AdminTokenVerifier, now func() time.Time) AdminIdentifier {
	if v == nil {
		panic("httpserver: NewSignedAdminIdentifier called with a nil verifier")
	}
	if now == nil {
		panic("httpserver: NewSignedAdminIdentifier called with a nil clock")
	}
	return signedAdminIdentifier{verifier: v, now: now}
}

// AdministratorID returns the administrator the request's bearer token names, or
// the empty ID on any failure.
//
// Every failure -- no Authorization header, the wrong shape, an owner token, a
// forged, expired, or wrong-key admin token -- returns "" and is
// indistinguishable from the others, so a caller learns nothing from probing.
// The empty ID is the fail-closed signal the whole admin surface is built on:
// listadmin refuses it, so a request the verifier rejects takes the same uniform
// 403 an unknown administrator gets, with no enumeration oracle. This never
// leaks WHY a token was refused, and it reuses bearerToken so the admin surface
// enforces the same one-Authorization-header, case-insensitive-Bearer,
// length-bounded rule the owner surface does.
func (s signedAdminIdentifier) AdministratorID(r *http.Request) domain.AdministratorID {
	token, ok := bearerToken(r)
	if !ok {
		return ""
	}
	id, err := s.verifier.Verify(token, s.now())
	if err != nil {
		return ""
	}
	return id
}
