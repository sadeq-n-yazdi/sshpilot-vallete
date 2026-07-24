package httpserver

import (
	"context"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/secrets"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/service/publish"
)

// stubPublisher is a Publisher whose answer is fixed per test case. It lets the
// handler tests drive every branch — success, the uniform 404, and an internal
// fault — without a database, so what is under test is the HTTP behavior alone.
//
// The zero value resolves to an empty body with no error, which is what the
// health and server tests want: they need a non-nil publisher to construct a
// handler and never call the publish routes.
type stubPublisher struct {
	body []byte
	err  error

	// protected makes the stub answer as an access-gated set would, so the
	// caching-policy tests can drive that path without a verifier.
	protected bool

	// gotToken captures the bearer token the handler extracted, so tests can
	// assert what was — and, for a query parameter or cookie, was not — passed
	// through to the service.
	gotToken *string

	// gotHandle and gotSet capture what the handler extracted from the path, so
	// tests can assert that routing passes the right segments through — in
	// particular that /{handle} yields an empty set name rather than a literal
	// one, which is what selects the owner's default set.
	gotHandle *string
	gotSet    *string
}

func (s stubPublisher) Resolve(_ context.Context, handle, setName string, presented secrets.Redacted) (publish.Result, error) {
	if s.gotHandle != nil {
		*s.gotHandle = handle
	}
	if s.gotSet != nil {
		*s.gotSet = setName
	}
	if s.gotToken != nil {
		*s.gotToken = presented.Reveal()
	}
	if s.err != nil {
		return publish.Result{}, s.err
	}
	return publish.Result{Body: s.body, Protected: s.protected}, nil
}
