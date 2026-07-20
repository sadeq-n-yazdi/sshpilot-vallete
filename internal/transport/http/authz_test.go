package httpserver_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/auth"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/secrets"
	httpserver "github.com/sadeq-n-yazdi/sshpilot-vallete/internal/transport/http"
)

const (
	ownerA = domain.OwnerID("own-aaaaaaaa")
	ownerB = domain.OwnerID("own-bbbbbbbb")
)

// permissiveAuthorizer is THE fake this file is built around, and its
// permissiveness is the point.
//
// It models an authorization backend that has forgotten the owner boundary
// entirely: it verifies the token's bytes against a table and returns whatever
// owner that table says, without ever comparing against the owner the request
// named. Nothing in it can refuse a cross-owner request.
//
// That matters for what a passing test proves. If the fake did the owner check,
// a test that saw a refusal would have learned nothing about the transport --
// the refusal would be the fake's. Because this one always admits, any refusal
// observed through it came from the code under test.
type permissiveAuthorizer struct {
	// tokens maps a presented credential to the owner it speaks for. An absent
	// credential is the only thing this fake refuses.
	tokens map[string]domain.OwnerID
	// calls records the Access each call was made with, so a test can assert
	// what the transport told the authorizer about the request.
	calls []auth.Access
	// err, when non-nil, is returned by every call instead of a verdict.
	err error
	// admitNil makes the fake return neither a verdict nor an error, which is a
	// contract violation the transport must read as a denial rather than as
	// "authorized as nobody".
	admitNil bool
}

func (a *permissiveAuthorizer) Authorize(_ context.Context, presented secrets.Redacted, acc auth.Access, _ time.Time) (*auth.Authorization, error) {
	a.calls = append(a.calls, acc)
	if a.err != nil {
		return nil, a.err
	}
	if a.admitNil {
		return nil, nil //nolint:nilnil // the broken-contract shape is the subject of the test
	}
	if _, ok := a.tokens[presented.Reveal()]; !ok {
		return nil, auth.ErrAuthFailed
	}
	// Deliberately no owner comparison, and deliberately no nil check on what
	// the request named. This fake admits owner A's token on owner B's
	// resource; see the type comment.
	return &auth.Authorization{}, nil
}

// realGuard builds a Guardian over the production auth.Guard, for the tests
// whose subject is the enforcement itself rather than the transport plumbing.
type realGuard struct {
	guardian *httpserver.Guardian
	signer   *auth.AccessTokenSigner
	denylist *auth.Denylist
	store    *breakableStore
	now      time.Time
}

func newRealGuard(t *testing.T, style httpserver.DenialStyle) *realGuard {
	t.Helper()
	rg := &realGuard{now: time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)}

	store, err := newTestCounterStore(func() time.Time { return rg.now })
	if err != nil {
		t.Fatalf("counter store: %v", err)
	}
	rg.store = store
	if rg.denylist, err = auth.NewDenylist(store); err != nil {
		t.Fatalf("NewDenylist: %v", err)
	}
	if rg.signer, err = auth.NewAccessTokenSigner([]byte(strings.Repeat("k", auth.MinSigningKeyLen))); err != nil {
		t.Fatalf("NewAccessTokenSigner: %v", err)
	}
	guard, err := auth.NewGuard(rg.signer, rg.denylist)
	if err != nil {
		t.Fatalf("NewGuard: %v", err)
	}
	if rg.guardian, err = httpserver.NewGuardian(guard, style, func() time.Time { return rg.now }, nil); err != nil {
		t.Fatalf("NewGuardian: %v", err)
	}
	return rg
}

func (rg *realGuard) issue(t *testing.T, owner domain.OwnerID, scopes ...domain.Scope) string {
	t.Helper()
	tok, err := rg.signer.Issue(domain.AccessToken{
		ID:                  "jti-1",
		OwnerID:             owner,
		RefreshCredentialID: "cred-1",
		Scopes:              scopes,
		IssuedAt:            rg.now,
		ExpiresAt:           rg.now.Add(auth.AccessTokenLifetime),
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	return tok.Reveal()
}

// seen records what a protected handler was handed, so a test can assert the
// owner a handler receives rather than only the status on the wire.
type seen struct {
	ran            bool
	paramOwner     domain.OwnerID
	contextOwner   domain.OwnerID
	contextCarried bool
}

// observingHandler is the ScopedHandler used throughout: it records the owner it
// was given by parameter and the one it can read from the context, and answers
// 200.
func observingHandler(s *seen) httpserver.ScopedHandler {
	return func(w http.ResponseWriter, r *http.Request, a *auth.Authorization) {
		s.ran = true
		s.paramOwner = a.Owner()
		if got, ok := auth.AuthorizationFromContext(r.Context()); ok {
			s.contextCarried = true
			s.contextOwner = got.Owner()
		}
		w.WriteHeader(http.StatusOK)
	}
}

// keySetAccess is the AccessFunc for a route addressing one key set, and the
// shape a Track C route will use: the resource comes out of the path, and the
// owner is named only when the request itself names one.
func keySetAccess(r *http.Request) (auth.Access, error) {
	return auth.Access{
		Owner:      domain.OwnerID(r.Header.Get("X-Test-Target-Owner")),
		Resource:   auth.ResourceKeySet,
		ResourceID: r.PathValue("set"),
	}, nil
}

// do issues a request through h and returns the recorder.
func do(h http.Handler, method, target, token string, headers map[string]string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, target, nil)
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestNewGuardianRejectsANilAuthorizer(t *testing.T) {
	g, err := httpserver.NewGuardian(nil, httpserver.DenyNotFound, nil, nil)
	if !errors.Is(err, httpserver.ErrNilAuthorizer) {
		t.Fatalf("err = %v, want ErrNilAuthorizer", err)
	}
	if g != nil {
		t.Fatal("a rejected construction must not return a Guardian")
	}
}

func TestNewGuardianDefaultsItsClockAndLogger(t *testing.T) {
	// A nil clock and nil logger are tolerated: neither is a security control,
	// and losing logs must never be why a request fails.
	g, err := httpserver.NewGuardian(&permissiveAuthorizer{tokens: map[string]domain.OwnerID{"t": ownerA}}, httpserver.DenyNotFound, nil, nil)
	if err != nil {
		t.Fatalf("NewGuardian: %v", err)
	}
	var s seen
	if got := do(g.Protect(httpserver.AccountAccess, observingHandler(&s)), http.MethodGet, "/x", "t", nil).Code; got != http.StatusOK {
		t.Fatalf("status = %d, want 200", got)
	}
}

// TestCrossOwnerRequestIsRefusedOnEveryRoute is the transport-level isolation
// test. A valid token for owner A is presented to every protected route in a
// mounted table, each time on a request naming owner B, for every scope kind.
//
// The routes are mounted on a real ServeMux behind Protect, so this also
// answers "can a route bypass the owner check by being registered differently":
// every route in the table refuses, and the handler behind each never runs.
func TestCrossOwnerRequestIsRefusedOnEveryRoute(t *testing.T) {
	scopes := []struct {
		name  string
		scope domain.Scope
	}{
		{name: "full owner", scope: domain.Scope{Kind: domain.ScopeFullOwner}},
		{name: "read only", scope: domain.Scope{Kind: domain.ScopeReadOnly}},
		{name: "single set", scope: domain.Scope{Kind: domain.ScopeSingleSet, ResourceID: "ks-alpha"}},
		{name: "single device", scope: domain.Scope{Kind: domain.ScopeSingleDevice, ResourceID: "ks-alpha"}},
	}
	routes := []struct {
		name    string
		method  string
		pattern string
		target  string
	}{
		{name: "read a set", method: http.MethodGet, pattern: "GET /sets/{set}", target: "/sets/ks-alpha"},
		{name: "write a set", method: http.MethodPut, pattern: "PUT /sets/{set}", target: "/sets/ks-alpha"},
		{name: "delete a set", method: http.MethodDelete, pattern: "DELETE /sets/{set}", target: "/sets/ks-alpha"},
	}

	for _, sc := range scopes {
		for _, rt := range routes {
			t.Run(sc.name+"/"+rt.name, func(t *testing.T) {
				rg := newRealGuard(t, httpserver.DenyNotFound)
				token := rg.issue(t, ownerA, sc.scope)

				var s seen
				mux := http.NewServeMux()
				mux.Handle(rt.pattern, rg.guardian.Protect(keySetAccess, observingHandler(&s)))

				w := do(mux, rt.method, rt.target, token, map[string]string{
					"X-Test-Target-Owner": string(ownerB),
				})
				if w.Code != http.StatusForbidden {
					t.Fatalf("status = %d, want 403", w.Code)
				}
				if s.ran {
					t.Fatal("the handler ran on a cross-owner request")
				}
			})
		}
	}
}

// TestOwnerReachesItsOwnResource is the other direction: the same tokens and
// routes, naming owner A, succeed wherever the scope allows. Without it the
// test above would pass against a middleware that refused everything.
func TestOwnerReachesItsOwnResource(t *testing.T) {
	tests := []struct {
		name   string
		scope  domain.Scope
		method string
		want   int
	}{
		{name: "full owner reads", scope: domain.Scope{Kind: domain.ScopeFullOwner}, method: http.MethodGet, want: http.StatusOK},
		{name: "full owner writes", scope: domain.Scope{Kind: domain.ScopeFullOwner}, method: http.MethodPut, want: http.StatusOK},
		{name: "read only reads", scope: domain.Scope{Kind: domain.ScopeReadOnly}, method: http.MethodGet, want: http.StatusOK},
		{
			name:   "read only refused a write",
			scope:  domain.Scope{Kind: domain.ScopeReadOnly},
			method: http.MethodPut,
			want:   http.StatusForbidden,
		},
		{
			name:   "single set reads its set",
			scope:  domain.Scope{Kind: domain.ScopeSingleSet, ResourceID: "ks-alpha"},
			method: http.MethodGet,
			want:   http.StatusOK,
		},
		{
			name:   "single set writes its set",
			scope:  domain.Scope{Kind: domain.ScopeSingleSet, ResourceID: "ks-alpha"},
			method: http.MethodPut,
			want:   http.StatusOK,
		},
		{
			name:   "single set refused another set",
			scope:  domain.Scope{Kind: domain.ScopeSingleSet, ResourceID: "ks-beta"},
			method: http.MethodGet,
			want:   http.StatusForbidden,
		},
		{
			// The device scope's resource id equals the key set's, so only the
			// resource KIND can be the reason this is refused.
			name:   "single device refused a set with the same id",
			scope:  domain.Scope{Kind: domain.ScopeSingleDevice, ResourceID: "ks-alpha"},
			method: http.MethodGet,
			want:   http.StatusForbidden,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rg := newRealGuard(t, httpserver.DenyNotFound)
			token := rg.issue(t, ownerA, tt.scope)

			var s seen
			mux := http.NewServeMux()
			mux.Handle("/sets/{set}", rg.guardian.Protect(keySetAccess, observingHandler(&s)))

			w := do(mux, tt.method, "/sets/ks-alpha", token, map[string]string{
				"X-Test-Target-Owner": string(ownerA),
			})
			if w.Code != tt.want {
				t.Fatalf("status = %d, want %d", w.Code, tt.want)
			}
			if s.ran != (tt.want == http.StatusOK) {
				t.Fatalf("handler ran = %v, want %v", s.ran, tt.want == http.StatusOK)
			}
			if tt.want == http.StatusOK && s.paramOwner != ownerA {
				t.Fatalf("handler received owner %q, want %q", s.paramOwner, ownerA)
			}
			// Every outcome must vary on the credential, and the allowed
			// outcomes are the ones that matter: two owners issuing the same
			// GET for a resource each may see would otherwise let a shared
			// cache serve one owner's body to the other. This runs on the 200
			// rows as well as the 403 rows, so it pins the success path.
			if got := w.Header().Get("Vary"); got != "Authorization" {
				t.Fatalf("Vary = %q, want %q", got, "Authorization")
			}
		})
	}
}

// TestHandlerReceivesTheTokensOwner is the guarantee that makes a forgetful
// handler safe: the owner in the handler's hand is the token's, and every
// attacker-controlled place an owner could have come from -- path, query,
// header -- names someone else in this request.
func TestHandlerReceivesTheTokensOwner(t *testing.T) {
	rg := newRealGuard(t, httpserver.DenyNotFound)
	token := rg.issue(t, ownerA, domain.Scope{Kind: domain.ScopeFullOwner})

	var s seen
	mux := http.NewServeMux()
	// The route names no owner, which is the management API's shape: resources
	// are addressed by their own identifiers and the owner comes from the token.
	mux.Handle("/owners/{owner}/sets", rg.guardian.Protect(httpserver.AccountAccess, observingHandler(&s)))

	w := do(mux, http.MethodGet, "/owners/"+string(ownerB)+"/sets?owner="+string(ownerB), token, map[string]string{
		"X-Owner-Id": string(ownerB),
	})
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if s.paramOwner != ownerA {
		t.Fatalf("handler received owner %q from the parameter, want the token's %q", s.paramOwner, ownerA)
	}
	if !s.contextCarried {
		t.Fatal("the Authorization did not reach the request context")
	}
	if s.contextOwner != ownerA {
		t.Fatalf("handler read owner %q from the context, want %q", s.contextOwner, ownerA)
	}
}

// TestRevokedAndUnconsultableTokensAreRefused covers the two denylist verdicts
// end to end, through the transport.
func TestRevokedAndUnconsultableTokensAreRefused(t *testing.T) {
	rg := newRealGuard(t, httpserver.DenyUnauthorized)
	token := rg.issue(t, ownerA, domain.Scope{Kind: domain.ScopeFullOwner})

	var s seen
	h := rg.guardian.Protect(httpserver.AccountAccess, observingHandler(&s))

	if got := do(h, http.MethodGet, "/x", token, nil).Code; got != http.StatusOK {
		t.Fatalf("a live token was refused: status = %d", got)
	}

	// Revoked.
	rg.revoke(t, "cred-1")
	s = seen{}
	if got := do(h, http.MethodGet, "/x", token, nil).Code; got != http.StatusUnauthorized {
		t.Fatalf("a revoked token got status %d, want 401", got)
	}
	if s.ran {
		t.Fatal("the handler ran on a revoked token")
	}

	// The store is down: fail closed.
	rg2 := newRealGuard(t, httpserver.DenyUnauthorized)
	token2 := rg2.issue(t, ownerA, domain.Scope{Kind: domain.ScopeFullOwner})
	h2 := rg2.guardian.Protect(httpserver.AccountAccess, observingHandler(&s))
	rg2.takeStoreDown()
	s = seen{}
	if got := do(h2, http.MethodGet, "/x", token2, nil).Code; got != http.StatusUnauthorized {
		t.Fatalf("an unconsultable denylist got status %d, want a denial", got)
	}
	if s.ran {
		t.Fatal("the handler ran while the denylist could not be consulted")
	}
}
