package httpserver_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/auth"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	httpserver "github.com/sadeq-n-yazdi/sshpilot-vallete/internal/transport/http"
)

// TestBearerExtraction covers what the transport will even attempt to verify.
// Every case here is refused before the authorizer is consulted, which the
// call count proves.
func TestBearerExtraction(t *testing.T) {
	long := strings.Repeat("a", 4097)
	tests := []struct {
		name    string
		headers []string
		want    bool
	}{
		{name: "bearer", headers: []string{"Bearer good"}, want: true},
		{name: "lowercase scheme", headers: []string{"bearer good"}, want: true},
		{name: "mixed case scheme", headers: []string{"BeArEr good"}, want: true},
		{name: "extra whitespace after the scheme", headers: []string{"Bearer \t good"}, want: true},

		{name: "absent"},
		{name: "empty"},
		{name: "scheme only", headers: []string{"Bearer"}},
		{name: "empty credential", headers: []string{"Bearer "}},
		{name: "whitespace credential", headers: []string{"Bearer    "}},
		{name: "wrong scheme", headers: []string{"Basic good"}},
		{name: "no scheme", headers: []string{"good"}},
		{name: "over the length bound", headers: []string{"Bearer " + long}},
		// Two Authorization headers is a smuggling shape: which one an
		// intermediary acted on and which this server reads need not agree.
		{name: "two headers", headers: []string{"Bearer good", "Bearer good"}},
		{name: "two headers one valid", headers: []string{"Bearer bad", "Bearer good"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := &permissiveAuthorizer{tokens: map[string]domain.OwnerID{"good": ownerA}}
			g, err := httpserver.NewGuardian(fake, httpserver.DenyNotFound, nil, nil)
			if err != nil {
				t.Fatalf("NewGuardian: %v", err)
			}
			var s seen
			h := g.Protect(httpserver.AccountAccess, observingHandler(&s))

			r := httptest.NewRequest(http.MethodGet, "/x", nil)
			for _, v := range tt.headers {
				r.Header.Add("Authorization", v)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)

			if tt.want {
				if w.Code != http.StatusOK {
					t.Fatalf("status = %d, want 200", w.Code)
				}
				return
			}
			if w.Code != http.StatusNotFound {
				t.Fatalf("status = %d, want 404", w.Code)
			}
			if len(fake.calls) != 0 {
				t.Fatal("a malformed credential reached the authorizer")
			}
			if s.ran {
				t.Fatal("the handler ran without a credential")
			}
		})
	}
}

// TestMutationIsDerivedFromTheMethod pins that the transport tells the
// authorizer whether the request writes, and that it does so from the method
// rather than from anything a route declares. A route cannot forget to set it.
func TestMutationIsDerivedFromTheMethod(t *testing.T) {
	tests := []struct {
		method string
		want   bool
	}{
		{method: http.MethodGet},
		{method: http.MethodHead},
		{method: http.MethodOptions},
		{method: http.MethodPost, want: true},
		{method: http.MethodPut, want: true},
		{method: http.MethodPatch, want: true},
		{method: http.MethodDelete, want: true},
		// A verb this code has never heard of is a write, not a read.
		{method: "FROBNICATE", want: true},
	}
	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			fake := &permissiveAuthorizer{tokens: map[string]domain.OwnerID{"good": ownerA}}
			g, err := httpserver.NewGuardian(fake, httpserver.DenyNotFound, nil, nil)
			if err != nil {
				t.Fatalf("NewGuardian: %v", err)
			}
			var s seen
			do(g.Protect(httpserver.AccountAccess, observingHandler(&s)), tt.method, "/x", "good", nil)

			if len(fake.calls) != 1 {
				t.Fatalf("authorizer calls = %d, want 1", len(fake.calls))
			}
			if fake.calls[0].Mutating != tt.want {
				t.Fatalf("Mutating = %v, want %v", fake.calls[0].Mutating, tt.want)
			}
		})
	}
}

// TestAccessFuncFailureRefuses shows a route whose target cannot be described
// does not serve, and tells the caller nothing about why.
func TestAccessFuncFailureRefuses(t *testing.T) {
	fake := &permissiveAuthorizer{tokens: map[string]domain.OwnerID{"good": ownerA}}
	g, err := httpserver.NewGuardian(fake, httpserver.DenyNotFound, nil, nil)
	if err != nil {
		t.Fatalf("NewGuardian: %v", err)
	}
	var s seen
	broken := func(*http.Request) (auth.Access, error) { return auth.Access{}, errors.New("unparsable id") }

	w := do(g.Protect(broken, observingHandler(&s)), http.MethodGet, "/x", "good", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", w.Code)
	}
	if len(fake.calls) != 0 {
		t.Fatal("an undescribable request reached the authorizer")
	}
	if s.ran {
		t.Fatal("the handler ran for an undescribable request")
	}
	if strings.Contains(w.Body.String(), "unparsable") {
		t.Fatalf("the body leaked the reason: %q", w.Body.String())
	}
}

// TestDenialStyles pins the exact status for each condition under each style,
// and the headers that go with them.
func TestDenialStyles(t *testing.T) {
	tests := []struct {
		name      string
		style     httpserver.DenialStyle
		err       error
		admitNil  bool
		token     string
		want      int
		challenge bool
	}{
		{name: "not found style, no token", style: httpserver.DenyNotFound, want: http.StatusNotFound},
		{
			name:  "not found style, bad token",
			style: httpserver.DenyNotFound,
			err:   auth.ErrAuthFailed,
			token: "good",
			want:  http.StatusNotFound,
		},
		{
			name:  "not found style, unauthorized grant",
			style: httpserver.DenyNotFound,
			err:   auth.ErrForbidden,
			token: "good",
			want:  http.StatusForbidden,
		},
		{
			name:      "unauthorized style, no token",
			style:     httpserver.DenyUnauthorized,
			want:      http.StatusUnauthorized,
			challenge: true,
		},
		{
			name:      "unauthorized style, bad token",
			style:     httpserver.DenyUnauthorized,
			err:       auth.ErrAuthFailed,
			token:     "good",
			want:      http.StatusUnauthorized,
			challenge: true,
		},
		{
			// The forbidden verdict is 403 under BOTH styles: it is reached
			// only by a valid token, and it reports on the caller's own grant
			// rather than on anything in the system.
			name:  "unauthorized style, unauthorized grant",
			style: httpserver.DenyUnauthorized,
			err:   auth.ErrForbidden,
			token: "good",
			want:  http.StatusForbidden,
		},
		{
			// An Authorizer that returns neither a verdict nor an error is
			// broken; the only safe reading is a denial.
			name:      "nil authorization with no error",
			style:     httpserver.DenyUnauthorized,
			admitNil:  true,
			token:     "good",
			want:      http.StatusUnauthorized,
			challenge: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := &permissiveAuthorizer{tokens: map[string]domain.OwnerID{"good": ownerA}, err: tt.err, admitNil: tt.admitNil}
			g, err := httpserver.NewGuardian(fake, tt.style, nil, nil)
			if err != nil {
				t.Fatalf("NewGuardian: %v", err)
			}
			var s seen
			w := do(g.Protect(httpserver.AccountAccess, observingHandler(&s)), http.MethodGet, "/x", tt.token, nil)

			if w.Code != tt.want {
				t.Fatalf("status = %d, want %d", w.Code, tt.want)
			}
			if s.ran {
				t.Fatal("the handler ran on a refused request")
			}
			if got := w.Header().Get("WWW-Authenticate"); (got != "") != tt.challenge {
				t.Fatalf("WWW-Authenticate = %q, want present = %v", got, tt.challenge)
			}
			if got := w.Header().Get("Vary"); got != "Authorization" {
				t.Fatalf("Vary = %q, want Authorization", got)
			}
			// Every refusal is the same fixed body, whatever the cause.
			if got := strings.TrimSpace(w.Body.String()); got != `{"status":"error"}` {
				t.Fatalf("body = %q, want a fixed error body", got)
			}
		})
	}
}

// TestProtectRefusesNilArguments shows a wiring fault stops the process while
// an operator is watching, rather than becoming a 500 under load.
func TestProtectRefusesNilArguments(t *testing.T) {
	g, err := httpserver.NewGuardian(&permissiveAuthorizer{}, httpserver.DenyNotFound, nil, nil)
	if err != nil {
		t.Fatalf("NewGuardian: %v", err)
	}
	tests := []struct {
		name   string
		access httpserver.AccessFunc
		h      httpserver.ScopedHandler
	}{
		{name: "nil access", h: func(http.ResponseWriter, *http.Request, *auth.Authorization) {}},
		{name: "nil handler", access: httpserver.AccountAccess},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatal("Protect accepted a nil argument")
				}
			}()
			g.Protect(tt.access, tt.h)
		})
	}
}

// TestAccountAccessNamesNothing pins the shape of the account-wide extractor: no
// owner, so the owner comes from the token, and no resource, so a
// resource-bound token cannot reach it.
func TestAccountAccessNamesNothing(t *testing.T) {
	acc, err := httpserver.AccountAccess(httptest.NewRequest(http.MethodGet, "/x", nil))
	if err != nil {
		t.Fatalf("AccountAccess: %v", err)
	}
	if acc.Owner != "" || acc.Resource != auth.ResourceNone || acc.ResourceID != "" {
		t.Fatalf("AccountAccess returned %+v, want a target that names nothing", acc)
	}
}
