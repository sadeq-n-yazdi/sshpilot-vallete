package auth_test

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/auth"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/counter"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/secrets"
)

// The two owners every isolation test in this file is about. They are distinct
// values of the same length, so a comparison that got the length right and the
// bytes wrong still fails.
const (
	ownerA = domain.OwnerID("own-aaaaaaaa")
	ownerB = domain.OwnerID("own-bbbbbbbb")
)

// guardFixture holds a Guard over a real signer and a real denylist backed by a
// controllable counter store, plus the clock all three share.
type guardFixture struct {
	guard  *auth.Guard
	signer *auth.AccessTokenSigner
	list   *auth.Denylist
	store  *flakyStore
	now    time.Time
}

// flakyStore is a counter.Store that can be taken offline mid-test. It is how
// the fail-closed rule is exercised: a denylist that cannot be consulted must
// deny, and the only way to show that is to break the store under a token that
// would otherwise be admitted.
type flakyStore struct {
	inner counter.Store
	down  bool
}

func (s *flakyStore) Increment(ctx context.Context, key string, delta int64, ttl time.Duration) (counter.Count, error) {
	if s.down {
		return counter.Count{}, counter.ErrStoreUnavailable
	}
	return s.inner.Increment(ctx, key, delta, ttl)
}

func (s *flakyStore) Get(ctx context.Context, key string) (counter.Count, error) {
	if s.down {
		return counter.Count{}, counter.ErrStoreUnavailable
	}
	return s.inner.Get(ctx, key)
}

func (s *flakyStore) Delete(ctx context.Context, key string) error {
	if s.down {
		return counter.ErrStoreUnavailable
	}
	return s.inner.Delete(ctx, key)
}

func newGuardFixture(t *testing.T) *guardFixture {
	t.Helper()
	f := &guardFixture{now: time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)}

	mem, err := counter.NewMemoryStore(func() time.Time { return f.now })
	if err != nil {
		t.Fatalf("NewMemoryStore: %v", err)
	}
	f.store = &flakyStore{inner: mem}

	if f.signer, err = auth.NewAccessTokenSigner([]byte(strings.Repeat("k", auth.MinSigningKeyLen))); err != nil {
		t.Fatalf("NewAccessTokenSigner: %v", err)
	}
	if f.list, err = auth.NewDenylist(f.store); err != nil {
		t.Fatalf("NewDenylist: %v", err)
	}
	if f.guard, err = auth.NewGuard(f.signer, f.list); err != nil {
		t.Fatalf("NewGuard: %v", err)
	}
	return f
}

// issue mints a real, signed access token for owner with the given scopes. The
// tokens under test are produced by the production signer, never hand-built, so
// a test cannot accidentally assert on a shape the issuer would never emit.
func (f *guardFixture) issue(t *testing.T, owner domain.OwnerID, cred domain.RefreshCredentialID, scopes ...domain.Scope) secrets.Redacted {
	t.Helper()
	tok, err := f.signer.Issue(domain.AccessToken{
		ID:                  "jti-" + string(owner),
		OwnerID:             owner,
		RefreshCredentialID: cred,
		Scopes:              scopes,
		IssuedAt:            f.now,
		ExpiresAt:           f.now.Add(auth.AccessTokenLifetime),
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	return tok
}

// authorize is the call under test, always at the fixture's current time.
func (f *guardFixture) authorize(tok secrets.Redacted, acc auth.Access) (*auth.Authorization, error) {
	return f.guard.Authorize(context.Background(), tok, acc, f.now)
}

// The four scope sets, named once so every table below agrees on them.
var (
	scopeFull   = domain.Scope{Kind: domain.ScopeFullOwner}
	scopeRead   = domain.Scope{Kind: domain.ScopeReadOnly}
	scopeSetA   = domain.Scope{Kind: domain.ScopeSingleSet, ResourceID: "ks-alpha"}
	scopeDevice = domain.Scope{Kind: domain.ScopeSingleDevice, ResourceID: "dev-alpha"}
)

func TestNewGuardRejectsMissingDependencies(t *testing.T) {
	f := newGuardFixture(t)
	tests := []struct {
		name     string
		signer   *auth.AccessTokenSigner
		denylist *auth.Denylist
	}{
		{name: "nil signer", denylist: f.list},
		{name: "nil denylist", signer: f.signer},
		{name: "both nil"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g, err := auth.NewGuard(tt.signer, tt.denylist)
			if !errors.Is(err, domain.ErrInvalidInput) {
				t.Fatalf("err = %v, want domain.ErrInvalidInput", err)
			}
			if g != nil {
				t.Fatal("a rejected construction must not return a Guard")
			}
		})
	}
}

// TestCrossOwnerIsolation is the core security property of this middleware: a
// perfectly valid, unrevoked token for owner A must be refused on a request
// that names owner B, whatever scope kind the token carries and whatever
// resource the request addresses.
//
// Every scope in this table is one that WOULD permit the same request under
// owner A -- the single-set case even names the exact key set the scope binds.
// So a refusal here can only come from the owner comparison; nothing else in
// the decision has a reason to say no.
func TestCrossOwnerIsolation(t *testing.T) {
	tests := []struct {
		name  string
		scope domain.Scope
		acc   auth.Access
	}{
		{name: "full owner", scope: scopeFull, acc: auth.Access{}},
		{name: "full owner mutating", scope: scopeFull, acc: auth.Access{Mutating: true}},
		{name: "read only", scope: scopeRead, acc: auth.Access{}},
		{
			name:  "single set on the very set it binds",
			scope: scopeSetA,
			acc:   auth.Access{Resource: auth.ResourceKeySet, ResourceID: scopeSetA.ResourceID},
		},
		{
			name:  "single device on the very device it binds",
			scope: scopeDevice,
			acc:   auth.Access{Resource: auth.ResourceDevice, ResourceID: scopeDevice.ResourceID},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newGuardFixture(t)
			tok := f.issue(t, ownerA, "cred-a", tt.scope)

			// The same access, once naming A and once naming B.
			allowed := tt.acc
			allowed.Owner = ownerA
			if _, err := f.authorize(tok, allowed); err != nil {
				t.Fatalf("owner A was refused its own resource: %v", err)
			}

			refused := tt.acc
			refused.Owner = ownerB
			got, err := f.authorize(tok, refused)
			if !errors.Is(err, auth.ErrForbidden) {
				t.Fatalf("err = %v, want ErrForbidden", err)
			}
			if got != nil {
				t.Fatal("a refused request must not yield an Authorization")
			}
		})
	}
}

// TestOwnerIsCheckedBeforeScopes pins the ORDER of the two checks.
//
// The token is for owner A and carries single-set scope for "ks-alpha". The
// request names owner B and addresses a key set whose id is also "ks-alpha" --
// which is the realistic shape of the bug: identifiers are per-owner, so two
// owners can hold sets that collide on the value a scope was minted against.
// Consulting the scope first finds a match and admits; consulting the owner
// first refuses. Only the second is correct, and only the second passes here.
func TestOwnerIsCheckedBeforeScopes(t *testing.T) {
	f := newGuardFixture(t)
	tok := f.issue(t, ownerA, "cred-a", scopeSetA)

	_, err := f.authorize(tok, auth.Access{
		Owner:      ownerB,
		Resource:   auth.ResourceKeySet,
		ResourceID: scopeSetA.ResourceID,
	})
	if !errors.Is(err, auth.ErrForbidden) {
		t.Fatalf("err = %v, want ErrForbidden: a scope match must never outrank the owner boundary", err)
	}
}

// TestAuthorizedOwnerComesFromTheToken shows that the owner a handler receives
// is the token's, never the request's, even on the routes that name no owner at
// all. This is what a handler is meant to scope its queries by.
func TestAuthorizedOwnerComesFromTheToken(t *testing.T) {
	f := newGuardFixture(t)
	tok := f.issue(t, ownerA, "cred-a", scopeFull)

	a, err := f.authorize(tok, auth.Access{})
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if a.Owner() != ownerA {
		t.Fatalf("Owner() = %q, want %q", a.Owner(), ownerA)
	}
	if a.TokenID() != "jti-"+string(ownerA) {
		t.Fatalf("TokenID() = %q", a.TokenID())
	}
	if a.CredentialID() != "cred-a" {
		t.Fatalf("CredentialID() = %q", a.CredentialID())
	}
	if got := a.Scopes(); len(got) != 1 || got[0] != scopeFull {
		t.Fatalf("Scopes() = %v", got)
	}
}

// TestScopesAreCopied shows the grant a caller receives is not the live one. A
// caller that edited it would be editing the permission set of every other
// request served under the same Authorization.
func TestScopesAreCopied(t *testing.T) {
	f := newGuardFixture(t)
	// A valid two-scope set (read-only modifying a single-set binding); Issue
	// preserves order, so scopeSetA stays at index 0 for the assertion below.
	tok := f.issue(t, ownerA, "cred-a", scopeSetA, scopeRead)

	a, err := f.authorize(tok, auth.Access{Resource: auth.ResourceKeySet, ResourceID: scopeSetA.ResourceID})
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	got := a.Scopes()
	got[0] = domain.Scope{Kind: domain.ScopeFullOwner}
	if again := a.Scopes(); again[0] != scopeSetA {
		t.Fatalf("mutating the returned scopes changed the Authorization: %v", again)
	}
}

// TestScopeEnforcement covers every scope kind in both directions: the requests
// it must permit, and the requests it must refuse. The owner matches
// throughout, so every verdict here is the fine-grained check speaking.
func TestScopeEnforcement(t *testing.T) {
	tests := []struct {
		name   string
		scopes []domain.Scope
		acc    auth.Access
		want   bool
	}{
		// full-owner: everything within the owner.
		{name: "full owner reads", scopes: []domain.Scope{scopeFull}, acc: auth.Access{}, want: true},
		{name: "full owner mutates", scopes: []domain.Scope{scopeFull}, acc: auth.Access{Mutating: true}, want: true},
		{
			name:   "full owner reaches any set",
			scopes: []domain.Scope{scopeFull},
			acc:    auth.Access{Resource: auth.ResourceKeySet, ResourceID: "ks-anything"},
			want:   true,
		},

		// read-only: reads yes, writes never.
		{name: "read only reads", scopes: []domain.Scope{scopeRead}, acc: auth.Access{}, want: true},
		{
			name:   "read only reads a set",
			scopes: []domain.Scope{scopeRead},
			acc:    auth.Access{Resource: auth.ResourceKeySet, ResourceID: "ks-anything"},
			want:   true,
		},
		{name: "read only refuses a mutation", scopes: []domain.Scope{scopeRead}, acc: auth.Access{Mutating: true}},
		{
			name:   "read only refuses a mutation of a set",
			scopes: []domain.Scope{scopeRead},
			acc:    auth.Access{Resource: auth.ResourceKeySet, ResourceID: "ks-anything", Mutating: true},
		},

		// single-set: exactly one key set, read and write.
		{
			name:   "single set reaches its own set",
			scopes: []domain.Scope{scopeSetA},
			acc:    auth.Access{Resource: auth.ResourceKeySet, ResourceID: scopeSetA.ResourceID},
			want:   true,
		},
		{
			name:   "single set mutates its own set",
			scopes: []domain.Scope{scopeSetA},
			acc:    auth.Access{Resource: auth.ResourceKeySet, ResourceID: scopeSetA.ResourceID, Mutating: true},
			want:   true,
		},
		{
			name:   "single set refuses another set",
			scopes: []domain.Scope{scopeSetA},
			acc:    auth.Access{Resource: auth.ResourceKeySet, ResourceID: "ks-beta"},
		},
		{
			// A prefix of the bound id, in case a comparison ever became a
			// HasPrefix rather than an equality.
			name:   "single set refuses a prefix of its set",
			scopes: []domain.Scope{scopeSetA},
			acc:    auth.Access{Resource: auth.ResourceKeySet, ResourceID: "ks-alph"},
		},
		{
			// The id matches but the kind does not: a device that happens to
			// carry the key set's identifier must not be reachable.
			name:   "single set refuses a device with the same id",
			scopes: []domain.Scope{scopeSetA},
			acc:    auth.Access{Resource: auth.ResourceDevice, ResourceID: scopeSetA.ResourceID},
		},
		{
			name:   "single set refuses an account wide request",
			scopes: []domain.Scope{scopeSetA},
			acc:    auth.Access{},
		},

		// single-device: the same rules, on the other axis.
		{
			name:   "single device reaches its own device",
			scopes: []domain.Scope{scopeDevice},
			acc:    auth.Access{Resource: auth.ResourceDevice, ResourceID: scopeDevice.ResourceID},
			want:   true,
		},
		{
			name:   "single device refuses another device",
			scopes: []domain.Scope{scopeDevice},
			acc:    auth.Access{Resource: auth.ResourceDevice, ResourceID: "dev-beta"},
		},
		{
			name:   "single device refuses a set with the same id",
			scopes: []domain.Scope{scopeDevice},
			acc:    auth.Access{Resource: auth.ResourceKeySet, ResourceID: scopeDevice.ResourceID},
		},
		{
			name:   "single device refuses an account wide request",
			scopes: []domain.Scope{scopeDevice},
			acc:    auth.Access{},
		},

		// read-only as a modifier over a single-set binding: reads of exactly
		// that set, and nothing else -- no write to it, no read of another set,
		// no account-wide read.
		{
			name:   "read only single set reads its own set",
			scopes: []domain.Scope{scopeRead, scopeSetA},
			acc:    auth.Access{Resource: auth.ResourceKeySet, ResourceID: scopeSetA.ResourceID},
			want:   true,
		},
		{
			name:   "read only single set refuses a mutation of its own set",
			scopes: []domain.Scope{scopeRead, scopeSetA},
			acc:    auth.Access{Resource: auth.ResourceKeySet, ResourceID: scopeSetA.ResourceID, Mutating: true},
		},
		{
			name:   "read only single set refuses reading another set",
			scopes: []domain.Scope{scopeRead, scopeSetA},
			acc:    auth.Access{Resource: auth.ResourceKeySet, ResourceID: "ks-beta"},
		},
		{
			name:   "read only single set refuses an account wide read",
			scopes: []domain.Scope{scopeRead, scopeSetA},
			acc:    auth.Access{},
		},
		// The same shape on the device axis.
		{
			name:   "read only single device reads its own device",
			scopes: []domain.Scope{scopeRead, scopeDevice},
			acc:    auth.Access{Resource: auth.ResourceDevice, ResourceID: scopeDevice.ResourceID},
			want:   true,
		},
		{
			name:   "read only single device refuses a mutation of its own device",
			scopes: []domain.Scope{scopeRead, scopeDevice},
			acc:    auth.Access{Resource: auth.ResourceDevice, ResourceID: scopeDevice.ResourceID, Mutating: true},
		},
		{
			name:   "read only single device refuses reading another device",
			scopes: []domain.Scope{scopeRead, scopeDevice},
			acc:    auth.Access{Resource: auth.ResourceDevice, ResourceID: "dev-beta"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newGuardFixture(t)
			tok := f.issue(t, ownerA, "cred-a", tt.scopes...)
			tt.acc.Owner = ownerA

			a, err := f.authorize(tok, tt.acc)
			if tt.want {
				if err != nil {
					t.Fatalf("permitted access was refused: %v", err)
				}
				if a.Owner() != ownerA {
					t.Fatalf("Owner() = %q, want %q", a.Owner(), ownerA)
				}
				return
			}
			if !errors.Is(err, auth.ErrForbidden) {
				t.Fatalf("err = %v, want ErrForbidden", err)
			}
			if a != nil {
				t.Fatal("a refused request must not yield an Authorization")
			}
		})
	}
}

// TestReadOnlyModifierIntersects is the security proof for the read-only
// modifier (ADR-0018, "read-only + single-set"): a token carrying read-only AND
// a single-set binding must grant the INTERSECTION of the two, never the union.
//
// The union would be the bug: single-set alone permits read and write of its
// set, and read-only alone permits reading anything, so a naive "any scope
// permits" would let this token WRITE its set (single-set said yes) and READ
// other sets (read-only said yes) -- widening past either half. The correct
// grant is neither: read of exactly this one set, and nothing more.
func TestReadOnlyModifierIntersects(t *testing.T) {
	f := newGuardFixture(t)
	tok := f.issue(t, ownerA, "cred-a", scopeRead, scopeSetA)

	own := auth.Access{Owner: ownerA, Resource: auth.ResourceKeySet, ResourceID: scopeSetA.ResourceID}

	// It MAY read its own set.
	if _, err := f.authorize(tok, own); err != nil {
		t.Fatalf("read-only+single-set was refused a read of its own set: %v", err)
	}

	// It must NOT mutate its own set: the binding's write authority does not
	// survive the read-only modifier.
	mutate := own
	mutate.Mutating = true
	if _, err := f.authorize(tok, mutate); !errors.Is(err, auth.ErrForbidden) {
		t.Fatalf("mutation err = %v, want ErrForbidden: read-only must cap the binding's write", err)
	}

	// It must NOT read a DIFFERENT set: read-only does not widen the binding to
	// account-wide read.
	other := auth.Access{Owner: ownerA, Resource: auth.ResourceKeySet, ResourceID: "ks-beta"}
	if _, err := f.authorize(tok, other); !errors.Is(err, auth.ErrForbidden) {
		t.Fatalf("other-set err = %v, want ErrForbidden: read-only must not widen the binding", err)
	}
}

// TestRevokedTokenIsRefused shows the denylist is consulted on every request:
// a token that authorized a moment ago stops working the instant its credential
// is listed, without waiting out its fifteen minutes.
func TestRevokedTokenIsRefused(t *testing.T) {
	f := newGuardFixture(t)
	tok := f.issue(t, ownerA, "cred-a", scopeFull)
	acc := auth.Access{Owner: ownerA}

	if _, err := f.authorize(tok, acc); err != nil {
		t.Fatalf("a live token was refused: %v", err)
	}
	if err := f.list.RevokeCredential(context.Background(), "cred-a"); err != nil {
		t.Fatalf("RevokeCredential: %v", err)
	}

	got, err := f.authorize(tok, acc)
	if !errors.Is(err, auth.ErrAuthFailed) {
		t.Fatalf("err = %v, want ErrAuthFailed", err)
	}
	if errors.Is(err, auth.ErrForbidden) {
		t.Fatal("a revoked token must be indistinguishable from a forged one, not reported as a scope problem")
	}
	if got != nil {
		t.Fatal("a revoked token must not yield an Authorization")
	}
}

// TestDenylistOutageDenies is the fail-closed test. The token is valid, its
// owner matches, and its scope covers the request: the ONLY thing wrong is that
// the denylist cannot be consulted. That must deny.
//
// A guard that failed open here would turn an outage of an auxiliary store into
// a silent, system-wide revocation bypass, arriving exactly when an attacker
// who could cause the outage would want it.
func TestDenylistOutageDenies(t *testing.T) {
	f := newGuardFixture(t)
	tok := f.issue(t, ownerA, "cred-a", scopeFull)
	acc := auth.Access{Owner: ownerA}

	if _, err := f.authorize(tok, acc); err != nil {
		t.Fatalf("a live token was refused while the store was up: %v", err)
	}

	f.store.down = true
	got, err := f.authorize(tok, acc)
	if !errors.Is(err, auth.ErrAuthFailed) {
		t.Fatalf("err = %v, want ErrAuthFailed", err)
	}
	if got != nil {
		t.Fatal("an unconsultable denylist must not yield an Authorization")
	}

	// And it recovers: the denial is an availability consequence, not a
	// permanent state.
	f.store.down = false
	if _, err := f.authorize(tok, acc); err != nil {
		t.Fatalf("the token stayed refused after the store came back: %v", err)
	}
}

// TestUnauthenticatedTokensAreRefused covers every way a presented token can
// fail before the owner is even known. All of them return the bare sentinel:
// none is distinguishable from any other.
func TestUnauthenticatedTokensAreRefused(t *testing.T) {
	f := newGuardFixture(t)
	good := f.issue(t, ownerA, "cred-a", scopeFull)

	// A token from a different signer: correctly shaped, wrong key.
	other, err := auth.NewAccessTokenSigner([]byte(strings.Repeat("x", auth.MinSigningKeyLen)))
	if err != nil {
		t.Fatalf("NewAccessTokenSigner: %v", err)
	}
	otherFixture := &guardFixture{now: f.now, signer: other}
	forged := otherFixture.issue(t, ownerA, "cred-a", scopeFull)

	tests := []struct {
		name string
		tok  secrets.Redacted
		at   time.Time
	}{
		{name: "empty", tok: secrets.NewRedacted(""), at: f.now},
		{name: "not a token", tok: secrets.NewRedacted("hello"), at: f.now},
		{name: "refresh token presented as an access token", tok: secrets.NewRedacted("svr_abc.def"), at: f.now},
		{name: "no mac segment", tok: secrets.NewRedacted("sva_abc"), at: f.now},
		{name: "signed by another key", tok: forged, at: f.now},
		{name: "expired", tok: good, at: f.now.Add(auth.AccessTokenLifetime)},
		{name: "not yet valid", tok: good, at: f.now.Add(-time.Second)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := f.guard.Authorize(context.Background(), tt.tok, auth.Access{Owner: ownerA}, tt.at)
			if !errors.Is(err, auth.ErrAuthFailed) {
				t.Fatalf("err = %v, want ErrAuthFailed", err)
			}
			if errors.Is(err, auth.ErrForbidden) {
				t.Fatal("an unauthenticated caller must not be told this is a scope problem")
			}
			if got != nil {
				t.Fatal("a refused token must not yield an Authorization")
			}
		})
	}
}

// TestMalformedAccessIsRefused shows a route whose Access extractor produced an
// incoherent target does not serve. A kind with no id, or an id with no kind,
// names no resource that any scope could be checked against, and a permission
// check on an unnameable target is a check on nothing.
func TestMalformedAccessIsRefused(t *testing.T) {
	f := newGuardFixture(t)
	tok := f.issue(t, ownerA, "cred-a", scopeFull)

	tests := []struct {
		name string
		acc  auth.Access
	}{
		{name: "kind without an id", acc: auth.Access{Resource: auth.ResourceKeySet}},
		{name: "id without a kind", acc: auth.Access{ResourceID: "ks-alpha"}},
		{name: "unknown kind", acc: auth.Access{Resource: auth.ResourceKind("owner"), ResourceID: "x"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.acc.Owner = ownerA
			got, err := f.authorize(tok, tt.acc)
			if !errors.Is(err, auth.ErrAuthFailed) {
				t.Fatalf("err = %v, want ErrAuthFailed", err)
			}
			if got != nil {
				t.Fatal("a malformed Access must not yield an Authorization")
			}
		})
	}
}

// TestZeroAuthorizationIsUnusable covers the value a caller outside this
// package CAN construct. The fields are unexported, so the zero value is the
// only one available, and it must name nobody: every repository and domain
// validator refuses an empty owner, so a query scoped by it finds nothing
// rather than everything.
func TestZeroAuthorizationIsUnusable(t *testing.T) {
	var zero auth.Authorization
	if zero.Owner() != "" {
		t.Fatalf("Owner() = %q, want empty", zero.Owner())
	}
	if zero.Scopes() != nil {
		t.Fatal("the zero Authorization must carry no grant")
	}

	// A nil one fails closed rather than panicking: a handler reached without
	// authorization must produce no owner, not take the process down.
	var nilAuth *auth.Authorization
	if nilAuth.Owner() != "" || nilAuth.TokenID() != "" || nilAuth.CredentialID() != "" || nilAuth.Scopes() != nil {
		t.Fatal("a nil Authorization must yield nothing")
	}
}

// TestAuthorizationRedaction shows the owner id is the most an Authorization
// ever renders. It holds no secret, but the scope set and credential id have no
// business in an access log.
func TestAuthorizationRedaction(t *testing.T) {
	f := newGuardFixture(t)
	tok := f.issue(t, ownerA, "cred-secret", scopeSetA)
	a, err := f.authorize(tok, auth.Access{Owner: ownerA, Resource: auth.ResourceKeySet, ResourceID: scopeSetA.ResourceID})
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}

	renderings := []string{
		a.String(),
		a.GoString(),
		fmt.Sprintf("%v", a),
		fmt.Sprintf("%+v", a),
		fmt.Sprintf("%#v", a),
		a.LogValue().String(),
	}
	for _, got := range renderings {
		if strings.Contains(got, "cred-secret") || strings.Contains(got, scopeSetA.ResourceID) {
			t.Fatalf("rendering leaked more than the owner: %q", got)
		}
		if !strings.Contains(got, string(ownerA)) {
			t.Fatalf("rendering = %q, want it to name the owner", got)
		}
	}
	if _, ok := any(a).(slog.LogValuer); !ok {
		t.Fatal("Authorization must implement slog.LogValuer")
	}
}

// TestAuthorizationContext covers the carrier. The key is unexported, so the
// only way an Authorization is in a context is that this package put it there,
// which is what makes "the context's owner came from a verified token" true.
func TestAuthorizationContext(t *testing.T) {
	f := newGuardFixture(t)
	tok := f.issue(t, ownerA, "cred-a", scopeFull)
	a, err := f.authorize(tok, auth.Access{Owner: ownerA})
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}

	if got, ok := auth.AuthorizationFromContext(context.Background()); ok || got != nil {
		t.Fatal("an unauthorized context must report no Authorization")
	}

	ctx := auth.ContextWithAuthorization(context.Background(), a)
	got, ok := auth.AuthorizationFromContext(ctx)
	if !ok {
		t.Fatal("the Authorization did not survive the context")
	}
	if got.Owner() != ownerA {
		t.Fatalf("Owner() = %q, want %q", got.Owner(), ownerA)
	}

	// A nil stored value must read as absent, not as "authorized as nobody".
	nilCtx := auth.ContextWithAuthorization(context.Background(), nil)
	if got, ok := auth.AuthorizationFromContext(nilCtx); ok || got != nil {
		t.Fatal("a nil Authorization in a context must report as absent")
	}
}
