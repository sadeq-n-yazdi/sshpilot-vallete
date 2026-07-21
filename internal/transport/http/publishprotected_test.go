package httpserver

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/audit"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/secrets"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/service/accesskey"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/service/publish"
)

// publishGet drives one publish request through the real handler.
func publishGet(t *testing.T, p Publisher, method, target string, header http.Header) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequest(method, target, nil)
	for k, vs := range header {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	rr := httptest.NewRecorder()
	NewHandler(nil, nil, okPinger{}, p).ServeHTTP(rr, req)
	return rr
}

// wireForm renders everything an observer of a response can see: the status,
// every header with its values, and the body.
//
// It is deliberately total rather than a list of headers the author thought to
// check. The uniform-404 property is that a protected miss and an absent set
// are INDISTINGUISHABLE, and a comparison that enumerated fields would only
// ever catch the leaks its author anticipated — a future header added to one
// path and not the other would sail through. Comparing the whole response means
// any new divergence fails this test the day it is introduced.
//
// Exactly one value is masked: X-Request-Id, which is freshly generated per
// request and so differs between any two responses, including two consecutive
// identical ones. It is a correlation handle for the server's own logs and is
// not derived from the request, the set, or the credential, so it carries
// nothing to read. Masking the VALUE while keeping the header's presence in the
// comparison means a path that stopped emitting it — or started emitting a
// second one — still fails.
func wireForm(rr *httptest.ResponseRecorder) string {
	names := make([]string, 0, len(rr.Header()))
	for name := range rr.Header() {
		names = append(names, name)
	}
	sort.Strings(names)

	var b strings.Builder
	fmt.Fprintf(&b, "status=%d\n", rr.Code)
	for _, name := range names {
		values := rr.Header().Values(name)
		if name == "X-Request-Id" {
			masked := make([]string, len(values))
			for i := range masked {
				masked[i] = "<per-request>"
			}
			values = masked
		}
		fmt.Fprintf(&b, "%s: %q\n", name, values)
	}
	fmt.Fprintf(&b, "body=%q", rr.Body.String())
	return b.String()
}

// TestProtectedMissIsIndistinguishableFromAnAbsentSet is the security control
// of this slice, asserted as the property it actually is.
//
// It does not check that both answers are 404 — two 404s that differed in a
// header, a body byte, or a cache directive would still be an existence oracle,
// and "both are 404" is exactly the weak assertion that lets one through. It
// compares the ENTIRE observable response of a set that does not exist against
// the entire observable response of a protected set whose credential was
// refused, for every way a credential can be refused, over both methods the
// route serves.
//
// The service is what makes this hold: it collapses every refusal into
// publish.ErrNotFound before the handler sees it, so the handler has nothing to
// branch on. This test is what would notice if that ever stopped being true.
func TestProtectedMissIsIndistinguishableFromAnAbsentSet(t *testing.T) {
	t.Parallel()

	// Every one of these reaches the handler as the identical error, because
	// the service is where they were collapsed. The names describe the
	// credential the caller sent; the response must not.
	credentials := map[string]http.Header{
		"no Authorization header at all": {},
		"an empty bearer token":          {"Authorization": {"Bearer "}},
		"a malformed token":              {"Authorization": {"Bearer not-a-token"}},
		"a token for the owner's other set": {
			"Authorization": {"Bearer ak_other.secret"},
		},
		"a revoked token":     {"Authorization": {"Bearer ak_revoked.secret"}},
		"a non-Bearer scheme": {"Authorization": {"Basic dXNlcjpwdw=="}},
		"two Authorization headers": {
			"Authorization": {"Bearer ak_a.b", "Bearer ak_c.d"},
		},
	}

	for _, method := range []string{http.MethodGet, http.MethodHead} {
		for name, header := range credentials {
			t.Run(method+"/"+name, func(t *testing.T) {
				t.Parallel()

				// The set that does not exist: no credential, and a name the
				// owner never claimed. This is the response an attacker can
				// obtain at will, and therefore the baseline the protected
				// miss must be identical to.
				absent := publishGet(t, stubPublisher{err: publish.ErrNotFound},
					method, "/alice/nosuchset", nil)

				// The protected set that exists and refused this credential.
				refused := publishGet(t, stubPublisher{err: publish.ErrNotFound},
					method, "/alice/prod", header)

				if got, want := wireForm(refused), wireForm(absent); got != want {
					t.Errorf("a protected miss is distinguishable from an absent set.\nrefused:\n%s\n\nabsent:\n%s", got, want)
				}
				if refused.Code != http.StatusNotFound {
					t.Errorf("status = %d, want 404", refused.Code)
				}
			})
		}
	}
}

// TestProtectedMissCarriesNoVaryHeader pins the one header this slice could
// most easily leak through.
//
// Vary belongs to the protected SUCCESS path. Setting it on a protected refusal
// — a natural-looking "the response depends on the credential, so declare it"
// — would mark every protected miss and leave every absent set unmarked,
// recreating the oracle in a header nobody thinks to look at. The property test
// above would catch it; this names it, so a future reader knows the omission is
// deliberate rather than forgotten.
func TestProtectedMissCarriesNoVaryHeader(t *testing.T) {
	t.Parallel()

	rr := publishGet(t, stubPublisher{err: publish.ErrNotFound}, http.MethodGet, "/alice/prod",
		http.Header{"Authorization": {"Bearer ak_x.y"}})

	if got := rr.Header().Get("Vary"); got != "" {
		t.Errorf("Vary = %q on a 404; it must appear only on a protected success", got)
	}
	if got := rr.Header().Get("ETag"); got != "" {
		t.Errorf("ETag = %q on a 404; a cached negative would outlive the fix", got)
	}
}

// TestProtectedSuccessIsNotSharedCacheable pins the caching rules ADR-0019
// requires of access-gated bodies: private so no shared cache stores them, and
// keyed by the credential so a cache that stores one anyway cannot hand one
// consumer's copy to a request bearing a different token.
func TestProtectedSuccessIsNotSharedCacheable(t *testing.T) {
	t.Parallel()

	body := []byte("ssh-ed25519 AAAA x\n")
	auth := http.Header{"Authorization": {"Bearer ak_good.secret"}}

	rr := publishGet(t, stubPublisher{body: body, protected: true}, http.MethodGet, "/alice/prod", auth)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	assertHeader(t, rr, "Cache-Control", "private, max-age=60")
	assertHeader(t, rr, "Vary", "Authorization")
	if strings.Contains(rr.Header().Get("Cache-Control"), "public") {
		t.Error("an access-gated body was marked public; a shared cache would hold key material")
	}

	// The public path must be unaffected. Marking public sets private would
	// cost the CDN efficiency the ADR keeps, and a Vary on them would fragment
	// a cache by a header no public consumer sends.
	pub := publishGet(t, stubPublisher{body: body}, http.MethodGet, "/alice/pub", nil)
	assertHeader(t, pub, "Cache-Control", "public, max-age=60")
	if got := pub.Header().Get("Vary"); got != "" {
		t.Errorf("Vary = %q on a public set", got)
	}
}

// TestProtectedNotModifiedKeepsItsRestrictions pins that a 304 carries the
// private directive and the Vary too.
//
// A conditional response that dropped them would answer "your copy is current"
// with no restriction on who may reuse that copy — the cache would then be
// entitled to serve the access-gated body it is holding to anyone, which is
// precisely the leak the directives on the 200 were set to prevent.
func TestProtectedNotModifiedKeepsItsRestrictions(t *testing.T) {
	t.Parallel()

	body := []byte("ssh-ed25519 AAAA x\n")
	p := stubPublisher{body: body, protected: true}
	auth := http.Header{"Authorization": {"Bearer ak_good.secret"}}

	first := publishGet(t, p, http.MethodGet, "/alice/prod", auth)
	etag := first.Header().Get("ETag")
	if etag == "" {
		t.Fatal("the protected success carried no ETag")
	}

	conditional := http.Header{"Authorization": auth["Authorization"], "If-None-Match": {etag}}
	rr := publishGet(t, p, http.MethodGet, "/alice/prod", conditional)
	if rr.Code != http.StatusNotModified {
		t.Fatalf("status = %d, want 304", rr.Code)
	}
	assertHeader(t, rr, "Cache-Control", "private, max-age=60")
	assertHeader(t, rr, "Vary", "Authorization")
	assertHeader(t, rr, "ETag", etag)
}

// TestConditionalRequestCannotProbeAProtectedSet closes a way around the whole
// gate.
//
// If the If-None-Match check ran before authorization, a caller with no
// credential could send "If-None-Match: *" and read existence off a 304 — a
// 200-vs-304 oracle in place of the 401-vs-404 one the uniform 404 closes, and
// one that needs no valid token at all. The ordering that prevents it is that
// the service refuses before the handler ever reaches a validator, so an
// unauthorized conditional request is answered by the same 404 as any other.
func TestConditionalRequestCannotProbeAProtectedSet(t *testing.T) {
	t.Parallel()

	for _, inm := range []string{"*", `"deadbeef"`, `W/"deadbeef"`} {
		t.Run(inm, func(t *testing.T) {
			t.Parallel()

			rr := publishGet(t, stubPublisher{err: publish.ErrNotFound}, http.MethodGet,
				"/alice/prod", http.Header{"If-None-Match": {inm}})

			if rr.Code == http.StatusNotModified {
				t.Fatal("a conditional request answered 304 for a set the caller may not read; existence leaked without any credential")
			}
			if rr.Code != http.StatusNotFound {
				t.Errorf("status = %d, want 404", rr.Code)
			}
		})
	}
}

// TestCredentialIsTakenFromTheAuthorizationHeaderOnly pins that no other part
// of the request can carry an access key.
//
// A query parameter lands in proxy logs, browser history, and Referer headers;
// a cookie is attached by the client to requests it never intended to
// authenticate. Accepting either would mean a key set's credential leaks
// through channels its holder does not control. The assertion is on what
// reached the service, not on the status code, because a token that was read
// and then happened to be refused would look identical from outside and would
// still have been read.
func TestCredentialIsTakenFromTheAuthorizationHeaderOnly(t *testing.T) {
	t.Parallel()

	const secret = "ak_smuggled.secret"

	cases := map[string]struct {
		target string
		header http.Header
	}{
		"query parameter": {
			target: "/alice/prod?access_key=" + secret,
			header: nil,
		},
		"alternative query parameter": {
			target: "/alice/prod?token=" + secret,
			header: nil,
		},
		"cookie": {
			target: "/alice/prod",
			header: http.Header{"Cookie": {"access_key=" + secret}},
		},
		"custom header": {
			target: "/alice/prod",
			header: http.Header{"X-Access-Key": {secret}},
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var got string
			publishGet(t, stubPublisher{err: publish.ErrNotFound, gotToken: &got},
				http.MethodGet, tc.target, tc.header)

			if got != "" {
				t.Errorf("a credential smuggled in a %s reached the service as %q; only the Authorization header may carry one", name, got)
			}
		})
	}
}

// TestBearerTokenIsPassedThroughVerbatim is the other half of the test above:
// having pinned what must not be read, pin that what must be read arrives
// unaltered. A handler that trimmed, lowercased, or truncated the token would
// refuse every legitimate consumer while every test asserting a refusal
// continued to pass.
func TestBearerTokenIsPassedThroughVerbatim(t *testing.T) {
	t.Parallel()

	const token = "ak_0123456789.aBcDeF-_secret"

	var got string
	publishGet(t, stubPublisher{body: []byte("k\n"), protected: true, gotToken: &got},
		http.MethodGet, "/alice/prod", http.Header{"Authorization": {"Bearer " + token}})

	if got != token {
		t.Errorf("token reached the service as %q, want %q", got, token)
	}
}

// TestStorageFaultOnAProtectedSetIsNotA404 pins that an outage is loud.
//
// This is the one place the uniform 404 must NOT absorb something. A verifier
// that could not reach its database has not decided the caller is unauthorized;
// answering 404 for it would fail closed for every consumer at once while
// looking exactly like ordinary, correct operation, and nothing would page.
func TestStorageFaultOnAProtectedSetIsNotA404(t *testing.T) {
	t.Parallel()

	rr := publishGet(t, stubPublisher{err: errAccessKeyStoreDown}, http.MethodGet, "/alice/prod",
		http.Header{"Authorization": {"Bearer ak_good.secret"}})

	if rr.Code == http.StatusNotFound {
		t.Fatal("a storage fault was answered with 404; an outage is indistinguishable from every credential being wrong")
	}
	if rr.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rr.Code)
	}
	// The 500 must still say nothing about the set or the credential.
	if body := rr.Body.String(); body != "internal server error\n" {
		t.Errorf("body = %q, want the fixed internal-error text", body)
	}
	if got := rr.Header().Get("Vary"); got != "" {
		t.Errorf("Vary = %q on a fault; only a protected success carries it", got)
	}
}

// errAccessKeyStoreDown stands in for any non-verdict error out of the service.
var errAccessKeyStoreDown = fmt.Errorf("publish: verify access key: access key store unreachable")

// TestProtectedSetEndToEnd assembles the whole slice — a migrated database, the
// real access key service, the real publish service, the real router, and a
// real HTTP client — and asserts the two outcomes that matter over the wire.
//
// The tests above use a stub publisher, which is right for pinning the
// handler's behavior but cannot tell a refused credential from an absent set
// because the stub is where that distinction was erased. This one puts the real
// verifier behind the real handler, so a regression anywhere along the chain —
// a repository that stopped filtering by owner, a verifier that stopped
// comparing key set ids, a handler that started distinguishing — shows up here.
func TestProtectedSetEndToEnd(t *testing.T) {
	t.Parallel()

	// Wired first without the store, because the harness builds the store; the
	// verifier is injected through a closure the option resolves at call time.
	var keySvc *accesskey.Service
	e := newE2E(t, publish.WithVerifier(lazyVerifier{svc: &keySvc}))

	repos := e.store.Repos()
	built, err := accesskey.New(e.store, e2eAuditor{}, e2ePepper)
	if err != nil {
		t.Fatalf("accesskey.New: %v", err)
	}
	keySvc = built

	alice := e.seed("alice", "public-key")
	prod := &domain.KeySet{
		ID: "set-prod-alice", OwnerID: alice.OwnerID, Name: "prod",
		Visibility: domain.VisibilityProtected, State: domain.NameStateActive,
		CreatedAt: e2eNow, UpdatedAt: e2eNow,
	}
	if err := repos.KeySets.Create(context.Background(), prod); err != nil {
		t.Fatalf("KeySets.Create: %v", err)
	}
	e.addKey(alice.OwnerID, prod.ID, "prod-key")

	_, token, err := keySvc.Mint(context.Background(), alice.OwnerID, prod.ID, "consumer", "req-1")
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	// A credential for the owner's OTHER set — here, the public default one.
	// It is genuinely valid, genuinely this owner's, and must still not open
	// prod or reveal that prod exists.
	_, wrongSet, err := keySvc.Mint(context.Background(), alice.OwnerID, alice.KeySetID, "other", "req-2")
	if err != nil {
		t.Fatalf("Mint(other set): %v", err)
	}

	t.Run("the correct key is served privately", func(t *testing.T) {
		got := e.request(http.MethodGet, "/alice/prod", map[string]string{
			"Authorization": "Bearer " + token.Reveal(),
		})
		if got.status != http.StatusOK {
			t.Fatalf("status = %d, want 200; body = %q", got.status, got.body)
		}
		if !strings.Contains(got.body, "prod-key") {
			t.Errorf("body = %q, want the protected set's key", got.body)
		}
		if cc := got.header.Get("Cache-Control"); cc != "private, max-age=60" {
			t.Errorf("Cache-Control = %q, want private", cc)
		}
		if v := got.header.Get("Vary"); v != "Authorization" {
			t.Errorf("Vary = %q, want Authorization", v)
		}
	})

	t.Run("every refusal is the absent-set response", func(t *testing.T) {
		absent := e.request(http.MethodGet, "/alice/nosuchset", nil)
		if absent.status != http.StatusNotFound {
			t.Fatalf("the baseline was %d, not a 404", absent.status)
		}

		refusals := map[string]map[string]string{
			"no credential":            nil,
			"a garbage token":          {"Authorization": "Bearer garbage"},
			"the other set's real key": {"Authorization": "Bearer " + wrongSet.Reveal()},
		}
		for name, headers := range refusals {
			got := e.request(http.MethodGet, "/alice/prod", headers)
			if got.status != absent.status || got.body != absent.body {
				t.Errorf("%s: (%d, %q) differs from the absent set's (%d, %q)",
					name, got.status, got.body, absent.status, absent.body)
			}
			if v := got.header.Get("Vary"); v != "" {
				t.Errorf("%s: refusal carried Vary %q", name, v)
			}
			if etag := got.header.Get("ETag"); etag != "" {
				t.Errorf("%s: refusal carried ETag %q", name, etag)
			}
		}
	})
}

// e2ePepper is the fixed pepper the end-to-end access key service is keyed
// with. A constant is correct here: what is under test is which credentials
// open which sets, not the secrecy of this value.
var e2ePepper = []byte("0123456789abcdef0123456789abcdef")

// e2eAuditor satisfies the access key service's audit dependency. Verification
// emits nothing, and what the mint path records is that package's own test.
type e2eAuditor struct{}

func (e2eAuditor) Emit(context.Context, audit.Event) error { return nil }

// lazyVerifier resolves the real service at call time.
//
// It exists only to break a construction-order knot in the harness: the publish
// service is built with its options before the store it shares with the access
// key service exists. It adds no behavior — the call is forwarded verbatim, and
// a nil target would be a fixture bug rather than a code path, so it is failed
// loudly rather than turned into a refusal that a test could mistake for the
// verifier's own verdict.
type lazyVerifier struct{ svc **accesskey.Service }

func (v lazyVerifier) Verify(ctx context.Context, ownerID domain.OwnerID, setID domain.KeySetID, presented secrets.Redacted) (*domain.AccessKey, error) {
	if *v.svc == nil {
		panic("test fixture: the access key service was not built before a request reached the verifier")
	}
	return (*v.svc).Verify(ctx, ownerID, setID, presented)
}
