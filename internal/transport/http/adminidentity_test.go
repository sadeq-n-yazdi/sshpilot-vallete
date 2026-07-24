package httpserver_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/auth"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	httpserver "github.com/sadeq-n-yazdi/sshpilot-vallete/internal/transport/http"
)

// adminIDKey is a 36-byte signing key, comfortably past auth.MinSigningKeyLen.
// A constant is correct here: what is under test is whether the identifier
// verifies a token minted by the SAME key, not the secrecy of this value.
const adminIDKey = "0123456789abcdef0123456789abcdef0123"

// adminIDOtherKey is a different adequate key, used to forge a well-formed token
// the identifier must reject on signature.
const adminIDOtherKey = "ffffffffffffffffffffffffffffffff1234"

func adminSigner(t *testing.T, key string) *auth.AdminTokenSigner {
	t.Helper()
	s, err := auth.NewAdminTokenSigner([]byte(key))
	if err != nil {
		t.Fatalf("NewAdminTokenSigner: %v", err)
	}
	return s
}

// mintAdminToken signs an admin token for id with key, valid around now.
func mintAdminToken(t *testing.T, key string, id domain.AdministratorID, now time.Time) string {
	t.Helper()
	tok, err := adminSigner(t, key).Issue(id, "jti-"+string(id), now.Add(-time.Minute), now.Add(time.Hour))
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	return tok.Reveal()
}

// requestWithBearer builds a request carrying the bearer credential, or none
// when bearer is empty.
func requestWithBearer(bearer string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/api/v1/admin/reserved/allowlist", nil)
	if bearer != "" {
		r.Header.Set("Authorization", "Bearer "+bearer)
	}
	return r
}

func TestSignedAdminIdentifierResolvesValidToken(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	const want = domain.AdministratorID("adm-1")
	id := httpserver.NewSignedAdminIdentifier(adminSigner(t, adminIDKey), func() time.Time { return now })

	got := id.AdministratorID(requestWithBearer(mintAdminToken(t, adminIDKey, want, now)))
	if got != want {
		t.Fatalf("AdministratorID = %q, want %q", got, want)
	}
}

// TestSignedAdminIdentifierFailsClosed proves every failure resolves to the
// empty ID and is indistinguishable from the others -- the fail-closed contract
// listadmin depends on. The owner-token case is the security-critical one: an
// owner access token, even one signed with the SAME key bytes, must never
// resolve to an AdministratorID (ADR-0018).
func TestSignedAdminIdentifierFailsClosed(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	id := httpserver.NewSignedAdminIdentifier(adminSigner(t, adminIDKey), func() time.Time { return now })

	// A well-formed owner access token signed with the same key bytes.
	ownerSigner, err := auth.NewAccessTokenSigner([]byte(adminIDKey))
	if err != nil {
		t.Fatalf("NewAccessTokenSigner: %v", err)
	}
	ownerTok, err := ownerSigner.Issue(domain.AccessToken{
		ID:                  "at-1",
		OwnerID:             "own-1",
		RefreshCredentialID: "rc-1",
		Scopes:              []domain.Scope{{Kind: domain.ScopeFullOwner}},
		IssuedAt:            now.Add(-time.Minute),
		ExpiresAt:           now.Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("owner Issue: %v", err)
	}

	// A validly-signed admin token that has expired at now.
	expired, err := adminSigner(t, adminIDKey).Issue("adm-1", "jti-x", now.Add(-2*time.Hour), now.Add(-time.Hour))
	if err != nil {
		t.Fatalf("expired Issue: %v", err)
	}

	cases := map[string]*http.Request{
		"no header":          requestWithBearer(""),
		"garbage":            requestWithBearer("not-a-token"),
		"wrong key":          requestWithBearer(mintAdminToken(t, adminIDOtherKey, "adm-1", now)),
		"expired":            requestWithBearer(expired.Reveal()),
		"owner access token": requestWithBearer(ownerTok.Reveal()),
	}
	for name, req := range cases {
		t.Run(name, func(t *testing.T) {
			if got := id.AdministratorID(req); got != "" {
				t.Fatalf("AdministratorID = %q, want empty (fail-closed)", got)
			}
		})
	}
}

// TestSignedAdminIdentifierRejectsTwoAuthorizationHeaders proves the identifier
// inherits bearerToken's one-header rule: two Authorization headers are a
// request-smuggling shape and resolve to the empty ID, never to whichever header
// this layer happened to read.
func TestSignedAdminIdentifierRejectsTwoAuthorizationHeaders(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	id := httpserver.NewSignedAdminIdentifier(adminSigner(t, adminIDKey), func() time.Time { return now })

	r := httptest.NewRequest(http.MethodPost, "/api/v1/admin/reserved/allowlist", nil)
	r.Header.Add("Authorization", "Bearer "+mintAdminToken(t, adminIDKey, "adm-1", now))
	r.Header.Add("Authorization", "Bearer "+mintAdminToken(t, adminIDKey, "adm-1", now))
	if got := id.AdministratorID(r); got != "" {
		t.Fatalf("two Authorization headers resolved to %q, want empty", got)
	}
}

// TestNewSignedAdminIdentifierRefusesNilDependencies proves a wiring fault
// panics at construction rather than degrading into a per-request failure.
func TestNewSignedAdminIdentifierRefusesNilDependencies(t *testing.T) {
	t.Run("nil verifier", func(t *testing.T) {
		defer func() {
			if recover() == nil {
				t.Fatal("nil verifier did not panic")
			}
		}()
		httpserver.NewSignedAdminIdentifier(nil, time.Now)
	})
	t.Run("nil clock", func(t *testing.T) {
		defer func() {
			if recover() == nil {
				t.Fatal("nil clock did not panic")
			}
		}()
		httpserver.NewSignedAdminIdentifier(adminSigner(t, adminIDKey), nil)
	})
}
