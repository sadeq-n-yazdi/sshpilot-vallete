package auth_test

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/auth"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/secrets"
)

// The token wire format is fixed by the package and restated here as literals
// on purpose: a test that derived the format from the same constants the code
// uses would keep passing if the format changed underneath it, and an access
// token is a value other systems will parse.
const (
	accessPrefix = "sva_"
	tokenSep     = "."
)

var tokenEnc = base64.RawURLEncoding

// signingKey returns a deterministic test key of the minimum accepted length.
func signingKey(fill byte) []byte {
	k := make([]byte, auth.MinSigningKeyLen)
	for i := range k {
		k[i] = fill + byte(i)
	}
	return k
}

func newSigner(t *testing.T, fill byte) *auth.AccessTokenSigner {
	t.Helper()
	s, err := auth.NewAccessTokenSigner(signingKey(fill))
	if err != nil {
		t.Fatalf("NewAccessTokenSigner: %v", err)
	}
	return s
}

// sampleAccess builds a well-formed access token value issued at issuedAt.
func sampleAccess(issuedAt time.Time) domain.AccessToken {
	return domain.AccessToken{
		ID:                  "tok-1",
		OwnerID:             "own-1",
		RefreshCredentialID: "rc-1",
		Scopes:              []domain.Scope{{Kind: domain.ScopeFullOwner}},
		IssuedAt:            issuedAt,
		ExpiresAt:           issuedAt.Add(auth.AccessTokenLifetime),
	}
}

func TestNewAccessTokenSignerRejectsShortKey(t *testing.T) {
	for _, n := range []int{0, 1, auth.MinSigningKeyLen - 1} {
		s, err := auth.NewAccessTokenSigner(make([]byte, n))
		if !errors.Is(err, domain.ErrInvalidInput) {
			t.Fatalf("key of %d bytes: error = %v, want ErrInvalidInput", n, err)
		}
		if s != nil {
			t.Fatalf("key of %d bytes: got a signer despite the error", n)
		}
	}
}

// TestNewAccessTokenSignerCopiesKey proves the signer cannot be re-keyed by a
// caller that reuses or zeroes the buffer it passed in. Sharing the buffer
// would let unrelated code invalidate every live token, or worse, set the key
// to something guessable.
func TestNewAccessTokenSignerCopiesKey(t *testing.T) {
	key := signingKey(1)
	s, err := auth.NewAccessTokenSigner(key)
	if err != nil {
		t.Fatalf("NewAccessTokenSigner: %v", err)
	}
	now := time.Unix(1_700_000_000, 0).UTC()
	tok, err := s.Issue(sampleAccess(now))
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	for i := range key {
		key[i] = 0
	}
	if _, err := s.Verify(tok, now); err != nil {
		t.Fatalf("zeroing the caller's key buffer broke verification: %v", err)
	}
}

func TestAccessTokenRoundTrip(t *testing.T) {
	s := newSigner(t, 1)
	now := time.Unix(1_700_000_000, 0).UTC()
	want := sampleAccess(now)
	want.Scopes = []domain.Scope{
		{Kind: domain.ScopeReadOnly},
		{Kind: domain.ScopeSingleSet, ResourceID: "ks-1"},
	}

	raw, err := s.Issue(want)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if !strings.HasPrefix(raw.Reveal(), accessPrefix) {
		t.Fatalf("token %q lacks the access prefix", raw.Reveal())
	}

	got, err := s.Verify(raw, now)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got.ID != want.ID || got.OwnerID != want.OwnerID || got.RefreshCredentialID != want.RefreshCredentialID {
		t.Fatalf("claims = %+v, want ids from %+v", got, want)
	}
	if !got.IssuedAt.Equal(want.IssuedAt) || !got.ExpiresAt.Equal(want.ExpiresAt) {
		t.Fatalf("times = (%v, %v), want (%v, %v)", got.IssuedAt, got.ExpiresAt, want.IssuedAt, want.ExpiresAt)
	}
	if len(got.Scopes) != len(want.Scopes) {
		t.Fatalf("got %d scopes, want %d", len(got.Scopes), len(want.Scopes))
	}
	for i := range want.Scopes {
		if got.Scopes[i] != want.Scopes[i] {
			t.Fatalf("scope %d = %+v, want %+v", i, got.Scopes[i], want.Scopes[i])
		}
	}
}

func TestAccessTokenIssueRejectsMalformedInput(t *testing.T) {
	s := newSigner(t, 1)
	now := time.Unix(1_700_000_000, 0).UTC()

	tests := []struct {
		name string
		mut  func(*domain.AccessToken)
	}{
		{name: "no id", mut: func(a *domain.AccessToken) { a.ID = "" }},
		{name: "no owner", mut: func(a *domain.AccessToken) { a.OwnerID = "" }},
		{name: "no refresh credential", mut: func(a *domain.AccessToken) { a.RefreshCredentialID = "" }},
		{name: "no scopes", mut: func(a *domain.AccessToken) { a.Scopes = nil }},
		{name: "invalid scope", mut: func(a *domain.AccessToken) {
			a.Scopes = []domain.Scope{{Kind: domain.ScopeKind("nonsense")}}
		}},
		{name: "expires before issuance", mut: func(a *domain.AccessToken) { a.ExpiresAt = a.IssuedAt.Add(-time.Second) }},
		{name: "expires at issuance", mut: func(a *domain.AccessToken) { a.ExpiresAt = a.IssuedAt }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tok := sampleAccess(now)
			tt.mut(&tok)
			raw, err := s.Issue(tok)
			if !errors.Is(err, domain.ErrInvalidInput) {
				t.Fatalf("error = %v, want ErrInvalidInput", err)
			}
			if raw.Reveal() != "" {
				t.Fatal("a rejected issuance still returned a token")
			}
		})
	}
}

// macOf recomputes the MAC the signer built from signingKey(1) would produce
// over a first segment. The test knows the key, so it can forge a validly
// signed token carrying claims no honest issuer would emit -- which is the only
// way to reach the checks that run after the MAC has already been accepted.
func macOf(encoded string) string {
	h := hmac.New(sha256.New, signingKey(1))
	h.Write([]byte(encoded))
	return tokenEnc.EncodeToString(h.Sum(nil))
}

// craft assembles a token carrying the given raw payload, signed with
// signingKey(1).
func craft(payload []byte) secrets.Redacted {
	encoded := tokenEnc.EncodeToString(payload)
	return secrets.NewRedacted(accessPrefix + encoded + tokenSep + macOf(encoded))
}

func TestAccessTokenVerifyRejects(t *testing.T) {
	s := newSigner(t, 1)
	other := newSigner(t, 99)
	now := time.Unix(1_700_000_000, 0).UTC()

	valid, err := s.Issue(sampleAccess(now))
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	fromOther, err := other.Issue(sampleAccess(now))
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	body := strings.TrimPrefix(valid.Reveal(), accessPrefix)
	encoded, mac, _ := strings.Cut(body, tokenSep)

	// A payload that decodes to valid JSON but carries a claim this version
	// does not define. Ignoring it is how a restriction silently disappears.
	unknownField := craft([]byte(`{"v":1,"jti":"a","own":"o","ref":"r","scp":[{"k":"full-owner"}],"iat":1700000000,"exp":1700000900,"admin":true}`))
	badVersion := craft([]byte(`{"v":2,"jti":"a","own":"o","ref":"r","scp":[{"k":"full-owner"}],"iat":1700000000,"exp":1700000900}`))
	noOwner := craft([]byte(`{"v":1,"jti":"a","own":"","ref":"r","scp":[{"k":"full-owner"}],"iat":1700000000,"exp":1700000900}`))
	noID := craft([]byte(`{"v":1,"jti":"","own":"o","ref":"r","scp":[{"k":"full-owner"}],"iat":1700000000,"exp":1700000900}`))
	noRefresh := craft([]byte(`{"v":1,"jti":"a","own":"o","ref":"","scp":[{"k":"full-owner"}],"iat":1700000000,"exp":1700000900}`))
	noScopes := craft([]byte(`{"v":1,"jti":"a","own":"o","ref":"r","scp":[],"iat":1700000000,"exp":1700000900}`))
	badScope := craft([]byte(`{"v":1,"jti":"a","own":"o","ref":"r","scp":[{"k":"nonsense"}],"iat":1700000000,"exp":1700000900}`))
	notJSON := craft([]byte(`{"v":1,`))

	// A first segment that is validly MAC'd but is not valid base64, reachable
	// only by someone holding the key -- which the test does.
	badBase64 := secrets.NewRedacted(accessPrefix + "***" + tokenSep + macOf("***"))

	tests := []struct {
		name string
		raw  secrets.Redacted
		now  time.Time
	}{
		{name: "empty", raw: secrets.NewRedacted(""), now: now},
		{name: "no prefix", raw: secrets.NewRedacted(body), now: now},
		{name: "refresh prefix", raw: secrets.NewRedacted("svr_" + body), now: now},
		{name: "no separator", raw: secrets.NewRedacted(accessPrefix + encoded), now: now},
		{name: "extra separator", raw: secrets.NewRedacted(valid.Reveal() + tokenSep + "x"), now: now},
		{name: "mac not base64", raw: secrets.NewRedacted(accessPrefix + encoded + tokenSep + "***"), now: now},
		{name: "truncated mac", raw: secrets.NewRedacted(accessPrefix + encoded + tokenSep + mac[:len(mac)-2]), now: now},
		{name: "empty mac", raw: secrets.NewRedacted(accessPrefix + encoded + tokenSep), now: now},
		{name: "signed by another key", raw: fromOther, now: now},
		{name: "payload tampered", raw: secrets.NewRedacted(accessPrefix + tokenEnc.EncodeToString([]byte(`{"v":1,"jti":"a","own":"attacker","ref":"r","scp":[{"k":"full-owner"}],"iat":1700000000,"exp":1700000900}`)) + tokenSep + mac), now: now},
		{name: "first segment not base64", raw: badBase64, now: now},
		{name: "payload not json", raw: notJSON, now: now},
		{name: "unknown claim", raw: unknownField, now: now},
		{name: "wrong version", raw: badVersion, now: now},
		{name: "empty owner claim", raw: noOwner, now: now},
		{name: "empty id claim", raw: noID, now: now},
		{name: "empty refresh claim", raw: noRefresh, now: now},
		{name: "empty scope set", raw: noScopes, now: now},
		{name: "invalid scope", raw: badScope, now: now},
		{name: "presented before issuance", raw: valid, now: now.Add(-time.Second)},
		{name: "presented at expiry", raw: valid, now: now.Add(auth.AccessTokenLifetime)},
		{name: "presented after expiry", raw: valid, now: now.Add(auth.AccessTokenLifetime + time.Second)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := s.Verify(tt.raw, tt.now)
			if !errors.Is(err, auth.ErrAuthFailed) {
				t.Fatalf("error = %v, want ErrAuthFailed", err)
			}
			// The denial must carry no cause: a wrapped reason is readable
			// through errors.Is and reinstates the distinction the sentinel
			// exists to erase.
			if !errors.Is(err, auth.ErrAuthFailed) || errors.Unwrap(err) != nil {
				t.Fatalf("error %v carries a cause", err)
			}
			if got != nil {
				t.Fatal("a rejected token still yielded claims")
			}
		})
	}
}

// TestAccessTokenExpiryBoundary pins the exact instant an access token stops
// being accepted. The boundary is half-open: valid up to but excluding
// ExpiresAt.
func TestAccessTokenExpiryBoundary(t *testing.T) {
	s := newSigner(t, 1)
	issued := time.Unix(1_700_000_000, 0).UTC()
	expires := issued.Add(auth.AccessTokenLifetime)
	raw, err := s.Issue(sampleAccess(issued))
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	tests := []struct {
		name  string
		now   time.Time
		valid bool
	}{
		{name: "at issuance", now: issued, valid: true},
		{name: "one nanosecond before expiry", now: expires.Add(-time.Nanosecond), valid: true},
		{name: "exactly at expiry", now: expires, valid: false},
		{name: "one nanosecond after expiry", now: expires.Add(time.Nanosecond), valid: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := s.Verify(raw, tt.now)
			if tt.valid && err != nil {
				t.Fatalf("token rejected at %v: %v", tt.now, err)
			}
			if !tt.valid && !errors.Is(err, auth.ErrAuthFailed) {
				t.Fatalf("token accepted at %v (err=%v), want ErrAuthFailed", tt.now, err)
			}
		})
	}
}

// TestAccessTokenIsRedacted proves the issued token cannot escape through a
// formatting or marshaling path.
func TestAccessTokenIsRedacted(t *testing.T) {
	s := newSigner(t, 1)
	now := time.Unix(1_700_000_000, 0).UTC()
	raw, err := s.Issue(sampleAccess(now))
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	secret := raw.Reveal()

	renderings := []string{
		raw.String(),
		strings.Join([]string{
			fmt.Sprintf("%v", raw), fmt.Sprintf("%s", raw), fmt.Sprintf("%q", raw),
			fmt.Sprintf("%#v", raw), fmt.Sprintf("%+v", struct{ T secrets.Redacted }{raw}),
		}, " "),
	}
	blob, err := json.Marshal(raw)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	renderings = append(renderings, string(blob))

	for _, r := range renderings {
		if strings.Contains(r, secret) {
			t.Fatalf("rendering %q leaked the access token", r)
		}
	}
}

// TestSignerRedactsItsKey proves the signing key cannot escape through any
// formatting, marshaling, or logging path.
//
// The key is unexported, which protects nothing: fmt prints unexported fields,
// so a signer caught in a "%+v" of an enclosing config struct, or passed to
// slog, would print the one secret that forges every access token this service
// will ever issue. The needles cover the three shapes the key would take --
// raw string, Go byte-slice literal, and the base64 a JSON handler emits.
func TestSignerRedactsItsKey(t *testing.T) {
	key := signingKey(1)
	signer := newSigner(t, 1)

	needles := []string{
		string(key),
		fmt.Sprintf("%d", key),
		base64.StdEncoding.EncodeToString(key),
		tokenEnc.EncodeToString(key),
	}

	var textLog, jsonLog bytes.Buffer
	slog.New(slog.NewTextHandler(&textLog, nil)).Info("cfg", "signer", signer)
	slog.New(slog.NewJSONHandler(&jsonLog, nil)).Info("cfg", "signer", *signer)

	blob, err := json.Marshal(signer)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	text, err := signer.MarshalText()
	if err != nil {
		t.Fatalf("MarshalText: %v", err)
	}

	renderings := map[string]string{
		"String":     signer.String(),
		"GoString":   signer.GoString(),
		"%v pointer": fmt.Sprintf("%v", signer),
		"%v value":   fmt.Sprintf("%v", *signer),
		"%s":         fmt.Sprintf("%s", signer),
		"%+v":        fmt.Sprintf("%+v", *signer),
		"%#v":        fmt.Sprintf("%#v", *signer),
		"nested ptr": fmt.Sprintf("%+v", struct{ S *auth.AccessTokenSigner }{signer}),
		"nested val": fmt.Sprintf("%+v", struct{ S auth.AccessTokenSigner }{*signer}),
		"json":       string(blob),
		"text":       string(text),
		"slog text":  textLog.String(),
		"slog json":  jsonLog.String(),
		"slog value": signer.LogValue().String(),
	}
	for name, r := range renderings {
		for _, needle := range needles {
			if strings.Contains(r, needle) {
				t.Fatalf("%s leaked the signing key: %s", name, r)
			}
		}
		if !strings.Contains(r, "[REDACTED]") {
			t.Fatalf("%s does not show the redaction marker: %s", name, r)
		}
	}

	// Redacting must not have broken signing.
	if _, err := signer.Issue(sampleAccess(baseTime)); err != nil {
		t.Fatalf("Issue after redaction: %v", err)
	}
}
