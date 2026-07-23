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

// The admin token wire format is fixed by the package and restated here as a
// literal on purpose: a test that derived the format from the same constant the
// code uses would keep passing if the format changed underneath it, and an
// admin token is a value an operator copies by hand.
const adminPrefix = "sadm_"

func newAdminSigner(t *testing.T, fill byte) *auth.AdminTokenSigner {
	t.Helper()
	s, err := auth.NewAdminTokenSigner(signingKey(fill))
	if err != nil {
		t.Fatalf("NewAdminTokenSigner: %v", err)
	}
	return s
}

// adminMacOf recomputes the MAC the signer built from signingKey(fill) would
// produce over a first segment. Knowing the key lets a test forge a validly
// signed token carrying claims no honest issuer would emit -- the only way to
// reach the checks that run after the MAC has already been accepted.
func adminMacOf(encoded string, fill byte) string {
	h := hmac.New(sha256.New, signingKey(fill))
	h.Write([]byte(encoded))
	return tokenEnc.EncodeToString(h.Sum(nil))
}

// craftAdmin assembles an admin token carrying the given raw payload, signed
// with signingKey(1).
func craftAdmin(payload []byte) secrets.Redacted {
	encoded := tokenEnc.EncodeToString(payload)
	return secrets.NewRedacted(adminPrefix + encoded + tokenSep + adminMacOf(encoded, 1))
}

func TestNewAdminTokenSignerRejectsShortKey(t *testing.T) {
	for _, n := range []int{0, 1, auth.MinSigningKeyLen - 1} {
		s, err := auth.NewAdminTokenSigner(make([]byte, n))
		if !errors.Is(err, domain.ErrInvalidInput) {
			t.Fatalf("key of %d bytes: error = %v, want ErrInvalidInput", n, err)
		}
		if s != nil {
			t.Fatalf("key of %d bytes: got a signer despite the error", n)
		}
	}
}

// TestNewAdminTokenSignerCopiesKey proves the signer cannot be re-keyed by a
// caller that reuses or zeroes the buffer it passed in.
func TestNewAdminTokenSignerCopiesKey(t *testing.T) {
	key := signingKey(1)
	s, err := auth.NewAdminTokenSigner(key)
	if err != nil {
		t.Fatalf("NewAdminTokenSigner: %v", err)
	}
	now := baseTime
	tok, err := s.Issue("adm-1", "jti-1", now, now.Add(time.Hour))
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

// TestNewAdminTokenID proves the jti helper produces non-empty, distinct,
// decodable identifiers -- it is the one RNG path the signer offers and a
// collision or an empty value would break audit correlation.
func TestNewAdminTokenID(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 64; i++ {
		id := auth.NewAdminTokenID()
		if id == "" {
			t.Fatal("NewAdminTokenID returned an empty id")
		}
		if _, err := base64.RawURLEncoding.DecodeString(id); err != nil {
			t.Fatalf("id %q is not raw-url base64: %v", id, err)
		}
		if seen[id] {
			t.Fatalf("NewAdminTokenID repeated %q", id)
		}
		seen[id] = true
	}
}

func TestAdminTokenRoundTrip(t *testing.T) {
	s := newAdminSigner(t, 1)
	now := baseTime
	const wantID = domain.AdministratorID("adm-42")

	raw, err := s.Issue(wantID, "jti-1", now, now.Add(time.Hour))
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if !strings.HasPrefix(raw.Reveal(), adminPrefix) {
		t.Fatalf("token %q lacks the admin prefix", raw.Reveal())
	}
	// The owner and admin prefixes must be distinct, so an owner access token can
	// never be mistaken for an admin token on shape.
	if strings.HasPrefix(raw.Reveal(), accessPrefix) {
		t.Fatalf("admin token %q also matches the owner access prefix", raw.Reveal())
	}

	got, err := s.Verify(raw, now)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got != wantID {
		t.Fatalf("Verify returned %q, want %q", got, wantID)
	}
}

func TestAdminTokenIssueRejectsMalformedInput(t *testing.T) {
	s := newAdminSigner(t, 1)
	now := baseTime

	tests := []struct {
		name              string
		id                domain.AdministratorID
		jti               string
		issuedAt, expires time.Time
	}{
		{name: "no admin id", id: "", jti: "j", issuedAt: now, expires: now.Add(time.Hour)},
		{name: "no jti", id: "adm-1", jti: "", issuedAt: now, expires: now.Add(time.Hour)},
		{name: "expires before issuance", id: "adm-1", jti: "j", issuedAt: now, expires: now.Add(-time.Second)},
		{name: "expires at issuance", id: "adm-1", jti: "j", issuedAt: now, expires: now},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw, err := s.Issue(tt.id, tt.jti, tt.issuedAt, tt.expires)
			if !errors.Is(err, domain.ErrInvalidInput) {
				t.Fatalf("error = %v, want ErrInvalidInput", err)
			}
			if raw.Reveal() != "" {
				t.Fatal("a rejected issuance still returned a token")
			}
		})
	}
}

func TestAdminTokenVerifyRejects(t *testing.T) {
	s := newAdminSigner(t, 1)
	other := newAdminSigner(t, 99)
	now := baseTime

	valid, err := s.Issue("adm-1", "jti-1", now, now.Add(time.Hour))
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	// A well-formed admin token signed by a DIFFERENT adequate key: it must be
	// rejected on the MAC, which is the forgery case the whole scheme rests on.
	fromOther, err := other.Issue("adm-1", "jti-1", now, now.Add(time.Hour))
	if err != nil {
		t.Fatalf("Issue (other): %v", err)
	}
	// A genuine OWNER access token, signed with the same key bytes: it must be
	// refused on prefix and shape, proving an owner credential never resolves to
	// an AdministratorID (ADR-0018).
	ownerSigner, err := auth.NewAccessTokenSigner(signingKey(1))
	if err != nil {
		t.Fatalf("NewAccessTokenSigner: %v", err)
	}
	ownerToken, err := ownerSigner.Issue(domain.AccessToken{
		ID:                  "at-1",
		OwnerID:             "own-1",
		RefreshCredentialID: "rc-1",
		Scopes:              []domain.Scope{{Kind: domain.ScopeFullOwner}},
		IssuedAt:            now,
		ExpiresAt:           now.Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("owner Issue: %v", err)
	}

	body := strings.TrimPrefix(valid.Reveal(), adminPrefix)
	encoded, mac, _ := strings.Cut(body, tokenSep)

	unknownField := craftAdmin([]byte(`{"v":1,"jti":"j","adm":"adm-1","iat":1700000000,"exp":1700003600,"root":true}`))
	badVersion := craftAdmin([]byte(`{"v":2,"jti":"j","adm":"adm-1","iat":1700000000,"exp":1700003600}`))
	noAdmin := craftAdmin([]byte(`{"v":1,"jti":"j","adm":"","iat":1700000000,"exp":1700003600}`))
	notJSON := craftAdmin([]byte(`{"v":1,`))
	// A first segment that is validly MAC'd but is not valid base64, reachable
	// only by someone holding the key -- which the test does.
	badBase64 := secrets.NewRedacted(adminPrefix + "***" + tokenSep + adminMacOf("***", 1))
	// A validly-signed payload whose adm names a different administrator: proves
	// the returned id comes from the signed claims, not from anywhere an attacker
	// controls without the key.
	tamperedAdm := secrets.NewRedacted(adminPrefix + tokenEnc.EncodeToString([]byte(`{"v":1,"jti":"j","adm":"attacker","iat":1700000000,"exp":1700003600}`)) + tokenSep + mac)

	tests := []struct {
		name string
		raw  secrets.Redacted
		now  time.Time
	}{
		{name: "empty", raw: secrets.NewRedacted(""), now: now},
		{name: "no prefix", raw: secrets.NewRedacted(body), now: now},
		{name: "owner access token", raw: secrets.NewRedacted(ownerToken.Reveal()), now: now},
		{name: "owner prefix on payload", raw: secrets.NewRedacted(accessPrefix + body), now: now},
		{name: "no separator", raw: secrets.NewRedacted(adminPrefix + encoded), now: now},
		{name: "extra separator", raw: secrets.NewRedacted(valid.Reveal() + tokenSep + "x"), now: now},
		{name: "mac not base64", raw: secrets.NewRedacted(adminPrefix + encoded + tokenSep + "***"), now: now},
		{name: "truncated mac", raw: secrets.NewRedacted(adminPrefix + encoded + tokenSep + mac[:len(mac)-2]), now: now},
		{name: "empty mac", raw: secrets.NewRedacted(adminPrefix + encoded + tokenSep), now: now},
		{name: "signed by another key", raw: fromOther, now: now},
		{name: "payload tampered", raw: tamperedAdm, now: now},
		{name: "first segment not base64", raw: badBase64, now: now},
		{name: "payload not json", raw: notJSON, now: now},
		{name: "unknown claim", raw: unknownField, now: now},
		{name: "wrong version", raw: badVersion, now: now},
		{name: "empty admin claim", raw: noAdmin, now: now},
		{name: "presented before issuance", raw: valid, now: now.Add(-time.Second)},
		{name: "presented at expiry", raw: valid, now: now.Add(time.Hour)},
		{name: "presented after expiry", raw: valid, now: now.Add(time.Hour + time.Second)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := s.Verify(tt.raw, tt.now)
			if !errors.Is(err, auth.ErrAuthFailed) {
				t.Fatalf("error = %v, want ErrAuthFailed", err)
			}
			// The denial must carry no cause: a wrapped reason is readable through
			// errors.Is and reinstates the distinction the sentinel exists to erase.
			if errors.Unwrap(err) != nil {
				t.Fatalf("error %v carries a cause", err)
			}
			if got != "" {
				t.Fatalf("a rejected token still yielded an administrator id %q", got)
			}
		})
	}
}

// TestAdminTokenExpiryBoundary pins the exact instant an admin token stops being
// accepted. The boundary is half-open: valid up to but excluding the expiry.
func TestAdminTokenExpiryBoundary(t *testing.T) {
	s := newAdminSigner(t, 1)
	issued := baseTime
	expires := issued.Add(time.Hour)
	raw, err := s.Issue("adm-1", "jti-1", issued, expires)
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

// TestAdminTokenIsRedacted proves the issued token cannot escape through a
// formatting or marshaling path.
func TestAdminTokenIsRedacted(t *testing.T) {
	s := newAdminSigner(t, 1)
	raw, err := s.Issue("adm-1", "jti-1", baseTime, baseTime.Add(time.Hour))
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	secret := raw.Reveal()

	renderings := []string{
		raw.String(),
		fmt.Sprintf("%v", raw), fmt.Sprintf("%s", raw), fmt.Sprintf("%q", raw),
		fmt.Sprintf("%#v", raw), fmt.Sprintf("%+v", struct{ T secrets.Redacted }{raw}),
	}
	blob, err := json.Marshal(raw)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	renderings = append(renderings, string(blob))

	for _, r := range renderings {
		if strings.Contains(r, secret) {
			t.Fatalf("rendering %q leaked the admin token", r)
		}
	}
}

// TestAdminSignerRedactsItsKey proves the signing key cannot escape through any
// formatting, marshaling, or logging path. The key is unexported, which protects
// nothing: fmt prints unexported fields, so a signer caught in a "%+v" of an
// enclosing config struct, or passed to slog, would print the one secret that
// forges every administrator token this service will ever issue.
func TestAdminSignerRedactsItsKey(t *testing.T) {
	key := signingKey(1)
	signer := newAdminSigner(t, 1)

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
		"nested ptr": fmt.Sprintf("%+v", struct{ S *auth.AdminTokenSigner }{signer}),
		"nested val": fmt.Sprintf("%+v", struct{ S auth.AdminTokenSigner }{*signer}),
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
	if _, err := signer.Issue("adm-1", "jti-1", baseTime, baseTime.Add(time.Hour)); err != nil {
		t.Fatalf("Issue after redaction: %v", err)
	}
}
