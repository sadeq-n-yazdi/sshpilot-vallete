package auth

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/secrets"
)

// The token primitives are unexported on purpose -- nothing outside this
// package has any business hashing a secret or splitting a token -- so they are
// exercised from an in-package test. Everything with an exported surface is
// tested from auth_test.

func TestRandomBytesLengthAndVariation(t *testing.T) {
	const n = refreshSecretBytes
	first := randomBytes(n)
	if len(first) != n {
		t.Fatalf("randomBytes(%d) returned %d bytes", n, len(first))
	}
	// Two draws colliding would mean the generator is not random. The odds of a
	// false failure here are 2^-256.
	if bytes.Equal(first, randomBytes(n)) {
		t.Fatal("two draws from randomBytes were identical")
	}
	// An all-zero buffer is what a generator that silently did nothing returns.
	if bytes.Equal(first, make([]byte, n)) {
		t.Fatal("randomBytes returned an all-zero buffer")
	}
}

func TestNewCredentialIDShapeAndUniqueness(t *testing.T) {
	seen := make(map[domain.RefreshCredentialID]struct{}, 100)
	for range 100 {
		id := newCredentialID()
		if len(id) != credentialIDChars {
			t.Fatalf("credential id %q has length %d, want %d", id, len(id), credentialIDChars)
		}
		if strings.Contains(string(id), tokenSeparator) {
			t.Fatalf("credential id %q contains the token separator", id)
		}
		if _, dup := seen[id]; dup {
			t.Fatalf("credential id %q was generated twice", id)
		}
		seen[id] = struct{}{}
	}
}

func TestHashRefreshSecretIsSHA256AndNotTheSecret(t *testing.T) {
	secret := randomBytes(refreshSecretBytes)
	got := hashRefreshSecret(secret)

	want := sha256.Sum256(secret)
	if !bytes.Equal(got, want[:]) {
		t.Fatal("hashRefreshSecret is not SHA-256 of the secret")
	}
	if bytes.Contains(got, secret) {
		t.Fatal("the digest contains the raw secret")
	}
	// Determinism: the same secret must hash the same way, or no stored hash
	// would ever match.
	if !bytes.Equal(got, hashRefreshSecret(secret)) {
		t.Fatal("hashRefreshSecret is not deterministic")
	}
}

func TestSecretMatches(t *testing.T) {
	secret := randomBytes(refreshSecretBytes)
	stored := hashRefreshSecret(secret)

	if !secretMatches(stored, secret) {
		t.Fatal("the correct secret did not match its own digest")
	}

	// A single flipped bit must not match.
	wrong := append([]byte(nil), secret...)
	wrong[0] ^= 0x01
	if secretMatches(stored, wrong) {
		t.Fatal("a secret differing in one bit matched")
	}

	tests := []struct {
		name   string
		stored []byte
		secret []byte
	}{
		{name: "empty stored hash", stored: nil, secret: secret},
		{name: "truncated stored hash", stored: stored[:16], secret: secret},
		{name: "empty secret", stored: stored, secret: nil},
		{name: "stored hash equal to the raw secret", stored: secret, secret: secret},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if secretMatches(tt.stored, tt.secret) {
				t.Fatal("match reported, want no match")
			}
		})
	}
}

func TestRefreshTokenRoundTrip(t *testing.T) {
	id := newCredentialID()
	secret := randomBytes(refreshSecretBytes)

	raw := formatRefreshToken(id, secret)
	if !strings.HasPrefix(raw.Reveal(), refreshTokenPrefix) {
		t.Fatalf("token %q lacks the refresh prefix", raw.Reveal())
	}

	gotID, gotSecret, err := parseRefreshToken(raw)
	if err != nil {
		t.Fatalf("parseRefreshToken: %v", err)
	}
	if gotID != id {
		t.Fatalf("parsed id %q, want %q", gotID, id)
	}
	if !bytes.Equal(gotSecret, secret) {
		t.Fatal("parsed secret differs from the one formatted")
	}
}

func TestParseRefreshTokenRejectsMalformed(t *testing.T) {
	id := string(newCredentialID())
	secret := tokenEncoding.EncodeToString(randomBytes(refreshSecretBytes))

	tests := []struct {
		name string
		raw  string
	}{
		{name: "empty", raw: ""},
		{name: "no prefix", raw: id + tokenSeparator + secret},
		{name: "access token prefix", raw: accessTokenPrefix + id + tokenSeparator + secret},
		{name: "no separator", raw: refreshTokenPrefix + id + secret},
		{name: "extra separator", raw: refreshTokenPrefix + id + tokenSeparator + secret + tokenSeparator + "x"},
		{name: "short id", raw: refreshTokenPrefix + id[:credentialIDChars-1] + tokenSeparator + secret},
		{name: "long id", raw: refreshTokenPrefix + id + "A" + tokenSeparator + secret},
		{name: "id not base64", raw: refreshTokenPrefix + strings.Repeat("*", credentialIDChars) + tokenSeparator + secret},
		{name: "secret not base64", raw: refreshTokenPrefix + id + tokenSeparator + strings.Repeat("*", 43)},
		{name: "secret too short", raw: refreshTokenPrefix + id + tokenSeparator + tokenEncoding.EncodeToString(randomBytes(16))},
		{name: "secret too long", raw: refreshTokenPrefix + id + tokenSeparator + tokenEncoding.EncodeToString(randomBytes(64))},
		{name: "empty secret", raw: refreshTokenPrefix + id + tokenSeparator},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotID, gotSecret, err := parseRefreshToken(secrets.NewRedacted(tt.raw))
			if !errors.Is(err, ErrAuthFailed) {
				t.Fatalf("error = %v, want ErrAuthFailed", err)
			}
			if gotID != "" || gotSecret != nil {
				t.Fatalf("a rejected token yielded id %q and a %d-byte secret", gotID, len(gotSecret))
			}
		})
	}
}

func TestCloneScopes(t *testing.T) {
	if got := cloneScopes(nil); got != nil {
		t.Fatalf("cloneScopes(nil) = %v, want nil", got)
	}
	if got := cloneScopes([]domain.Scope{}); got != nil {
		t.Fatalf("cloneScopes(empty) = %v, want nil", got)
	}

	orig := []domain.Scope{{Kind: domain.ScopeSingleSet, ResourceID: "ks-1"}}
	clone := cloneScopes(orig)
	// Mutating the original must not reach the clone: a stored entity and a
	// caller's slice sharing a backing array is how a grant gets widened after
	// it was validated.
	orig[0].ResourceID = "ks-2"
	if clone[0].ResourceID != "ks-1" {
		t.Fatal("cloneScopes shares a backing array with its input")
	}
}

func TestValidateClientLabel(t *testing.T) {
	tests := []struct {
		name    string
		label   string
		wantErr bool
	}{
		{name: "empty is allowed", label: ""},
		{name: "ordinary label", label: "sadeq's laptop"},
		{name: "non-ascii", label: "دفتر"},
		{name: "at the length bound", label: strings.Repeat("a", MaxClientLabelLen)},
		{name: "over the length bound", label: strings.Repeat("a", MaxClientLabelLen+1), wantErr: true},
		{name: "invalid utf-8", label: "\xff\xfe", wantErr: true},
		{name: "newline", label: "laptop\nadmin=true", wantErr: true},
		{name: "terminal escape", label: "laptop\x1b[31m", wantErr: true},
		{name: "nul", label: "laptop\x00", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateClientLabel(tt.label)
			if tt.wantErr && !errors.Is(err, domain.ErrInvalidInput) {
				t.Fatalf("error = %v, want ErrInvalidInput", err)
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestAccountWideScope(t *testing.T) {
	tests := []struct {
		kind domain.ScopeKind
		want bool
	}{
		{kind: domain.ScopeFullOwner, want: true},
		{kind: domain.ScopeReadOnly, want: true},
		{kind: domain.ScopeSingleSet, want: false},
		{kind: domain.ScopeSingleDevice, want: false},
		{kind: domain.ScopeKind("nonsense"), want: false},
	}
	for _, tt := range tests {
		t.Run(string(tt.kind), func(t *testing.T) {
			if got := accountWideScope(tt.kind); got != tt.want {
				t.Fatalf("accountWideScope(%q) = %v, want %v", tt.kind, got, tt.want)
			}
		})
	}
}
