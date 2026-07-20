package auth_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/auth"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/secrets"
)

func TestProviderIDValidate(t *testing.T) {
	tests := []struct {
		name    string
		id      auth.ProviderID
		wantErr bool
	}{
		{name: "simple", id: "oidc"},
		{name: "hyphenated", id: "api-token"},
		{name: "digits", id: "oidc2"},
		{name: "max length", id: auth.ProviderID(strings.Repeat("a", auth.MaxProviderIDLen))},
		{name: "empty", id: "", wantErr: true},
		{name: "too long", id: auth.ProviderID(strings.Repeat("a", auth.MaxProviderIDLen+1)), wantErr: true},
		{name: "uppercase", id: "OIDC", wantErr: true},
		{name: "leading hyphen", id: "-oidc", wantErr: true},
		{name: "trailing hyphen", id: "oidc-", wantErr: true},
		{name: "underscore", id: "api_token", wantErr: true},
		// The separator cases are the security-relevant ones: a provider id
		// containing ':' or '/' could be crafted to make a composed key
		// ambiguous, so the charset must exclude them.
		{name: "colon separator", id: "api:token", wantErr: true},
		{name: "slash separator", id: "api/token", wantErr: true},
		{name: "dot separator", id: "api.token", wantErr: true},
		{name: "nul byte", id: "api\x00token", wantErr: true},
		{name: "space", id: "api token", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.id.Validate()
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ProviderID(%q).Validate() = nil, want error", tt.id)
				}
				if !errors.Is(err, domain.ErrInvalidInput) {
					t.Fatalf("error %v does not wrap domain.ErrInvalidInput", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("ProviderID(%q).Validate() = %v, want nil", tt.id, err)
			}
			if got := tt.id.String(); got != string(tt.id) {
				t.Fatalf("String() = %q, want %q", got, string(tt.id))
			}
		})
	}
}

func TestPrincipalValidate(t *testing.T) {
	tests := []struct {
		name    string
		p       auth.Principal
		wantErr bool
	}{
		{name: "opaque subject", p: "1234567890"},
		{name: "base64url credential id", p: "AAECAwQFBgcICQoLDA0ODw_-"},
		{name: "contains colon", p: "urn:example:sub"},
		{name: "unicode", p: "üser"},
		{name: "max length", p: auth.Principal(strings.Repeat("a", auth.MaxPrincipalLen))},
		{name: "empty", p: "", wantErr: true},
		{name: "too long", p: auth.Principal(strings.Repeat("a", auth.MaxPrincipalLen+1)), wantErr: true},
		{name: "invalid utf8", p: auth.Principal([]byte{0xff, 0xfe}), wantErr: true},
		{name: "nul byte", p: "abc\x00def", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.p.Validate()
			if tt.wantErr {
				if err == nil {
					t.Fatalf("Principal(%q).Validate() = nil, want error", tt.p)
				}
				if !errors.Is(err, domain.ErrInvalidInput) {
					t.Fatalf("error %v does not wrap domain.ErrInvalidInput", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Principal(%q).Validate() = %v, want nil", tt.p, err)
			}
		})
	}
}

func TestIdentityValidate(t *testing.T) {
	tests := []struct {
		name    string
		id      auth.Identity
		wantErr bool
	}{
		{name: "valid", id: auth.Identity{Provider: "oidc", Principal: "sub-1"}},
		{name: "bad provider", id: auth.Identity{Provider: "OIDC", Principal: "sub-1"}, wantErr: true},
		{name: "bad principal", id: auth.Identity{Provider: "oidc", Principal: ""}, wantErr: true},
		{name: "both bad", id: auth.Identity{}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.id.Validate()
			if (err != nil) != tt.wantErr {
				t.Fatalf("Validate() = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestCredentialNeverRendersSecret drives every rendering path a Credential
// exposes and asserts the secret text appears in none of them. It covers the
// realistic leak: a Credential logged as a field of a surrounding struct.
func TestCredentialNeverRendersSecret(t *testing.T) {
	const secret = "super-secret-bearer-token"
	cred := auth.Credential{Secret: secrets.NewRedacted(secret)}
	wrapper := struct {
		Cred auth.Credential
		Note string
	}{Cred: cred, Note: "ctx"}

	renders := map[string]string{}
	renders["String"] = cred.String()
	renders["GoString"] = cred.GoString()
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%d"} {
		renders["fmt "+verb] = fmt.Sprintf(verb, cred)
		renders["wrapped "+verb] = fmt.Sprintf(verb, wrapper)
	}
	text, err := cred.MarshalText()
	if err != nil {
		t.Fatalf("MarshalText: %v", err)
	}
	renders["MarshalText"] = string(text)

	raw, err := json.Marshal(cred)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	renders["json"] = string(raw)
	wrapped, err := json.Marshal(wrapper)
	if err != nil {
		t.Fatalf("json.Marshal wrapper: %v", err)
	}
	renders["json wrapper"] = string(wrapped)

	for name, out := range renders {
		if strings.Contains(out, secret) {
			t.Fatalf("%s leaked the secret: %s", name, out)
		}
		if !strings.Contains(out, "[REDACTED]") {
			t.Fatalf("%s did not redact: %s", name, out)
		}
	}

	// The value must still be recoverable through the one deliberate exit.
	if got := cred.Secret.Reveal(); got != secret {
		t.Fatalf("Reveal() = %q, want %q", got, secret)
	}
	// The marshaled JSON must remain valid JSON, not a bare unquoted token.
	var decoded string
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("marshaled credential is not valid JSON: %v", err)
	}
}
