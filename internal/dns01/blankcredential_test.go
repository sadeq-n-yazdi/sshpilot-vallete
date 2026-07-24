package dns01

import (
	"errors"
	"strings"
	"testing"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/secrets"
)

// blankCredentials are the whitespace-only forms a DNS credential arrives in
// when the operator supplied whitespace instead of a token. The names keep the
// raw bytes out of test output.
var blankCredentials = []struct {
	name  string
	value string
}{
	{"empty", ""},
	{"space", " "},
	{"spaces", "   "},
	{"tab", "\t"},
	{"newline", "\n"},
	{"mixed ascii whitespace", " \t\r\n "},
	{"no-break space", "\u00a0"},
}

// TestAPIProvidersRejectBlankCredential is the constructor-level gate.
//
// It is a SEPARATE guard from the one in the secret providers, and it is worth
// having separately because it is independently reachable: NewAPIProvider is
// exported and takes a value, so any caller that resolves a credential some
// other way — a future secret provider, a test harness — reaches this and not
// the env/file check.
//
// Before this, the constructors compared the token against "" alone, so a
// credential of "   " built a provider, the process reported healthy, and the
// failure arrived as a TLS provisioning error at the first issuance.
//
// route53 is in the table to prove, rather than assert from a code read, that
// its stricter parse already covered this case.
func TestAPIProvidersRejectBlankCredential(t *testing.T) {
	t.Parallel()

	// Each provider's own sentinel is named, so the refusal is asserted to be
	// THIS one rather than any error at all. Without it a future check inserted
	// ahead of the blank gate — an unreachable-endpoint probe, a client-build
	// failure — would keep these tests green while the gate itself rotted.
	providers := []struct {
		name string
		want error
	}{
		{"cloudflare", ErrCloudflareAPI},
		{"route53", ErrRoute53API},
		{"digitalocean", ErrDigitalOceanAPI},
		{"dnsimple", ErrDNSimpleAPI},
		{"gandi", ErrGandiAPI},
		{"godaddy", ErrGoDaddyAPI},
		{"arvancloud", ErrArvanCloudAPI},
		{"gcp", ErrGCPAPI},
	}

	for _, prov := range providers {
		t.Run(prov.name, func(t *testing.T) {
			t.Parallel()

			for _, tc := range blankCredentials {
				t.Run(tc.name, func(t *testing.T) {
					t.Parallel()

					p, err := NewAPIProvider(prov.name, NewSingleCredential(secrets.Redacted(tc.value)), nil)
					if !errors.Is(err, prov.want) {
						t.Fatalf("err = %v, want %v", err, prov.want)
					}
					if p != nil {
						t.Fatal("a provider with no usable credential must not be returned")
					}
					if trimmed := strings.TrimSpace(tc.value); trimmed != "" && strings.Contains(err.Error(), trimmed) {
						t.Error("error must never echo the credential")
					}
				})
			}
		})
	}
}

// TestRoute53RejectsBlankCredentialHalves covers the blank shape only route53
// has: its credential is a packed "ACCESS_KEY_ID:SECRET_ACCESS_KEY" pair, so a
// credential can be blank in a HALF while the whole string is not blank at all.
//
// This case cannot live in the shared table above. "  :  " is correctly a
// perfectly ordinary token as far as the single-token providers are concerned —
// only route53 gives the colon meaning — so asserting a refusal of it for all
// four would be asserting the wrong thing for three of them.
//
// It is here because the sibling sweep found route53 ALREADY correct, and a
// claim that a guard works is worth only what a test that reaches it is worth.
// Without this, the route53 rows above pass through the "no colon at all"
// branch and never exercise the per-half check.
func TestRoute53RejectsBlankCredentialHalves(t *testing.T) {
	t.Parallel()

	tests := []struct{ name, credential string }{
		{"both halves blank", "  :  "},
		{"key id blank", "  :wJalrXUtnFEMI"},
		{"secret blank", "AKIDEXAMPLE:  "},
		{"secret is a newline", "AKIDEXAMPLE:\n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			p, err := NewAPIProvider("route53", NewSingleCredential(secrets.Redacted(tt.credential)), nil)
			if !errors.Is(err, ErrRoute53API) {
				t.Fatalf("err = %v, want ErrRoute53API", err)
			}
			if p != nil {
				t.Fatal("a provider with no usable credential must not be returned")
			}
			if strings.Contains(err.Error(), "AKIDEXAMPLE") || strings.Contains(err.Error(), "wJalrXUtnFEMI") {
				t.Error("error must never echo either half of the credential")
			}
		})
	}
}

// TestAPIProvidersAcceptCredentialWithSurroundingWhitespace records the other
// half of the decision, and guards against the fix being mistaken for a rule
// that rejects every credential carrying whitespace.
//
// A padded token is accepted here and, if it is genuinely wrong, fails visibly
// at the provider's API with the operator's own bytes — rather than being
// silently rewritten by a validation step.
func TestAPIProvidersAcceptCredentialWithSurroundingWhitespace(t *testing.T) {
	t.Parallel()

	tests := []struct{ provider, credential string }{
		{"cloudflare", "  cf-token  "},
		{"route53", "  AKIDEXAMPLE:wJalrXUtnFEMI  "},
		{"digitalocean", "  do-token  "},
		{"dnsimple", "  ds-token  "},
		{"gandi", "  gandi-token  "},
		{"godaddy", "  gd-key:gd-secret  "},
		{"arvancloud", "  arvan-key  "},
	}

	for _, tt := range tests {
		t.Run(tt.provider, func(t *testing.T) {
			t.Parallel()

			p, err := NewAPIProvider(tt.provider, NewSingleCredential(secrets.Redacted(tt.credential)), nil)
			if err != nil {
				t.Fatalf("a non-blank credential must build a provider: %v", err)
			}
			if p == nil {
				t.Fatal("provider must not be nil when construction succeeded")
			}
			if p.Name() != tt.provider {
				t.Errorf("Name = %q, want %q", p.Name(), tt.provider)
			}
		})
	}
}
