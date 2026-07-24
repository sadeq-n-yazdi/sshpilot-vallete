package dns01

import (
	"errors"
	"strings"
	"testing"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/secrets"
)

// TestAPIProvidersRejectEmptyCredentialSet is the fail-closed gate at the seam:
// a zero Credentials value carries nothing, so every provider must refuse it
// with its own sentinel and return no provider. Single() reports absence, so
// the refusal is the "no credential" path rather than a misleading blank one.
func TestAPIProvidersRejectEmptyCredentialSet(t *testing.T) {
	t.Parallel()

	providers := []struct {
		name string
		want error
	}{
		{"cloudflare", ErrCloudflareAPI},
		{"route53", ErrRoute53API},
		{"digitalocean", ErrDigitalOceanAPI},
		{"dnsimple", ErrDNSimpleAPI},
		{"gandi", ErrGandiAPI},
		{"arvancloud", ErrArvanCloudAPI},
		{"namecheap", ErrNamecheapAPI},
		{"ovh", ErrOVHAPI},
	}

	for _, prov := range providers {
		t.Run(prov.name, func(t *testing.T) {
			t.Parallel()
			p, err := NewAPIProvider(prov.name, Credentials{}, nil)
			if !errors.Is(err, prov.want) {
				t.Fatalf("err = %v, want %v", err, prov.want)
			}
			if p != nil {
				t.Fatal("a provider with no credential must not be returned")
			}
		})
	}
}

// TestRoute53AcceptsNamedCredentials proves the named form (access_key_id +
// secret_access_key) builds a provider, and that it normalizes to EXACTLY the
// packed "keyID:secret" credential the existing (well-tested) signing path
// consumes — so the named path inherits that path's coverage rather than
// duplicating the fake-API harness.
func TestRoute53AcceptsNamedCredentials(t *testing.T) {
	t.Parallel()

	named, err := NewAPIProvider("route53", NewNamedCredentials(map[string]secrets.Redacted{
		"access_key_id":     secrets.NewRedacted(testAWSKeyID),
		"secret_access_key": secrets.NewRedacted(testAWSSecret),
	}), nil)
	if err != nil {
		t.Fatalf("NewAPIProvider(route53, named): %v", err)
	}

	packed, err := NewRoute53(NewSingleCredential(secrets.NewRedacted(testAWSCred)), nil)
	if err != nil {
		t.Fatalf("NewRoute53(packed): %v", err)
	}

	gotNamed := named.(*route53Provider).credential.Reveal()
	wantPacked := packed.(*route53Provider).credential.Reveal()
	if gotNamed != wantPacked {
		t.Error("named credentials did not normalize to the packed keyID:secret form")
	}
}

// TestRoute53AcceptsSingleEntryNamedCredentialsAsPacked confirms a lone named
// entry falls through Single() and is treated as the packed single form, so an
// operator who put the packed pair under one arbitrary key still works.
func TestRoute53AcceptsSingleEntryNamedCredentialsAsPacked(t *testing.T) {
	t.Parallel()

	p, err := NewAPIProvider("route53", NewNamedCredentials(map[string]secrets.Redacted{
		"credentials": secrets.NewRedacted(testAWSCred),
	}), nil)
	if err != nil {
		t.Fatalf("NewAPIProvider(route53, one named entry): %v", err)
	}
	if p == nil {
		t.Fatal("provider must not be nil")
	}
}

// TestRoute53RejectsPartialNamedCredentials is the abuse case the advisor
// flagged: exactly one named half present must REFUSE, not silently
// colon-split the lone value into the wrong parts. The error must name neither
// half.
func TestRoute53RejectsPartialNamedCredentials(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		creds map[string]secrets.Redacted
	}{
		{"only access_key_id", map[string]secrets.Redacted{
			"access_key_id": secrets.NewRedacted(testAWSKeyID),
		}},
		{"only secret_access_key", map[string]secrets.Redacted{
			"secret_access_key": secrets.NewRedacted(testAWSSecret),
		}},
		// The dangerous case the explicit partial guard exists for: an operator
		// pastes the packed "id:secret" pair into access_key_id and leaves the
		// secret unset. Without the guard this lone entry would fall through to
		// the single-value path and be colon-split into the wrong halves and
		// silently accepted. It must be refused.
		{"packed pair pasted into access_key_id", map[string]secrets.Redacted{
			"access_key_id": secrets.NewRedacted(testAWSCred),
		}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p, err := NewAPIProvider("route53", NewNamedCredentials(tc.creds), nil)
			if !errors.Is(err, ErrRoute53API) {
				t.Fatalf("err = %v, want ErrRoute53API", err)
			}
			if p != nil {
				t.Fatal("a provider with an incomplete credential must not be returned")
			}
			if strings.Contains(err.Error(), testAWSKeyID) || strings.Contains(err.Error(), testAWSSecret) {
				t.Error("error must never echo a credential half")
			}
		})
	}
}
