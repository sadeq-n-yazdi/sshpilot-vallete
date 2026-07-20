package httpserver

import (
	"bytes"
	"crypto/x509"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/config"
)

// TestSelfSignedRefusedUnlessExplicitlyDevelopment is the production-refusal
// test, and it is written as an ENUMERATION rather than a single "production is
// refused" case on purpose.
//
// The dangerous bug is not "production is allowed"; it is "anything that is not
// the literal string production is allowed". A check written as
// Environment == "production" passes a test that only ever sets "production"
// and "development", while silently permitting a self-signed certificate for
// "", "prod", "Production", "staging" and every typo an operator can make. Each
// of those is a real deployment that would serve a certificate no client can
// authenticate, so each is listed here.
//
// Note especially the UNSET case. config.Default() sets environment to
// production and config.Validate() rejects anything outside the enum, but
// buildTLSConfig accepts a *config.Config nobody has proven went through either,
// so the refusal must hold on a config constructed directly in code.
func TestSelfSignedRefusedUnlessExplicitlyDevelopment(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		environment string
		allow       bool
		wantRefused bool
	}{
		{name: "unset environment refuses", environment: "", wantRefused: true},
		{name: "production refuses", environment: "production", wantRefused: true},
		{name: "whitespace refuses", environment: " ", wantRefused: true},
		{name: "abbreviation refuses", environment: "prod", wantRefused: true},
		{name: "wrong case refuses", environment: "Production", wantRefused: true},
		{name: "staging refuses", environment: "staging", wantRefused: true},
		{name: "abbreviated development refuses", environment: "dev", wantRefused: true},
		{name: "capitalized development refuses", environment: "Development", wantRefused: true},
		{name: "development with trailing space refuses", environment: "development ", wantRefused: true},
		{name: "unrecognized value refuses", environment: "nonsense", wantRefused: true},

		{name: "development allows", environment: "development"},
		{name: "explicit override allows in production", environment: "production", allow: true},
		{name: "explicit override allows when unset", environment: "", allow: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			cfg := &config.Config{}
			cfg.Server.Environment = tc.environment
			cfg.TLS.AllowSelfSignedInProduction = tc.allow

			provider, err := newSelfSignedProvider(cfg, staticClock(certTestBase))

			if !tc.wantRefused {
				if err != nil {
					t.Fatalf("newSelfSignedProvider: %v", err)
				}
				if provider == nil {
					t.Error("an allowed configuration must yield a provider")
				}
				return
			}

			if !errors.Is(err, ErrSelfSignedInProduction) {
				t.Fatalf("err = %v, want ErrSelfSignedInProduction for environment %q", err, tc.environment)
			}
			if provider != nil {
				t.Error("a refused configuration must not yield a provider")
			}
			if !strings.Contains(err.Error(), "allow_self_signed_in_production") {
				t.Errorf("error should name the override knob: %v", err)
			}
		})
	}
}

// TestSelfSignedRefusesNilConfig covers the degenerate input. A nil config
// carries no evidence that this is a development instance, and absence of
// evidence must deny.
func TestSelfSignedRefusesNilConfig(t *testing.T) {
	t.Parallel()

	if _, err := newSelfSignedProvider(nil, staticClock(certTestBase)); !errors.Is(err, ErrSelfSignedInProduction) {
		t.Fatalf("err = %v, want ErrSelfSignedInProduction", err)
	}
	if !isProduction(nil) {
		t.Error("a nil config must be treated as production")
	}
}

// TestSelfSignedValidityCeiling enforces ADR-0015's guardrail: an ephemeral
// certificate may live at most ~6 hours.
//
// The ceiling is what stops the dev-only mode from becoming a steady-state
// production posture, so it is asserted on the constant AND on a real generated
// certificate — a constant nothing reads would be decoration.
func TestSelfSignedValidityCeiling(t *testing.T) {
	t.Parallel()

	const ceiling = 6 * time.Hour

	if selfSignedValidity > ceiling {
		t.Errorf("selfSignedValidity = %v, want at most %v (ADR-0015 guardrail)", selfSignedValidity, ceiling)
	}

	cert := mustSelfSigned(t, certTestBase)
	if got := cert.Leaf.NotAfter.Sub(certTestBase); got > ceiling {
		t.Errorf("generated certificate is valid for %v, want at most %v", got, ceiling)
	}

	// The skew allowance backdates NotBefore, so the total window is slightly
	// larger than the validity. Bound it too, or a large allowance could
	// reintroduce a long-lived certificate through the back door.
	if got := cert.Leaf.NotAfter.Sub(cert.Leaf.NotBefore); got > ceiling+5*time.Minute {
		t.Errorf("total validity window is %v, want at most %v", got, ceiling+5*time.Minute)
	}
}

// TestSelfSignedRenewsBeforeExpiry proves the provider returns DIFFERENT
// material over the process lifetime.
//
// This is the behavior that justifies CertProvider carrying GetCertificate's
// signature instead of a one-shot Load: with a 6-hour ceiling, a process running
// longer than that would otherwise hit the guard's expiry check and stop serving.
func TestSelfSignedRenewsBeforeExpiry(t *testing.T) {
	t.Parallel()

	now := certTestBase
	cfg := &config.Config{}
	cfg.Server.Environment = "development"

	provider, err := newSelfSignedProvider(cfg, func() time.Time { return now })
	if err != nil {
		t.Fatalf("newSelfSignedProvider: %v", err)
	}

	first, err := provider.GetCertificate(nil)
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}

	// Well inside the window: the SAME certificate is reused, so a busy server
	// is not minting a key per handshake.
	now = certTestBase.Add(time.Hour)
	again, err := provider.GetCertificate(nil)
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	if !bytes.Equal(first.Certificate[0], again.Certificate[0]) {
		t.Error("a certificate well inside its window must be reused")
	}

	// Inside the renewal threshold: new material, and it must be valid at a
	// point where the old certificate was not.
	now = certTestBase.Add(selfSignedValidity - selfSignedRenewBefore + time.Minute)
	renewed, err := provider.GetCertificate(nil)
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	if bytes.Equal(first.Certificate[0], renewed.Certificate[0]) {
		t.Fatal("the certificate must be renewed before it expires")
	}
	if !renewed.Leaf.NotAfter.After(first.Leaf.NotAfter) {
		t.Error("the renewed certificate must outlive the one it replaced")
	}

	// The renewed material must survive the guard, or renewal would merely
	// have replaced an expired certificate with an invalid one.
	guard := newCertGuard(provider, func() time.Time { return now })
	if _, err := guard.GetCertificate(nil); err != nil {
		t.Fatalf("renewed certificate must pass validation: %v", err)
	}
}

// TestSelfSignedProviderIsConcurrencySafe exercises the lazy-renewal path from
// many goroutines, because crypto/tls calls GetCertificate from every connection
// goroutine. Run under -race, this is what proves the mutex is doing its job.
func TestSelfSignedProviderIsConcurrencySafe(t *testing.T) {
	t.Parallel()

	cfg := &config.Config{}
	cfg.Server.Environment = "development"
	provider, err := newSelfSignedProvider(cfg, time.Now)
	if err != nil {
		t.Fatalf("newSelfSignedProvider: %v", err)
	}

	var wg sync.WaitGroup
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := provider.GetCertificate(nil); err != nil {
				t.Errorf("GetCertificate: %v", err)
			}
		}()
	}
	wg.Wait()
}

// TestSelfSignedCoversConfiguredHosts checks the generated certificate carries
// the names it is meant to, and that the loopback default applies when the
// operator configured none.
func TestSelfSignedCoversConfiguredHosts(t *testing.T) {
	t.Parallel()

	t.Run("configured domain and SANs", func(t *testing.T) {
		t.Parallel()

		cfg := &config.Config{}
		cfg.Server.Environment = "development"
		cfg.TLS.Domain = "vallet.example.com"
		cfg.TLS.SANs = []string{"alt.example.com", "10.0.0.5"}

		provider, err := newSelfSignedProvider(cfg, staticClock(certTestBase))
		if err != nil {
			t.Fatalf("newSelfSignedProvider: %v", err)
		}
		cert, err := provider.GetCertificate(nil)
		if err != nil {
			t.Fatalf("GetCertificate: %v", err)
		}

		if got := cert.Leaf.DNSNames; len(got) != 2 || got[0] != "vallet.example.com" || got[1] != "alt.example.com" {
			t.Errorf("DNSNames = %v, want the domain and its DNS SAN", got)
		}
		// An IP SAN must land in IPAddresses, not DNSNames, or clients
		// connecting by address will reject the certificate.
		if len(cert.Leaf.IPAddresses) != 1 || cert.Leaf.IPAddresses[0].String() != "10.0.0.5" {
			t.Errorf("IPAddresses = %v, want the IP SAN", cert.Leaf.IPAddresses)
		}
	})

	t.Run("defaults to loopback", func(t *testing.T) {
		t.Parallel()

		hosts := certHosts(nil)
		if len(hosts) != 3 || hosts[0] != "localhost" {
			t.Errorf("certHosts(nil) = %v, want the loopback set", hosts)
		}

		cfg := &config.Config{}
		if got := certHosts(cfg); len(got) != 3 {
			t.Errorf("certHosts(empty) = %v, want the loopback set", got)
		}
	})
}

// TestSelfSignedIsNotACertificateAuthority guards a subtle escalation. A
// developer who adds this certificate to a trust store must not thereby grant it
// the power to vouch for other names.
func TestSelfSignedIsNotACertificateAuthority(t *testing.T) {
	t.Parallel()

	leaf := mustSelfSigned(t, certTestBase).Leaf
	if leaf.IsCA {
		t.Error("the ephemeral certificate must not be a CA")
	}
	if leaf.KeyUsage&x509.KeyUsageCertSign != 0 {
		t.Error("the ephemeral certificate must not be allowed to sign certificates")
	}
}
