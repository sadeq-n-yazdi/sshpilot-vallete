package config

import (
	"errors"
	"strings"
	"testing"
)

// validConfig returns a Config that passes Validate, used as the baseline that
// each failure case mutates in exactly one way.
func validConfig() Config {
	c := Default()
	c.Server.Environment = "production"
	c.Server.PublicBaseURL = "https://vallet.example.com"
	c.TLS.Mode = "acme"
	c.TLS.Domain = "vallet.example.com"
	c.TLS.ACME.Solver = "tls_alpn_01"
	c.Auth.TokenSigningKeyRef = "env:VALLET_SIGNING_KEY"
	return c
}

func TestValidateBaselineValid(t *testing.T) {
	c := validConfig()
	if err := c.Validate(); err != nil {
		t.Fatalf("baseline should be valid, got: %v", err)
	}
}

func TestValidateReturnsNilNotEmptyAggregate(t *testing.T) {
	c := validConfig()
	err := c.Validate()
	if err != nil {
		t.Fatalf("want nil error, got %v", err)
	}
	// Guard against returning a non-nil zero-length ValidationErrors.
	if err != nil {
		t.Fatal("interface should be nil")
	}
}

func TestValidateFailures(t *testing.T) {
	tests := []struct {
		name  string
		mut   func(c *Config)
		field string
	}{
		{"bad environment", func(c *Config) { c.Server.Environment = "staging" }, "server.environment"},
		{"missing public url", func(c *Config) { c.Server.PublicBaseURL = "" }, "server.public_base_url"},
		{"non-https public url", func(c *Config) { c.Server.PublicBaseURL = "http://x.example.com" }, "server.public_base_url"},
		{"missing tls mode", func(c *Config) { c.TLS.Mode = "" }, "tls.mode"},
		{"unknown tls mode", func(c *Config) { c.TLS.Mode = "weird" }, "tls.mode"},
		{"acme missing domain", func(c *Config) { c.TLS.Domain = "" }, "tls.domain"},
		{"acme ip domain in prod", func(c *Config) { c.TLS.Domain = "203.0.113.5" }, "tls.domain"},
		{"acme localhost in prod", func(c *Config) { c.TLS.Domain = "localhost" }, "tls.domain"},
		{"acme dotless in prod", func(c *Config) { c.TLS.Domain = "vallet" }, "tls.domain"},
		{"acme missing solver", func(c *Config) { c.TLS.ACME.Solver = "" }, "tls.acme.solver"},
		{"acme bad solver", func(c *Config) { c.TLS.ACME.Solver = "http_01" }, "tls.acme.solver"},
		{"dns api missing provider", func(c *Config) {
			c.TLS.ACME.Solver = "dns_01"
			c.TLS.ACME.DNS.Mode = "api"
			c.TLS.ACME.DNS.CredentialsRef = "env:X"
		}, "tls.acme.dns.provider"},
		{"dns api missing creds", func(c *Config) {
			c.TLS.ACME.Solver = "dns_01"
			c.TLS.ACME.DNS.Mode = "api"
			c.TLS.ACME.DNS.Provider = "cloudflare"
		}, "tls.acme.dns.credentials_ref"},
		{"cloudflare missing token", func(c *Config) {
			c.TLS.Mode = "cloudflare_origin"
		}, "tls.cloudflare_origin.api_token_ref"},
		{"manual missing cert", func(c *Config) {
			c.TLS.Mode = "manual"
			c.TLS.Manual.KeyFile = "/k"
		}, "tls.manual.cert_file"},
		{"upstream no proxies", func(c *Config) {
			c.TLS.Mode = "upstream"
		}, "server.trusted_proxies"},
		{"csr missing domain", func(c *Config) {
			c.TLS.Mode = "csr"
			c.TLS.Domain = ""
		}, "tls.domain"},
		{"self signed prod refused", func(c *Config) {
			c.TLS.Mode = "self_signed"
		}, "tls.mode"},
		{"postgres missing dsn", func(c *Config) {
			c.Database.Driver = "postgres"
		}, "database.postgres.dsn_ref"},
		{"sqlite missing path", func(c *Config) {
			c.Database.SQLite.Path = ""
		}, "database.sqlite.path"},
		{"unknown driver", func(c *Config) {
			c.Database.Driver = "mysql"
		}, "database.driver"},
		{"access ttl zero", func(c *Config) {
			c.Auth.AccessTokenTTL = 0
		}, "auth.access_token_ttl"},
		{"access ttl too long", func(c *Config) {
			c.Auth.AccessTokenTTL = Duration(48 * 3600 * 1e9)
		}, "auth.access_token_ttl"},
		{"refresh not greater", func(c *Config) {
			c.Auth.RefreshTokenMaxAge = c.Auth.AccessTokenTTL
		}, "auth.refresh_token_max_age"},
		{"no providers", func(c *Config) {
			c.Auth.Providers.APIToken.Enabled = false
			c.Auth.Providers.Passkey.Enabled = false
			c.Auth.Providers.OIDC.Enabled = false
		}, "auth.providers"},
		{"prod missing signing key", func(c *Config) {
			c.Auth.TokenSigningKeyRef = ""
		}, "auth.token_signing_key_ref"},
		{"shared missing address", func(c *Config) {
			c.RateLimit.Store = "shared"
		}, "rate_limit.shared.address"},
		{"unknown store", func(c *Config) {
			c.RateLimit.Store = "disk"
		}, "rate_limit.store"},
		{"tier zero requests", func(c *Config) {
			c.RateLimit.Tiers.Auth.Requests = 0
		}, "rate_limit.tiers.auth.requests"},
		{"tier zero window", func(c *Config) {
			c.RateLimit.Tiers.Publish.Window = 0
		}, "rate_limit.tiers.publish.window"},
		{"otlp missing endpoint", func(c *Config) {
			c.Telemetry.Metrics.OTLP.Enabled = true
		}, "telemetry.metrics.otlp.endpoint"},
		{"traces missing endpoint", func(c *Config) {
			c.Telemetry.Traces.Enabled = true
		}, "telemetry.traces.endpoint"},
		{"bad onboarding", func(c *Config) {
			c.Onboarding.Mode = "closed"
		}, "onboarding.mode"},
		{"retention quarantine zero", func(c *Config) {
			c.Retention.HandleQuarantine = 0
		}, "retention.handle_quarantine"},
		{"retention audit zero", func(c *Config) {
			c.Retention.AuditRetention = 0
		}, "retention.audit_retention"},
		{"max sets zero", func(c *Config) {
			c.Retention.MaxSetsPerOwner = 0
		}, "retention.max_sets_per_owner"},
		{"malformed ref", func(c *Config) {
			c.Database.Postgres.DSNRef = "notaref"
		}, "database.postgres.dsn_ref"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := validConfig()
			tc.mut(&c)
			err := c.Validate()
			if err == nil {
				t.Fatalf("expected validation error for field %s", tc.field)
			}
			if !strings.Contains(err.Error(), tc.field) {
				t.Errorf("error %q does not mention field %s", err, tc.field)
			}
		})
	}
}

func TestValidateTrustedProxies(t *testing.T) {
	tests := []struct {
		name    string
		proxies []string
		wantErr bool
	}{
		{"valid ip", []string{"10.0.0.1"}, false},
		{"valid ipv6", []string{"2001:db8::1"}, false},
		{"valid cidr", []string{"10.0.0.0/8"}, false},
		{"valid cidr ipv6", []string{"2001:db8::/32"}, false},
		{"mixed valid", []string{"10.0.0.1", "192.168.0.0/16"}, false},
		{"invalid string", []string{"not-an-ip"}, true},
		{"empty entry", []string{""}, true},
		{"cidr missing mask", []string{"10.0.0.0/"}, true},
		{"one bad among good", []string{"10.0.0.1", "garbage"}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := validConfig()
			c.Server.TrustedProxies = tc.proxies
			err := c.Validate()
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected validation error for proxies %v", tc.proxies)
				}
				if !strings.Contains(err.Error(), "server.trusted_proxies") {
					t.Errorf("error %q does not name server.trusted_proxies", err)
				}
			} else if err != nil {
				t.Fatalf("proxies %v should be valid, got: %v", tc.proxies, err)
			}
		})
	}
}

func TestValidateCollectsAllProblems(t *testing.T) {
	c := validConfig()
	c.Server.Environment = "staging"
	c.TLS.Mode = ""
	c.Onboarding.Mode = "closed"
	err := c.Validate()
	var verrs ValidationErrors
	if !errors.As(err, &verrs) {
		t.Fatalf("want ValidationErrors, got %T", err)
	}
	if len(verrs) < 3 {
		t.Errorf("expected >=3 problems, got %d: %v", len(verrs), verrs)
	}
}

func TestValidateDevelopmentRelaxations(t *testing.T) {
	c := validConfig()
	c.Server.Environment = "development"
	c.Server.PublicBaseURL = ""    // allowed in dev
	c.TLS.Domain = "localhost"     // FQDN strictness relaxed in dev
	c.Auth.TokenSigningKeyRef = "" // signing key not required in dev
	if err := c.Validate(); err != nil {
		t.Fatalf("development config should be valid: %v", err)
	}
}
