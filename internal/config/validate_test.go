package config

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/secrets"
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
	c.TLS.ACME.AccountKeyFile = "/var/lib/vallet/acme/account.key"
	c.TLS.ACME.CacheDir = "/var/lib/vallet/acme"
	c.TLS.ACME.AcceptTOS = true
	c.Auth.TokenSigningKeyRef = "env:VALLET_SIGNING_KEY"
	c.Auth.AccessKeyPepperRef = "env:VALLET_ACCESS_KEY_PEPPER"
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
		{"tls min version below floor", func(c *Config) { c.TLS.MinVersion = "1.0" }, "tls.min_version"},
		{"tls min version empty", func(c *Config) { c.TLS.MinVersion = "" }, "tls.min_version"},
		{"tls min version unknown", func(c *Config) { c.TLS.MinVersion = "TLSv1.3" }, "tls.min_version"},
		{"unknown tls mode", func(c *Config) { c.TLS.Mode = "weird" }, "tls.mode"},
		{"acme missing domain", func(c *Config) { c.TLS.Domain = "" }, "tls.domain"},
		{"acme ip domain in prod", func(c *Config) { c.TLS.Domain = "203.0.113.5" }, "tls.domain"},
		{"acme localhost in prod", func(c *Config) { c.TLS.Domain = "localhost" }, "tls.domain"},
		{"acme dotless in prod", func(c *Config) { c.TLS.Domain = "vallet" }, "tls.domain"},
		{"acme missing solver", func(c *Config) { c.TLS.ACME.Solver = "" }, "tls.acme.solver"},
		{"acme bad solver", func(c *Config) { c.TLS.ACME.Solver = "http_01" }, "tls.acme.solver"},
		// The account-level settings are required for EVERY solver, so each is
		// asserted under tls_alpn_01 (the baseline) and again under dns_01
		// below: a check accidentally scoped to one solver would let the other
		// reach issuance with no account key, no cache, or no TOS agreement.
		{"acme missing account key", func(c *Config) { c.TLS.ACME.AccountKeyFile = "" }, "tls.acme.account_key_file"},
		{"acme missing cache dir", func(c *Config) { c.TLS.ACME.CacheDir = "" }, "tls.acme.cache_dir"},
		{"acme missing tos", func(c *Config) { c.TLS.ACME.AcceptTOS = false }, "tls.acme.accept_tos"},
		{"acme blank directory url", func(c *Config) { c.TLS.ACME.DirectoryURL = "" }, "tls.acme.directory_url"},
		{"dns_01 missing account key", func(c *Config) {
			c.TLS.ACME.Solver = "dns_01"
			c.TLS.ACME.DNS.Mode = "manual"
			c.TLS.ACME.AccountKeyFile = ""
		}, "tls.acme.account_key_file"},
		{"dns_01 missing cache dir", func(c *Config) {
			c.TLS.ACME.Solver = "dns_01"
			c.TLS.ACME.DNS.Mode = "manual"
			c.TLS.ACME.CacheDir = ""
		}, "tls.acme.cache_dir"},
		{"dns_01 missing tos", func(c *Config) {
			c.TLS.ACME.Solver = "dns_01"
			c.TLS.ACME.DNS.Mode = "manual"
			c.TLS.ACME.AcceptTOS = false
		}, "tls.acme.accept_tos"},
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
		{"dns api both cred sources", func(c *Config) {
			c.TLS.ACME.Solver = "dns_01"
			c.TLS.ACME.DNS.Mode = "api"
			c.TLS.ACME.DNS.Provider = "cloudflare"
			c.TLS.ACME.DNS.CredentialsRef = "env:X"
			c.TLS.ACME.DNS.CredentialsRefs = map[string]secrets.Ref{"access_key_id": "env:Y"}
		}, "tls.acme.dns.credentials_refs"},
		{"dns api named cred empty value", func(c *Config) {
			c.TLS.ACME.Solver = "dns_01"
			c.TLS.ACME.DNS.Mode = "api"
			c.TLS.ACME.DNS.Provider = "route53"
			c.TLS.ACME.DNS.CredentialsRefs = map[string]secrets.Ref{"access_key_id": ""}
		}, "tls.acme.dns.credentials_refs.access_key_id"},
		{"dns api named cred empty name", func(c *Config) {
			c.TLS.ACME.Solver = "dns_01"
			c.TLS.ACME.DNS.Mode = "api"
			c.TLS.ACME.DNS.Provider = "route53"
			c.TLS.ACME.DNS.CredentialsRefs = map[string]secrets.Ref{"": "env:Y"}
		}, "tls.acme.dns.credentials_refs"},
		{"dns_01 missing mode", func(c *Config) {
			c.TLS.ACME.Solver = "dns_01"
		}, "tls.acme.dns.mode"},
		{"dns_01 unknown mode", func(c *Config) {
			c.TLS.ACME.Solver = "dns_01"
			c.TLS.ACME.DNS.Mode = "automatic"
			c.TLS.ACME.DNS.Provider = "cloudflare"
			c.TLS.ACME.DNS.CredentialsRef = "env:X"
		}, "tls.acme.dns.mode"},
		{"cloudflare missing token", func(c *Config) {
			c.TLS.Mode = "cloudflare_origin"
		}, "tls.cloudflare_origin.api_token_ref"},
		// cache_dir is required rather than defaulted for the same reason
		// tls.acme.cache_dir is: without it every restart re-requests a
		// certificate, so a crash loop floods the API and churns keys.
		{"cloudflare missing cache dir", func(c *Config) {
			c.TLS.Mode = "cloudflare_origin"
			c.TLS.Domain = "vallet.example.com"
			c.TLS.CloudflareOrigin.APITokenRef = "env:X"
			c.Server.TrustedProxies = []string{"192.0.2.0/24"}
		}, "tls.cloudflare_origin.cache_dir"},
		// Cloudflare accepts only a fixed set of lifetimes. Anything else is
		// rejected by the API with an opaque error, so it is caught at startup
		// where the operator can actually act on it.
		{"cloudflare invalid validity", func(c *Config) {
			c.TLS.Mode = "cloudflare_origin"
			c.TLS.Domain = "vallet.example.com"
			c.TLS.CloudflareOrigin.APITokenRef = "env:X"
			c.TLS.CloudflareOrigin.CacheDir = "/tmp/cf"
			c.TLS.CloudflareOrigin.ValidityDays = 400
			c.Server.TrustedProxies = []string{"192.0.2.0/24"}
		}, "tls.cloudflare_origin.validity_days"},
		// A domain is required: it is what the CSR's hostnames are built from,
		// and Cloudflare refuses a certificate for a name outside the zone.
		{"cloudflare missing domain", func(c *Config) {
			c.TLS.Mode = "cloudflare_origin"
			c.TLS.Domain = ""
			c.TLS.CloudflareOrigin.APITokenRef = "env:X"
			c.TLS.CloudflareOrigin.CacheDir = "/tmp/cf"
			c.Server.TrustedProxies = []string{"192.0.2.0/24"}
		}, "tls.domain"},
		{"manual missing cert", func(c *Config) {
			c.TLS.Mode = "manual"
			c.TLS.Manual.KeyFile = "/k"
		}, "tls.manual.cert_file"},
		{"manual missing key", func(c *Config) {
			c.TLS.Mode = "manual"
			c.TLS.Manual.CertFile = "/c"
		}, "tls.manual.key_file"},
		{"upstream no proxies", func(c *Config) {
			c.TLS.Mode = "upstream"
		}, "server.trusted_proxies"},
		{"csr missing domain", func(c *Config) {
			c.TLS.Mode = "csr"
			c.TLS.Domain = ""
		}, "tls.domain"},
		// The three csr paths have no defaults on purpose: a default key path
		// would have the server create key material somewhere the operator
		// never chose, and a key nobody knows exists is a key nobody protects.
		{"csr missing key file", func(c *Config) {
			c.TLS.Mode = "csr"
			c.TLS.Domain = "vallet.example.com"
			c.TLS.CSR.CSRFile = "/tmp/v.csr"
			c.TLS.CSR.CertFile = "/tmp/v.crt"
		}, "tls.csr.key_file"},
		{"csr missing csr file", func(c *Config) {
			c.TLS.Mode = "csr"
			c.TLS.Domain = "vallet.example.com"
			c.TLS.CSR.KeyFile = "/tmp/v.key"
			c.TLS.CSR.CertFile = "/tmp/v.crt"
		}, "tls.csr.csr_file"},
		{"csr missing cert file", func(c *Config) {
			c.TLS.Mode = "csr"
			c.TLS.Domain = "vallet.example.com"
			c.TLS.CSR.KeyFile = "/tmp/v.key"
			c.TLS.CSR.CSRFile = "/tmp/v.csr"
		}, "tls.csr.cert_file"},
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
		{"retention audit negative", func(c *Config) {
			c.Retention.AuditRetention = Duration(-time.Hour)
		}, "retention.audit_retention"},
		{"purge interval negative", func(c *Config) {
			c.Retention.AuditPurgeInterval = Duration(-time.Second)
		}, "retention.audit_purge_interval"},
		{"purge batch zero", func(c *Config) {
			c.Retention.AuditPurgeBatch = 0
		}, "retention.audit_purge_batch"},
		{"purge batch negative", func(c *Config) {
			c.Retention.AuditPurgeBatch = -1
		}, "retention.audit_purge_batch"},
		{"purge max per run zero", func(c *Config) {
			c.Retention.AuditPurgeMaxPerRun = 0
		}, "retention.audit_purge_max_per_run"},
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

// TestValidateRefErrorDoesNotLeakValue guards the one validation path that
// handles fields an operator may have mistakenly filled with a secret instead
// of a reference to one. The error must name the field so the mistake is
// fixable, and must not reproduce the value, which would land in startup logs.
func TestValidateRefErrorDoesNotLeakValue(t *testing.T) {
	const secretish = "sup3rs3cr3t-password-value"

	tests := []struct {
		name  string
		mut   func(c *Config)
		field string
	}{
		{"postgres dsn", func(c *Config) {
			c.Database.Driver = "postgres"
			c.Database.Postgres.DSNRef = secretish
		}, "database.postgres.dsn_ref"},
		{"signing key", func(c *Config) {
			c.Auth.TokenSigningKeyRef = secretish
		}, "auth.token_signing_key_ref"},
		{"rate limit password", func(c *Config) {
			c.RateLimit.Shared.PasswordRef = secretish
		}, "rate_limit.shared.password_ref"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := validConfig()
			tc.mut(&c)
			err := c.Validate()
			if err == nil {
				t.Fatalf("expected a malformed-reference error for %s", tc.field)
			}
			msg := err.Error()
			if !strings.Contains(msg, tc.field) {
				t.Errorf("error %q does not name the offending field %s", msg, tc.field)
			}
			if strings.Contains(msg, secretish) {
				t.Errorf("error leaks the offending value: %q", msg)
			}
		})
	}
}

func TestValidateTLSMinVersionAccepted(t *testing.T) {
	for _, ver := range []string{"1.2", "1.3"} {
		t.Run(ver, func(t *testing.T) {
			c := validConfig()
			c.TLS.MinVersion = ver
			if err := c.Validate(); err != nil {
				t.Fatalf("min_version %q should be valid, got: %v", ver, err)
			}
		})
	}
}

// TestValidateACMEDNSModeAccepted covers the accepting side of the DNS-01 mode
// gate: both documented modes pass, and the mode is only consulted for the
// dns_01 solver so a leftover value cannot fail an unrelated solver.
func TestValidateACMEDNSModeAccepted(t *testing.T) {
	tests := []struct {
		name string
		mut  func(c *Config)
	}{
		{"manual mode needs no provider or credentials", func(c *Config) {
			c.TLS.ACME.Solver = "dns_01"
			c.TLS.ACME.DNS.Mode = "manual"
		}},
		{"api mode with provider and credentials", func(c *Config) {
			c.TLS.ACME.Solver = "dns_01"
			c.TLS.ACME.DNS.Mode = "api"
			c.TLS.ACME.DNS.Provider = "cloudflare"
			c.TLS.ACME.DNS.CredentialsRef = "env:VALLET_DNS_CREDS"
		}},
		{"mode ignored for tls_alpn_01 solver", func(c *Config) {
			c.TLS.ACME.Solver = "tls_alpn_01"
			c.TLS.ACME.DNS.Mode = "" // unset must not matter here
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := validConfig()
			tc.mut(&c)
			if err := c.Validate(); err != nil {
				t.Fatalf("config should be valid, got: %v", err)
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

// TestValidateRateLimitDisabledSkipsTierChecks documents a deliberate
// zero-is-legitimate decision: when rate limiting is off, the tier requests and
// windows are not consumed by anything, so a zero or unset tier is not an
// error. The checks apply only to values that will actually be used.
func TestValidateRateLimitDisabledSkipsTierChecks(t *testing.T) {
	c := validConfig()
	c.RateLimit.Enabled = false
	c.RateLimit.Store = ""
	c.RateLimit.Tiers = RateLimitTiers{}
	if err := c.Validate(); err != nil {
		t.Fatalf("disabled rate limiting should not require tiers, got: %v", err)
	}
}

// TestValidateRateLimitSharedStore covers the shared store's accepted form.
func TestValidateRateLimitSharedStore(t *testing.T) {
	c := validConfig()
	c.RateLimit.Store = "shared"
	c.RateLimit.Shared.Address = "redis.internal:6379"
	c.RateLimit.Shared.PasswordRef = "env:VALLET_RL_PASSWORD"
	if err := c.Validate(); err != nil {
		t.Fatalf("shared store config should be valid, got: %v", err)
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

// TestPurgeIntervalZeroIsTheOnlyOffSwitch pins the asymmetry that keeps a
// config typo from erasing the audit log.
//
// It asserts the mechanism, not a message: a zero *retention window* must be a
// hard validation failure (a cutoff of now-0 would make every record eligible),
// while a zero *interval* must validate cleanly because "never purge" is the
// safe, reversible way to switch the job off. If a future change ever relaxes
// the retention check to treat 0 as "disabled", this test fails.
func TestPurgeIntervalZeroIsTheOnlyOffSwitch(t *testing.T) {
	t.Run("zero retention window is rejected", func(t *testing.T) {
		c := validConfig()
		c.Retention.AuditRetention = 0
		if err := c.Validate(); err == nil {
			t.Fatal("audit_retention=0 validated; a zero window makes every record eligible for deletion and must never be accepted")
		}
	})

	t.Run("zero interval is accepted", func(t *testing.T) {
		c := validConfig()
		c.Retention.AuditPurgeInterval = 0
		if err := c.Validate(); err != nil {
			t.Fatalf("audit_purge_interval=0 must be valid (it is the documented way to disable purging): %v", err)
		}
		// And it must not have been silently rewritten to something that runs.
		if c.Retention.AuditPurgeInterval.Std() != 0 {
			t.Fatalf("Validate mutated the interval to %v; a disabled purge must stay disabled", c.Retention.AuditPurgeInterval.Std())
		}
	})
}

// TestDefaultPurgeIntervalActuallySchedules guards against re-creating the very
// defect this wiring removes: a retention policy that exists in config and never
// runs. A zero default interval would ship a documented-but-unenforced policy,
// so the default is asserted to be a positive cadence.
func TestDefaultPurgeIntervalActuallySchedules(t *testing.T) {
	c := Default()
	if got := c.Retention.AuditPurgeInterval.Std(); got <= 0 {
		t.Fatalf("default audit_purge_interval = %v; the default must schedule a real pass, or retention is documented and never enforced", got)
	}
	if got, want := c.Retention.AuditPurgeInterval.Std(), 24*time.Hour; got != want {
		t.Errorf("default audit_purge_interval = %v, want %v", got, want)
	}
	// The default must also survive validation, or the shipped default is unusable.
	d := validConfig()
	if err := d.Validate(); err != nil {
		t.Fatalf("default retention settings must validate: %v", err)
	}
}
