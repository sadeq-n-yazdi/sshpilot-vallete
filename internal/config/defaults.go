package config

import "time"

// leDirectoryURL is the Let's Encrypt production ACME directory endpoint.
const leDirectoryURL = "https://acme-v02.api.letsencrypt.org/directory"

// day is 24 hours, matching the Duration "d" suffix semantics.
const day = 24 * time.Hour

// defaultOriginValidityDays is the requested lifetime for a Cloudflare Origin
// CA certificate. See CloudflareOriginConfig.ValidityDays for why a year is
// chosen over Cloudflare's 5475-day maximum.
const defaultOriginValidityDays = 365

// Default returns a Config populated with every built-in default value. It is
// the single source of truth for defaults; Load starts from Default() and
// decodes the file and environment over it.
//
// Note the deliberate zero-value defaults that Validate later rejects when the
// relevant mode is selected: TLSConfig.Mode is "" (an operator must choose a
// mode) and all secrets.Ref fields default to "".
func Default() Config {
	return Config{
		Server: ServerConfig{
			Environment:    "production",
			ListenAddr:     ":8443",
			PublicBaseURL:  "",
			TrustedProxies: nil,
		},
		TLS: TLSConfig{
			Mode:       "", // no default: operator must choose.
			MinVersion: "1.2",
			ACME: ACMEConfig{
				DirectoryURL: leDirectoryURL,
			},
			CloudflareOrigin: CloudflareOriginConfig{
				// See CloudflareOriginConfig.ValidityDays for why this is a
				// year and not Cloudflare's 15-year maximum.
				ValidityDays: defaultOriginValidityDays,
			},
			Upstream: UpstreamTLSConfig{
				RequireForwardedProto: true,
			},
			AllowSelfSignedInProduction: false,
		},
		Database: DatabaseConfig{
			Driver: "sqlite",
			SQLite: SQLiteConfig{
				Path: "./data/vallet.db",
			},
		},
		Auth: AuthConfig{
			AccessTokenTTL:     Duration(15 * time.Minute),
			RefreshTokenMaxAge: Duration(90 * day),
			Providers: AuthProviders{
				APIToken: APITokenProvider{Enabled: true},
				Passkey:  PasskeyProvider{Enabled: false},
				OIDC:     OIDCProvider{Enabled: false},
			},
		},
		RateLimit: RateLimitConfig{
			Enabled: true,
			Store:   "memory",
			Tiers: RateLimitTiers{
				Auth:       Tier{Requests: 5, Window: Duration(time.Minute)},
				Publish:    Tier{Requests: 60, Window: Duration(time.Minute)},
				Management: Tier{Requests: 120, Window: Duration(time.Minute)},
				Admin:      Tier{Requests: 60, Window: Duration(time.Minute)},
			},
		},
		Telemetry: TelemetryConfig{
			Log: LogConfig{
				Level:  "info",
				Format: "json",
			},
			Metrics: MetricsConfig{
				Prometheus: PrometheusConfig{
					// Collection is on; SERVING it is not. The empty
					// ListenAddr is the fail-closed default documented on
					// PrometheusConfig: no scrape endpoint exists anywhere
					// until an operator names an address for it, so /metrics
					// is unreachable on a default deployment and can never
					// appear on the public API listener.
					Enabled:    true,
					ListenAddr: "",
					Path:       "/metrics",
				},
				OTLP: OTLPMetricsConfig{
					Enabled: false,
				},
			},
			Traces: TracesConfig{
				Enabled:     false,
				SampleRatio: 1,
			},
		},
		Onboarding: OnboardingConfig{
			Mode: "invite",
		},
		Blocklist: BlocklistConfig{
			SeedFile: "",
		},
		Retention: RetentionConfig{
			HandleQuarantine: Duration(30 * day),
			AuditRetention:   Duration(365 * day),
			// A concrete, non-zero cadence: the default must actually schedule
			// a pass. Defaulting this to 0 would ship a retention policy that
			// is documented and never enforced, which is the exact defect this
			// wiring exists to remove.
			AuditPurgeInterval:  Duration(24 * time.Hour),
			AuditPurgeBatch:     500,
			AuditPurgeMaxPerRun: 100_000,
			// Hourly, not daily. The quarantine window is measured in days, so
			// the sweep's cadence only decides how long a name stays held past
			// its deadline; an hour keeps that overshoot small without making
			// the sweep a meaningful load.
			HandleQuarantineSweepInterval: Duration(time.Hour),
			HandleQuarantineSweepBatch:    200,
			// Off by default: see the field. The batch is still a real number
			// so that an operator who enables the sweep gets a working bound
			// without having to discover a second setting, and so validation
			// has something positive to check either way.
			AccessKeyGraceSweepInterval: 0,
			AccessKeyGraceSweepBatch:    200,
			MaxSetsPerOwner:             100,
		},
		Install: InstallConfig{
			// Enabled and unauthenticated by default, per ADR-0013: the
			// served installer is a bootstrap path. See InstallConfig for
			// the reasoning and for how to turn it off.
			Enabled: true,
		},
		Docs: DocsConfig{
			// Enabled and public by default, per ADR-0021: the contract is
			// not secret. See DocsConfig for the reasoning and for how to
			// turn it off.
			Enabled: true,
		},
	}
}
