package config

import "time"

// leDirectoryURL is the Let's Encrypt production ACME directory endpoint.
const leDirectoryURL = "https://acme-v02.api.letsencrypt.org/directory"

// day is 24 hours, matching the Duration "d" suffix semantics.
const day = 24 * time.Hour

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
					Enabled:    true,
					ListenAddr: "",
					Path:       "/metrics",
				},
				OTLP: OTLPMetricsConfig{
					Enabled: false,
				},
			},
			Traces: TracesConfig{
				Enabled: false,
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
			MaxSetsPerOwner:  100,
		},
		Install: InstallConfig{
			// Enabled and unauthenticated by default, per ADR-0013: the
			// served installer is a bootstrap path. See InstallConfig for
			// the reasoning and for how to turn it off.
			Enabled: true,
		},
	}
}
