package config

import (
	"testing"
	"time"
)

func TestDefaultSanity(t *testing.T) {
	c := Default()

	checks := []struct {
		name string
		got  any
		want any
	}{
		{"server.environment", c.Server.Environment, "production"},
		{"server.listen_addr", c.Server.ListenAddr, ":8443"},
		{"tls.mode", c.TLS.Mode, ""},
		{"tls.min_version", c.TLS.MinVersion, "1.2"},
		{"tls.acme.directory_url", c.TLS.ACME.DirectoryURL, leDirectoryURL},
		{"tls.upstream.require_forwarded_proto", c.TLS.Upstream.RequireForwardedProto, true},
		{"tls.allow_self_signed_in_production", c.TLS.AllowSelfSignedInProduction, false},
		{"database.driver", c.Database.Driver, "sqlite"},
		{"database.sqlite.path", c.Database.SQLite.Path, "./data/vallet.db"},
		{"auth.access_token_ttl", c.Auth.AccessTokenTTL.Std(), 15 * time.Minute},
		{"auth.refresh_token_max_age", c.Auth.RefreshTokenMaxAge.Std(), 90 * 24 * time.Hour},
		{"auth.providers.api_token.enabled", c.Auth.Providers.APIToken.Enabled, true},
		{"auth.providers.passkey.enabled", c.Auth.Providers.Passkey.Enabled, false},
		{"auth.providers.oidc.enabled", c.Auth.Providers.OIDC.Enabled, false},
		{"rate_limit.enabled", c.RateLimit.Enabled, true},
		{"rate_limit.store", c.RateLimit.Store, "memory"},
		{"rate_limit.tiers.auth.requests", c.RateLimit.Tiers.Auth.Requests, 5},
		{"rate_limit.tiers.publish.requests", c.RateLimit.Tiers.Publish.Requests, 60},
		{"rate_limit.tiers.management.requests", c.RateLimit.Tiers.Management.Requests, 120},
		{"rate_limit.tiers.admin.requests", c.RateLimit.Tiers.Admin.Requests, 60},
		{"telemetry.log.level", c.Telemetry.Log.Level, "info"},
		{"telemetry.log.format", c.Telemetry.Log.Format, "json"},
		{"telemetry.metrics.prometheus.enabled", c.Telemetry.Metrics.Prometheus.Enabled, true},
		{"telemetry.metrics.prometheus.path", c.Telemetry.Metrics.Prometheus.Path, "/metrics"},
		{"telemetry.metrics.otlp.enabled", c.Telemetry.Metrics.OTLP.Enabled, false},
		{"telemetry.traces.enabled", c.Telemetry.Traces.Enabled, false},
		{"onboarding.mode", c.Onboarding.Mode, "invite"},
		{"retention.handle_quarantine", c.Retention.HandleQuarantine.Std(), 30 * 24 * time.Hour},
		{"retention.audit_retention", c.Retention.AuditRetention.Std(), 365 * 24 * time.Hour},
		{"retention.audit_purge_batch", c.Retention.AuditPurgeBatch, 500},
		{"retention.audit_purge_max_per_run", c.Retention.AuditPurgeMaxPerRun, 100_000},
		{"retention.max_sets_per_owner", c.Retention.MaxSetsPerOwner, 100},
	}
	for _, ch := range checks {
		if ch.got != ch.want {
			t.Errorf("%s = %v, want %v", ch.name, ch.got, ch.want)
		}
	}

	for _, w := range []struct {
		name string
		got  time.Duration
	}{
		{"auth.tier.auth.window", c.RateLimit.Tiers.Auth.Window.Std()},
	} {
		if w.got != time.Minute {
			t.Errorf("%s = %v, want 1m", w.name, w.got)
		}
	}
}
