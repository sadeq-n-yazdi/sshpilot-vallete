package config

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadDefaultsWhenNoPath(t *testing.T) {
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load(\"\"): %v", err)
	}
	if cfg.Server.Environment != "production" {
		t.Errorf("environment = %q, want production", cfg.Server.Environment)
	}
	if cfg.Database.Driver != "sqlite" {
		t.Errorf("driver = %q, want sqlite", cfg.Database.Driver)
	}
}

func TestLoadFileOverDefaults(t *testing.T) {
	cfg, err := Load(filepath.Join("testdata", "full.yaml"))
	if err != nil {
		t.Fatalf("Load full: %v", err)
	}
	if cfg.Server.Environment != "development" {
		t.Errorf("environment = %q, want development", cfg.Server.Environment)
	}
	if cfg.Database.Driver != "postgres" {
		t.Errorf("driver = %q, want postgres", cfg.Database.Driver)
	}
	if got := cfg.Database.Postgres.DSNRef; got != "file:/run/secrets/pg-dsn" {
		t.Errorf("dsn_ref = %q", got)
	}
	if cfg.Auth.RefreshTokenMaxAge.Std() != 30*24*time.Hour {
		t.Errorf("refresh max age = %v", cfg.Auth.RefreshTokenMaxAge.Std())
	}
	// A field not present in the file keeps its default.
	if cfg.Telemetry.Metrics.Prometheus.Path != "/metrics" {
		t.Errorf("prometheus path = %q, want default /metrics", cfg.Telemetry.Metrics.Prometheus.Path)
	}
}

func TestLoadMissingFileErrors(t *testing.T) {
	if _, err := Load(filepath.Join("testdata", "does-not-exist.yaml")); err == nil {
		t.Fatal("expected error for missing named file")
	}
}

func TestLoadUnknownKeyRejected(t *testing.T) {
	_, err := Load(filepath.Join("testdata", "invalid-unknown-key.yaml"))
	if err == nil {
		t.Fatal("expected KnownFields rejection")
	}
}

func TestLoadBadDurationRejected(t *testing.T) {
	if _, err := Load(filepath.Join("testdata", "invalid-bad-duration.yaml")); err == nil {
		t.Fatal("expected duration parse error")
	}
}

// TestLoadUnreadablePathErrors covers the non-ErrNotExist open failure: a path
// whose parent component is a regular file cannot be opened, and Load must
// report it rather than silently proceeding on defaults.
func TestLoadUnreadablePathErrors(t *testing.T) {
	notADir := filepath.Join("testdata", "empty.yaml", "config.yaml")
	if _, err := Load(notADir); err == nil {
		t.Fatal("expected an open error for a path under a regular file")
	}
}

// TestLoadRejectsBadEnvOverride asserts the environment layer fails the whole
// Load. Precedence is env > file, so a malformed override must not fall back to
// the file or default value it was meant to replace.
func TestLoadRejectsBadEnvOverride(t *testing.T) {
	t.Setenv("VALLET_AUTH_ACCESS_TOKEN_TTL", "-15m")
	cfg, err := Load("")
	if err == nil {
		t.Fatalf("expected a load error, got config %+v", cfg)
	}
	if !strings.Contains(err.Error(), "VALLET_AUTH_ACCESS_TOKEN_TTL") {
		t.Errorf("error %q does not name the offending variable", err)
	}
}

func TestLoadMinimal(t *testing.T) {
	cfg, err := Load(filepath.Join("testdata", "minimal.yaml"))
	if err != nil {
		t.Fatalf("Load minimal: %v", err)
	}
	if cfg.TLS.Mode != "upstream" {
		t.Errorf("tls.mode = %q, want upstream", cfg.TLS.Mode)
	}
	if cfg.Server.PublicBaseURL != "https://vallet.example.com" {
		t.Errorf("public_base_url = %q", cfg.Server.PublicBaseURL)
	}
}

// TestLoadEmptyFileYieldsDefaults asserts that an empty or comments-only file
// loads cleanly as "no overrides" rather than failing on the io.EOF that yaml
// returns for a document with nothing to decode. Concrete defaults must
// survive, guarding against both an erroring path and a silent zeroing of cfg.
func TestLoadEmptyFileYieldsDefaults(t *testing.T) {
	for _, name := range []string{"empty.yaml", "comments-only.yaml"} {
		t.Run(name, func(t *testing.T) {
			cfg, err := Load(filepath.Join("testdata", name))
			if err != nil {
				t.Fatalf("Load(%s): %v", name, err)
			}
			if cfg.Server.Environment != "production" {
				t.Errorf("environment = %q, want default production", cfg.Server.Environment)
			}
			if cfg.Database.Driver != "sqlite" {
				t.Errorf("driver = %q, want default sqlite", cfg.Database.Driver)
			}
		})
	}
}

// applyEnvFrom is a test helper overlaying a fixed environment map.
func applyEnvFrom(t *testing.T, cfg *Config, env map[string]string) {
	t.Helper()
	if err := applyEnv(cfg, func(k string) (string, bool) {
		v, ok := env[k]
		return v, ok
	}); err != nil {
		t.Fatalf("applyEnv: %v", err)
	}
}

func TestEnvOverridesFile(t *testing.T) {
	cfg := Default()
	cfg.Server.Environment = "production" // pretend file set this
	applyEnvFrom(t, &cfg, map[string]string{
		"VALLET_SERVER_ENVIRONMENT":                   "development",
		"VALLET_SERVER_TRUSTED_PROXIES":               "10.0.0.1, 10.0.0.2 ,",
		"VALLET_TLS_UPSTREAM_REQUIRE_FORWARDED_PROTO": "false",
		"VALLET_RATE_LIMIT_TIERS_AUTH_REQUESTS":       "42",
		"VALLET_AUTH_ACCESS_TOKEN_TTL":                "20m",
		"VALLET_DATABASE_POSTGRES_DSN_REF":            "env:PG",
	})
	if cfg.Server.Environment != "development" {
		t.Errorf("env did not override environment: %q", cfg.Server.Environment)
	}
	if len(cfg.Server.TrustedProxies) != 2 {
		t.Errorf("trusted_proxies = %v, want 2 items", cfg.Server.TrustedProxies)
	}
	if cfg.TLS.Upstream.RequireForwardedProto {
		t.Error("bool env override failed")
	}
	if cfg.RateLimit.Tiers.Auth.Requests != 42 {
		t.Errorf("int env override failed: %d", cfg.RateLimit.Tiers.Auth.Requests)
	}
	if cfg.Auth.AccessTokenTTL.Std() != 20*time.Minute {
		t.Errorf("duration env override failed: %v", cfg.Auth.AccessTokenTTL.Std())
	}
	if cfg.Database.Postgres.DSNRef != "env:PG" {
		t.Errorf("ref env override failed: %q", cfg.Database.Postgres.DSNRef)
	}
}

func TestApplyEnvCollectsErrors(t *testing.T) {
	cfg := Default()
	err := applyEnv(&cfg, func(k string) (string, bool) {
		m := map[string]string{
			"VALLET_RATE_LIMIT_TIERS_AUTH_REQUESTS":       "notint",
			"VALLET_TLS_UPSTREAM_REQUIRE_FORWARDED_PROTO": "notbool",
		}
		v, ok := m[k]
		return v, ok
	})
	if err == nil {
		t.Fatal("expected aggregated parse errors")
	}
}
