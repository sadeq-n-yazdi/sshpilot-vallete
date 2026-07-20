package httpserver

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/config"
)

// TestNewCertProviderReturnsNilInterfaceOnError pins the one property a caller
// cannot re-derive from the signature: when newCertProvider fails, the returned
// CertProvider is nil AS AN INTERFACE.
//
// This is not a restatement of "it returns an error". Each constructor returns a
// concrete *T, so `return newXProvider(...)` hands back an interface holding a
// typed nil, which is itself NON-nil. A caller that checked `provider != nil`
// instead of the error would sail past that check and then use a provider that
// is nil underneath — on a TLS seam, that means serving without the certificate
// policy the provider exists to enforce.
//
// Every mode is covered because the defect is the function's SHAPE, not any one
// case's bug: a case added later that returns its concrete type directly
// reintroduces it, and only a per-case assertion catches that.
//
// Each row must produce a genuinely non-nil error from the REAL constructor, and
// wantErr pins which one. A row whose config accidentally succeeded would skip
// the nil assertion entirely and prove nothing — that is exactly how this kind
// of test passes vacuously, so the error identity is asserted too.
func TestNewCertProviderReturnsNilInterfaceOnError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		// setup returns a config whose construction is guaranteed to fail, and
		// the error it must fail with.
		setup   func(t *testing.T, dir string) *config.Config
		wantErr error
		// wantMsg is a substring identifying WHICH branch refused, for rows
		// whose sentinel cannot say.
		//
		// ErrTLSModeUnsupported is returned from four distinct branches: the
		// tls.mode default, the acme solver default, the unsupported dns
		// provider, and the dns mode default. errors.Is therefore cannot tell
		// them apart, and a row whose config starts failing at a DIFFERENT one
		// of the four keeps passing while no longer testing the branch it was
		// written for. That is not hypothetical: the row that used to name
		// dns_01 as the unimplemented solver migrated exactly this way when
		// dns_01 was implemented -- it began failing at the dns-mode default
		// and stayed green, asserting nothing about the solver default.
		//
		// Each site's message carries a unique discriminator ("acme solver",
		// "acme dns mode", "dns provider", or the bare quoted mode), so pinning
		// it turns a silent migration into a loud failure. This is NOT redundant
		// belt-and-braces on the sentinel; deleting it restores the trap.
		wantMsg string
	}{
		{
			// The refusal is the production guard, reached without any I/O.
			name: "self_signed refused in production",
			setup: func(_ *testing.T, _ string) *config.Config {
				cfg := &config.Config{}
				cfg.TLS.Mode = "self_signed"
				cfg.Server.Environment = "production"
				cfg.TLS.AllowSelfSignedInProduction = false
				return cfg
			},
			wantErr: ErrSelfSignedInProduction,
		},
		{
			name: "manual with missing files",
			setup: func(_ *testing.T, dir string) *config.Config {
				cfg := &config.Config{}
				cfg.TLS.Mode = "manual"
				cfg.TLS.Manual.CertFile = filepath.Join(dir, "absent.crt")
				cfg.TLS.Manual.KeyFile = filepath.Join(dir, "absent.key")
				return cfg
			},
			wantErr: ErrTLSCertificateInvalid,
		},
		{
			// A world-readable key file: loadOrCreateKey finds it, parseKey
			// refuses the mode. Deterministic, and it exercises the real
			// constructor rather than a missing-file shortcut.
			name: "csr with world-readable key",
			setup: func(t *testing.T, dir string) *config.Config {
				t.Helper()
				keyFile := filepath.Join(dir, "csr.key")
				if err := os.WriteFile(keyFile, []byte("not-a-key"), 0o644); err != nil { //nolint:gosec // the loose mode is the condition under test.
					t.Fatalf("write key: %v", err)
				}
				cfg := &config.Config{}
				cfg.TLS.Mode = "csr"
				cfg.TLS.CSR.KeyFile = keyFile
				cfg.TLS.CSR.CSRFile = filepath.Join(dir, "csr.csr")
				cfg.TLS.CSR.CertFile = filepath.Join(dir, "csr.crt")
				return cfg
			},
			wantErr: ErrTLSKeyPermissions,
		},
		{
			// Solver tls_alpn_01 deliberately: that is the branch that calls the
			// concrete newACMEProvider and so is the true source of the typed
			// nil. A bogus solver would land on the already-safe default branch
			// and test nothing. accept_tos unset fails inside newACMEProvider
			// before any network or filesystem work.
			name: "acme tls_alpn_01 without accepted TOS",
			setup: func(_ *testing.T, dir string) *config.Config {
				cfg := &config.Config{}
				cfg.TLS.Mode = "acme"
				cfg.TLS.ACME.Solver = "tls_alpn_01"
				cfg.TLS.ACME.AcceptTOS = false
				cfg.TLS.ACME.CacheDir = filepath.Join(dir, "acme")
				cfg.TLS.ACME.AccountKeyFile = filepath.Join(dir, "acme", "account.key")
				return cfg
			},
			wantErr: ErrACMETermsNotAccepted,
		},
		{
			// This row used to name dns_01 as the unimplemented solver. E8's
			// stack implements it, so it now needs a solver that genuinely is
			// not, or the row would stop reaching the default branch it exists
			// to cover -- and would land in newDNS01ACMEProvider instead, which
			// is a different assertion wearing this one's name.
			name: "acme with unimplemented solver",
			setup: func(_ *testing.T, _ string) *config.Config {
				cfg := &config.Config{}
				cfg.TLS.Mode = "acme"
				cfg.TLS.ACME.Solver = "http_01"
				return cfg
			},
			wantErr: ErrTLSModeUnsupported,
			// Pins the SOLVER default. Without this the row inherits the trap
			// that caught its dns_01 predecessor: implement HTTP-01 with its own
			// sub-dispatch that refuses unset config with the same sentinel, and
			// this row migrates there and keeps passing.
			wantMsg: "acme solver",
		},
		{
			// The dns_01 branch is a SECOND source of the typed nil: it calls
			// the concrete newACMEProvider too, on a path that arrived on a
			// different branch than the ALPN one, so it does not inherit that
			// case's guard. dns mode manual builds a DNS provider without any
			// credential or network, and accept_tos unset then fails inside
			// newACMEProvider -- deterministic, and it reaches the constructor
			// whose concrete return is the hazard.
			name: "acme dns_01 without accepted TOS",
			setup: func(_ *testing.T, dir string) *config.Config {
				cfg := &config.Config{}
				cfg.TLS.Mode = "acme"
				cfg.TLS.ACME.Solver = "dns_01"
				cfg.TLS.ACME.DNS.Mode = "manual"
				cfg.TLS.ACME.AcceptTOS = false
				cfg.TLS.ACME.CacheDir = filepath.Join(dir, "acme")
				cfg.TLS.ACME.AccountKeyFile = filepath.Join(dir, "acme", "account.key")
				return cfg
			},
			wantErr: ErrACMETermsNotAccepted,
		},
		{
			// Origin CA landed on develop after this table was written, which
			// is precisely the "case added later" this test exists to catch.
			// The unset reference fails inside newOriginCAProvider before any
			// network or filesystem work, so the row is deterministic.
			name: "cloudflare_origin with an unresolvable credential",
			setup: func(t *testing.T, _ string) *config.Config {
				t.Helper()
				cfg := originTestConfig(t)
				cfg.TLS.CloudflareOrigin.APITokenRef = "env:VALLET_TEST_UNSET_ORIGIN_CA_KEY"
				return cfg
			},
			wantErr: ErrOriginCACredential,
		},
		{
			name: "unsupported mode",
			setup: func(_ *testing.T, _ string) *config.Config {
				cfg := &config.Config{}
				cfg.TLS.Mode = "upstream"
				return cfg
			},
			wantErr: ErrTLSModeUnsupported,
			// The tls.mode default renders the mode bare and quoted; every other
			// site prefixes its own discriminator, so a migration would drop
			// this substring.
			wantMsg: `"upstream"`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			cfg := tc.setup(t, t.TempDir())

			provider, err := newCertProvider(context.Background(), cfg, time.Now, slog.New(slog.DiscardHandler))

			// Asserted first: a row that stopped failing would otherwise make
			// the nil check below unreachable and the case silently vacuous.
			if err == nil {
				t.Fatalf("newCertProvider(%q) succeeded; the row no longer exercises an error path", cfg.TLS.Mode)
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("newCertProvider(%q) error = %v, want %v", cfg.TLS.Mode, err, tc.wantErr)
			}
			// The sentinel alone cannot say which branch refused; see wantMsg.
			if tc.wantMsg != "" && !strings.Contains(err.Error(), tc.wantMsg) {
				t.Fatalf("newCertProvider(%q) error = %v, want it to name %q: the row is "+
					"failing at a different branch than the one it was written for",
					cfg.TLS.Mode, err, tc.wantMsg)
			}

			// The assertion under test. A typed nil makes this comparison
			// FALSE even though the pointer inside is nil.
			if provider != nil {
				t.Errorf("newCertProvider(%q) returned non-nil interface %T alongside an error; "+
					"a caller checking provider != nil would proceed with a nil provider",
					cfg.TLS.Mode, provider)
			}
		})
	}
}
