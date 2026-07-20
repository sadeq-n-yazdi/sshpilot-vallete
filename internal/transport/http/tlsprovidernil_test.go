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
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/secrets"
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
			// This row was written with "dns_01" as the unimplemented solver.
			// The DNS-01 branch implements it, so leaving it would have left the
			// row passing while asserting nothing about the default branch it
			// exists for -- the same silently-vacuous failure this table's own
			// doc warns a later case will cause. Switched to a solver that is
			// still genuinely unimplemented.
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
			// This row does NOT reach a conversion site. An unset dns mode
			// refuses inside newDNSProvider, which returns an explicit nil, so
			// the typed-nil guard is never exercised -- confirmed by mutation:
			// removing either guard leaves this row passing.
			//
			// It is kept for the branch it genuinely pins, the dns-mode default,
			// which nothing else covers, and it is labeled so its presence is
			// not read as typed-nil depth it does not have. wantMsg is what
			// stops it drifting to one of the other three sites of this
			// sentinel.
			name: "acme dns_01 with an unset dns mode",
			setup: func(_ *testing.T, _ string) *config.Config {
				cfg := &config.Config{}
				cfg.TLS.Mode = "acme"
				cfg.TLS.ACME.Solver = "dns_01"
				return cfg
			},
			wantErr: ErrTLSModeUnsupported,
			wantMsg: "acme dns mode",
		},
		{
			// THE row that pins the typed-nil guard on the dns_01 path. Every
			// OTHER dns_01 row fails inside newDNSProvider and returns an
			// explicit nil, so none of them reaches the line where a concrete
			// *acmeProvider is converted to a CertProvider -- they pass even
			// with the guard removed. This one uses the manual dns mode, which
			// needs no credential and SUCCEEDS, so the failure happens inside
			// newACMEProvider, at the conversion site itself.
			//
			// Verified by mutation: this is the only dns_01 row that fails when
			// the guard is dropped. Note that the guard is stated in TWO places
			// on this path -- here and at the switch branch -- and they mask
			// each other, so only removing BOTH is caught. See tls.go.
			name: "acme dns_01 reaching the acme constructor without accepted TOS",
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
			// The other dns_01 failure shape: a provider name this build does
			// not implement, reached only after the solver and dns mode are
			// both accepted. It is the deepest of the explicit-nil paths.
			//
			// Like the unset-dns-mode row, this does NOT reach a conversion
			// site -- newDNSProvider returns a literal nil -- so it does not
			// exercise the typed-nil guard, and mutation confirms it passes
			// with the guard removed. Kept for the dns-provider branch it
			// uniquely pins, and labeled so the row count is not mistaken for
			// typed-nil depth.
			name: "acme dns_01 with an unsupported provider",
			setup: func(t *testing.T, dir string) *config.Config {
				t.Helper()
				cfg := &config.Config{}
				cfg.TLS.Mode = "acme"
				cfg.TLS.ACME.Solver = "dns_01"
				cfg.TLS.ACME.DNS.Mode = "api"
				cfg.TLS.ACME.DNS.Provider = "no-such-provider"
				// A file-backed credential rather than an env one: the table
				// runs its rows in parallel, and t.Setenv is incompatible with
				// t.Parallel. The credential must RESOLVE for this row to reach
				// the provider-name check it exists to exercise.
				credFile := filepath.Join(dir, "dns-credential")
				if err := os.WriteFile(credFile, []byte("token-value"), 0o600); err != nil {
					t.Fatalf("write credential file: %v", err)
				}
				cfg.TLS.ACME.DNS.CredentialsRef = secrets.Ref("file:" + credFile)
				return cfg
			},
			wantErr: ErrTLSModeUnsupported,
			wantMsg: "dns provider",
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
