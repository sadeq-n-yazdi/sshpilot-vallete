package httpserver

import (
	"errors"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"testing"
	"time"

	"golang.org/x/crypto/acme"
)

// challengeFakeProvider is a provider that solves in band, used to test the
// wiring decisions buildTLSConfig makes from that property alone.
type challengeFakeProvider struct {
	*fakeProvider
	protos []string
}

func (c challengeFakeProvider) challengeALPNProtos() []string { return c.protos }

// TestChallengeALPNAdvertisedOnlyForInBandSolvers proves the acme-tls/1
// protocol reaches the listener's ALPN set only when a provider that answers it
// is installed.
//
// This is a containment property. If acme-tls/1 were advertised
// unconditionally, every deployment — manual, CSR, self-signed, upstream —
// would negotiate a protocol no provider can answer, leaving a handshake path
// whose only possible outcome is serving something unintended.
func TestChallengeALPNAdvertisedOnlyForInBandSolvers(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		provider CertProvider
		want     []string
	}{
		{
			name:     "ordinary provider advertises nothing extra",
			provider: &fakeProvider{},
			want:     nil,
		},
		{
			name:     "in-band solver advertises its challenge protocol",
			provider: challengeFakeProvider{fakeProvider: &fakeProvider{}, protos: []string{acme.ALPNProto}},
			want:     []string{acme.ALPNProto},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := challengeALPNProtos(tt.provider); !slices.Equal(got, tt.want) {
				t.Errorf("challengeALPNProtos() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestStartupProbeRequiredForEveryModeExceptInBandSolvers pins the exemption
// that lets ACME start without a certificate.
//
// The direction that matters most is the second case NOT spreading to the
// first. Every operator-owned mode must keep the strict startup check, so
// missing, mismatched or expired material is still reported at startup rather
// than discovered by a client.
func TestStartupProbeRequiredForEveryModeExceptInBandSolvers(t *testing.T) {
	t.Parallel()

	if !startupProbeRequired(&fakeProvider{}) {
		t.Error("an ordinary provider must be probed at startup; skipping the probe " +
			"would let a server with unusable certificate material come up healthy")
	}

	inBand := challengeFakeProvider{fakeProvider: &fakeProvider{}, protos: []string{acme.ALPNProto}}
	if startupProbeRequired(inBand) {
		t.Error("an in-band solver cannot be probed before its listener exists")
	}
}

// TestBuildTLSConfigKeepsStrictProbeForOperatorModes proves the exemption above
// did not quietly disable the startup check for the modes that must keep it.
//
// Manual mode is given a certificate that has already expired. It can only
// start if the probe was skipped, so a successful start is the failure.
func TestBuildTLSConfigKeepsStrictProbeForOperatorModes(t *testing.T) {
	t.Parallel()

	base := time.Date(2026, time.July, 19, 12, 0, 0, 0, time.UTC)
	certFile, keyFile := writeCertPair(t, t.TempDir(), base, base.Add(time.Hour))

	cfg := devConfig()
	cfg.TLS.Mode = "manual"
	cfg.TLS.Manual.CertFile = certFile
	cfg.TLS.Manual.KeyFile = keyFile

	_, _, err := buildTLSConfig(t.Context(), cfg, staticClock(base.Add(48*time.Hour)))
	if !errors.Is(err, ErrTLSCertificateExpired) {
		t.Fatalf("err = %v, want ErrTLSCertificateExpired: the startup probe was "+
			"skipped for a mode that must keep it", err)
	}
}

// newTestServerWithCertCloser builds a Server around a closer, with a real but
// never-started http.Server so Shutdown exercises the production path.
func newTestServerWithCertCloser(t *testing.T, closer io.Closer) *Server {
	t.Helper()

	return &Server{
		logger:     slog.New(slog.DiscardHandler),
		httpSrv:    &http.Server{ReadHeaderTimeout: readHeaderTimeout},
		certCloser: closer,
	}
}

// TestServerShutdownClosesCertProvider proves the renewal loop has a shutdown
// path.
//
// Before this wiring the guard was created inside buildTLSConfig and discarded,
// so certGuard.Close was unreachable from production code: a provider with
// background work would have leaked a goroutine for the process lifetime. The
// test asserts on the provider being closed, which is the mechanism, rather
// than on Shutdown merely returning nil.
func TestServerShutdownClosesCertProvider(t *testing.T) {
	t.Parallel()

	provider := &fakeProvider{}
	guard := newCertGuard(closableProvider{fakeProvider: provider}, time.Now)

	srv := newTestServerWithCertCloser(t, guard)
	if err := srv.Shutdown(t.Context()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}

	if !provider.closed {
		t.Error("Shutdown did not close the certificate provider; a renewal " +
			"goroutine would outlive the server it renews for")
	}
}

// TestServerShutdownToleratesNoCertProvider proves the close path does not
// panic on a Server whose construction never reached the TLS config.
func TestServerShutdownToleratesNoCertProvider(t *testing.T) {
	t.Parallel()

	srv := newTestServerWithCertCloser(t, nil)
	if err := srv.Shutdown(t.Context()); err != nil {
		t.Errorf("Shutdown with no provider: %v", err)
	}
}

// TestACMEProviderDeclaresChallengeALPN pins the real provider to the protocol
// RFC 8737 defines. A provider that declared the wrong name would advertise an
// ALPN the CA never asks for, so validation would fail with no local symptom.
func TestACMEProviderDeclaresChallengeALPN(t *testing.T) {
	t.Parallel()

	p := acmeTestProvider(t, time.Now())
	if got := p.challengeALPNProtos(); !slices.Equal(got, []string{"acme-tls/1"}) {
		t.Errorf("challengeALPNProtos() = %v, want [acme-tls/1]", got)
	}
}

// TestDNS01SolverIsRefusedRatherThanSubstituted proves a configured but
// unimplemented solver fails closed.
//
// Falling back to TLS-ALPN-01 would issue through a challenge the operator did
// not select — for a deployment whose port 443 is unreachable from the CA, that
// is a silent, permanent issuance failure instead of an immediate, legible one.
func TestDNS01SolverIsRefusedRatherThanSubstituted(t *testing.T) {
	t.Parallel()

	cfg := acmeTestConfig(t)
	cfg.TLS.ACME.Solver = "dns_01"
	cfg.TLS.ACME.DNS.Mode = "manual"

	_, err := newACMEProviderForSolver(t.Context(), cfg, time.Now)
	if !errors.Is(err, ErrTLSModeUnsupported) {
		t.Errorf("error = %v, want ErrTLSModeUnsupported", err)
	}
}
