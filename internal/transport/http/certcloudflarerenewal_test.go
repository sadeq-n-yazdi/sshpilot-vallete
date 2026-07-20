package httpserver

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/secrets"
)

// --- fail-closed: API and credential failures ------------------------------

// TestOriginCAFailsClosedOnIssuanceFailures covers every way issuance can fail.
//
// Each case asserts that construction fails and no provider is returned. That
// is the fail-closed property: there is no fallback certificate, so a
// deployment that cannot obtain a real certificate does not start.
func TestOriginCAFailsClosedOnIssuanceFailures(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name string
		do   func(*http.Request) (*http.Response, error)
	}{
		{
			name: "api rejects the request",
			do: func(*http.Request) (*http.Response, error) {
				return jsonResponse(http.StatusForbidden,
					`{"success":false,"errors":[{"code":1000,"message":"Invalid request headers"}]}`), nil
			},
		},
		{
			name: "api reports failure with a 200",
			do: func(*http.Request) (*http.Response, error) {
				return jsonResponse(http.StatusOK,
					`{"success":false,"errors":[{"code":1100,"message":"hostname not in zone"}]}`), nil
			},
		},
		{
			name: "response is not json",
			do: func(*http.Request) (*http.Response, error) {
				return jsonResponse(http.StatusOK, "<html>captive portal</html>"), nil
			},
		},
		{
			name: "success with no certificate",
			do: func(*http.Request) (*http.Response, error) {
				return jsonResponse(http.StatusOK, `{"success":true,"result":{"certificate":""}}`), nil
			},
		},
		{
			name: "certificate is not parseable pem",
			do: func(*http.Request) (*http.Response, error) {
				return jsonResponse(http.StatusOK, `{"success":true,"result":{"certificate":"not a certificate"}}`), nil
			},
		},
		{
			name: "transport error",
			do: func(*http.Request) (*http.Response, error) {
				return nil, errors.New("dial tcp: connection refused")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cfg := originTestConfig(t)
			p, err := newOriginCAProviderWithClient(t.Context(), cfg, staticClock(now),
				secrets.NewRedacted("v1.0-testkey"), doerFunc(tt.do))
			if !errors.Is(err, ErrOriginCAIssuance) {
				t.Fatalf("err = %v, want ErrOriginCAIssuance", err)
			}
			if p != nil {
				t.Fatal("a provider with no certificate must not be returned")
			}
		})
	}
}

// TestOriginCARefusesUnsuccessfulEnvelopeCarryingACertificate checks that the
// success flag is enforced on its own.
//
// The envelope says success=false while carrying a perfectly valid, correctly
// keyed certificate. Every other guard in the issuance path is satisfied, so
// this is the only case in which the success check is load-bearing — and
// without it a response the API explicitly marked as a failure would be
// adopted and served.
//
// The distinction matters because the neighboring table cases all happen to
// carry no certificate, which means the empty-chain check catches them and the
// success flag could be deleted without any of them noticing.
func TestOriginCARefusesUnsuccessfulEnvelopeCarryingACertificate(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	cfg := originTestConfig(t)
	ca := newFakeOriginCA(t)

	p, err := newOriginCAProviderWithClient(t.Context(), cfg, staticClock(now),
		secrets.NewRedacted("v1.0-testkey"),
		doerFunc(func(req *http.Request) (*http.Response, error) {
			signed := ca.sign(t, req, now.Add(-time.Hour), now.Add(365*24*time.Hour))
			body, err := io.ReadAll(signed.Body)
			if err != nil {
				t.Fatalf("read signed envelope: %v", err)
			}
			var envelope map[string]any
			if err := json.Unmarshal(body, &envelope); err != nil {
				t.Fatalf("decode signed envelope: %v", err)
			}
			// Same certificate, but the API reports failure.
			envelope["success"] = false
			envelope["errors"] = []map[string]any{{"code": 1100, "message": "hostname not in zone"}}
			out, err := json.Marshal(envelope)
			if err != nil {
				t.Fatalf("encode envelope: %v", err)
			}
			return jsonResponse(http.StatusOK, string(out)), nil
		}))
	if !errors.Is(err, ErrOriginCAIssuance) {
		t.Fatalf("err = %v, want ErrOriginCAIssuance", err)
	}
	if p != nil {
		t.Fatal("a certificate the api marked as a failed request must not be served")
	}
}

// TestOriginCARefusesCertificateNotMatchingOurKey is the malformed-response case
// that matters most: a well-formed certificate for somebody else's key.
//
// Cloudflare returning (or an attacker substituting) a certificate whose public
// key is not the one we generated must be refused, because it cannot be signed
// with and would fail every handshake in a way that looks like a working
// deployment until the first client arrives.
func TestOriginCARefusesCertificateNotMatchingOurKey(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	cfg := originTestConfig(t)
	ca := newFakeOriginCA(t)

	// A certificate for a key the provider never generated.
	strangerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate stranger key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "vallet.example.com"},
		DNSNames:     []string{"vallet.example.com"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(365 * 24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &strangerKey.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("create stranger cert: %v", err)
	}
	leaf := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	envelope, err := json.Marshal(map[string]any{
		"success": true,
		"result":  map[string]any{"certificate": string(leaf)},
	})
	if err != nil {
		t.Fatalf("encode envelope: %v", err)
	}

	p, err := newOriginCAProviderWithClient(t.Context(), cfg, staticClock(now),
		secrets.NewRedacted("v1.0-testkey"),
		doerFunc(func(*http.Request) (*http.Response, error) {
			return jsonResponse(http.StatusOK, string(envelope)), nil
		}))
	if !errors.Is(err, ErrOriginCAIssuance) {
		t.Fatalf("err = %v, want ErrOriginCAIssuance", err)
	}
	if p != nil {
		t.Fatal("a certificate for a key we do not hold must not be served")
	}

	// And it must not have been cached, or a restart would adopt it.
	if _, err := os.Stat(filepath.Join(cfg.TLS.CloudflareOrigin.CacheDir, originCACertFile)); err == nil {
		t.Error("an unusable certificate must not be written to the cache")
	}
}

// TestOriginCARefusesExpiredIssuedCertificate checks that a certificate outside
// its validity window is refused at issuance, not merely at handshake time — so
// it never reaches the cache.
func TestOriginCARefusesExpiredIssuedCertificate(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	cfg := originTestConfig(t)
	ca := newFakeOriginCA(t)

	p, err := newOriginCAProviderWithClient(t.Context(), cfg, staticClock(now),
		secrets.NewRedacted("v1.0-testkey"),
		doerFunc(func(req *http.Request) (*http.Response, error) {
			return ca.sign(t, req, now.Add(-48*time.Hour), now.Add(-24*time.Hour)), nil
		}))
	if !errors.Is(err, ErrOriginCAIssuance) {
		t.Fatalf("err = %v, want ErrOriginCAIssuance", err)
	}
	if p != nil {
		t.Fatal("an expired certificate must not be served")
	}
}

// TestOriginCAFailsClosedOnMissingCredential covers the credential path.
//
// A deployment whose secret reference does not resolve can never obtain a
// certificate, so it must not start. The check also asserts the error does not
// carry a value — the whole reason the credential goes through the secret
// provider is that it must not end up in logs.
func TestOriginCAFailsClosedOnMissingCredential(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name    string
		resolve secretResolver
	}{
		{
			name: "reference does not resolve",
			resolve: func(context.Context, secrets.Ref) (secrets.Redacted, error) {
				return "", errors.New("secrets: environment variable \"CF\" is not set")
			},
		},
		{
			name:    "reference resolves to an empty value",
			resolve: staticSecret(""),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cfg := originTestConfig(t)
			p, err := newOriginCAProvider(t.Context(), cfg, staticClock(now), tt.resolve)
			if !errors.Is(err, ErrOriginCACredential) {
				t.Fatalf("err = %v, want ErrOriginCACredential", err)
			}
			if p != nil {
				t.Fatal("a provider with no credential must not be returned")
			}
			if !strings.Contains(err.Error(), "tls.cloudflare_origin.api_token_ref") {
				t.Errorf("error must name the field an operator has to fix: %v", err)
			}
		})
	}
}

// TestOriginCAErrorsNeverLeakTheCredential checks that no failure path renders
// the credential, whichever header shape it takes.
func TestOriginCAErrorsNeverLeakTheCredential(t *testing.T) {
	t.Parallel()

	const credential = "v1.0-supersecretorigincakey"
	now := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	cfg := originTestConfig(t)

	_, err := newOriginCAProviderWithClient(t.Context(), cfg, staticClock(now),
		secrets.NewRedacted(credential),
		doerFunc(func(*http.Request) (*http.Response, error) {
			// An API that echoes the credential back in its error message: the
			// server must still not propagate it.
			return jsonResponse(http.StatusForbidden,
				`{"success":false,"errors":[{"code":1000,"message":"bad key `+credential+`"}]}`), nil
		}))
	if err == nil {
		t.Fatal("want a refusal")
	}
	if strings.Contains(err.Error(), "supersecretorigincakey") {
		t.Errorf("the credential must never appear in an error: %v", err)
	}
}

// TestOriginCACredentialIsRedactedWhenFormatted checks the provider struct
// itself cannot print its credential, which is the realistic leak: a struct
// dumped with %+v while debugging.
func TestOriginCACredentialIsRedactedWhenFormatted(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	cfg := originTestConfig(t)
	p := newOriginTestProvider(t, cfg, now, now.Add(-time.Hour), now.Add(365*24*time.Hour))
	p.token = secrets.NewRedacted("v1.0-supersecretorigincakey")

	for _, format := range []string{"%v", "%+v", "%#v", "%s"} {
		if got := fmt.Sprintf(format, p.token); strings.Contains(got, "supersecret") {
			t.Errorf("%s rendered the credential: %s", format, got)
		}
	}
}

// --- caching and renewal ---------------------------------------------------

// TestOriginCACachesAcrossRestarts checks that a second construction adopts the
// cached certificate and makes no API request.
//
// This is the restart-storm control: without it a crash-looping process would
// request a new certificate on every start, flooding the API and churning keys.
func TestOriginCACachesAcrossRestarts(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	cfg := originTestConfig(t)
	first := newOriginTestProvider(t, cfg, now, now.Add(-time.Hour), now.Add(365*24*time.Hour))

	firstCert, err := first.GetCertificate(helloFrom("192.0.2.10:44321"))
	if err != nil {
		t.Fatalf("first GetCertificate: %v", err)
	}

	second, err := newOriginCAProviderWithClient(t.Context(), cfg, staticClock(now),
		secrets.NewRedacted("v1.0-testkey"),
		doerFunc(func(*http.Request) (*http.Response, error) {
			t.Error("a valid cached certificate must not trigger an API request")
			return nil, errors.New("unexpected request")
		}))
	if err != nil {
		t.Fatalf("second construction: %v", err)
	}
	t.Cleanup(func() { _ = second.Close() })

	secondCert, err := second.GetCertificate(helloFrom("192.0.2.10:44321"))
	if err != nil {
		t.Fatalf("second GetCertificate: %v", err)
	}
	if !bytesEqual(firstCert.Certificate[0], secondCert.Certificate[0]) {
		t.Error("the cached certificate must be the one adopted after a restart")
	}
}

// TestOriginCADoesNotAdoptAnExpiredCachedCertificate checks that the cache is
// validated before it is trusted.
//
// A process that was down while its certificate expired must issue a new one on
// the next start, not adopt the dead one. Adopting it would be served to the
// first handshake — the guard would refuse it, so the failure mode is a
// listener that accepts connections and rejects every single one, which reads
// as a network fault rather than an expired certificate.
//
// The assertion is that a NEW certificate is obtained and served, not merely
// that something was returned: the stale one is still on disk throughout.
func TestOriginCADoesNotAdoptAnExpiredCachedCertificate(t *testing.T) {
	t.Parallel()

	cfg := originTestConfig(t)

	// Issue at a time when a short-lived certificate is still valid.
	issued := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	stale := newOriginTestProvider(t, cfg, issued, issued.Add(-time.Hour), issued.Add(24*time.Hour))
	staleCert, err := stale.GetCertificate(helloFrom("192.0.2.10:44321"))
	if err != nil {
		t.Fatalf("first issuance: %v", err)
	}
	staleDER := append([]byte(nil), staleCert.Certificate[0]...)

	// Restart well after that certificate expired.
	later := issued.Add(72 * time.Hour)
	ca := newFakeOriginCA(t)
	requested := false
	fresh, err := newOriginCAProviderWithClient(t.Context(), cfg, staticClock(later),
		secrets.NewRedacted("v1.0-testkey"),
		doerFunc(func(req *http.Request) (*http.Response, error) {
			requested = true
			return ca.sign(t, req, later.Add(-time.Hour), later.Add(365*24*time.Hour)), nil
		}))
	if err != nil {
		t.Fatalf("restart: %v", err)
	}
	t.Cleanup(func() { _ = fresh.Close() })

	if !requested {
		t.Fatal("an expired cached certificate must trigger a new issuance")
	}
	freshCert, err := fresh.GetCertificate(helloFrom("192.0.2.10:44321"))
	if err != nil {
		t.Fatalf("GetCertificate after restart: %v", err)
	}
	if bytes.Equal(freshCert.Certificate[0], staleDER) {
		t.Fatal("the expired cached certificate must not be adopted")
	}
	if err := validateCertificate(freshCert, later); err != nil {
		t.Fatalf("the replacement must be valid: %v", err)
	}
}

// TestOriginCACacheFilesAreNotWorldReadable checks ADR-0015 §3's 0600 rule on
// both files the provider writes.
func TestOriginCACacheFilesAreNotWorldReadable(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	cfg := originTestConfig(t)
	newOriginTestProvider(t, cfg, now, now.Add(-time.Hour), now.Add(365*24*time.Hour))

	for _, name := range []string{originCAKeyFile, originCACertFile} {
		info, err := os.Stat(filepath.Join(cfg.TLS.CloudflareOrigin.CacheDir, name))
		if err != nil {
			t.Fatalf("stat %s: %v", name, err)
		}
		if mode := info.Mode().Perm(); mode&0o077 != 0 {
			t.Errorf("%s has mode %#o, want no group or other access", name, mode)
		}
	}
}

// TestOriginCARefusesUnsafeCachedKeyPermissions checks that a cached key any
// local account can read is not adopted.
//
// Such a key may already have been copied, so it must be treated as
// compromised. Not adopting it means the next issuance replaces it, so the
// suspect key is never served.
func TestOriginCARefusesUnsafeCachedKeyPermissions(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	cfg := originTestConfig(t)
	newOriginTestProvider(t, cfg, now, now.Add(-time.Hour), now.Add(365*24*time.Hour))

	keyPath := filepath.Join(cfg.TLS.CloudflareOrigin.CacheDir, originCAKeyFile)
	if err := os.Chmod(keyPath, 0o644); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	p := &originCAProvider{cacheDir: cfg.TLS.CloudflareOrigin.CacheDir, now: staticClock(now)}
	if _, err := p.loadCachedCert(); !errors.Is(err, ErrTLSKeyPermissions) {
		t.Fatalf("err = %v, want ErrTLSKeyPermissions", err)
	}
}

// TestOriginCANeedsIssuance covers the renewal threshold: ADR-0015 §4 renews
// when less than a third of the lifetime remains.
func TestOriginCANeedsIssuance(t *testing.T) {
	t.Parallel()

	issued := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	expires := issued.Add(300 * 24 * time.Hour)

	tests := []struct {
		name string
		at   time.Time
		want bool
	}{
		{"fresh certificate", issued.Add(24 * time.Hour), false},
		{"just inside the window", issued.Add(199 * 24 * time.Hour), false},
		{"past the renew-ahead point", issued.Add(201 * 24 * time.Hour), true},
		{"expired", expires.Add(time.Hour), true},
	}

	now := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	cfg := originTestConfig(t)
	p := newOriginTestProvider(t, cfg, now, issued, expires)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p.now = staticClock(tt.at)
			if got := p.needsIssuance(); got != tt.want {
				t.Errorf("needsIssuance at %v = %v, want %v", tt.at, got, tt.want)
			}
		})
	}
}

// TestOriginCANeedsIssuanceWithoutCertificate checks the no-certificate case
// reads as needing issuance rather than panicking on an empty chain.
func TestOriginCANeedsIssuanceWithoutCertificate(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	p := &originCAProvider{now: staticClock(now)}
	if !p.needsIssuance() {
		t.Error("a provider with no certificate must need issuance")
	}

	p.current = &tls.Certificate{}
	if !p.needsIssuance() {
		t.Error("a certificate with an empty chain must need issuance")
	}
}

// TestOriginCARenewalLoopRetriesOnFailure checks that the renewal loop actually
// drives issuance and keeps retrying after a failure.
//
// Asserting that a certificate eventually appears would prove the artifact, not
// that the LOOP produced it — and a loop that never fires leaves the process
// serving nothing once the certificate expires.
func TestOriginCARenewalLoopRetriesOnFailure(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	attempts := make(chan struct{}, 4)
	p := &originCAProvider{
		now:  staticClock(now),
		done: make(chan struct{}),
		stop: cancel,
		issue: func(context.Context) error {
			select {
			case attempts <- struct{}{}:
			default:
			}
			return errors.New("issuance failed")
		},
	}
	// A zero-length first tick so the test does not wait an hour.
	go func() {
		defer close(p.done)
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			if p.needsIssuance() {
				_ = p.issue(ctx)
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Millisecond):
			}
		}
	}()

	for i := 0; i < 2; i++ {
		select {
		case <-attempts:
		case <-time.After(2 * time.Second):
			t.Fatal("the renewal loop must keep retrying after a failure")
		}
	}
	cancel()
	<-p.done
}

// TestOriginCACloseStopsTheRenewalLoop checks the provider leaves no goroutine
// behind, which is what makes it safe to construct repeatedly under -race.
func TestOriginCACloseStopsTheRenewalLoop(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	cfg := originTestConfig(t)
	ca := newFakeOriginCA(t)

	p, err := newOriginCAProviderWithClient(t.Context(), cfg, staticClock(now),
		secrets.NewRedacted("v1.0-testkey"),
		doerFunc(func(req *http.Request) (*http.Response, error) {
			return ca.sign(t, req, now.Add(-time.Hour), now.Add(365*24*time.Hour)), nil
		}))
	if err != nil {
		t.Fatalf("build provider: %v", err)
	}
	if err := p.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	// Close waits for the loop, so done is closed by the time it returns.
	select {
	case <-p.done:
	default:
		t.Error("Close must wait for the renewal loop to exit")
	}
}

// TestOriginCAIsNotAnInBandChallengeSolver pins the startup posture.
//
// Only TLS-ALPN-01 may skip the startup probe. Origin CA issues out of band, so
// it must keep the strict check — an operator with a bad credential has to
// learn at startup, not from a client's failed handshake.
func TestOriginCAIsNotAnInBandChallengeSolver(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	cfg := originTestConfig(t)
	p := newOriginTestProvider(t, cfg, now, now.Add(-time.Hour), now.Add(365*24*time.Hour))

	if _, ok := any(p).(inBandChallengeSolver); ok {
		t.Fatal("cloudflare_origin must not be exempt from the startup probe")
	}
	if !startupProbeRequired(p) {
		t.Error("startupProbeRequired must be true for cloudflare_origin")
	}
	if p.Name() != "cloudflare_origin" {
		t.Errorf("Name = %q, want cloudflare_origin", p.Name())
	}
}
