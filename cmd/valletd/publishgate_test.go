package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/audit"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/config"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/keys"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/migrate"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/nameguard"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/repository"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/secrets"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/service/accesskey"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/service/bootstrap"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/storage/sqlite"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/telemetry"
)

// gatePepper is the pepper these tests configure the server with. A constant is
// correct here: what is under test is whether the server consults the verifier,
// not the secrecy of this value.
const gatePepper = "0123456789abcdef0123456789abcdef"

// gateNow is the fixed instant seeded rows are stamped with.
var gateNow = time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)

// gateFixture is a migrated database plus the config that names it, so a test
// can seed rows and then hand the very same config to buildServer.
type gateFixture struct {
	t     *testing.T
	cfg   *config.Config
	store *sqlite.Store
	logs  *syncBuffer
}

// newGateFixture builds a development configuration over a throwaway SQLite
// file, migrates it, and returns the store for seeding.
//
// pepperRef is written into the config verbatim, so a test can supply a good
// reference, a short one, an unresolvable one, or none at all.
func newGateFixture(t *testing.T, pepperRef string) *gateFixture {
	t.Helper()

	defaults := config.Default()
	cfg := &defaults
	cfg.Server.Environment = "development"
	cfg.Server.ListenAddr = "127.0.0.1:0"
	cfg.TLS.Mode = "self_signed"
	cfg.Database.Driver = "sqlite"
	cfg.Database.SQLite.Path = filepath.Join(t.TempDir(), "vallet.db")
	cfg.Auth.AccessKeyPepperRef = "" // set below only when asked for

	db, err := sqlite.Open(sqlite.Options{Path: cfg.Database.SQLite.Path})
	if err != nil {
		t.Fatalf("sqlite.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := applyMigrations(context.Background(), sqlite.NewMigrateDB(db), migrate.EngineSQLite); err != nil {
		t.Fatalf("applyMigrations: %v", err)
	}

	if pepperRef != "" {
		cfg.Auth.AccessKeyPepperRef = secrets.Ref(pepperRef)
	}

	return &gateFixture{t: t, cfg: cfg, store: sqlite.NewStore(db), logs: &syncBuffer{}}
}

// handler builds the server through the production assembly and returns the
// handler it will actually serve with.
//
// This is the whole point of the fixture: the request below travels through
// buildServer -> newPublisher -> publish.New's option set -> NewHandler, which
// is the same chain run uses. A gate that was never mounted cannot answer any
// of these requests correctly.
func (f *gateFixture) handler() http.Handler {
	f.t.Helper()

	logger := slog.New(slog.NewTextHandler(f.logs, nil))

	// Shut down through the same helper run defers, rather than leaving the
	// provider to the garbage collector. Under this fixture's config the
	// provider is pull-only -- traces and OTLP metrics are both disabled by
	// default, so the one reader that runs a background export loop is never
	// built -- but handler() is called once per test and more than once in
	// some, and the fixture must not depend on those defaults staying false.
	// Enabling traces here later would otherwise start a batch worker per call
	// with nothing to stop it.
	tel := telemetry.New(f.cfg, logger)
	f.t.Cleanup(func() { shutdownTelemetry(tel, logger) })

	srv, err := buildServer(context.Background(), f.cfg, logger, nil, f.store, tel, nil)
	if err != nil {
		f.t.Fatalf("buildServer: %v", err)
	}
	return srv.Handler()
}

// TestBuildUpstreamServerSelectsPlaintextListener pins the composition root that
// Decision 31 exists to deliver: upstream mode was unstartable before this change
// (newCertProvider had no upstream case), so proving the plaintext listener merely
// enforces its gate is not enough -- the assembly run() runs must actually build
// it and hand it the configured private bind. This travels the SAME
// buildUpstreamServer -> buildAPIDeps -> NewUpstreamServer chain run uses, off a
// socket, so a regression that stops upstream mode from constructing its listener
// fails here rather than only at deploy time.
func TestBuildUpstreamServerSelectsPlaintextListener(t *testing.T) {
	t.Setenv("VALLET_TEST_ACCESS_KEY_PEPPER", gatePepper)
	f := newGateFixture(t, "env:VALLET_TEST_ACCESS_KEY_PEPPER")
	const bind = "127.0.0.1:8899"
	f.cfg.TLS.Mode = "upstream"
	f.cfg.TLS.Upstream.ListenAddr = bind

	logger := slog.New(slog.NewTextHandler(f.logs, nil))
	tel := telemetry.New(f.cfg, logger)
	t.Cleanup(func() { shutdownTelemetry(tel, logger) })

	srv, err := buildUpstreamServer(context.Background(), f.cfg, logger, nil, f.store, tel, nil)
	if err != nil {
		t.Fatalf("buildUpstreamServer: %v", err)
	}
	if srv == nil {
		t.Fatal("buildUpstreamServer returned a nil server in upstream mode")
	}
	if got := srv.Addr(); got != bind {
		t.Errorf("upstream listener bind: got %q, want %q", got, bind)
	}
}

// get issues one publish request through the built handler.
func (f *gateFixture) get(h http.Handler, target, bearer string) *httptest.ResponseRecorder {
	f.t.Helper()

	req := httptest.NewRequest(http.MethodGet, target, nil)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

// seedOwner creates an owner, its handle, and its public default key set with
// one key in it.
func (f *gateFixture) seedOwner(handle, comment string) bootstrap.Result {
	f.t.Helper()

	res, err := bootstrap.Seed(context.Background(), f.store, bootstrap.Params{
		Handle:  handle,
		KeyLine: gateKeyLine(f.t, comment),
		Now:     gateNow,
		Guard:   f.guard(),
	})
	if err != nil {
		f.t.Fatalf("bootstrap.Seed(%q): %v", handle, err)
	}
	return res
}

// guard builds the default reserved-identifier matcher the seeding helpers
// need. bootstrap refuses a nil one by design, so every seed path supplies it.
func (f *gateFixture) guard() *nameguard.Guard {
	f.t.Helper()

	guard, err := nameguard.Default()
	if err != nil {
		f.t.Fatalf("nameguard.Default: %v", err)
	}
	return guard
}

// seedProtectedSet creates a protected key set holding one key.
func (f *gateFixture) seedProtectedSet(ownerID domain.OwnerID, name, comment string) domain.KeySetID {
	f.t.Helper()

	set := &domain.KeySet{
		ID: domain.KeySetID("set-" + name + "-" + string(ownerID)), OwnerID: ownerID, Name: name,
		Visibility: domain.VisibilityProtected, State: domain.NameStateActive,
		CreatedAt: gateNow, UpdatedAt: gateNow,
	}
	if err := f.store.Repos().KeySets.Create(context.Background(), set); err != nil {
		f.t.Fatalf("KeySets.Create: %v", err)
	}

	parsed, err := keys.Parse(gateKeyLine(f.t, comment))
	if err != nil {
		f.t.Fatalf("keys.Parse: %v", err)
	}
	err = f.store.WithTx(context.Background(), func(ctx context.Context, r repository.Repos) error {
		_, addErr := bootstrap.AddKey(ctx, r, bootstrap.AddKeyParams{
			OwnerID: ownerID, KeySetID: set.ID, DeviceName: "gate", Key: parsed, Now: gateNow,
			// Required since the reserved-identifier blocklist reached device
			// names: a nil Guard refuses every name rather than passing them
			// through, so omitting it fails the seed rather than writing an
			// unchecked name. Supplying the real default matcher keeps this
			// fixture on the same path production takes.
			Guard: f.guard(),
		})
		return addErr
	})
	if err != nil {
		f.t.Fatalf("AddKey: %v", err)
	}
	return set.ID
}

// mint issues a real access key for a set, keyed by the SAME pepper the server
// will resolve. If the two ever diverge the digest cannot match and the gate's
// success path becomes untestable, so this deliberately shares one constant
// with the environment the test sets.
func (f *gateFixture) mint(ownerID domain.OwnerID, setID domain.KeySetID) string {
	f.t.Helper()

	svc, err := accesskey.New(f.store, gateAuditor{}, []byte(gatePepper))
	if err != nil {
		f.t.Fatalf("accesskey.New: %v", err)
	}
	_, token, err := svc.Mint(context.Background(), ownerID, setID, "consumer", "req-gate")
	if err != nil {
		f.t.Fatalf("Mint: %v", err)
	}
	return token.Reveal()
}

// gateAuditor satisfies the access key service's audit dependency for the
// fixture's own minting; what the mint path records is that package's test.
type gateAuditor struct{}

func (gateAuditor) Emit(context.Context, audit.Event) error { return nil }

// gateKeyLine returns a fresh authorized_keys line.
func gateKeyLine(t *testing.T, comment string) []byte {
	t.Helper()

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("NewPublicKey: %v", err)
	}
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub)))
	if comment != "" {
		line += " " + comment
	}
	return []byte(line + "\n")
}

// TestProtectedSetIsUnlockedThroughTheRealServerWiring is THE test for this
// change, and the success case is the reason it exists.
//
// A test that only asserted a protected set 404s would pass just as well
// against the previous, deliberately unwired state -- an unmounted gate and a
// consulted gate that refused are the same response, which is exactly the
// property the uniform 404 was designed to have. So the load-bearing assertion
// here is the 200: a server whose publish service has no verifier resolves NO
// protected set for anybody, so it cannot produce this body for any credential.
// The only way this passes is if buildServer actually handed a verifier to
// publish.New and the handler actually consulted it.
//
// The refusals are asserted alongside, because a gate that is reached and
// always says yes would also produce the 200.
func TestProtectedSetIsUnlockedThroughTheRealServerWiring(t *testing.T) {
	t.Setenv("VALLET_TEST_ACCESS_KEY_PEPPER", gatePepper)
	f := newGateFixture(t, "env:VALLET_TEST_ACCESS_KEY_PEPPER")

	alice := f.seedOwner("alice", "public-key")
	prodSet := f.seedProtectedSet(alice.OwnerID, "prod", "prod-key")
	token := f.mint(alice.OwnerID, prodSet)
	otherSetToken := f.mint(alice.OwnerID, alice.KeySetID)

	h := f.handler()

	t.Run("a valid access key unlocks the protected set", func(t *testing.T) {
		rr := f.get(h, "/alice/prod", token)
		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200; the serving path never consulted the verifier.\nbody = %q",
				rr.Code, rr.Body.String())
		}
		if !strings.Contains(rr.Body.String(), "prod-key") {
			t.Errorf("body = %q, want the protected set's key", rr.Body.String())
		}
		// A protected success is privately cacheable and varies on the
		// credential; a response missing these came from some other path.
		if got := rr.Header().Get("Cache-Control"); got != "private, max-age=60" {
			t.Errorf("Cache-Control = %q, want private", got)
		}
		if got := rr.Header().Get("Vary"); got != "Authorization" {
			t.Errorf("Vary = %q, want Authorization", got)
		}
	})

	t.Run("the gate still refuses everything else", func(t *testing.T) {
		absent := f.get(h, "/alice/nosuchset", "")
		if absent.Code != http.StatusNotFound {
			t.Fatalf("baseline for an absent set = %d, want 404", absent.Code)
		}
		for name, bearer := range map[string]string{
			"no credential":            "",
			"a garbage token":          "garbage",
			"the other set's real key": otherSetToken,
		} {
			rr := f.get(h, "/alice/prod", bearer)
			if rr.Code != absent.Code || rr.Body.String() != absent.Body.String() {
				t.Errorf("%s: (%d, %q) differs from the absent set's (%d, %q)",
					name, rr.Code, rr.Body.String(), absent.Code, absent.Body.String())
			}
		}
	})

	t.Run("a public set still serves unauthenticated", func(t *testing.T) {
		rr := f.get(h, "/alice", "")
		if rr.Code != http.StatusOK {
			t.Fatalf("public set status = %d, want 200; wiring the gate broke the public path", rr.Code)
		}
		if !strings.Contains(rr.Body.String(), "public-key") {
			t.Errorf("public body = %q, want the default set's key", rr.Body.String())
		}
	})

	// The pepper travels as a secrets.Redacted and is never logged. Startup
	// writes several lines; none of them may contain it.
	if strings.Contains(f.logs.String(), gatePepper) {
		t.Error("the access key pepper appeared in the server's own log output")
	}
}

// TestWithoutAPepperNoProtectedSetIsServed pins the fail-closed interim mode a
// development checkout selects by naming no pepper: the public path is
// unchanged and every protected set is invisible to everyone.
//
// The warning is asserted too. A server silently not serving protected sets is
// the failure an operator debugs from the consumer's side for an hour, so the
// log line is part of the contract, not decoration.
func TestWithoutAPepperNoProtectedSetIsServed(t *testing.T) {
	f := newGateFixture(t, "")

	alice := f.seedOwner("alice", "public-key")
	f.seedProtectedSet(alice.OwnerID, "prod", "prod-key")

	h := f.handler()

	if rr := f.get(h, "/alice", ""); rr.Code != http.StatusOK {
		t.Errorf("public set status = %d, want 200", rr.Code)
	}
	if rr := f.get(h, "/alice/prod", ""); rr.Code != http.StatusNotFound {
		t.Errorf("protected set status = %d, want 404 with no verifier", rr.Code)
	}
	if !strings.Contains(f.logs.String(), "no access key pepper configured") {
		t.Errorf("startup did not warn that protected sets are unserved.\nlogs:\n%s", f.logs.String())
	}
}

// TestAnInadequatePepperRefusesStartup is the confidentiality-critical one.
//
// A pepper that was NAMED and cannot be turned into an adequate key must stop
// the process. The tempting alternative -- fall back to the verifier-less mode
// -- is the silent downgrade this whole design exists to prevent: the server
// would report a clean start while every protected set quietly stopped being
// reachable, or worse, while digests were keyed by something too short to
// resist an offline attack on a stolen database.
//
// Development is deliberately included: the length rule and the resolution rule
// are NOT relaxed outside production. Only an entirely unset reference is.
func TestAnInadequatePepperRefusesStartup(t *testing.T) {
	t.Setenv("VALLET_TEST_SHORT_PEPPER", strings.Repeat("a", accesskey.MinPepperLen-1))

	cases := map[string]string{
		"one byte short":          "env:VALLET_TEST_SHORT_PEPPER",
		"unset environment":       "env:VALLET_TEST_PEPPER_THAT_IS_NOT_SET",
		"unreadable file":         "file:/nonexistent/vallet/pepper",
		"a malformed reference":   "not-a-reference",
		"an unknown scheme":       "vault:secret/vallet/pepper",
		"a pasted secret, no ref": "0123456789abcdef0123456789abcdef",
	}
	for name, ref := range cases {
		t.Run(name, func(t *testing.T) {
			f := newGateFixture(t, ref)
			for _, env := range []string{"development", "production"} {
				f.cfg.Server.Environment = env
				logger := slog.New(slog.NewTextHandler(f.logs, nil))
				_, err := newPublisher(context.Background(), f.cfg, logger, f.store)
				if err == nil {
					t.Fatalf("%s: startup accepted an inadequate pepper and built a publisher anyway", env)
				}
				if strings.Contains(err.Error(), gatePepper) {
					t.Errorf("%s: the error text carried a secret value: %v", env, err)
				}
			}
		})
	}
}

// TestProductionRefusesAnAbsentPepper pins the one place the absent reference
// is not a valid choice.
//
// In development an unset pepper selects the verifier-less mode, which is safe.
// In production it is refused instead: a deployment that believes it serves
// protected key sets and serves none, with no complaint, is indistinguishable
// from one that works right up until a consumer files a ticket.
//
// The check lives in run's own path as well as in config.Validate, and this
// test drives the former, so a future entry point that skipped validation
// cannot reintroduce the unverified production mode.
func TestProductionRefusesAnAbsentPepper(t *testing.T) {
	f := newGateFixture(t, "")
	f.cfg.Server.Environment = "production"

	logger := slog.New(slog.NewTextHandler(f.logs, nil))
	if _, err := newPublisher(context.Background(), f.cfg, logger, f.store); err == nil {
		t.Fatal("production started with no access key pepper")
	} else if !strings.Contains(err.Error(), "auth.access_key_pepper_ref") {
		t.Errorf("the refusal does not name the config field an operator must set: %v", err)
	}
}

// TestConfigRefusesProductionWithoutAPepper pins the same rule at the config
// layer, where an operator meets it before the process ever opens a database.
func TestConfigRefusesProductionWithoutAPepper(t *testing.T) {
	f := newGateFixture(t, "")
	f.cfg.Server.Environment = "production"
	f.cfg.Server.PublicBaseURL = "https://vallet.example.com"
	f.cfg.TLS.AllowSelfSignedInProduction = true
	f.cfg.Auth.TokenSigningKeyRef = "env:VALLET_SIGNING_KEY"

	err := f.cfg.Validate()
	if err == nil {
		t.Fatal("Validate accepted a production config with no access key pepper")
	}
	if !strings.Contains(err.Error(), "auth.access_key_pepper_ref") {
		t.Errorf("validation error does not name the field: %v", err)
	}
}

// TestRunItselfReachesTheAccessGate closes the one hole every other test in
// this file shares: they all enter at buildServer or newPublisher, so they
// prove the gate assembly is correct without proving that run still calls it.
//
// That gap is not hypothetical -- it is the exact shape of the defect this
// change removes. A regression that re-inlined the old, verifier-less
// publish.New(store.Repos()) into run and stopped calling buildServer compiles
// cleanly, leaves buildServer referenced (by these tests, so no unused-symbol
// complaint), and passes every other assertion here, because a test that never
// enters through run cannot see which publisher run built. The gate would be
// perfectly constructed and never reached, which looks identical to a gate that
// is reached and refusing.
//
// The discriminator is a pepper that is one byte too short, in DEVELOPMENT:
//
//   - config.Validate accepts it. Validate only checks IsZero; the length rule
//     lives in accesskey.New, next to the HMAC it protects. So this config gets
//     all the way past validation.
//   - run therefore returns an error here if and ONLY if it actually executed
//     the gate construction, which is the single place that length is ruled on.
//   - a run that bypasses the gate never resolves the pepper at all, reaches
//     serve, and blocks forever -- so it fails this test by deadline rather
//     than by assertion.
//
// No seeding and no listener are needed: the refusal happens at construction,
// before serve is ever called.
func TestRunItselfReachesTheAccessGate(t *testing.T) {
	// Not parallel: it sets process environment and may signal itself.
	t.Setenv("VALLET_TEST_RUN_SHORT_PEPPER", strings.Repeat("a", accesskey.MinPepperLen-1))

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "vallet.yaml")
	cfgText := "" +
		"server:\n" +
		"  environment: development\n" +
		"  listen_addr: 127.0.0.1:0\n" +
		"tls:\n" +
		"  mode: self_signed\n" +
		"database:\n" +
		"  driver: sqlite\n" +
		"  sqlite:\n" +
		"    path: " + filepath.Join(dir, "vallet.db") + "\n" +
		"auth:\n" +
		"  access_key_pepper_ref: env:VALLET_TEST_RUN_SHORT_PEPPER\n" +
		"telemetry:\n" +
		"  log:\n" +
		"    level: info\n" +
		"    format: text\n"
	if err := os.WriteFile(cfgPath, []byte(cfgText), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	var logs syncBuffer
	done := make(chan error, 1)
	go func() { done <- run([]string{"-config", cfgPath}, &logs, &logs) }()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("run returned success with a pepper too short to key any digest")
		}
		if !strings.Contains(err.Error(), "pepper") {
			t.Fatalf("run failed for some other reason than the pepper: %v\nlogs:\n%s", err, logs.String())
		}
	case <-time.After(30 * time.Second):
		// Either run began serving despite the short pepper, or -- the
		// regression this test exists for -- it never consulted the gate at all.
		if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
			t.Errorf("signal self: %v", err)
		}
		<-done
		t.Fatalf("run started serving without ever ruling on the access key pepper; "+
			"the gate is constructed somewhere run does not call.\nlogs:\n%s", logs.String())
	}
}
