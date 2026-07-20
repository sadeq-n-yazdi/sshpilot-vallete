package httpserver_test

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/audit"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	httpserver "github.com/sadeq-n-yazdi/sshpilot-vallete/internal/transport/http"
)

// TestKeyLifecycle walks the slice end to end through the real router: enroll,
// list, revoke, and list again.
func TestKeyLifecycle(t *testing.T) {
	t.Parallel()

	env := newKeyEnv(t)
	token := env.fullToken(t, "owner-a")
	dev := env.seedDevice(t, "owner-a", "dev-a")

	added := env.mustAdd(t, token, dev, ed25519Line(t, "work laptop"))
	if added.Status != string(domain.KeyStatusActive) {
		t.Errorf("status = %q, want active", added.Status)
	}
	if added.Algorithm != string(domain.AlgEd25519) {
		t.Errorf("algorithm = %q, want %q", added.Algorithm, domain.AlgEd25519)
	}
	if added.Comment != "work laptop" {
		t.Errorf("comment = %q, want %q", added.Comment, "work laptop")
	}
	if !strings.HasPrefix(added.Fingerprint, "SHA256:") {
		t.Errorf("fingerprint = %q, want an OpenSSH SHA256 fingerprint", added.Fingerprint)
	}
	if added.BitLen != 256 {
		t.Errorf("bit_len = %d, want 256", added.BitLen)
	}
	if added.DeviceID != string(dev) {
		t.Errorf("device_id = %q, want %q", added.DeviceID, dev)
	}

	listed := env.mustList(t, token)
	if len(listed) != 1 || listed[0].ID != added.ID {
		t.Fatalf("list = %+v, want the one key just added", listed)
	}

	rr := env.do(t, http.MethodDelete, keysPath+"/"+added.ID, token, "")
	if rr.Code != http.StatusNoContent {
		t.Fatalf("revoke = %d (%s), want 204", rr.Code, rr.Body.String())
	}

	// The revoked key stays in the owner's own inventory. Hiding it would make
	// a revoked key indistinguishable from one that was never enrolled -- for
	// the owner, who is entitled to the difference.
	after := env.mustList(t, token)
	if len(after) != 1 || after[0].Status != string(domain.KeyStatusRevoked) {
		t.Fatalf("list after revoke = %+v, want one revoked key", after)
	}
	if after[0].RevokedAt == "" {
		t.Error("revoked key carries no revoked_at")
	}
}

// TestResponseOmitsOwnerAndKeyMaterial pins what the wire form does NOT carry.
// The owner is absent so a client is never invited to start sending one; the
// blob is absent so this authenticated surface cannot become a second
// distribution channel for key material.
func TestResponseOmitsOwnerAndKeyMaterial(t *testing.T) {
	t.Parallel()

	env := newKeyEnv(t)
	token := env.fullToken(t, "owner-a")
	dev := env.seedDevice(t, "owner-a", "dev-a")
	line := ed25519Line(t, "laptop")

	rr := env.do(t, http.MethodPost, keysPath, token, addBody(t, dev, line))
	if rr.Code != http.StatusCreated {
		t.Fatalf("add = %d, want 201", rr.Code)
	}

	// The assertion is on the raw bytes, not on a decoded struct: a struct with
	// no owner field would silently pass while the server sent one.
	body := rr.Body.String()
	for _, forbidden := range []string{"owner_id", "owner-a", "blob"} {
		if strings.Contains(body, forbidden) {
			t.Errorf("response body contains %q: %s", forbidden, body)
		}
	}
	// The base64 body of the key must not be echoed either. The comment may be,
	// since it is a display name the owner chose.
	if b64 := strings.Fields(line)[1]; strings.Contains(body, b64) {
		t.Error("response body echoes the key blob")
	}
}

// TestAddRejectsPrivateKeyMaterial is the ADR-0002 control at the HTTP edge: a
// pasted private key is refused, and no part of it reaches the response body,
// the request log, the audit log, or storage.
func TestAddRejectsPrivateKeyMaterial(t *testing.T) {
	t.Parallel()

	var logged bytes.Buffer
	env := newKeyEnvWithLogger(t, slog.New(slog.NewJSONHandler(&logged, nil)))
	token := env.fullToken(t, "owner-a")
	dev := env.seedDevice(t, "owner-a", "dev-a")

	priv := privateKeyPEM(t)
	rr := env.do(t, http.MethodPost, keysPath, token, addBody(t, dev, priv))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("add private key = %d (%s), want 400", rr.Code, rr.Body.String())
	}

	// The refusal explains itself -- that is the point of the fixed message --
	// but explains itself without quoting anything it was given.
	if !strings.Contains(rr.Body.String(), "private key material detected") {
		t.Errorf("body does not carry the guidance message: %s", rr.Body.String())
	}

	// Every line of the PEM body is checked, not just the header: a leak of the
	// base64 payload is the leak that matters, and asserting only on "BEGIN"
	// would pass while the whole key sat in the log.
	for _, line := range strings.Split(strings.TrimSpace(priv), "\n") {
		if line == "" {
			continue
		}
		if strings.Contains(rr.Body.String(), line) {
			t.Errorf("response echoes private key line %q", line)
		}
		if strings.Contains(logged.String(), line) {
			t.Errorf("request log contains private key line %q", line)
		}
		for _, rec := range env.sink.records {
			for k, v := range rec.Metadata {
				if strings.Contains(v, line) {
					t.Errorf("audit detail %q contains private key line %q", k, line)
				}
			}
		}
	}

	if env.keys.count() != 0 {
		t.Error("a private key submission created a stored row")
	}
	if len(env.sink.records) != 0 {
		t.Errorf("a rejected submission emitted %d audit records, want 0", len(env.sink.records))
	}
}

// TestAddRejectsUnacceptableKeys covers the rest of the ingest contract. Every
// case here is refused by internal/keys, and this test exists to prove the
// transport routes those refusals to 400 rather than swallowing or
// misclassifying them.
func TestAddRejectsUnacceptableKeys(t *testing.T) {
	t.Parallel()

	env := newKeyEnv(t)
	token := env.fullToken(t, "owner-a")
	dev := env.seedDevice(t, "owner-a", "dev-a")
	good := ed25519Line(t, "laptop")

	for _, tc := range []struct {
		name string
		line string
	}{
		// ADR-0006: an options-bearing line is never accepted. Options are how
		// an authorized_keys entry gains a forced command or a source
		// restriction, so silently storing one would let a submission carry
		// behavior the server never reviewed.
		{"command option", `command="/bin/sh" ` + good},
		{"restrict option", "restrict," + good},
		{"no-pty option", "no-pty " + good},
		// Below the RSA floor (domain.MinRSABits = 3072).
		{"weak rsa", rsaLine(t, 2048, "old")},
		// More than one key in one submission.
		{"two keys", good + "\n" + ed25519Line(t, "second")},
		{"empty", ""},
		{"not a key", "hello world"},
		{"comment line", "# " + good},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			rr := env.do(t, http.MethodPost, keysPath, token, addBody(t, dev, tc.line))
			if rr.Code != http.StatusBadRequest {
				t.Fatalf("add = %d (%s), want 400", rr.Code, rr.Body.String())
			}
		})
	}
}

// TestWeakRSAIsRefusedButStrongRSAIsAccepted checks the strength floor from
// both sides. A test that only asserts the refusal would pass against a server
// that refused every RSA key, which is a different bug wearing the same result.
func TestWeakRSAIsRefusedButStrongRSAIsAccepted(t *testing.T) {
	t.Parallel()

	env := newKeyEnv(t)
	token := env.fullToken(t, "owner-a")
	dev := env.seedDevice(t, "owner-a", "dev-a")

	weak := env.do(t, http.MethodPost, keysPath, token, addBody(t, dev, rsaLine(t, 2048, "weak")))
	if weak.Code != http.StatusBadRequest {
		t.Errorf("2048-bit rsa = %d, want 400", weak.Code)
	}

	strong := env.mustAdd(t, token, dev, rsaLine(t, domain.MinRSABits, "strong"))
	if strong.BitLen != domain.MinRSABits {
		t.Errorf("bit_len = %d, want %d", strong.BitLen, domain.MinRSABits)
	}
}

// TestAddRejectsBadBodies checks the JSON surface. An owner field is the case
// that matters: it must be refused outright, not silently dropped, so a request
// that tried to assert an owner never looks like it succeeded.
func TestAddRejectsBadBodies(t *testing.T) {
	t.Parallel()

	env := newKeyEnv(t)
	token := env.fullToken(t, "owner-a")
	dev := env.seedDevice(t, "owner-a", "dev-a")
	good := ed25519Line(t, "laptop")
	body := addBody(t, dev, good)

	for _, tc := range []struct {
		name string
		body string
	}{
		{"empty", ""},
		{"not json", "{"},
		{"owner asserted", `{"device_id":"dev-a","public_key":"x","owner_id":"owner-b"}`},
		{"unknown field", `{"device_id":"dev-a","public_key":"x","algorithm":"ssh-ed25519"}`},
		{"fingerprint asserted", `{"device_id":"dev-a","public_key":"x","fingerprint":"SHA256:x"}`},
		{"trailing json value", body + `{"device_id":"dev-a"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			rr := env.do(t, http.MethodPost, keysPath, token, tc.body)
			if rr.Code != http.StatusBadRequest {
				t.Fatalf("add = %d (%s), want 400", rr.Code, rr.Body.String())
			}
			// A decode failure carries no reason: a JSON error can quote the
			// bytes it choked on, and the field it would quote is the one a
			// user pastes a private key into.
			if strings.Contains(rr.Body.String(), "reason") && tc.name != "owner asserted" {
				t.Errorf("decode refusal carries a reason: %s", rr.Body.String())
			}
		})
	}
	if env.keys.count() != 0 {
		t.Error("a rejected body created a stored row")
	}
}

// TestCrossOwnerIsolation is the tenant boundary. Owner B must not be able to
// see, revoke, or even confirm the existence of owner A's key -- and the
// response it gets must be byte-identical to the one an invented id gets.
func TestCrossOwnerIsolation(t *testing.T) {
	t.Parallel()

	env := newKeyEnv(t)
	tokenA := env.fullToken(t, "owner-a")
	tokenB := env.fullToken(t, "owner-b")
	devA := env.seedDevice(t, "owner-a", "dev-a")
	env.seedDevice(t, "owner-b", "dev-b")

	keyA := env.mustAdd(t, tokenA, devA, ed25519Line(t, "a laptop"))

	t.Run("b cannot see a's key in its own list", func(t *testing.T) {
		if got := env.mustList(t, tokenB); len(got) != 0 {
			t.Fatalf("owner-b list = %+v, want empty", got)
		}
	})

	t.Run("b's revoke of a's key is indistinguishable from a miss", func(t *testing.T) {
		foreign := env.do(t, http.MethodDelete, keysPath+"/"+keyA.ID, tokenB, "")
		invented := env.do(t, http.MethodDelete, keysPath+"/"+"NOSUCHKEYIDENTIFIER0000000", tokenB, "")

		if foreign.Code != http.StatusNotFound {
			t.Errorf("revoking another owner's key = %d, want 404", foreign.Code)
		}
		if foreign.Code != invented.Code || foreign.Body.String() != invented.Body.String() {
			t.Errorf("foreign key answered %d %q, invented id answered %d %q; the two must be identical",
				foreign.Code, foreign.Body.String(), invented.Code, invented.Body.String())
		}
	})

	t.Run("a's key is untouched", func(t *testing.T) {
		got := env.mustList(t, tokenA)
		if len(got) != 1 || got[0].Status != string(domain.KeyStatusActive) {
			t.Fatalf("owner-a list = %+v, want the key still active", got)
		}
	})

	t.Run("b cannot enroll on a's device", func(t *testing.T) {
		foreign := env.do(t, http.MethodPost, keysPath, tokenB, addBody(t, devA, ed25519Line(t, "b key")))
		invented := env.do(t, http.MethodPost, keysPath, tokenB,
			addBody(t, "NOSUCHDEVICEIDENTIFIER0000", ed25519Line(t, "b key")))

		if foreign.Code != http.StatusNotFound {
			t.Errorf("enrolling on another owner's device = %d, want 404", foreign.Code)
		}
		if foreign.Code != invented.Code || foreign.Body.String() != invented.Body.String() {
			t.Errorf("foreign device answered %d %q, invented id answered %d %q; the two must be identical",
				foreign.Code, foreign.Body.String(), invented.Code, invented.Body.String())
		}
		if env.keys.count() != 1 {
			t.Errorf("stored rows = %d, want 1; a cross-owner enrollment was written", env.keys.count())
		}
	})
}

// TestRevokeIsIdempotentSafe pins that a repeat revoke changes nothing and
// answers exactly as an unknown id does. It is deliberately NOT the REST
// convention of answering the repeat with 204: that would make a key's
// lifecycle state observable as a third answer, distinct from absent.
func TestRevokeIsIdempotentSafe(t *testing.T) {
	t.Parallel()

	env := newKeyEnv(t)
	token := env.fullToken(t, "owner-a")
	dev := env.seedDevice(t, "owner-a", "dev-a")
	added := env.mustAdd(t, token, dev, ed25519Line(t, "laptop"))

	if rr := env.do(t, http.MethodDelete, keysPath+"/"+added.ID, token, ""); rr.Code != http.StatusNoContent {
		t.Fatalf("first revoke = %d, want 204", rr.Code)
	}
	repeat := env.do(t, http.MethodDelete, keysPath+"/"+added.ID, token, "")
	invented := env.do(t, http.MethodDelete, keysPath+"/"+"NOSUCHKEYIDENTIFIER0000000", token, "")

	if repeat.Code != http.StatusNotFound {
		t.Errorf("repeat revoke = %d, want 404", repeat.Code)
	}
	if repeat.Code != invented.Code || repeat.Body.String() != invented.Body.String() {
		t.Errorf("repeat answered %d %q, invented id answered %d %q; the two must be identical",
			repeat.Code, repeat.Body.String(), invented.Code, invented.Body.String())
	}
	// Exactly one revocation was recorded: the second call did nothing.
	if n := len(env.auditRecords(domain.AuditActionKeyRevoked)); n != 1 {
		t.Errorf("key.revoked records = %d, want 1", n)
	}
}

// TestScopeEnforcement is the B5 boundary at this route. A read-only token may
// list and may not mutate, and a device-bound token reaches none of these
// account-addressed routes.
func TestScopeEnforcement(t *testing.T) {
	t.Parallel()

	env := newKeyEnv(t)
	full := env.fullToken(t, "owner-a")
	dev := env.seedDevice(t, "owner-a", "dev-a")
	added := env.mustAdd(t, full, dev, ed25519Line(t, "laptop"))

	readOnly := env.token(t, "owner-a", domain.Scope{Kind: domain.ScopeReadOnly})
	bound := env.token(t, "owner-a", domain.Scope{Kind: domain.ScopeSingleDevice, ResourceID: string(dev)})

	t.Run("read-only may list", func(t *testing.T) {
		if rr := env.do(t, http.MethodGet, keysPath, readOnly, ""); rr.Code != http.StatusOK {
			t.Fatalf("read-only list = %d (%s), want 200", rr.Code, rr.Body.String())
		}
	})
	t.Run("read-only may not add", func(t *testing.T) {
		rr := env.do(t, http.MethodPost, keysPath, readOnly, addBody(t, dev, ed25519Line(t, "second")))
		if rr.Code != http.StatusForbidden {
			t.Fatalf("read-only add = %d (%s), want 403", rr.Code, rr.Body.String())
		}
	})
	t.Run("read-only may not revoke", func(t *testing.T) {
		rr := env.do(t, http.MethodDelete, keysPath+"/"+added.ID, readOnly, "")
		if rr.Code != http.StatusForbidden {
			t.Fatalf("read-only revoke = %d (%s), want 403", rr.Code, rr.Body.String())
		}
	})
	t.Run("device-bound reaches no key route", func(t *testing.T) {
		for _, spec := range [][3]string{
			{http.MethodGet, keysPath, ""},
			{http.MethodPost, keysPath, addBody(t, dev, ed25519Line(t, "third"))},
			{http.MethodDelete, keysPath + "/" + added.ID, ""},
		} {
			rr := env.do(t, spec[0], spec[1], bound, spec[2])
			if rr.Code != http.StatusForbidden {
				t.Errorf("device-bound %s %s = %d, want 403", spec[0], spec[1], rr.Code)
			}
		}
	})

	// Nothing above changed state. Asserted separately because a 403 that
	// arrived after the handler ran would still read as a 403.
	if got := env.mustList(t, full); len(got) != 1 || got[0].Status != string(domain.KeyStatusActive) {
		t.Fatalf("list = %+v, want the single key still active", got)
	}
}

// TestListReturnsAnEmptyArrayNotNull pins the wire form for an owner with no
// keys. The service passes the repository's nil slice through; the transport is
// what turns it into an array, and a nil reaching json.Marshal would send
// `null` and break a client that iterates.
func TestListReturnsAnEmptyArrayNotNull(t *testing.T) {
	t.Parallel()

	env := newKeyEnv(t)
	rr := env.do(t, http.MethodGet, keysPath, env.fullToken(t, "owner-empty"), "")
	if rr.Code != http.StatusOK {
		t.Fatalf("list = %d, want 200", rr.Code)
	}
	if got := strings.TrimSpace(rr.Body.String()); got != `{"keys":[]}` {
		t.Errorf("body = %s, want {\"keys\":[]}", got)
	}
}

// TestDuplicateFingerprintConflicts pins the one negative verdict that is
// deliberately NOT collapsed. It is safe because the uniqueness constraint is
// per-owner: the only key it can report on is one the caller already holds.
func TestDuplicateFingerprintConflicts(t *testing.T) {
	t.Parallel()

	env := newKeyEnv(t)
	token := env.fullToken(t, "owner-a")
	dev := env.seedDevice(t, "owner-a", "dev-a")
	line := ed25519Line(t, "laptop")

	env.mustAdd(t, token, dev, line)
	rr := env.do(t, http.MethodPost, keysPath, token, addBody(t, dev, line))
	if rr.Code != http.StatusConflict {
		t.Fatalf("duplicate add = %d (%s), want 409", rr.Code, rr.Body.String())
	}
	if env.keys.count() != 1 {
		t.Errorf("stored rows = %d, want 1", env.keys.count())
	}

	// The same key under a different owner is not a conflict: the constraint is
	// per-owner, and a cross-owner 409 would be an oracle telling owner B that
	// owner A holds a key B happens to have guessed.
	env.seedDevice(t, "owner-b", "dev-b")
	other := env.do(t, http.MethodPost, keysPath, env.fullToken(t, "owner-b"), addBody(t, "dev-b", line))
	if other.Code != http.StatusCreated {
		t.Fatalf("same key for another owner = %d (%s), want 201", other.Code, other.Body.String())
	}
}

// TestAddRefusesRevokedDevice pins that a retired device gains no new keys, and
// that the refusal is the same one an unknown device gets so a stranger's
// device lifecycle stays unobservable.
func TestAddRefusesRevokedDevice(t *testing.T) {
	t.Parallel()

	env := newKeyEnv(t)
	token := env.fullToken(t, "owner-a")
	dev := env.seedDevice(t, "owner-a", "dev-a")
	if err := env.devices.Revoke(t.Context(), "owner-a", dev, env.now); err != nil {
		t.Fatalf("revoke device: %v", err)
	}

	revoked := env.do(t, http.MethodPost, keysPath, token, addBody(t, dev, ed25519Line(t, "laptop")))
	invented := env.do(t, http.MethodPost, keysPath, token,
		addBody(t, "NOSUCHDEVICEIDENTIFIER0000", ed25519Line(t, "laptop")))

	if revoked.Code != http.StatusNotFound {
		t.Errorf("enroll on revoked device = %d (%s), want 404", revoked.Code, revoked.Body.String())
	}
	if revoked.Code != invented.Code || revoked.Body.String() != invented.Body.String() {
		t.Errorf("revoked device answered %d %q, invented id answered %d %q; the two must be identical",
			revoked.Code, revoked.Body.String(), invented.Code, invented.Body.String())
	}
	if env.keys.count() != 0 {
		t.Error("a key was written for a revoked device")
	}
}

// TestAuditRecordsOnAddAndRevoke pins the shape of the accountability trail
// (ADR-0007): who acted, on what, and the two derived facts that make the
// record readable -- and nothing else.
func TestAuditRecordsOnAddAndRevoke(t *testing.T) {
	t.Parallel()

	env := newKeyEnv(t)
	token := env.fullToken(t, "owner-a")
	dev := env.seedDevice(t, "owner-a", "dev-a")
	line := ed25519Line(t, "work laptop")
	added := env.mustAdd(t, token, dev, line)

	if rr := env.do(t, http.MethodDelete, keysPath+"/"+added.ID, token, ""); rr.Code != http.StatusNoContent {
		t.Fatalf("revoke = %d, want 204", rr.Code)
	}

	for _, want := range []domain.AuditAction{domain.AuditActionKeyAdded, domain.AuditActionKeyRevoked} {
		recs := env.auditRecords(want)
		if len(recs) != 1 {
			t.Fatalf("%s records = %d, want 1", want, len(recs))
		}
		rec := recs[0]
		if rec.ActorType != domain.ActorTypeOwner || rec.ActorID != "owner-a" {
			t.Errorf("%s actor = %s/%s, want owner/owner-a", want, rec.ActorType, rec.ActorID)
		}
		if rec.TargetType != domain.TargetTypePublicKey || rec.TargetID != added.ID {
			t.Errorf("%s target = %s/%s, want public_key/%s", want, rec.TargetType, rec.TargetID, added.ID)
		}
		if got := rec.Metadata[string(audit.DetailFingerprint)]; got != added.Fingerprint {
			t.Errorf("%s fingerprint detail = %q, want %q", want, got, added.Fingerprint)
		}
		if got := rec.Metadata[string(audit.DetailAlgorithm)]; got != string(domain.AlgEd25519) {
			t.Errorf("%s algorithm detail = %q, want %q", want, got, domain.AlgEd25519)
		}
		if rec.Metadata[string(audit.DetailRequestID)] == "" {
			t.Errorf("%s carries no request_id, so it cannot be correlated with the request log", want)
		}
		// The key material is never recorded. The fingerprint answers every
		// incident question a blob would, without putting a second copy of the
		// key in a second store.
		if b64 := strings.Fields(line)[1]; strings.Contains(strings.Join(metadataValues(rec), " "), b64) {
			t.Errorf("%s audit details carry the key blob", want)
		}
	}
}

func metadataValues(rec *domain.AuditRecord) []string {
	out := make([]string, 0, len(rec.Metadata))
	for _, v := range rec.Metadata {
		out = append(out, v)
	}
	return out
}

// TestKeyRoutesFailClosedWithoutAnAuthorizer covers the wiring gap in
// cmd/valletd today: a handler built without WithAuthorizer must refuse every
// key request rather than serve one, and must not answer 404 as though the
// feature were absent.
func TestKeyRoutesFailClosedWithoutAnAuthorizer(t *testing.T) {
	t.Parallel()

	handler := httpserver.NewHandler(nil, nil, devicePinger{}, devicePublisher{})
	for _, spec := range [][2]string{
		{http.MethodPost, keysPath},
		{http.MethodGet, keysPath},
		{http.MethodDelete, keysPath + "/anything"},
	} {
		req := httptest.NewRequest(spec[0], spec[1], strings.NewReader(`{"device_id":"d","public_key":"x"}`))
		// A well-formed credential, so the refusal cannot be blamed on parsing.
		req.Header.Set("Authorization", "Bearer "+strings.Repeat("t", 40))
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s %s with no authorizer wired = %d, want 401", spec[0], spec[1], rec.Code)
		}
	}
}

// TestKeyRoutesReturn500WhenTheServiceIsMissing pins the other half of the
// wiring story: authorization present, service absent. It must be a 500, not a
// 404 that reads as "no such key" and hides a broken deployment.
func TestKeyRoutesReturn500WhenTheServiceIsMissing(t *testing.T) {
	t.Parallel()

	env := newKeyEnv(t)
	handler := httpserver.NewHandler(nil, nil, devicePinger{}, devicePublisher{},
		httpserver.WithAuthorizer(env.guard))
	token := env.fullToken(t, "owner-a")

	for _, spec := range [][3]string{
		{http.MethodGet, keysPath, ""},
		{http.MethodPost, keysPath, `{"device_id":"d","public_key":"x"}`},
		{http.MethodDelete, keysPath + "/anything", ""},
	} {
		req := httptest.NewRequest(spec[0], spec[1], strings.NewReader(spec[2]))
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusInternalServerError {
			t.Errorf("%s %s with no service wired = %d, want 500", spec[0], spec[1], rec.Code)
		}
	}
}

// TestStorageFailureIsNotLeakedToTheCaller pins that an unexpected repository
// error becomes a bare 500 whose body carries no diagnostics, while the reason
// goes to the log where an operator can find it.
func TestStorageFailureIsNotLeakedToTheCaller(t *testing.T) {
	t.Parallel()

	var logged bytes.Buffer
	env := newKeyEnvWithLogger(t, slog.New(slog.NewJSONHandler(&logged, nil)))
	token := env.fullToken(t, "owner-a")
	dev := env.seedDevice(t, "owner-a", "dev-a")
	env.keys.createErr = errDatastoreDown

	rr := env.do(t, http.MethodPost, keysPath, token, addBody(t, dev, ed25519Line(t, "laptop")))
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("add with a failing store = %d, want 500", rr.Code)
	}
	if strings.Contains(rr.Body.String(), errDatastoreDown.Error()) {
		t.Errorf("500 body leaks the storage error: %s", rr.Body.String())
	}
	if !strings.Contains(logged.String(), errDatastoreDown.Error()) {
		t.Error("the storage error was not logged, so an operator cannot diagnose it")
	}
}
