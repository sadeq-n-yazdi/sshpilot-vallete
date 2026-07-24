package publickey_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/audit"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/keys"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/service/publickey"
)

// TestNewRequiresEveryCollaborator pins the construction-time refusals. Each is
// a service that would look wired up and behave differently: without the key
// repository it stores nothing, without the device repository it cannot perform
// the owner check on Add at all, and without the auditor it mutates leaving no
// trace.
func TestNewRequiresEveryCollaborator(t *testing.T) {
	t.Parallel()

	env := newEnv(t)
	for _, tc := range []struct {
		name    string
		build   func() (*publickey.Service, error)
		wantErr error
	}{
		{"nil keys", func() (*publickey.Service, error) {
			return publickey.New(nil, env.devices, env.auditor)
		}, publickey.ErrMissingDependency},
		{"nil devices", func() (*publickey.Service, error) {
			return publickey.New(env.keys, nil, env.auditor)
		}, publickey.ErrMissingDependency},
		{"nil auditor", func() (*publickey.Service, error) {
			return publickey.New(env.keys, env.devices, nil)
		}, publickey.ErrMissingDependency},
		{"nil option", func() (*publickey.Service, error) {
			return publickey.New(env.keys, env.devices, env.auditor, nil)
		}, publickey.ErrMissingDependency},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			svc, err := tc.build()
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
			if svc != nil {
				t.Error("a failed construction returned a usable service")
			}
		})
	}
}

// TestListReturnsNilForAnOwnerWithNoKeys pins the repository's nil-collection
// convention at the service boundary. It matters because the alternative -- a
// service that helpfully materializes an empty slice -- would hide a repository
// that stopped returning nil, and would put the wire-format decision in the
// wrong layer.
func TestListReturnsNilForAnOwnerWithNoKeys(t *testing.T) {
	t.Parallel()

	env := newEnv(t)
	got, err := env.svc.List(t.Context(), "owner-a")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if got != nil {
		t.Errorf("List = %#v, want a nil slice", got)
	}
}

// TestAddStoresTheCanonicalParsedKey pins that what is stored is what
// internal/keys derived, not what the caller sent (ADR-0006). The blob in
// particular must be the re-serialized wire form.
func TestAddStoresTheCanonicalParsedKey(t *testing.T) {
	t.Parallel()

	env := newEnv(t)
	env.seedDevice("owner-a", "dev-a")
	line := ed25519Line(t, "work laptop")

	got, err := env.svc.Add(t.Context(), "owner-a", "dev-a", []byte(line), "req-1")
	if err != nil {
		t.Fatalf("Add: %v", err)
	}

	parsed, err := keys.Parse([]byte(line))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got.Fingerprint != parsed.Fingerprint || got.Algorithm != parsed.Algorithm ||
		got.BitLen != parsed.BitLen || got.Comment != parsed.Comment {
		t.Errorf("stored key = %+v, does not match what keys.Parse derived", got)
	}
	if string(got.Blob) != string(parsed.Blob) {
		t.Error("stored blob is not the canonical re-serialized form")
	}
	if got.OwnerID != "owner-a" || got.DeviceID != "dev-a" {
		t.Errorf("owner/device = %s/%s, want owner-a/dev-a", got.OwnerID, got.DeviceID)
	}
	if got.Status != domain.KeyStatusActive {
		t.Errorf("status = %q, want active", got.Status)
	}
	if got.RevokedAt != nil {
		t.Error("a new key carries a revoked_at")
	}

	// The stored row is the one that was returned, not a partially-populated
	// copy.
	stored, err := env.keys.Get(t.Context(), "owner-a", got.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if stored.Fingerprint != got.Fingerprint {
		t.Errorf("stored fingerprint = %q, returned %q", stored.Fingerprint, got.Fingerprint)
	}
}

// TestAddRefusesWithoutStoringAnything walks the refusals that must leave the
// datastore and the audit log untouched. A refusal that wrote a row would be
// the worst outcome for the private-key case in particular.
func TestAddRefusesWithoutStoringAnything(t *testing.T) {
	t.Parallel()

	priv := privateKeyPEM(t)
	good := ed25519Line(t, "laptop")

	for _, tc := range []struct {
		name    string
		owner   domain.OwnerID
		device  domain.DeviceID
		raw     string
		wantErr error
	}{
		{"empty owner", "", "dev-a", good, domain.ErrInvalidInput},
		{"private key", "owner-a", "dev-a", priv, keys.ErrPrivateKey},
		{"options present", "owner-a", "dev-a", `command="/bin/sh" ` + good, keys.ErrOptionsPresent},
		{"malformed", "owner-a", "dev-a", "not a key", keys.ErrMalformed},
		{"empty device", "owner-a", "", good, publickey.ErrNotFound},
		{"unknown device", "owner-a", "dev-nope", good, publickey.ErrNotFound},
		{"another owner's device", "owner-b", "dev-a", good, publickey.ErrNotFound},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			env := newEnv(t)
			env.seedDevice("owner-a", "dev-a")

			got, err := env.svc.Add(t.Context(), tc.owner, tc.device, []byte(tc.raw), "req-1")
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
			if got != nil {
				t.Error("a refused Add returned a key")
			}
			if n := len(env.keys.rows); n != 0 {
				t.Errorf("stored rows = %d, want 0", n)
			}
			if n := len(env.auditor.events); n != 0 {
				t.Errorf("audit events = %d, want 0", n)
			}
			// No error from this path may carry the submission back.
			if tc.raw != "" && err != nil && strings.Contains(err.Error(), tc.raw) {
				t.Error("the error echoes the submission")
			}
		})
	}
}

// TestPrivateKeyMaterialNeverReachesAnError checks the ADR-0002 boundary at the
// service layer, line by line rather than on the PEM header alone: an assertion
// that only looked for "BEGIN" would pass while the payload sat in the message.
func TestPrivateKeyMaterialNeverReachesAnError(t *testing.T) {
	t.Parallel()

	env := newEnv(t)
	env.seedDevice("owner-a", "dev-a")
	priv := privateKeyPEM(t)

	_, err := env.svc.Add(t.Context(), "owner-a", "dev-a", []byte(priv), "req-1")
	if !errors.Is(err, keys.ErrPrivateKey) {
		t.Fatalf("err = %v, want ErrPrivateKey", err)
	}
	for _, line := range strings.Split(strings.TrimSpace(priv), "\n") {
		if line != "" && strings.Contains(err.Error(), line) {
			t.Errorf("error contains private key line %q", line)
		}
	}
}

// TestAddRefusesARevokedDevice pins that a retired device gains no keys, and
// that the refusal is the same verdict an unknown device gets.
func TestAddRefusesARevokedDevice(t *testing.T) {
	t.Parallel()

	env := newEnv(t)
	d := env.seedDevice("owner-a", "dev-a")
	d.Status = domain.DeviceStatusRevoked

	_, err := env.svc.Add(t.Context(), "owner-a", "dev-a", []byte(ed25519Line(t, "laptop")), "req-1")
	if !errors.Is(err, publickey.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
	if n := len(env.keys.rows); n != 0 {
		t.Errorf("stored rows = %d, want 0", n)
	}
}

// TestAddReportsADuplicateDistinctly is the deliberate exception to the
// collapse. It is safe because the constraint is per-owner.
func TestAddReportsADuplicateDistinctly(t *testing.T) {
	t.Parallel()

	env := newEnv(t)
	env.seedDevice("owner-a", "dev-a")
	line := []byte(ed25519Line(t, "laptop"))

	if _, err := env.svc.Add(t.Context(), "owner-a", "dev-a", line, "req-1"); err != nil {
		t.Fatalf("first Add: %v", err)
	}
	_, err := env.svc.Add(t.Context(), "owner-a", "dev-a", line, "req-2")
	if !errors.Is(err, publickey.ErrDuplicate) {
		t.Fatalf("err = %v, want ErrDuplicate", err)
	}
	if errors.Is(err, publickey.ErrNotFound) {
		t.Error("a duplicate must not be reported as not-found")
	}
	if !errors.Is(err, domain.ErrConflict) {
		t.Error("ErrDuplicate must wrap domain.ErrConflict so the transport can map it")
	}
}

// TestRevokeCollapsesEveryNegativeVerdict is the enumeration control. Unknown,
// foreign, already-revoked, and empty must all be the identical error value, so
// no caller can tell them apart by any means.
func TestRevokeCollapsesEveryNegativeVerdict(t *testing.T) {
	t.Parallel()

	env := newEnv(t)
	env.seedDevice("owner-a", "dev-a")
	k, err := env.svc.Add(t.Context(), "owner-a", "dev-a", []byte(ed25519Line(t, "laptop")), "req-1")
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	if err := env.svc.Revoke(t.Context(), "owner-a", k.ID, "req-2"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	for _, tc := range []struct {
		name  string
		owner domain.OwnerID
		id    domain.PublicKeyID
	}{
		{"already revoked", "owner-a", k.ID},
		{"unknown id", "owner-a", "nope"},
		{"empty id", "owner-a", ""},
		{"another owner's key", "owner-b", k.ID},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := env.svc.Revoke(t.Context(), tc.owner, tc.id, "req-3")
			// Identity, not merely errors.Is: two distinct sentinels that both
			// wrapped domain.ErrNotFound would pass an errors.Is check while
			// being distinguishable to any caller that compared them.
			if err != publickey.ErrNotFound { //nolint:errorlint // identity is the property under test
				t.Fatalf("err = %v, want exactly publickey.ErrNotFound", err)
			}
		})
	}

	// Exactly one revocation was recorded, so none of the four attempts above
	// silently succeeded.
	if n := countAction(env.auditor.events, domain.AuditActionKeyRevoked); n != 1 {
		t.Errorf("key.revoked events = %d, want 1", n)
	}
}

// TestRevokeLeavesAnotherOwnersKeyUntouched proves the collapse above is a real
// refusal and not merely a misleading error over a completed write.
func TestRevokeLeavesAnotherOwnersKeyUntouched(t *testing.T) {
	t.Parallel()

	env := newEnv(t)
	env.seedDevice("owner-a", "dev-a")
	k, err := env.svc.Add(t.Context(), "owner-a", "dev-a", []byte(ed25519Line(t, "laptop")), "req-1")
	if err != nil {
		t.Fatalf("Add: %v", err)
	}

	if err := env.svc.Revoke(t.Context(), "owner-b", k.ID, "req-2"); !errors.Is(err, publickey.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
	stored, err := env.keys.Get(t.Context(), "owner-a", k.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if stored.Status != domain.KeyStatusActive || stored.RevokedAt != nil {
		t.Fatalf("owner-a's key = %q/%v after owner-b's revoke; it must be untouched",
			stored.Status, stored.RevokedAt)
	}
}

// TestListIsOwnerScoped pins that the owner argument reaches the query. A
// service that ignored it would return every key in the store.
func TestListIsOwnerScoped(t *testing.T) {
	t.Parallel()

	env := newEnv(t)
	env.seedDevice("owner-a", "dev-a")
	env.seedDevice("owner-b", "dev-b")
	if _, err := env.svc.Add(t.Context(), "owner-a", "dev-a", []byte(ed25519Line(t, "a")), ""); err != nil {
		t.Fatalf("Add a: %v", err)
	}
	if _, err := env.svc.Add(t.Context(), "owner-b", "dev-b", []byte(ed25519Line(t, "b")), ""); err != nil {
		t.Fatalf("Add b: %v", err)
	}

	for _, owner := range []domain.OwnerID{"owner-a", "owner-b"} {
		got, err := env.svc.List(t.Context(), owner)
		if err != nil {
			t.Fatalf("List %s: %v", owner, err)
		}
		if len(got) != 1 || got[0].OwnerID != owner {
			t.Fatalf("List %s = %+v, want exactly that owner's one key", owner, got)
		}
	}
	if _, err := env.svc.List(t.Context(), ""); !errors.Is(err, domain.ErrInvalidInput) {
		t.Errorf("List with no owner = %v, want ErrInvalidInput", err)
	}
}

// TestAnUnrecordableChangeIsReportedAsFailed is the "audit is not optional"
// rule (ADR-0007): a change that could not be recorded is reported as a
// failure rather than silently proceeding unrecorded.
func TestAnUnrecordableChangeIsReportedAsFailed(t *testing.T) {
	t.Parallel()

	t.Run("add", func(t *testing.T) {
		t.Parallel()

		env := newEnv(t)
		env.seedDevice("owner-a", "dev-a")
		env.auditor.err = errSinkDown

		_, err := env.svc.Add(t.Context(), "owner-a", "dev-a", []byte(ed25519Line(t, "laptop")), "req-1")
		if !errors.Is(err, errSinkDown) {
			t.Fatalf("err = %v, want the audit failure", err)
		}
	})

	t.Run("revoke", func(t *testing.T) {
		t.Parallel()

		env := newEnv(t)
		env.seedDevice("owner-a", "dev-a")
		k, err := env.svc.Add(t.Context(), "owner-a", "dev-a", []byte(ed25519Line(t, "laptop")), "req-1")
		if err != nil {
			t.Fatalf("Add: %v", err)
		}
		env.auditor.err = errSinkDown

		if err := env.svc.Revoke(t.Context(), "owner-a", k.ID, "req-2"); !errors.Is(err, errSinkDown) {
			t.Fatalf("err = %v, want the audit failure", err)
		}
	})
}

// TestAuditDetailsCarryTheDerivedFactsOnly pins what is recorded: the two
// allowlisted, non-secret facts plus the request correlation, and nothing that
// came from the submission verbatim.
func TestAuditDetailsCarryTheDerivedFactsOnly(t *testing.T) {
	t.Parallel()

	env := newEnv(t)
	env.seedDevice("owner-a", "dev-a")
	line := ed25519Line(t, "work laptop")
	k, err := env.svc.Add(t.Context(), "owner-a", "dev-a", []byte(line), "req-1")
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	if err := env.svc.Revoke(t.Context(), "owner-a", k.ID, "req-2"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if len(env.auditor.events) != 2 {
		t.Fatalf("events = %d, want 2", len(env.auditor.events))
	}

	for i, want := range []domain.AuditAction{domain.AuditActionKeyAdded, domain.AuditActionKeyRevoked} {
		ev := env.auditor.events[i]
		if ev.Action != want {
			t.Errorf("event %d action = %q, want %q", i, ev.Action, want)
		}
		if ev.ActorType != domain.ActorTypeOwner || ev.ActorID != "owner-a" {
			t.Errorf("event %d actor = %s/%s, want owner/owner-a", i, ev.ActorType, ev.ActorID)
		}
		if ev.TargetType != domain.TargetTypePublicKey || ev.TargetID != string(k.ID) {
			t.Errorf("event %d target = %s/%s, want public_key/%s", i, ev.TargetType, ev.TargetID, k.ID)
		}
	}

	// The details are read back through a real audit.Emitter, because Details
	// keeps its pairs unexported: what a record ends up carrying is the only
	// observable that matters.
	sink := &memSink{}
	emitter, err := audit.NewEmitter(sink)
	if err != nil {
		t.Fatalf("NewEmitter: %v", err)
	}
	for _, ev := range env.auditor.events {
		if err := emitter.Emit(t.Context(), ev); err != nil {
			t.Fatalf("Emit: %v", err)
		}
	}
	for i, rec := range sink.records {
		if got := rec.Metadata[string(audit.DetailFingerprint)]; got != k.Fingerprint {
			t.Errorf("record %d fingerprint = %q, want %q", i, got, k.Fingerprint)
		}
		if got := rec.Metadata[string(audit.DetailAlgorithm)]; got != string(domain.AlgEd25519) {
			t.Errorf("record %d algorithm = %q, want ssh-ed25519", i, got)
		}
		if b64 := strings.Fields(line)[1]; strings.Contains(strings.Join(values(rec.Metadata), " "), b64) {
			t.Errorf("record %d carries the key blob", i)
		}
	}
}

// TestKeyIDsAreUnguessable asserts the generator's properties rather than
// replacing it. There is deliberately no option overriding it: key IDs are how
// the management API addresses a key, and a predictable one would make the
// cross-owner refusal pointless because an attacker would not need to guess.
func TestKeyIDsAreUnguessable(t *testing.T) {
	t.Parallel()

	env := newEnv(t)
	env.seedDevice("owner-a", "dev-a")

	const n = 32
	seen := make(map[domain.PublicKeyID]bool, n)
	for range n {
		k, err := env.svc.Add(t.Context(), "owner-a", "dev-a", []byte(ed25519Line(t, "")), "")
		if err != nil {
			t.Fatalf("Add: %v", err)
		}
		if len(k.ID) < 26 {
			t.Fatalf("id %q is %d chars, want at least 26", k.ID, len(k.ID))
		}
		if seen[k.ID] {
			t.Fatalf("id %q was generated twice", k.ID)
		}
		seen[k.ID] = true
	}
}

// TestTimestampsComeFromTheInjectedClock pins that the clock option reaches
// both the create and the revoke stamps.
func TestTimestampsComeFromTheInjectedClock(t *testing.T) {
	t.Parallel()

	env := newEnv(t)
	env.seedDevice("owner-a", "dev-a")
	k, err := env.svc.Add(t.Context(), "owner-a", "dev-a", []byte(ed25519Line(t, "laptop")), "")
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	if !k.CreatedAt.Equal(fixedNow) || !k.UpdatedAt.Equal(fixedNow) {
		t.Errorf("timestamps = %v/%v, want %v", k.CreatedAt, k.UpdatedAt, fixedNow)
	}

	env.now = fixedNow.Add(time.Hour)
	if err := env.svc.Revoke(t.Context(), "owner-a", k.ID, ""); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	stored, err := env.keys.Get(t.Context(), "owner-a", k.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if stored.RevokedAt == nil || !stored.RevokedAt.Equal(env.now) {
		t.Errorf("revoked_at = %v, want %v", stored.RevokedAt, env.now)
	}
}
