package accesskey

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/audit"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/repository"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/secrets"
)

func TestNewRejectsMissingDependencies(t *testing.T) {
	f := newFixture(t)
	repos := f.store.Repos()

	if _, err := New(nil, repos.KeySets, f.audit, testPepper); !errors.Is(err, ErrMissingDependency) {
		t.Fatalf("New with no access key repository: %v", err)
	}
	if _, err := New(repos.AccessKeys, nil, f.audit, testPepper); !errors.Is(err, ErrMissingDependency) {
		t.Fatalf("New with no key set repository: %v", err)
	}
	if _, err := New(repos.AccessKeys, repos.KeySets, nil, testPepper); !errors.Is(err, ErrMissingDependency) {
		t.Fatalf("New with no auditor: %v", err)
	}
	if _, err := New(repos.AccessKeys, repos.KeySets, f.audit, nil); !errors.Is(err, ErrMissingDependency) {
		t.Fatalf("New with no pepper: %v", err)
	}
	short := make([]byte, MinPepperLen-1)
	if _, err := New(repos.AccessKeys, repos.KeySets, f.audit, short); !errors.Is(err, ErrMissingDependency) {
		t.Fatalf("New with a short pepper: %v", err)
	}
	if _, err := New(repos.AccessKeys, repos.KeySets, f.audit, testPepper, nil); !errors.Is(err, ErrMissingDependency) {
		t.Fatalf("New with a nil option: %v", err)
	}
}

// TestNewCopiesPepper asserts a caller that zeroes its buffer after
// construction cannot change the key underneath a running service.
func TestNewCopiesPepper(t *testing.T) {
	f := newFixture(t)
	repos := f.store.Repos()

	pepper := append([]byte(nil), testPepper...)
	svc, err := New(repos.AccessKeys, repos.KeySets, f.audit, pepper)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	before := svc.hasher.hash("id", "secret")
	for i := range pepper {
		pepper[i] = 0
	}
	after := svc.hasher.hash("id", "secret")
	if string(before) != string(after) {
		t.Fatal("zeroing the caller's buffer changed the service's digests")
	}
}

// TestWithClockIgnoresNil asserts the option refuses to install a nil clock
// rather than leaving the service to panic on its first timestamp.
func TestWithClockIgnoresNil(t *testing.T) {
	f := newFixture(t)
	repos := f.store.Repos()

	svc, err := New(repos.AccessKeys, repos.KeySets, f.audit, testPepper, WithClock(nil))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if svc.now == nil {
		t.Fatal("WithClock(nil) installed a nil clock")
	}
}

// TestMintStoresNoPlaintext is the property the whole design rests on: what
// reaches the database is a digest, and neither half of the returned token
// appears in it.
func TestMintStoresNoPlaintext(t *testing.T) {
	f := newFixture(t)
	owner := f.seedOwner("alice")
	k, token := f.mint(owner.OwnerID, owner.KeySetID, "ci")

	id, secret, ok := parseToken(token.Reveal())
	if !ok {
		t.Fatalf("minted token does not parse: %q", token.Reveal())
	}
	if id != k.ID {
		t.Fatalf("token id %q does not match the stored key %q", id, k.ID)
	}
	if strings.Contains(string(k.SecretHash), secret) {
		t.Fatal("the stored digest contains the plaintext secret")
	}
	if !f.svc.hasher.equal(k.SecretHash, id, secret) {
		t.Fatal("the stored digest does not verify against the minted secret")
	}

	var stored []byte
	if err := f.db.QueryRow(`SELECT secret_hash FROM access_keys WHERE id = ?`, string(k.ID)).Scan(&stored); err != nil {
		t.Fatalf("reading secret_hash: %v", err)
	}
	if strings.Contains(string(stored), secret) {
		t.Fatal("the persisted row contains the plaintext secret")
	}
}

// TestMintTokenShape pins the format callers will be documented against, and
// the entropy behind it. A token whose secret shrank would still verify, so the
// width is asserted rather than inferred.
func TestMintTokenShape(t *testing.T) {
	f := newFixture(t)
	owner := f.seedOwner("alice")

	seen := map[string]bool{}
	for range 8 {
		_, token := f.mint(owner.OwnerID, owner.KeySetID, "ci")
		raw := token.Reveal()
		if !strings.HasPrefix(raw, tokenPrefix) {
			t.Fatalf("token %q lacks the %q prefix", raw, tokenPrefix)
		}
		id, secret, ok := parseToken(raw)
		if !ok {
			t.Fatalf("token %q does not parse", raw)
		}
		if len(secret) != secretEncoding.EncodedLen(secretBytes) {
			t.Fatalf("secret is %d characters, want %d", len(secret), secretEncoding.EncodedLen(secretBytes))
		}
		if seen[raw] {
			t.Fatalf("crypto/rand returned a repeated token: %q", raw)
		}
		seen[raw] = true
		if seen[string(id)] {
			t.Fatalf("crypto/rand returned a repeated id: %q", id)
		}
		seen[string(id)] = true
	}
}

// TestMintTokenRedactsItself asserts the plaintext does not survive being
// formatted. secrets.Redacted is what stands between an accidental log line and
// a live credential.
func TestMintTokenRedactsItself(t *testing.T) {
	f := newFixture(t)
	owner := f.seedOwner("alice")
	_, token := f.mint(owner.OwnerID, owner.KeySetID, "ci")

	for _, rendered := range []string{token.String(), token.GoString()} {
		if strings.Contains(rendered, token.Reveal()) {
			t.Fatalf("a formatted token exposed its plaintext: %q", rendered)
		}
	}
}

// TestMintRejectsForeignAndUnusableKeySets covers the check the schema's
// non-composite foreign key does not make: key_set_id references key_sets(id)
// alone, so nothing in the database stops a row naming one owner and another
// owner's set. Mint must refuse before writing.
func TestMintRejectsForeignAndUnusableKeySets(t *testing.T) {
	f := newFixture(t)
	alice := f.seedOwner("alice")
	bob := f.seedOwner("bob")
	quarantined := f.seedSet(alice.OwnerID, "held", domain.NameStateQuarantined)
	retired := f.seedSet(alice.OwnerID, "gone", domain.NameStateRetired)

	for _, tc := range []struct {
		name  string
		owner domain.OwnerID
		set   domain.KeySetID
	}{
		{"another owner's set", alice.OwnerID, bob.KeySetID},
		{"an unknown set", alice.OwnerID, "no-such-set"},
		{"an empty set id", alice.OwnerID, ""},
		{"a quarantined set", alice.OwnerID, quarantined},
		{"a retired set", alice.OwnerID, retired},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := f.svc.Mint(context.Background(), tc.owner, tc.set, "ci", "req-1")
			denied(t, "Mint for "+tc.name, err)
		})
	}

	keys, err := f.svc.List(context.Background(), alice.OwnerID)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(keys) != 0 {
		t.Fatalf("a refused Mint wrote %d rows", len(keys))
	}
}

// TestMintRejectsBadInput covers the arguments that never reach storage.
func TestMintRejectsBadInput(t *testing.T) {
	f := newFixture(t)
	owner := f.seedOwner("alice")

	for _, tc := range []struct {
		name  string
		owner domain.OwnerID
		label string
	}{
		{"no owner", "", "ci"},
		{"no name", owner.OwnerID, ""},
		{"blank name", owner.OwnerID, "   "},
		{"oversized name", owner.OwnerID, strings.Repeat("x", maxNameLen+1)},
		{"invalid utf-8 name", owner.OwnerID, "\xff\xfe"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := f.svc.Mint(context.Background(), tc.owner, owner.KeySetID, tc.label, "req-1")
			if !errors.Is(err, domain.ErrInvalidInput) {
				t.Fatalf("Mint with %s: got %v, want ErrInvalidInput", tc.name, err)
			}
		})
	}
}

// TestMintTrimsName asserts the stored label is the trimmed one, so the audit
// record and the owner's inventory agree on what the credential is called.
func TestMintTrimsName(t *testing.T) {
	f := newFixture(t)
	owner := f.seedOwner("alice")
	k, _ := f.mint(owner.OwnerID, owner.KeySetID, "  ci runner  ")

	if k.Name != "ci runner" {
		t.Fatalf("stored name %q, want %q", k.Name, "ci runner")
	}
}

// TestMintAudits asserts the record carries the credential's identity and its
// context — and neither the plaintext nor the digest.
func TestMintAudits(t *testing.T) {
	f := newFixture(t)
	owner := f.seedOwner("alice")
	k, token := f.mint(owner.OwnerID, owner.KeySetID, "ci")

	if len(f.audit.events) != 1 {
		t.Fatalf("Mint emitted %d audit events, want 1", len(f.audit.events))
	}
	ev := f.audit.events[0]
	if ev.Action != domain.AuditActionAccessKeyCreated {
		t.Fatalf("audit action %q, want %q", ev.Action, domain.AuditActionAccessKeyCreated)
	}
	if ev.TargetType != domain.TargetTypeAccessKey || ev.TargetID != string(k.ID) {
		t.Fatalf("audit target %q/%q, want access_key/%q", ev.TargetType, ev.TargetID, k.ID)
	}
	if ev.ActorType != domain.ActorTypeOwner || ev.ActorID != string(owner.OwnerID) {
		t.Fatalf("audit actor %q/%q, want owner/%q", ev.ActorType, ev.ActorID, owner.OwnerID)
	}
	assertNoSecret(t, ev.Details, token, k.SecretHash)
}

// TestMintReturnsNoTokenWhenAuditFails asserts a credential minted without an
// accountability trail is not handed back. The caller that never receives the
// token cannot use it.
func TestMintReturnsNoTokenWhenAuditFails(t *testing.T) {
	f := newFixture(t)
	owner := f.seedOwner("alice")
	f.audit.err = errors.New("audit store unavailable")

	k, token, err := f.svc.Mint(context.Background(), owner.OwnerID, owner.KeySetID, "ci", "req-1")
	if err == nil {
		t.Fatal("Mint succeeded with a failing auditor")
	}
	if k != nil || token != "" {
		t.Fatal("Mint returned a credential despite failing to record it")
	}
}

// TestMintRejectsUnrecordableRequestID asserts details are built before the
// write, so a value the audit screen refuses cannot leave a committed
// credential unrecorded.
func TestMintRejectsUnrecordableRequestID(t *testing.T) {
	f := newFixture(t)
	owner := f.seedOwner("alice")

	_, _, err := f.svc.Mint(context.Background(), owner.OwnerID, owner.KeySetID, "ci", strings.Repeat("r", 512))
	if !errors.Is(err, domain.ErrInvalidInput) {
		t.Fatalf("Mint with an unrecordable request id: got %v, want ErrInvalidInput", err)
	}

	keys, err := f.svc.List(context.Background(), owner.OwnerID)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(keys) != 0 {
		t.Fatalf("a refused Mint wrote %d rows", len(keys))
	}
}

// TestListIsOwnerScoped asserts the inventory shows the owner's own credentials
// and only those, across every lifecycle state.
func TestListIsOwnerScoped(t *testing.T) {
	f := newFixture(t)
	alice := f.seedOwner("alice")
	bob := f.seedOwner("bob")

	first, _ := f.mint(alice.OwnerID, alice.KeySetID, "ci")
	second, _ := f.mint(alice.OwnerID, alice.KeySetID, "deploy")
	f.mint(bob.OwnerID, bob.KeySetID, "bob's")

	if err := f.svc.Revoke(context.Background(), alice.OwnerID, second.ID, "req-2"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	keys, err := f.svc.List(context.Background(), alice.OwnerID)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("List returned %d keys, want 2 (including the revoked one)", len(keys))
	}
	for _, k := range keys {
		if k.OwnerID != alice.OwnerID {
			t.Fatalf("List returned a key owned by %q", k.OwnerID)
		}
	}
	if _, err := f.svc.List(context.Background(), ""); !errors.Is(err, domain.ErrInvalidInput) {
		t.Fatalf("List with no owner: got %v, want ErrInvalidInput", err)
	}
	_ = first
}

// TestListBySetIsOwnerAndSetScoped asserts the per-set view is filtered by both
// predicates, and that an unknown or foreign set is an empty answer rather than
// a distinguishable error.
func TestListBySetIsOwnerAndSetScoped(t *testing.T) {
	f := newFixture(t)
	alice := f.seedOwner("alice")
	bob := f.seedOwner("bob")
	other := f.seedSet(alice.OwnerID, "prod", domain.NameStateActive)

	f.mint(alice.OwnerID, alice.KeySetID, "ci")
	f.mint(alice.OwnerID, other, "prod-ci")
	f.mint(bob.OwnerID, bob.KeySetID, "bob's")

	keys, err := f.svc.ListBySet(context.Background(), alice.OwnerID, other)
	if err != nil {
		t.Fatalf("ListBySet: %v", err)
	}
	if len(keys) != 1 || keys[0].KeySetID != other {
		t.Fatalf("ListBySet returned %d keys for the wrong set", len(keys))
	}

	for _, tc := range []struct {
		name string
		set  domain.KeySetID
	}{
		{"another owner's set", bob.KeySetID},
		{"an unknown set", "no-such-set"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := f.svc.ListBySet(context.Background(), alice.OwnerID, tc.set)
			if err != nil {
				t.Fatalf("ListBySet for %s: %v", tc.name, err)
			}
			if len(got) != 0 {
				t.Fatalf("ListBySet for %s returned %d keys", tc.name, len(got))
			}
		})
	}

	if _, err := f.svc.ListBySet(context.Background(), "", other); !errors.Is(err, domain.ErrInvalidInput) {
		t.Fatalf("ListBySet with no owner: got %v, want ErrInvalidInput", err)
	}
	if _, err := f.svc.ListBySet(context.Background(), alice.OwnerID, ""); !errors.Is(err, domain.ErrInvalidInput) {
		t.Fatalf("ListBySet with no set: got %v, want ErrInvalidInput", err)
	}
}

// TestRevokeCollapsesEveryFailure asserts an unknown id, another owner's id and
// an already-revoked id are one answer, so a repeat revoke reports exactly what
// a stranger's id reports.
func TestRevokeCollapsesEveryFailure(t *testing.T) {
	f := newFixture(t)
	alice := f.seedOwner("alice")
	bob := f.seedOwner("bob")

	mine, _ := f.mint(alice.OwnerID, alice.KeySetID, "ci")
	theirs, _ := f.mint(bob.OwnerID, bob.KeySetID, "bob's")

	if err := f.svc.Revoke(context.Background(), alice.OwnerID, mine.ID, "req-2"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	for _, tc := range []struct {
		name string
		id   domain.AccessKeyID
	}{
		{"the same key again", mine.ID},
		{"another owner's key", theirs.ID},
		{"an unknown key", "no-such-key"},
		{"an empty id", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			denied(t, "Revoke "+tc.name, f.svc.Revoke(context.Background(), alice.OwnerID, tc.id, "req-3"))
		})
	}

	if err := f.svc.Revoke(context.Background(), "", mine.ID, "req-3"); !errors.Is(err, domain.ErrInvalidInput) {
		t.Fatalf("Revoke with no owner: got %v, want ErrInvalidInput", err)
	}

	// Bob's key was named in a refused call and must be untouched by it.
	still, err := f.svc.List(context.Background(), bob.OwnerID)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(still) != 1 || still[0].Status != domain.AccessKeyStatusActive {
		t.Fatal("a cross-owner Revoke altered the other owner's key")
	}
}

// TestRevokeAcceptsAGraceKey asserts revocation reaches a credential that
// rotation left briefly live. Ending that window early is the whole reason an
// operator reaches for revoke during an incident.
func TestRevokeAcceptsAGraceKey(t *testing.T) {
	f := newFixture(t)
	owner := f.seedOwner("alice")
	k, token := f.mint(owner.OwnerID, owner.KeySetID, "ci")

	if err := f.store.Repos().AccessKeys.MarkRotated(context.Background(), owner.OwnerID, k.ID, "replacement", fixedNow.Add(time.Hour)); err != nil {
		t.Fatalf("MarkRotated: %v", err)
	}
	if err := f.svc.Revoke(context.Background(), owner.OwnerID, k.ID, "req-2"); err != nil {
		t.Fatalf("Revoke of a grace key: %v", err)
	}

	_, err := f.svc.Verify(context.Background(), owner.OwnerID, owner.KeySetID, token)
	denied(t, "Verify after revoking a grace key", err)
}

// TestRevokeAudits asserts the record identifies the credential and carries no
// secret material.
func TestRevokeAudits(t *testing.T) {
	f := newFixture(t)
	owner := f.seedOwner("alice")
	k, token := f.mint(owner.OwnerID, owner.KeySetID, "ci")
	f.audit.events = nil

	if err := f.svc.Revoke(context.Background(), owner.OwnerID, k.ID, "req-2"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if len(f.audit.events) != 1 {
		t.Fatalf("Revoke emitted %d audit events, want 1", len(f.audit.events))
	}
	ev := f.audit.events[0]
	if ev.Action != domain.AuditActionAccessKeyRevoked || ev.TargetID != string(k.ID) {
		t.Fatalf("audit event %q/%q, want access_key.revoked/%q", ev.Action, ev.TargetID, k.ID)
	}
	assertNoSecret(t, ev.Details, token, k.SecretHash)
}

// TestRevokeReturnsAuditFailure asserts a failure to record is surfaced rather
// than swallowed. The revocation itself has landed, which is the safe direction;
// what the caller learns is that the trail did not.
func TestRevokeReturnsAuditFailure(t *testing.T) {
	f := newFixture(t)
	owner := f.seedOwner("alice")
	k, _ := f.mint(owner.OwnerID, owner.KeySetID, "ci")
	f.audit.err = errors.New("audit store unavailable")

	if err := f.svc.Revoke(context.Background(), owner.OwnerID, k.ID, "req-2"); err == nil {
		t.Fatal("Revoke succeeded with a failing auditor")
	}
}

// TestManagementPropagatesStorageFailure asserts the management paths, like
// Verify, distinguish "no" from "could not tell".
func TestManagementPropagatesStorageFailure(t *testing.T) {
	f := newFixture(t)
	owner := f.seedOwner("alice")
	k, _ := f.mint(owner.OwnerID, owner.KeySetID, "ci")

	if err := f.db.Close(); err != nil {
		t.Fatalf("db.Close: %v", err)
	}

	if _, err := f.svc.List(context.Background(), owner.OwnerID); err == nil || errors.Is(err, ErrNotFound) {
		t.Fatalf("List against a closed database: %v", err)
	}
	if _, err := f.svc.ListBySet(context.Background(), owner.OwnerID, owner.KeySetID); err == nil || errors.Is(err, ErrNotFound) {
		t.Fatalf("ListBySet against a closed database: %v", err)
	}
	if err := f.svc.Revoke(context.Background(), owner.OwnerID, k.ID, "req-2"); err == nil || errors.Is(err, ErrNotFound) {
		t.Fatalf("Revoke against a closed database: %v", err)
	}
	if _, _, err := f.svc.Mint(context.Background(), owner.OwnerID, owner.KeySetID, "ci", "req-1"); err == nil || errors.Is(err, ErrNotFound) {
		t.Fatalf("Mint against a closed database: %v", err)
	}
}

// renderDetails formats an audit.Details for substring inspection. fmt prints
// unexported fields under %+v, which is exactly what this assertion needs: it
// sees the values as stored, not a filtered view that could hide the thing it
// is looking for.
func renderDetails(t *testing.T, details audit.Details) string {
	t.Helper()

	return fmt.Sprintf("%+v", details)
}

// assertNoSecret walks an audit record's details for anything that must never
// appear in one: either half of the plaintext token, or the stored digest.
func assertNoSecret(t *testing.T, details audit.Details, token secrets.Redacted, digest []byte) {
	t.Helper()

	id, secret, ok := parseToken(token.Reveal())
	if !ok {
		t.Fatalf("token does not parse")
	}
	rendered := renderDetails(t, details)
	for _, forbidden := range []string{token.Reveal(), secret, string(digest)} {
		if strings.Contains(rendered, forbidden) {
			t.Fatalf("audit details carry secret material: %q", rendered)
		}
	}
	// The id is not secret and identifies the record's target, so it is checked
	// only to confirm the details are the ones being inspected.
	_ = id
}

// faultyKeys wraps the real repository so a single method can be made to fail.
// It is fault injection and nothing else: every method it does not override is
// the real SQLite one, so the tests using it still exercise the adapter, and
// the invariants that live in the SQL predicates are still enforced by the SQL.
type faultyKeys struct {
	repository.AccessKeyRepository
	createErr error
	revokeErr error
}

func (f *faultyKeys) Create(ctx context.Context, k *domain.AccessKey) error {
	if f.createErr != nil {
		return f.createErr
	}
	return f.AccessKeyRepository.Create(ctx, k)
}

func (f *faultyKeys) Revoke(ctx context.Context, ownerID domain.OwnerID, id domain.AccessKeyID, now time.Time) error {
	if f.revokeErr != nil {
		return f.revokeErr
	}
	return f.AccessKeyRepository.Revoke(ctx, ownerID, id, now)
}

// withFaultyKeys rebuilds the fixture's service over a fault-injecting access
// key repository, returning the injector.
func (f *fixture) withFaultyKeys(t *testing.T) *faultyKeys {
	t.Helper()

	repos := f.store.Repos()
	faulty := &faultyKeys{AccessKeyRepository: repos.AccessKeys}
	svc, err := New(faulty, repos.KeySets, f.audit, testPepper, WithClock(func() time.Time { return f.now }))
	if err != nil {
		t.Fatalf("accesskey.New: %v", err)
	}
	f.svc = svc
	return faulty
}

// TestMintSurfacesCreateFailure asserts a write fault is neither swallowed nor
// collapsed into the negative verdict, and that no token is handed back for a
// credential that was not stored.
func TestMintSurfacesCreateFailure(t *testing.T) {
	f := newFixture(t)
	owner := f.seedOwner("alice")
	faulty := f.withFaultyKeys(t)
	faulty.createErr = errors.New("disk full")

	k, token, err := f.svc.Mint(context.Background(), owner.OwnerID, owner.KeySetID, "ci", "req-1")
	if err == nil || errors.Is(err, ErrNotFound) {
		t.Fatalf("Mint with a failing Create: %v", err)
	}
	if k != nil || token != "" {
		t.Fatal("Mint returned a credential it did not store")
	}
	if len(f.audit.events) != 0 {
		t.Fatal("Mint recorded a credential it did not store")
	}
}

// TestRevokeSurfacesWriteFailure asserts the write fault propagates, and that
// the one fault the repository reports as absence — the row vanished between
// the read and the write — becomes the ordinary negative verdict rather than a
// server error.
func TestRevokeSurfacesWriteFailure(t *testing.T) {
	f := newFixture(t)
	owner := f.seedOwner("alice")
	k, _ := f.mint(owner.OwnerID, owner.KeySetID, "ci")
	faulty := f.withFaultyKeys(t)

	faulty.revokeErr = errors.New("disk full")
	err := f.svc.Revoke(context.Background(), owner.OwnerID, k.ID, "req-2")
	if err == nil || errors.Is(err, ErrNotFound) {
		t.Fatalf("Revoke with a failing write: %v", err)
	}

	faulty.revokeErr = domain.ErrNotFound
	denied(t, "Revoke of a row that vanished after the read", f.svc.Revoke(context.Background(), owner.OwnerID, k.ID, "req-2"))
}

// TestRevokeRefusesAnUnrecordableStoredName covers a stored label the audit
// screen will not accept — a state the mint path cannot produce, since the same
// screen runs before the write, but which a direct database write or an older
// row could leave behind. The revoke is refused rather than performed silently,
// and the rejected text is not quoted back into the error.
func TestRevokeRefusesAnUnrecordableStoredName(t *testing.T) {
	f := newFixture(t)
	owner := f.seedOwner("alice")
	k, _ := f.mint(owner.OwnerID, owner.KeySetID, "ci")

	const poisoned = "ci\nrunner"
	f.exec(`UPDATE access_keys SET name = ? WHERE id = ?`, poisoned, string(k.ID))

	err := f.svc.Revoke(context.Background(), owner.OwnerID, k.ID, "req-2")
	if err == nil {
		t.Fatal("Revoke succeeded for a key whose name cannot be recorded")
	}
	if strings.Contains(err.Error(), poisoned) {
		t.Fatalf("the error quoted the rejected value: %v", err)
	}

	keys, err := f.svc.List(context.Background(), owner.OwnerID)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if keys[0].Status != domain.AccessKeyStatusActive {
		t.Fatal("the key was revoked despite the refusal")
	}
}
