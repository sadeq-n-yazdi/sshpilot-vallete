package publish

import (
	"context"
	"errors"
	"testing"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/audit"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/secrets"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/service/accesskey"
)

// testPepper is a fixed 32-byte pepper. A constant is correct here: what these
// tests assert is which credentials open which sets, not that this particular
// key is secret.
var testPepper = []byte("0123456789abcdef0123456789abcdef")

// protectedFixture is a publish service wired to a REAL access key service over
// the same store.
//
// The verifier is the real one on purpose. The invariant this file exists to
// pin lives in the seam between two packages — publish checks the key set's
// state, accesskey checks the credential, and neither checks the other's half —
// and a fake verifier would be written to whatever this package assumed, which
// is to say it would agree with the assumption whether or not the real service
// did.
type protectedFixture struct {
	*fixture
	keys *accesskey.Service
}

func newProtectedFixture(t *testing.T) *protectedFixture {
	t.Helper()

	f := newFixture(t)
	repos := f.store.Repos()
	keySvc, err := accesskey.New(f.store, noopAuditor{}, testPepper)
	if err != nil {
		t.Fatalf("accesskey.New: %v", err)
	}
	svc, err := New(repos, WithVerifier(keySvc))
	if err != nil {
		t.Fatalf("publish.New: %v", err)
	}
	f.svc = svc
	return &protectedFixture{fixture: f, keys: keySvc}
}

// seedSet creates an extra key set for an owner with the given visibility and
// state, and returns its ID.
func (f *protectedFixture) seedSet(ownerID domain.OwnerID, name string, vis domain.Visibility, state domain.NameState) domain.KeySetID {
	f.t.Helper()

	set := &domain.KeySet{
		ID:         domain.KeySetID("set-" + name + "-" + string(ownerID)),
		OwnerID:    ownerID,
		Name:       name,
		Visibility: vis,
		State:      state,
		CreatedAt:  testNow,
		UpdatedAt:  testNow,
	}
	if err := f.store.Repos().KeySets.Create(context.Background(), set); err != nil {
		f.t.Fatalf("KeySets.Create(%q): %v", name, err)
	}
	return set.ID
}

// mint issues a credential for a set and returns the plaintext token.
func (f *protectedFixture) mint(ownerID domain.OwnerID, setID domain.KeySetID) (domain.AccessKeyID, secrets.Redacted) {
	f.t.Helper()

	k, token, err := f.keys.Mint(context.Background(), ownerID, setID, "consumer", "req-1")
	if err != nil {
		f.t.Fatalf("Mint(%q): %v", setID, err)
	}
	return k.ID, token
}

// noopAuditor satisfies the access key service's audit dependency. What these
// tests assert is the verification verdict, which emits nothing.
type noopAuditor struct{}

func (noopAuditor) Emit(context.Context, audit.Event) error { return nil }

// denied asserts a refusal is THE refusal, and that it carried nothing back.
//
// The Result check is the part that matters beyond the sentinel: a refusal that
// returned a body would publish key material to a caller that was turned away,
// and a refusal that set Protected would let the transport shape a response
// around the visibility of a set it declined to serve.
func denied(t *testing.T, what string, res Result, err error) {
	t.Helper()

	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("%s: err = %v, want ErrNotFound", what, err)
	}
	if res.Body != nil {
		t.Errorf("%s: refusal carried a body: %q", what, res.Body)
	}
	if res.Protected {
		t.Errorf("%s: refusal reported Protected; a failure must not describe the set", what)
	}
}

// TestProtectedSetRequiresItsOwnAccessKey walks the credential axis: what opens
// a protected set, and what — indistinguishably — does not.
func TestProtectedSetRequiresItsOwnAccessKey(t *testing.T) {
	t.Parallel()

	f := newProtectedFixture(t)
	alice := f.seedOwner("alice")
	prod := f.seedSet(alice.OwnerID, "prod", domain.VisibilityProtected, domain.NameStateActive)
	f.addKey(alice.OwnerID, prod, "prod-key")

	_, good := f.mint(alice.OwnerID, prod)

	// The one case that succeeds, asserted first so the rest are refusals of
	// something that demonstrably works rather than of a broken fixture.
	res, err := f.svc.Resolve(context.Background(), "alice", "prod", good)
	if err != nil {
		t.Fatalf("Resolve with the correct key: %v", err)
	}
	if len(res.Body) == 0 {
		t.Error("the correct key resolved an empty body; the set's key was not published")
	}
	if !res.Protected {
		t.Error("a protected set resolved with Protected = false; the transport would cache it publicly")
	}

	// A credential minted for the owner's OTHER set. Per-set access keys are
	// the guarantee ADR-0016 makes: a consumer trusted with one set must not
	// reach another, and must not learn that the other exists.
	otherSet := f.seedSet(alice.OwnerID, "staging", domain.VisibilityProtected, domain.NameStateActive)
	_, wrongSet := f.mint(alice.OwnerID, otherSet)

	// A revoked credential, which must be refused even though its secret is
	// still the right one. That ordering is the whole meaning of revocation.
	revokedID, revoked := f.mint(alice.OwnerID, prod)
	if err := f.keys.Revoke(context.Background(), alice.OwnerID, revokedID, "req-2"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	// Another owner's credential for their own set, to confirm the owner
	// derived from the handle is what scopes the lookup.
	bob := f.seedOwner("bob")
	bobSet := f.seedSet(bob.OwnerID, "prod", domain.VisibilityProtected, domain.NameStateActive)
	_, bobToken := f.mint(bob.OwnerID, bobSet)

	refusals := map[string]secrets.Redacted{
		"no token at all":              "",
		"a token that is not a token":  secrets.NewRedacted("garbage"),
		"a well-shaped but unknown id": secrets.NewRedacted("ak_nosuchid.nosuchsecret"),
		"the owner's other set's key":  wrongSet,
		"a revoked key":                revoked,
		"another owner's key":          bobToken,
	}
	for name, token := range refusals {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			res, err := f.svc.Resolve(context.Background(), "alice", "prod", token)
			denied(t, name, res, err)
		})
	}
}

// TestProtectedSetRefusesTheCorrectKeyOnANonActiveSet is the seam this slice
// exists to close.
//
// accesskey.Verify is handed an owner id and a key set id and loads the ACCESS
// KEY; it never reads the KeySet row, so it cannot see that the set has been
// quarantined or retired and answers "this credential is live and names that
// set" — which is true. If this package also assumed the other side looked, a
// freed-name tombstone would keep publishing to everyone still holding a token
// for it. The credential below is the genuinely correct one, and the ONLY
// reason it is refused is the state check that runs before it is consulted.
func TestProtectedSetRefusesTheCorrectKeyOnANonActiveSet(t *testing.T) {
	t.Parallel()

	for _, state := range []domain.NameState{domain.NameStateQuarantined, domain.NameStateRetired} {
		t.Run(string(state), func(t *testing.T) {
			t.Parallel()

			f := newProtectedFixture(t)
			alice := f.seedOwner("alice")

			// Minted while the set is active, because Mint refuses a set that
			// is not — so the token must be issued first and the set moved
			// afterwards, exactly as a real quarantine does to a live consumer.
			setID := f.seedSet(alice.OwnerID, "prod", domain.VisibilityProtected, domain.NameStateActive)
			f.addKey(alice.OwnerID, setID, "prod-key")
			_, token := f.mint(alice.OwnerID, setID)

			// Sanity: the credential works while the set is active. Without
			// this, a fixture that never resolved anything would let the
			// refusal below pass for the wrong reason.
			if _, err := f.svc.Resolve(context.Background(), "alice", "prod", token); err != nil {
				t.Fatalf("Resolve before quarantine: %v", err)
			}

			f.exec(`UPDATE key_sets SET state = ? WHERE id = ?`, string(state), string(setID))

			res, err := f.svc.Resolve(context.Background(), "alice", "prod", token)
			denied(t, "a valid key against a "+string(state)+" set", res, err)

			// And the verifier really would have said yes: the same credential
			// still verifies against the same set id in isolation. This is the
			// evidence that the refusal came from THIS package's state check
			// and not from the credential having gone stale.
			if _, err := f.keys.Verify(context.Background(), alice.OwnerID, setID, token); err != nil {
				t.Fatalf("the verifier refused the credential itself (%v); the set-state refusal above proved nothing", err)
			}
		})
	}
}

// TestNonActiveSetIsRefusedWithoutTouchingTheCredentialStore pins the ORDERING
// that the test above depends on but cannot see.
//
// A quarantined set is refused either way — before the credential is checked,
// or after — so a test that only compares verdicts cannot tell the two orderings
// apart, and the ordering would be held by a comment alone. This one can, and
// it does it two ways.
//
// The verifier here faults rather than denies. With the state checked FIRST the
// credential store is never touched: the answer is the ordinary 404, and the
// spy records no call. With the state checked after, the fault is reached first
// and propagates as a 500 — so a tombstoned set would start returning a
// different answer during a credential-store outage than it returns normally,
// and that difference is readable from outside.
//
// The stronger of the two assertions is spy.calls == 0. A set that is dead is
// dead regardless of any credential, and no verification work should run
// against it at all.
func TestNonActiveSetIsRefusedWithoutTouchingTheCredentialStore(t *testing.T) {
	t.Parallel()

	f := newProtectedFixture(t)
	alice := f.seedOwner("alice")
	setID := f.seedSet(alice.OwnerID, "prod", domain.VisibilityProtected, domain.NameStateActive)
	f.addKey(alice.OwnerID, setID, "prod-key")
	f.exec(`UPDATE key_sets SET state = ? WHERE id = ?`, string(domain.NameStateQuarantined), string(setID))

	spy := &countingVerifier{err: errors.New("access key store unreachable")}
	svc, err := New(f.store.Repos(), WithVerifier(spy))
	if err != nil {
		t.Fatalf("publish.New: %v", err)
	}

	res, err := svc.Resolve(context.Background(), "alice", "prod", secrets.NewRedacted("anything"))
	denied(t, "a quarantined set with a faulting verifier", res, err)
	if spy.calls != 0 {
		t.Errorf("the credential store was consulted %d time(s) for a non-active set; "+
			"the state check must run before the credential, not after", spy.calls)
	}
}

// TestPublicSetIgnoresTheCredentialEntirely pins that the token is consulted
// only where it means something. A public set that started refusing callers who
// sent a stray or stale Authorization header would be an outage; one that
// changed its answer based on the header would be a channel.
func TestPublicSetIgnoresTheCredentialEntirely(t *testing.T) {
	t.Parallel()

	f := newProtectedFixture(t)
	alice := f.seedOwner("alice")
	f.addKey(alice.OwnerID, alice.KeySetID, "public-key")

	tokens := []secrets.Redacted{"", secrets.NewRedacted("garbage"), secrets.NewRedacted("ak_x.y")}
	var first string
	for i, token := range tokens {
		res, err := f.svc.Resolve(context.Background(), "alice", "", token)
		if err != nil {
			t.Fatalf("Resolve(public, token %d): %v", i, err)
		}
		if res.Protected {
			t.Error("a public set reported Protected; its body would stop being shared-cacheable")
		}
		if i == 0 {
			first = string(res.Body)
			continue
		}
		if got := string(res.Body); got != first {
			t.Errorf("public body varied with the credential: %q vs %q", got, first)
		}
	}
}

// TestProtectedSetWithNoVerifierIsRefusedNotPanicked pins the fail-closed
// default. A deployment that has not wired an access key service must answer
// the ordinary negative verdict — not an internal error that would mark
// protected sets as existing, and not a nil dereference reachable by an
// unauthenticated request naming any protected name.
func TestProtectedSetWithNoVerifierIsRefusedNotPanicked(t *testing.T) {
	t.Parallel()

	f := newProtectedFixture(t)
	alice := f.seedOwner("alice")
	setID := f.seedSet(alice.OwnerID, "prod", domain.VisibilityProtected, domain.NameStateActive)
	f.addKey(alice.OwnerID, setID, "prod-key")
	_, token := f.mint(alice.OwnerID, setID)

	unwired, err := New(f.store.Repos())
	if err != nil {
		t.Fatalf("publish.New: %v", err)
	}
	res, err := unwired.Resolve(context.Background(), "alice", "prod", token)
	denied(t, "a valid key against a service with no verifier", res, err)
}

// TestUnrecognizedVisibilityIsRefusedWithoutConsultingTheVerifier pins the
// fail-closed direction of the visibility gate. A value added to the domain
// later must be unreachable through this endpoint until someone decides what it
// means — and must not be handed to the verifier, because "some credential may
// open it" is a decision this code has not been told to make.
//
// The gate is exercised directly rather than through a seeded row, because the
// schema's own CHECK constraint refuses to store a visibility outside the two
// known values — a second, independent layer of the same defense, and the
// reason a row like this cannot be manufactured here. The check under test
// exists for the day that constraint is widened.
func TestUnrecognizedVisibilityIsRefusedWithoutConsultingTheVerifier(t *testing.T) {
	t.Parallel()

	spy := &countingVerifier{}
	svc, err := New(newFixture(t).store.Repos(), WithVerifier(spy))
	if err != nil {
		t.Fatalf("publish.New: %v", err)
	}

	set := &domain.KeySet{ID: "set-1", OwnerID: "owner-1", Visibility: domain.Visibility("org-only"), State: domain.NameStateActive}
	protected, err := svc.resolveAccess(context.Background(), "owner-1", set, secrets.NewRedacted("anything"))
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("resolveAccess(unknown visibility) err = %v, want ErrNotFound", err)
	}
	if protected {
		t.Error("a refused visibility reported Protected")
	}
	if spy.calls != 0 {
		t.Errorf("the verifier was consulted %d time(s) for a visibility this code does not understand", spy.calls)
	}
}

// TestVerifierStorageFaultIsNotADenial pins the difference between "no" and
// "the database did not answer". Folding a fault into ErrNotFound would make an
// access key outage look exactly like every consumer's credential being wrong,
// which is silent, uniform, and indistinguishable from correct operation.
func TestVerifierStorageFaultIsNotADenial(t *testing.T) {
	t.Parallel()

	f := newProtectedFixture(t)
	alice := f.seedOwner("alice")
	setID := f.seedSet(alice.OwnerID, "prod", domain.VisibilityProtected, domain.NameStateActive)
	f.addKey(alice.OwnerID, setID, "prod-key")

	fault := errors.New("access key store unreachable")
	svc, err := New(f.store.Repos(), WithVerifier(&countingVerifier{err: fault}))
	if err != nil {
		t.Fatalf("publish.New: %v", err)
	}

	res, err := svc.Resolve(context.Background(), "alice", "prod", secrets.NewRedacted("anything"))
	if !errors.Is(err, fault) {
		t.Fatalf("err = %v, want the storage fault to propagate", err)
	}
	if errors.Is(err, ErrNotFound) {
		t.Fatal("a storage fault was reported as the negative verdict; an outage would answer 404 and look like normal operation")
	}
	if res.Body != nil {
		t.Errorf("a faulted resolution carried a body: %q", res.Body)
	}
}

// countingVerifier is a Verifier that records how often it was asked and can be
// made to fault. It is used only where the assertion is about whether this
// package consults a verifier at all, or about how it treats a non-verdict.
type countingVerifier struct {
	calls int
	err   error
}

func (v *countingVerifier) Verify(context.Context, domain.OwnerID, domain.KeySetID, secrets.Redacted) (*domain.AccessKey, error) {
	v.calls++
	if v.err != nil {
		return nil, v.err
	}
	return &domain.AccessKey{}, nil
}
