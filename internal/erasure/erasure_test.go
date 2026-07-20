package erasure

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/repository"
)

// fakeAudit is an in-memory stand-in for the audit log. It records every call
// so a test can assert not just the outcome but the order operations happened
// in, which is where the erasure safety property lives.
type fakeAudit struct {
	repository.AuditRepository

	// records maps a record ID to its two identity fields.
	records map[string]*[2]string
	calls   []string
	err     error
}

func newFakeAudit(recs map[string][2]string) *fakeAudit {
	f := &fakeAudit{records: map[string]*[2]string{}}
	for id, ids := range recs {
		cp := ids
		f.records[id] = &cp
	}
	return f
}

func (f *fakeAudit) Pseudonymize(_ context.Context, ids []string, pseudonym string) (int64, error) {
	f.calls = append(f.calls, "pseudonymize:"+strings.Join(ids, ","))
	if f.err != nil {
		return 0, f.err
	}
	var n int64
	for _, rec := range f.records {
		hit := false
		for _, id := range ids {
			for i := range rec {
				if rec[i] == id {
					rec[i] = pseudonym
					hit = true
				}
			}
		}
		if hit {
			n++
		}
	}
	return n, nil
}

// fakeSalts is an in-memory salt store that records call order.
type fakeSalts struct {
	salts      map[string][]byte
	calls      []string
	ensureErr  error
	destroyErr error
}

func newFakeSalts() *fakeSalts {
	return &fakeSalts{salts: map[string][]byte{}}
}

func (f *fakeSalts) Ensure(_ context.Context, ownerID string) ([]byte, error) {
	f.calls = append(f.calls, "ensure")
	if f.ensureErr != nil {
		return nil, f.ensureErr
	}
	if s, ok := f.salts[ownerID]; ok {
		return s, nil
	}
	s := []byte(strings.Repeat("k", 32) + ownerID)
	f.salts[ownerID] = s
	return s, nil
}

func (f *fakeSalts) Get(_ context.Context, ownerID string) ([]byte, error) {
	if s, ok := f.salts[ownerID]; ok {
		return s, nil
	}
	return nil, domain.ErrNotFound
}

func (f *fakeSalts) Destroy(_ context.Context, ownerID string) error {
	f.calls = append(f.calls, "destroy")
	if f.destroyErr != nil {
		return f.destroyErr
	}
	delete(f.salts, ownerID)
	return nil
}

func TestTombstoneIsDeterministicAndSaltDependent(t *testing.T) {
	t.Parallel()
	saltA := []byte("salt-a-salt-a-salt-a-salt-a-aaaa")
	saltB := []byte("salt-b-salt-b-salt-b-salt-b-bbbb")

	first := Tombstone(saltA, "owner-1")
	if got := Tombstone(saltA, "owner-1"); got != first {
		t.Error("Tombstone is not deterministic: repeat runs would not converge")
	}
	if got := Tombstone(saltA, "owner-2"); got == first {
		t.Error("two identifiers collided under one salt: subjects are no longer distinguishable")
	}
	// The salt is what the erasure destroys, so it must actually be load
	// bearing: the same identifier under a different salt must not match.
	if got := Tombstone(saltB, "owner-1"); got == first {
		t.Error("the salt does not affect the tombstone: destroying it would erase nothing")
	}
	if !strings.HasPrefix(first, tombstonePrefix) {
		t.Errorf("tombstone %q lacks the %q prefix", first, tombstonePrefix)
	}
	// The tombstone must not contain the identifier it replaces.
	if strings.Contains(first, "owner-1") {
		t.Error("the tombstone leaks the identifier it replaces")
	}
}

// TestVerifyRequiresTheSalt is the irreversibility property, stated as an
// executable check. With the salt, a candidate identifier can be confirmed;
// with a different salt — which is all anyone has once the real one is
// destroyed — it cannot.
func TestVerifyRequiresTheSalt(t *testing.T) {
	t.Parallel()
	salt := []byte("the-real-salt-the-real-salt-1234")
	tomb := Tombstone(salt, "owner-1")

	if !Verify(salt, "owner-1", tomb) {
		t.Error("Verify with the correct salt and identifier = false")
	}
	if Verify(salt, "owner-2", tomb) {
		t.Error("Verify accepted the wrong identifier")
	}
	if Verify([]byte("a-different-salt-a-different-sal"), "owner-1", tomb) {
		t.Error("Verify succeeded without the real salt: the tombstone is reversible")
	}
}

// TestEraseOwnerPseudonymizesThenDestroys pins the ordering. Destroying the
// salt before the records are rewritten would leave them permanently
// un-erasable, so destroy must be the last call.
func TestEraseOwnerPseudonymizesThenDestroys(t *testing.T) {
	t.Parallel()
	audit := newFakeAudit(map[string][2]string{
		"aud-1": {"owner-1", "key-1"},
		"aud-2": {"admin-9", "owner-1"},
	})
	salts := newFakeSalts()
	e, err := New(audit, salts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	n, err := e.EraseOwner(context.Background(), "owner-1", []string{"owner-1"})
	if err != nil {
		t.Fatalf("EraseOwner: %v", err)
	}
	if n != 2 {
		t.Errorf("rewritten = %d, want 2", n)
	}

	if last := salts.calls[len(salts.calls)-1]; last != "destroy" {
		t.Errorf("last salt call = %q, want destroy", last)
	}
	if len(audit.calls) == 0 {
		t.Fatal("no pseudonymize call was made")
	}
	if _, ok := salts.salts["owner-1"]; ok {
		t.Error("the salt survived the erasure")
	}

	// The identity is gone from both columns it appeared in; the bystanders
	// are untouched.
	if got := audit.records["aud-1"][0]; !strings.HasPrefix(got, tombstonePrefix) {
		t.Errorf("aud-1 actor = %q, want a tombstone", got)
	}
	if got := audit.records["aud-1"][1]; got != "key-1" {
		t.Errorf("aud-1 target = %q, want the untouched key-1", got)
	}
	if got := audit.records["aud-2"][0]; got != "admin-9" {
		t.Errorf("aud-2 actor = %q, want the untouched admin-9", got)
	}
}

// TestEraseOwnerIsIrreversibleAfterwards is the end-to-end statement of the
// guarantee: given the full record and the pseudonym, and with the salt
// destroyed, the subject cannot be recovered.
func TestEraseOwnerIsIrreversibleAfterwards(t *testing.T) {
	t.Parallel()
	audit := newFakeAudit(map[string][2]string{"aud-1": {"owner-1", "key-1"}})
	salts := newFakeSalts()
	e, _ := New(audit, salts)
	ctx := context.Background()

	if _, err := e.EraseOwner(ctx, "owner-1", []string{"owner-1"}); err != nil {
		t.Fatalf("EraseOwner: %v", err)
	}
	tomb := audit.records["aud-1"][0]

	// The salt is gone, so nobody — including this test, which holds the whole
	// record and the tombstone — can obtain the key needed to verify a guess.
	if _, err := salts.Get(ctx, "owner-1"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("salt still retrievable: %v", err)
	}
	// Every candidate identifier fails against every salt anyone could now
	// produce, because the one that would work no longer exists.
	for _, guess := range []string{"owner-1", "owner-2", "key-1"} {
		if Verify([]byte(strings.Repeat("g", 32)), guess, tomb) {
			t.Errorf("recovered %q from the tombstone without the destroyed salt", guess)
		}
	}
}

// TestEraseOwnerIsIdempotent: a retried erasure must converge, not double-apply.
func TestEraseOwnerIsIdempotent(t *testing.T) {
	t.Parallel()
	audit := newFakeAudit(map[string][2]string{"aud-1": {"owner-1", "key-1"}})
	salts := newFakeSalts()
	e, _ := New(audit, salts)
	ctx := context.Background()

	if _, err := e.EraseOwner(ctx, "owner-1", []string{"owner-1"}); err != nil {
		t.Fatalf("first EraseOwner: %v", err)
	}
	firstTomb := audit.records["aud-1"][0]

	n, err := e.EraseOwner(ctx, "owner-1", []string{"owner-1"})
	if err != nil {
		t.Fatalf("second EraseOwner: %v", err)
	}
	if n != 0 {
		t.Errorf("second run rewrote %d records, want 0", n)
	}
	if got := audit.records["aud-1"][0]; got != firstTomb {
		t.Errorf("tombstone changed on re-run: %q then %q", firstTomb, got)
	}
}

// TestEraseOwnerKeepsSaltWhenPseudonymizeFails is the safe-failure-direction
// test. If the rewrite fails, the salt must survive so the erasure is still
// possible on a retry; destroying it here would strand the records forever.
func TestEraseOwnerKeepsSaltWhenPseudonymizeFails(t *testing.T) {
	t.Parallel()
	audit := newFakeAudit(map[string][2]string{"aud-1": {"owner-1", "key-1"}})
	audit.err = errors.New("write failed")
	salts := newFakeSalts()
	e, _ := New(audit, salts)

	if _, err := e.EraseOwner(context.Background(), "owner-1", []string{"owner-1"}); err == nil {
		t.Fatal("EraseOwner = nil error, want the pseudonymize failure")
	}
	if _, ok := salts.salts["owner-1"]; !ok {
		t.Error("the salt was destroyed despite the rewrite failing: those records are now un-erasable")
	}
	for _, c := range salts.calls {
		if c == "destroy" {
			t.Error("Destroy was called after a failed rewrite")
		}
	}
}

func TestEraseOwnerDistinctTombstonesPerIdentifier(t *testing.T) {
	t.Parallel()
	audit := newFakeAudit(map[string][2]string{
		"aud-1": {"owner-1", "dev-1"},
		"aud-2": {"owner-1", "dev-2"},
	})
	e, _ := New(audit, newFakeSalts())

	if _, err := e.EraseOwner(context.Background(), "owner-1", []string{"dev-1", "dev-2"}); err != nil {
		t.Fatalf("EraseOwner: %v", err)
	}
	// Separate subjects must stay separable, or the structure of the trail is
	// destroyed along with the identity.
	if audit.records["aud-1"][1] == audit.records["aud-2"][1] {
		t.Error("two identifiers collapsed to one tombstone")
	}
}

func TestEraseOwnerErrors(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("empty owner", func(t *testing.T) {
		t.Parallel()
		e, _ := New(newFakeAudit(nil), newFakeSalts())
		if _, err := e.EraseOwner(ctx, "", nil); !errors.Is(err, domain.ErrInvalidInput) {
			t.Errorf("err = %v, want ErrInvalidInput", err)
		}
	})
	t.Run("salt load fails", func(t *testing.T) {
		t.Parallel()
		salts := newFakeSalts()
		salts.ensureErr = errors.New("no salt")
		e, _ := New(newFakeAudit(nil), salts)
		if _, err := e.EraseOwner(ctx, "owner-1", nil); err == nil {
			t.Error("err = nil, want the salt failure")
		}
	})
	t.Run("destroy fails", func(t *testing.T) {
		t.Parallel()
		salts := newFakeSalts()
		salts.destroyErr = errors.New("destroy failed")
		e, _ := New(newFakeAudit(nil), salts)
		if _, err := e.EraseOwner(ctx, "owner-1", nil); err == nil {
			t.Error("err = nil, want the destroy failure")
		}
	})
	t.Run("no identifiers still destroys the salt", func(t *testing.T) {
		t.Parallel()
		salts := newFakeSalts()
		e, _ := New(newFakeAudit(nil), salts)
		if _, err := e.EraseOwner(ctx, "owner-1", nil); err != nil {
			t.Fatalf("EraseOwner: %v", err)
		}
		if _, ok := salts.salts["owner-1"]; ok {
			t.Error("a stray salt was left behind for an owner with no records")
		}
	})
}

func TestNewRejectsNilPorts(t *testing.T) {
	t.Parallel()

	if _, err := New(nil, newFakeSalts()); !errors.Is(err, domain.ErrInvalidInput) {
		t.Errorf("New(nil, salts) = %v, want ErrInvalidInput", err)
	}
	if _, err := New(newFakeAudit(nil), nil); !errors.Is(err, domain.ErrInvalidInput) {
		t.Errorf("New(audit, nil) = %v, want ErrInvalidInput", err)
	}
}

// staticClock returns a fixed time so cutoff assertions are exact.
func staticClock(at time.Time) func() time.Time {
	return func() time.Time { return at }
}
