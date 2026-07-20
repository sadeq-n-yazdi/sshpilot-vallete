package publish

import (
	"context"
	"errors"
	"testing"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/repository"
)

// A repository that returns a nil row together with a nil error violates the
// port contract, and no adapter in this tree does it — which is exactly why
// these fakes exist. The real store cannot be made to break its own contract,
// so a fake is the only way to reach the guard at all, and an unreachable guard
// that is never exercised is how this class of bug survives a review and then
// arrives with a future adapter.
//
// Each fake embeds the port interface and overrides ONE method. The embedded
// interface is left nil on purpose: any method these tests do not expect to be
// called panics loudly instead of quietly returning a zero value, so the test
// cannot drift into passing for the wrong reason.

type nilHandleRepo struct{ repository.HandleRepository }

func (nilHandleRepo) GetByName(context.Context, string) (*domain.Handle, error) {
	return nil, nil
}

type nilOwnerRepo struct{ repository.OwnerRepository }

func (nilOwnerRepo) Get(context.Context, domain.OwnerID) (*domain.Owner, error) {
	return nil, nil
}

type nilKeySetRepo struct{ repository.KeySetRepository }

func (nilKeySetRepo) GetByName(context.Context, domain.OwnerID, string) (*domain.KeySet, error) {
	return nil, nil
}

func (nilKeySetRepo) GetDefault(context.Context, domain.OwnerID) (*domain.KeySet, error) {
	return nil, nil
}

// TestNilRowFromTheStoreIsRefusedRatherThanDereferenced pins that a contract
// violation on the publish path is answered, not crashed on.
//
// The publish endpoint is UNAUTHENTICATED: anyone who can send a GET reaches
// every one of these three lookups. A nil dereference here would therefore not
// be a bug that shows up in an operator's own session — it would be a remote
// denial of service against the whole process, triggerable by a stranger, and
// on the keyset site it would crash BEFORE the state check that gates protected
// sets had run.
//
// The load-bearing assertion is simply that the call RETURNS. The ErrNotFound
// check is secondary: any answer beats a panic, and a refusal is the safe
// reading of "the store told us nothing".
func TestNilRowFromTheStoreIsRefusedRatherThanDereferenced(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		setName string
		break_  func(*repository.Repos)
	}{
		{
			name:    "the handle lookup",
			setName: "prod",
			break_:  func(r *repository.Repos) { r.Handles = nilHandleRepo{} },
		},
		{
			name:    "the owner lookup",
			setName: "prod",
			break_:  func(r *repository.Repos) { r.Owners = nilOwnerRepo{} },
		},
		{
			name:    "the named key set lookup",
			setName: "prod",
			break_:  func(r *repository.Repos) { r.KeySets = nilKeySetRepo{} },
		},
		{
			// The default-set path is a separate call (GetDefault, not
			// GetByName) and so is a separate way to reach the same
			// dereference. An empty set name selects it.
			name:    "the default key set lookup",
			setName: "",
			break_:  func(r *repository.Repos) { r.KeySets = nilKeySetRepo{} },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newProtectedFixture(t)
			alice := f.seedOwner("alice")
			setID := f.seedSet(alice.OwnerID, "prod", domain.VisibilityPublic, domain.NameStateActive)
			f.addKey(alice.OwnerID, setID, "key")

			repos := f.store.Repos()
			tc.break_(&repos)

			svc, err := New(repos)
			if err != nil {
				t.Fatalf("publish.New: %v", err)
			}

			res, err := svc.Resolve(context.Background(), "alice", tc.setName, "")
			if !errors.Is(err, ErrNotFound) {
				t.Fatalf("%s returned a nil row: got err %v, want ErrNotFound", tc.name, err)
			}
			if res.Body != nil {
				t.Errorf("%s: refusal carried a body: %q", tc.name, res.Body)
			}
		})
	}
}
