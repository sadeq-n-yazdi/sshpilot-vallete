package bootstrap_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/nameguard"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/repository"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/service/bootstrap"
)

var seedNow = time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)

// tripwireStore fails the test if a transaction is ever opened.
//
// It is what turns "Seed returned an error" into the stronger claim the
// choke point actually has to make: a refused identifier must never reach
// storage at all. A test that only checked the returned error would still
// pass if the handle row had been written and the error raised afterwards.
type tripwireStore struct {
	t *testing.T
}

func (s *tripwireStore) Repos() repository.Repos {
	s.t.Helper()
	s.t.Fatal("Repos() called: a refused identifier reached storage")
	return repository.Repos{}
}

func (s *tripwireStore) WithTx(context.Context, func(context.Context, repository.Repos) error) error {
	s.t.Helper()
	s.t.Fatal("WithTx() called: a refused identifier reached storage")
	return nil
}

// recordingStore accepts the seed and records the names that were written, so
// an accepted name can be checked against what actually landed.
type recordingStore struct {
	handle string
	set    string
}

func (s *recordingStore) Repos() repository.Repos { return repository.Repos{} }

func (s *recordingStore) WithTx(ctx context.Context, fn func(context.Context, repository.Repos) error) error {
	return fn(ctx, repository.Repos{
		Owners:  &fakeOwners{},
		Handles: &fakeHandles{store: s},
		KeySets: &fakeKeySets{store: s},
	})
}

// The fakes embed their interface so only the methods Seed actually calls need
// bodies; any other call panics loudly rather than silently succeeding.
type fakeOwners struct{ repository.OwnerRepository }

func (f *fakeOwners) Create(context.Context, *domain.Owner) error { return nil }

type fakeHandles struct {
	repository.HandleRepository
	store *recordingStore
}

func (f *fakeHandles) Register(_ context.Context, h *domain.Handle) error {
	f.store.handle = h.Name
	return nil
}

type fakeKeySets struct {
	repository.KeySetRepository
	store *recordingStore
}

func (f *fakeKeySets) Create(_ context.Context, s *domain.KeySet) error {
	f.store.set = s.Name
	return nil
}

func mustGuard(t *testing.T) *nameguard.Guard {
	t.Helper()
	g, err := nameguard.Default()
	if err != nil {
		t.Fatalf("nameguard.Default(): %v", err)
	}
	return g
}

// seedErr runs Seed against the tripwire store and returns only the error.
func seedErr(t *testing.T, p bootstrap.Params) error {
	t.Helper()
	_, err := bootstrap.Seed(context.Background(), &tripwireStore{t: t}, p)
	return err
}

// TestSeedRefusesBlockedHandleNames refuses every reachable spelling of a
// blocked handle, and proves nothing was written.
func TestSeedRefusesBlockedHandleNames(t *testing.T) {
	t.Parallel()
	for _, handle := range []string{"admin", "adm1n", "ad-min", "4dm1n", "root", "r00t", "support", "healthz", "api"} {
		err := seedErr(t, bootstrap.Params{Handle: handle, Now: seedNow, Guard: mustGuard(t)})
		if !errors.Is(err, domain.ErrBlockedName) {
			t.Errorf("Seed(handle=%q) = %v, want ErrBlockedName", handle, err)
		}
	}
}

// TestSeedRefusesBlockedSetName pins the second identifier kind. A caller who
// supplies a set name is choosing it, so it is checked.
func TestSeedRefusesBlockedSetName(t *testing.T) {
	t.Parallel()
	for _, set := range []string{"admin", "r00t", "support"} {
		err := seedErr(t, bootstrap.Params{Handle: "alice", SetName: set, Now: seedNow, Guard: mustGuard(t)})
		if !errors.Is(err, domain.ErrBlockedName) {
			t.Errorf("Seed(set=%q) = %v, want ErrBlockedName", set, err)
		}
	}
}

// TestSeedRefusesWithoutAGuard is the fail-closed invariant at the wiring
// level: a Params built without a Guard must refuse every name, so forgetting
// to wire the guard can never become a silent bypass.
func TestSeedRefusesWithoutAGuard(t *testing.T) {
	t.Parallel()
	err := seedErr(t, bootstrap.Params{Handle: "alice", Now: seedNow})
	if !errors.Is(err, domain.ErrBlockedName) {
		t.Errorf("Seed with nil Guard = %v, want ErrBlockedName", err)
	}
}

// TestSeedRefusalDoesNotNameTheRule keeps the no-oracle property end to end:
// wrapping the guard's error in bootstrap context must not reintroduce the
// matched term.
func TestSeedRefusalDoesNotNameTheRule(t *testing.T) {
	t.Parallel()
	err := seedErr(t, bootstrap.Params{Handle: "adm1n", Now: seedNow, Guard: mustGuard(t)})
	if err == nil {
		t.Fatal("Seed(handle=adm1n) = nil, want refusal")
	}
	msg := strings.ToLower(err.Error())
	for _, s := range []string{"admin", "adm1n", "routing", "impersonation", "offensive", "substring"} {
		if strings.Contains(msg, s) {
			t.Errorf("refusal %q leaks %q", err.Error(), s)
		}
	}
}

// TestSeedAcceptsOrdinaryNames pins that enforcement did not break the ordinary
// path, and that the accepted name is the one written.
func TestSeedAcceptsOrdinaryNames(t *testing.T) {
	t.Parallel()
	store := &recordingStore{}
	res, err := bootstrap.Seed(context.Background(), store, bootstrap.Params{
		Handle: "alice", SetName: "laptops", Now: seedNow, Guard: mustGuard(t),
	})
	if err != nil {
		t.Fatalf("Seed = %v, want nil", err)
	}
	if store.handle != "alice" || store.set != "laptops" {
		t.Errorf("wrote handle=%q set=%q, want alice/laptops", store.handle, store.set)
	}
	if res.SetName != "laptops" {
		t.Errorf("Result.SetName = %q, want laptops", res.SetName)
	}
}

// TestSeedUsesSystemDefaultSetNameUnchecked pins the one deliberate carve-out.
// DefaultSetName ("default") is itself a curated routing term, so if the
// system's own fallback were checked like a user choice every bootstrap would
// fail. ADR-0017 scopes the blocklist to USER-CHOSEN identifiers; this asserts
// the carve-out is exactly that and no wider.
func TestSeedUsesSystemDefaultSetNameUnchecked(t *testing.T) {
	t.Parallel()
	store := &recordingStore{}
	res, err := bootstrap.Seed(context.Background(), store, bootstrap.Params{
		Handle: "alice", Now: seedNow, Guard: mustGuard(t),
	})
	if err != nil {
		t.Fatalf("Seed with empty SetName = %v, want nil", err)
	}
	if store.set != bootstrap.DefaultSetName || res.SetName != bootstrap.DefaultSetName {
		t.Errorf("set = %q / %q, want %q", store.set, res.SetName, bootstrap.DefaultSetName)
	}
	// The carve-out is for the SYSTEM's choice only: the same name supplied
	// explicitly by a caller is a user choice and must still be refused.
	if err := seedErr(t, bootstrap.Params{
		Handle: "alice", SetName: bootstrap.DefaultSetName, Now: seedNow, Guard: mustGuard(t),
	}); !errors.Is(err, domain.ErrBlockedName) {
		t.Errorf("Seed with explicit %q = %v, want ErrBlockedName", bootstrap.DefaultSetName, err)
	}
}

// TestSeedStillRejectsMalformedNames pins that routing through the guard did
// not drop the syntax rules the validators enforced before.
func TestSeedStillRejectsMalformedNames(t *testing.T) {
	t.Parallel()
	for _, p := range []bootstrap.Params{
		{Handle: "", Now: seedNow},
		{Handle: "Upper", Now: seedNow},
		{Handle: "-lead", Now: seedNow},
		{Handle: "alice", SetName: "has space", Now: seedNow},
	} {
		p.Guard = mustGuard(t)
		if err := seedErr(t, p); !errors.Is(err, domain.ErrInvalidInput) {
			t.Errorf("Seed(%+v) = %v, want ErrInvalidInput", p, err)
		}
	}
}

// TestSeedRejectsNilStoreBeforeAnythingElse keeps the pre-existing guard on the
// store argument working alongside the new one.
func TestSeedRejectsNilStoreBeforeAnythingElse(t *testing.T) {
	t.Parallel()
	if _, err := bootstrap.Seed(context.Background(), nil, bootstrap.Params{
		Handle: "alice", Now: seedNow, Guard: mustGuard(t),
	}); !errors.Is(err, domain.ErrInvalidInput) {
		t.Errorf("Seed(nil store) = %v, want ErrInvalidInput", err)
	}
}
