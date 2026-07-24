package listadmin

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/audit"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/blocklist"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/config"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/nameguard"
)

// These tests exercise the Fb4 invariant end to end: a nameguard.Guard and a
// listadmin.Service built over the SAME blocklist.Matcher, so a runtime edit is
// observed by the enforcement choke point. They live in package listadmin so
// they can reuse the harness fakes; they import nameguard, which does not
// import listadmin, so there is no cycle.

// TestGuardEnforcesRuntimeAddedBlocklistTerm proves the serving-path seam (#36)
// is closed: a term an administrator adds at runtime is refused on the NEXT
// create and rename checked through the shared guard, with no restart and no
// re-wiring. If the guard read a different matcher than the service edits, the
// term would be accepted.
func TestGuardEnforcesRuntimeAddedBlocklistTerm(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	guard := nameguard.New(h.matcher)
	ctx := context.Background()

	const term = "newbadword"
	// Not blocked before the edit.
	if err := guard.Check(nameguard.KindKeySetName, nameguard.OpCreate, term); err != nil {
		t.Fatalf("precondition Check(%q) = %v, want nil", term, err)
	}

	if err := h.svc.AddBlocklistTerm(ctx, activeAdminID, term); err != nil {
		t.Fatalf("AddBlocklistTerm: %v", err)
	}

	// Refused on the next create AND rename, both through the shared guard.
	for _, op := range []nameguard.Op{nameguard.OpCreate, nameguard.OpRename} {
		if err := guard.Check(nameguard.KindKeySetName, op, term); !errors.Is(err, domain.ErrBlockedName) {
			t.Errorf("Check(%q, %v) after runtime add = %v, want domain.ErrBlockedName", term, op, err)
		}
	}
}

// TestGuardObservesRuntimeRemovedBlocklistTerm proves the reverse direction:
// dropping an administrator-added term re-permits it through the same guard.
func TestGuardObservesRuntimeRemovedBlocklistTerm(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	guard := nameguard.New(h.matcher)
	ctx := context.Background()

	const term = "tempreserved"
	if err := h.svc.AddBlocklistTerm(ctx, activeAdminID, term); err != nil {
		t.Fatalf("AddBlocklistTerm: %v", err)
	}
	if err := guard.Check(nameguard.KindKeySetName, nameguard.OpCreate, term); !errors.Is(err, domain.ErrBlockedName) {
		t.Fatalf("Check after add = %v, want domain.ErrBlockedName", err)
	}

	if err := h.svc.RemoveBlocklistTerm(ctx, activeAdminID, term); err != nil {
		t.Fatalf("RemoveBlocklistTerm: %v", err)
	}
	if err := guard.Check(nameguard.KindKeySetName, nameguard.OpCreate, term); err != nil {
		t.Errorf("Check after remove = %v, want nil", err)
	}
}

// TestGuardCheckRacesCleanWithListEdits runs guard checks concurrently with
// runtime edits on the shared matcher under the race detector.
//
// The synchronization it proves is not added by this package: blocklist.Matcher
// holds its administrator-added terms behind an atomic.Pointer and Set* swaps
// it, so a captured *Matcher a guard reads sees a whole old or whole new set,
// never a half-built map. This test pins that the shared-matcher wiring keeps
// that property -- guard.Check reading concurrently with listadmin's apply must
// stay data-race free.
//
// A FRESH matcher, guard, and service are built each round rather than reused,
// so a latent race in the per-instance access is exercised on an object no
// prior round has already quiesced.
func TestGuardCheckRacesCleanWithListEdits(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	for round := 0; round < 20; round++ {
		h := newHarness(t)
		guard := nameguard.New(h.matcher)

		var wg sync.WaitGroup
		// Readers: hammer the guard, the exact call the serving path makes.
		for r := 0; r < 4; r++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := 0; i < 50; i++ {
					_ = guard.Check(nameguard.KindKeySetName, nameguard.OpCreate, "candidatename")
				}
			}()
		}
		// Writers: each adds and removes its own unique term, so the two never
		// collide on a duplicate and the matcher is being swapped throughout the
		// readers' loop.
		for w := 0; w < 2; w++ {
			wg.Add(1)
			go func(w int) {
				defer wg.Done()
				term := fmt.Sprintf("runtimeterm%d", w)
				for i := 0; i < 25; i++ {
					_ = h.svc.AddBlocklistTerm(ctx, activeAdminID, term)
					_ = h.svc.RemoveBlocklistTerm(ctx, activeAdminID, term)
				}
			}(w)
		}
		wg.Wait()
	}
}

// TestRemovedAllowlistEntrySurvivesReload is the #35 proof: an allowlist entry
// an administrator removes at runtime stays removed after a restart, rather than
// being resurrected by the seed. Resurrection is the fail-open direction --
// re-exempting an identifier somebody deliberately re-blocked -- which is why
// the durable tombstone must outrank the seed at replay.
//
// The "restart" is modeled by composing a brand-new matcher from the same seed
// config and the same persisted overrides, exactly as LoadPolicy does at
// startup. The overrides repository is the durable record that survives; the
// matcher's in-memory state does not.
func TestRemovedAllowlistEntrySurvivesReload(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	// The seed exempts "admin", which the curated list would otherwise block.
	cfg := config.BlocklistConfig{AllowEntries: []string{"admin"}}
	overrides := newFakeOverrides()

	// First boot: seed + (empty) overrides. The exemption is in force.
	m1 := blockedMatcher(t)
	if err := LoadPolicy(ctx, m1, cfg, overrides); err != nil {
		t.Fatalf("LoadPolicy (first boot): %v", err)
	}
	guard1 := nameguard.New(m1)
	if err := guard1.Check(nameguard.KindKeySetName, nameguard.OpCreate, "admin"); err != nil {
		t.Fatalf("precondition Check(admin) with exemption = %v, want nil", err)
	}

	// An administrator removes the exemption at runtime; the tombstone persists.
	svc := serviceOver(t, m1, overrides)
	if err := svc.RemoveAllowlistEntry(ctx, activeAdminID, "admin"); err != nil {
		t.Fatalf("RemoveAllowlistEntry: %v", err)
	}
	if err := guard1.Check(nameguard.KindKeySetName, nameguard.OpCreate, "admin"); !errors.Is(err, domain.ErrBlockedName) {
		t.Fatalf("Check(admin) after removal = %v, want domain.ErrBlockedName", err)
	}

	// Restart: a fresh matcher composed from the SAME seed and overrides. The
	// seed still names "admin" as an exemption, so only the replayed tombstone
	// keeps it out.
	m2 := blockedMatcher(t)
	if err := LoadPolicy(ctx, m2, cfg, overrides); err != nil {
		t.Fatalf("LoadPolicy (reload): %v", err)
	}
	guard2 := nameguard.New(m2)
	if err := guard2.Check(nameguard.KindKeySetName, nameguard.OpCreate, "admin"); !errors.Is(err, domain.ErrBlockedName) {
		t.Errorf("Check(admin) after reload = %v, want domain.ErrBlockedName (entry must stay removed)", err)
	}
}

// blockedMatcher builds a matcher whose curated list blocks "admin", so an
// allowlist exemption for it is observable and its removal re-blocks it.
func blockedMatcher(t *testing.T) *blocklist.Matcher {
	t.Helper()
	m, err := blocklist.NewMatcher(blocklist.List{
		Name:  "impersonation",
		Mode:  blocklist.MatchWholeSkeleton,
		Terms: []string{"admin"},
	})
	if err != nil {
		t.Fatalf("NewMatcher: %v", err)
	}
	return m
}

// serviceOver builds a Service authorized for the active admin over the given
// matcher and overrides, so a test can drive a runtime edit against a matcher it
// also composed with LoadPolicy.
func serviceOver(t *testing.T, m *blocklist.Matcher, overrides *fakeOverrides) *Service {
	t.Helper()
	em, err := audit.NewEmitter(&recordingSink{})
	if err != nil {
		t.Fatalf("NewEmitter: %v", err)
	}
	svc, err := New(Params{
		Admins:    newFakeAdmins(activeAdmin()),
		Overrides: overrides,
		Emitter:   em,
		Matcher:   m,
		Now:       func() time.Time { return testNow },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return svc
}
