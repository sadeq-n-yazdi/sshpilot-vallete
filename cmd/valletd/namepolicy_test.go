package main

import (
	"context"
	"errors"
	"testing"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/blocklist"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/config"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/nameguard"
)

// stubOverrides is a minimal ListOverrideRepository the composition test drives
// directly, so a test controls exactly which persisted overrides LoadPolicy
// replays without standing up a database.
type stubOverrides struct {
	rows    []domain.ListOverride
	listErr error
}

func (s stubOverrides) Put(context.Context, *domain.ListOverride) error { return nil }

func (s stubOverrides) List(context.Context) ([]domain.ListOverride, error) {
	return s.rows, s.listErr
}

// blockCfg returns a config whose blocklist section adds one operator term, so
// a test can prove the seed reaches the composed guard.
func blockCfg(extra ...string) *config.Config {
	c := config.Default()
	c.Blocklist.ExtraEntries = extra
	return &c
}

// TestNewNamePolicyEnforcesOperatorSeed proves the guard the helper returns
// enforces the operator's configured extra terms, not merely the curated
// defaults -- the disconnected-matcher seam (#36) is what this closes.
func TestNewNamePolicyEnforcesOperatorSeed(t *testing.T) {
	t.Parallel()
	pol, err := newNamePolicy(context.Background(), blockCfg("zzcustomterm"), stubOverrides{})
	if err != nil {
		t.Fatalf("newNamePolicy: %v", err)
	}

	if err := pol.Guard.Check(nameguard.KindKeySetName, nameguard.OpCreate, "zzcustomterm"); !errors.Is(err, domain.ErrBlockedName) {
		t.Errorf("Check(operator term) = %v, want domain.ErrBlockedName", err)
	}
	// A name the operator did not reserve and no default blocks is allowed, so
	// the guard is not simply refusing everything.
	if err := pol.Guard.Check(nameguard.KindKeySetName, nameguard.OpCreate, "myteamkeys"); err != nil {
		t.Errorf("Check(ordinary name) = %v, want nil", err)
	}
}

// TestNewNamePolicyReplaysOverrides proves LoadPolicy -- not ApplySeed -- backs
// the helper: a persisted runtime blocklist term is in force at startup. Seeding
// without replay would leave it out.
func TestNewNamePolicyReplaysOverrides(t *testing.T) {
	t.Parallel()
	// UpdatedAt is left zero: replay keys on list, skeleton, and state only.
	rows := []domain.ListOverride{{
		List:     domain.ListKindBlocklistTerm,
		Skeleton: blocklist.Skeleton("myruntimeterm"),
		Entry:    "myruntimeterm",
		State:    domain.ListOverridePresent,
		ActorID:  "adm-1",
	}}
	pol, err := newNamePolicy(context.Background(), blockCfg(), stubOverrides{rows: rows})
	if err != nil {
		t.Fatalf("newNamePolicy: %v", err)
	}

	if err := pol.Guard.Check(nameguard.KindKeySetName, nameguard.OpCreate, "myruntimeterm"); !errors.Is(err, domain.ErrBlockedName) {
		t.Errorf("Check(replayed term) = %v, want domain.ErrBlockedName", err)
	}
}

// TestNewNamePolicyGuardReadsTheSharedMatcher is the load-bearing check: the
// guard and the matcher are one instance, so an edit applied to the matcher --
// exactly what listadmin does at runtime -- is observed by the guard with no
// re-wiring. If these were separate matchers the runtime-edit seam would still
// be open.
func TestNewNamePolicyGuardReadsTheSharedMatcher(t *testing.T) {
	t.Parallel()
	pol, err := newNamePolicy(context.Background(), blockCfg(), stubOverrides{})
	if err != nil {
		t.Fatalf("newNamePolicy: %v", err)
	}

	// Not blocked yet.
	if err := pol.Guard.Check(nameguard.KindKeySetName, nameguard.OpCreate, "laterterm"); err != nil {
		t.Fatalf("precondition Check(laterterm) = %v, want nil", err)
	}
	// Apply the edit straight to the shared matcher, the way listadmin's apply
	// step does through SetExtraTerms.
	if err := pol.Matcher.SetExtraTerms([]string{"laterterm"}); err != nil {
		t.Fatalf("SetExtraTerms: %v", err)
	}
	if err := pol.Guard.Check(nameguard.KindKeySetName, nameguard.OpCreate, "laterterm"); !errors.Is(err, domain.ErrBlockedName) {
		t.Errorf("Check after shared-matcher edit = %v, want domain.ErrBlockedName", err)
	}
}

// TestNewNamePolicyFailsClosedOnOverrideReadError proves a startup that cannot
// read the persisted overrides refuses to build a policy rather than falling
// back to the seed alone -- the fallback would resurrect a removed allowlist
// entry, which is the fail-open direction.
func TestNewNamePolicyFailsClosedOnOverrideReadError(t *testing.T) {
	t.Parallel()
	_, err := newNamePolicy(context.Background(), blockCfg(), stubOverrides{listErr: errors.New("db down")})
	if err == nil {
		t.Fatal("newNamePolicy returned nil error when the override read failed, want a startup failure")
	}
}
