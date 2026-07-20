package listadmin

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/audit"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/blocklist"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/config"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
)

// deployment is one process lifetime: a freshly composed matcher plus the
// Service editing it. The override repository and the audit sink live OUTSIDE
// it, exactly as a database does, so restarting means building a new deployment
// over the same durable state.
type deployment struct {
	matcher *blocklist.Matcher
	svc     *Service
}

// boot composes the policy the way startup does -- seed first, persisted
// overrides replayed over it -- and wires a Service to the result.
//
// Tests drive this rather than calling the repository directly. LoadPolicy is
// the composition entry point, so a change that stopped replaying overrides, or
// that let the seed outrank a tombstone, is caught here rather than being
// invisible to a test that had already reached past it.
func boot(t *testing.T, cfg config.BlocklistConfig, ov *fakeOverrides, sink *recordingSink) *deployment {
	t.Helper()

	m, err := blocklist.NewMatcher(blocklist.List{
		Name:  "impersonation",
		Mode:  blocklist.MatchWholeSkeleton,
		Terms: []string{"admin", "root"},
	})
	if err != nil {
		t.Fatalf("NewMatcher: %v", err)
	}

	if err := LoadPolicy(context.Background(), m, cfg, ov); err != nil {
		t.Fatalf("LoadPolicy: %v", err)
	}

	em, err := audit.NewEmitter(sink)
	if err != nil {
		t.Fatalf("NewEmitter: %v", err)
	}
	svc, err := New(Params{
		Admins:    newFakeAdmins(activeAdmin()),
		Overrides: ov,
		Emitter:   em,
		Matcher:   m,
		Now:       func() time.Time { return testNow },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return &deployment{matcher: m, svc: svc}
}

// blocked reports whether the composed policy refuses name, asked of the real
// match engine rather than of the list contents. A test that compared slices
// would pass even if the composed lists never reached the matcher.
func (d *deployment) blocked(t *testing.T, name string) bool {
	t.Helper()
	return !d.matcher.Check(name).Allowed
}

// TestRemovedAllowlistEntryStaysRemovedAcrossARestart is the headline
// invariant, and the fail-open direction this whole mechanism exists to close.
//
// Removing an allowlist entry RE-BLOCKS the term. If the removal does not
// survive a restart, the seed restores the exemption and an identifier an
// administrator deliberately refused becomes registrable again -- while the
// audit log still shows the removal. The audit trail would describe a policy
// that is not in force.
func TestRemovedAllowlistEntryStaysRemovedAcrossARestart(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	// The seed grants the exemption. Only a runtime removal takes it away, so
	// this test cannot pass by the seed simply never having granted it.
	cfg := config.BlocklistConfig{AllowEntries: []string{"Admin"}}
	ov := newFakeOverrides()
	sink := &recordingSink{}

	first := boot(t, cfg, ov, sink)
	if first.blocked(t, "Admin") {
		t.Fatal("the seeded allowlist entry was not in force before the edit")
	}

	if err := first.svc.RemoveAllowlistEntry(ctx, activeAdminID, "Admin"); err != nil {
		t.Fatalf("RemoveAllowlistEntry: %v", err)
	}
	if !first.blocked(t, "Admin") {
		t.Fatal("the removal did not re-block the term in the running process")
	}

	// Restart: the old matcher is discarded and the policy is composed again
	// from the seed and whatever was durably recorded.
	second := boot(t, cfg, ov, sink)
	if !second.blocked(t, "Admin") {
		t.Error("FAIL-OPEN: the removed allowlist entry was restored by the seed after a restart, " +
			"re-permitting an identifier an administrator refused")
	}
}

// TestAddedAllowlistEntrySurvivesARestart is the fail-closed direction. Losing
// it is merely annoying rather than dangerous, but an edit that silently
// reverts still makes the audit log wrong about the live policy.
func TestAddedAllowlistEntrySurvivesARestart(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	cfg := config.BlocklistConfig{}
	ov := newFakeOverrides()
	sink := &recordingSink{}

	first := boot(t, cfg, ov, sink)
	if !first.blocked(t, "root") {
		t.Fatal("root was not blocked before the edit")
	}
	if err := first.svc.AddAllowlistEntry(ctx, activeAdminID, "root"); err != nil {
		t.Fatalf("AddAllowlistEntry: %v", err)
	}

	second := boot(t, cfg, ov, sink)
	if second.blocked(t, "root") {
		t.Error("the added allowlist entry did not survive the restart")
	}
}

// TestAddedBlocklistTermSurvivesARestart covers the other list. A term an
// administrator added to refuse a name must not quietly stop refusing it.
func TestAddedBlocklistTermSurvivesARestart(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	cfg := config.BlocklistConfig{}
	ov := newFakeOverrides()
	sink := &recordingSink{}

	first := boot(t, cfg, ov, sink)
	if first.blocked(t, "billing") {
		t.Fatal("billing was already blocked before the edit")
	}
	if err := first.svc.AddBlocklistTerm(ctx, activeAdminID, "billing"); err != nil {
		t.Fatalf("AddBlocklistTerm: %v", err)
	}

	second := boot(t, cfg, ov, sink)
	if !second.blocked(t, "billing") {
		t.Error("FAIL-OPEN: the added blocklist term stopped refusing the name after a restart")
	}
}

// TestRemovedBlocklistTermStaysRemovedAcrossARestart pins the tombstone on the
// other list too, so the two lists cannot drift in how a removal is treated.
func TestRemovedBlocklistTermStaysRemovedAcrossARestart(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	cfg := config.BlocklistConfig{ExtraEntries: []string{"billing"}}
	ov := newFakeOverrides()
	sink := &recordingSink{}

	first := boot(t, cfg, ov, sink)
	if !first.blocked(t, "billing") {
		t.Fatal("the seeded extra term was not in force before the edit")
	}
	if err := first.svc.RemoveBlocklistTerm(ctx, activeAdminID, "billing"); err != nil {
		t.Fatalf("RemoveBlocklistTerm: %v", err)
	}

	second := boot(t, cfg, ov, sink)
	if second.blocked(t, "billing") {
		t.Error("the removed blocklist term was restored by the seed after a restart")
	}
}

// TestSeedCannotResurrectARemovedEntry is the explicit answer to "what happens
// when a seed file gains an entry that was previously removed at runtime".
//
// The tombstone wins. This is asserted rather than left incidental because the
// alternative is the resurrection bug arriving through a config change instead
// of through a restart: an operator editing a seed file must not be able to
// silently reverse another administrator's audited removal. Undoing it requires
// an audited runtime addition, which names who decided it.
func TestSeedCannotResurrectARemovedEntry(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ov := newFakeOverrides()
	sink := &recordingSink{}

	// The entry starts in the seed and is removed at runtime.
	before := config.BlocklistConfig{AllowEntries: []string{"Admin"}}
	first := boot(t, before, ov, sink)
	if err := first.svc.RemoveAllowlistEntry(ctx, activeAdminID, "Admin"); err != nil {
		t.Fatalf("RemoveAllowlistEntry: %v", err)
	}

	// The operator now re-adds it to the seed, in a different spelling that
	// folds to the same skeleton -- the confusable case a raw-string comparison
	// would miss.
	after := config.BlocklistConfig{AllowEntries: []string{"Admin", "adm1n"}}
	second := boot(t, after, ov, sink)
	if !second.blocked(t, "Admin") {
		t.Error("FAIL-OPEN: a seed entry resurrected a runtime-removed allowlist entry")
	}
	if !second.blocked(t, "adm1n") {
		t.Error("FAIL-OPEN: a confusable seed spelling resurrected a runtime-removed allowlist entry")
	}
}

// TestSeedFileCannotResurrectARemovedEntry drives the same property through an
// on-disk seed file rather than inline config, since that is the surface an
// operator actually edits between restarts.
func TestSeedFileCannotResurrectARemovedEntry(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ov := newFakeOverrides()
	sink := &recordingSink{}

	path := filepath.Join(t.TempDir(), "seed.yaml")
	write := func(body string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatalf("write seed file: %v", err)
		}
	}

	write("allow_entries:\n  - Admin\n")
	cfg := config.BlocklistConfig{SeedFile: path}
	first := boot(t, cfg, ov, sink)
	if first.blocked(t, "Admin") {
		t.Fatal("the seeded allowlist entry was not in force before the edit")
	}
	if err := first.svc.RemoveAllowlistEntry(ctx, activeAdminID, "Admin"); err != nil {
		t.Fatalf("RemoveAllowlistEntry: %v", err)
	}

	// The file still lists the entry, as it would after an operator edit.
	write("allow_entries:\n  - Admin\n  - root\n")
	second := boot(t, cfg, ov, sink)
	if !second.blocked(t, "Admin") {
		t.Error("FAIL-OPEN: a seed file entry resurrected a runtime-removed allowlist entry")
	}
	// The unrelated new entry in the same file still takes effect, so the
	// tombstone is narrow rather than poisoning the whole file.
	if second.blocked(t, "root") {
		t.Error("the tombstone suppressed an unrelated seed entry")
	}
}

// TestAuditRecordMatchesPostRestartReality is the invariant that ties the two
// halves together: the record must describe policy that is actually in force
// after a restart. A removal recorded but not enforced is worse than an
// unrecorded one, because a reviewer reading the log would believe the hole was
// closed.
func TestAuditRecordMatchesPostRestartReality(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	cfg := config.BlocklistConfig{AllowEntries: []string{"Admin"}}
	ov := newFakeOverrides()
	sink := &recordingSink{}

	first := boot(t, cfg, ov, sink)
	if err := first.svc.RemoveAllowlistEntry(ctx, activeAdminID, "Admin"); err != nil {
		t.Fatalf("RemoveAllowlistEntry: %v", err)
	}

	records := sink.all()
	if len(records) != 1 {
		t.Fatalf("audit sink holds %d records, want 1", len(records))
	}
	rec := records[0]
	if rec.Action != domain.AuditActionAllowlistEntryRemoved {
		t.Errorf("audit action = %q, want %q", rec.Action, domain.AuditActionAllowlistEntryRemoved)
	}
	if rec.TargetID != "Admin" {
		t.Errorf("audit target = %q, want the raw spelling %q", rec.TargetID, "Admin")
	}

	// The log says the exemption was removed. After a restart it must still be
	// removed, or the log is describing a policy nobody is enforcing.
	second := boot(t, cfg, ov, sink)
	if !second.blocked(t, "Admin") {
		t.Error("the audit log records a removal that is not in force after a restart")
	}

	// The persisted decision names the same administrator the audit record
	// does, so a reviewer can reconcile the two without joining on time.
	o, ok := ov.get(domain.ListKindAllowlist, "Admin")
	if !ok {
		t.Fatal("no override was persisted for the removal")
	}
	if o.State != domain.ListOverrideRemoved {
		t.Errorf("persisted state = %q, want %q", o.State, domain.ListOverrideRemoved)
	}
	if string(o.ActorID) != rec.ActorID {
		t.Errorf("persisted actor = %q, audit actor = %q; want the same administrator",
			o.ActorID, rec.ActorID)
	}
	if !o.UpdatedAt.Equal(testNow) {
		t.Errorf("persisted UpdatedAt = %v, want the service clock %v", o.UpdatedAt, testNow)
	}
}

// TestEditIsRefusedWhenItCannotBePersisted pins the fail-closed write boundary.
//
// An edit applied in memory but never recorded would silently revert at the
// next restart while the audit log claimed it happened. Refusing outright makes
// that divergence unreachable rather than merely detectable: an edit that
// cannot be recorded is an edit that did not happen.
func TestEditIsRefusedWhenItCannotBePersisted(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	cfg := config.BlocklistConfig{AllowEntries: []string{"Admin"}}
	ov := newFakeOverrides()
	sink := &recordingSink{}

	d := boot(t, cfg, ov, sink)
	ov.putErr = errors.New("database unavailable")

	err := d.svc.RemoveAllowlistEntry(ctx, activeAdminID, "Admin")
	if err == nil {
		t.Fatal("the edit was accepted although it could not be persisted")
	}
	// The in-memory policy is untouched, so it still agrees with the durable
	// record: both say the exemption stands.
	if d.blocked(t, "Admin") {
		t.Error("the edit was applied in memory despite failing to persist, " +
			"leaving the live policy ahead of the durable record")
	}
}

// TestLoadPolicyRefusesWithoutAnOverrideRepository pins that seed-only
// composition cannot be reached by omitting an argument. Composing from the
// seed alone IS the bug, so it must not be the accidental default.
func TestLoadPolicyRefusesWithoutAnOverrideRepository(t *testing.T) {
	t.Parallel()
	m, err := blocklist.NewMatcher()
	if err != nil {
		t.Fatalf("NewMatcher: %v", err)
	}
	if err := LoadPolicy(context.Background(), m, config.BlocklistConfig{}, nil); err == nil {
		t.Error("LoadPolicy composed a policy with no override repository")
	}
}

func TestLoadPolicyRefusesANilMatcher(t *testing.T) {
	t.Parallel()
	err := LoadPolicy(context.Background(), nil, config.BlocklistConfig{}, newFakeOverrides())
	if err == nil {
		t.Error("LoadPolicy accepted a nil matcher")
	}
}

// failingOverrides reports an error from List, standing in for a database that
// is unreachable at boot.
type failingOverrides struct{ *fakeOverrides }

func (f failingOverrides) List(context.Context) ([]domain.ListOverride, error) {
	return nil, errors.New("database unavailable")
}

// TestLoadPolicyAbortsWhenOverridesCannotBeRead pins that a read failure stops
// startup instead of falling back to the seed. A fallback would be the
// resurrection bug reached through an error path: a database hiccup at boot
// must not quietly re-open a hole an administrator closed.
func TestLoadPolicyAbortsWhenOverridesCannotBeRead(t *testing.T) {
	t.Parallel()
	m, err := blocklist.NewMatcher(blocklist.List{
		Name: "impersonation", Mode: blocklist.MatchWholeSkeleton, Terms: []string{"admin"}})
	if err != nil {
		t.Fatalf("NewMatcher: %v", err)
	}

	cfg := config.BlocklistConfig{AllowEntries: []string{"Admin"}}
	err = LoadPolicy(context.Background(), m, cfg, failingOverrides{newFakeOverrides()})
	if err == nil {
		t.Fatal("LoadPolicy succeeded although the overrides could not be read")
	}
	// Nothing was installed, so the matcher did not silently acquire the
	// seed's exemptions on the way out.
	if len(m.Allowlist()) != 0 {
		t.Errorf("allowlist = %v after a failed load, want nothing installed", m.Allowlist())
	}
}

// TestLoadPolicyWithNoOverridesMatchesTheSeed pins that replay is a no-op when
// nothing was ever edited, so adding this machinery did not change what a fresh
// deployment enforces.
func TestLoadPolicyWithNoOverridesMatchesTheSeed(t *testing.T) {
	t.Parallel()
	cfg := config.BlocklistConfig{
		AllowEntries: []string{"Admin"},
		ExtraEntries: []string{"billing"},
	}

	seeded, err := blocklist.NewMatcher()
	if err != nil {
		t.Fatalf("NewMatcher: %v", err)
	}
	if err := ApplySeed(seeded, cfg); err != nil {
		t.Fatalf("ApplySeed: %v", err)
	}

	composed, err := blocklist.NewMatcher()
	if err != nil {
		t.Fatalf("NewMatcher: %v", err)
	}
	if err := LoadPolicy(context.Background(), composed, cfg, newFakeOverrides()); err != nil {
		t.Fatalf("LoadPolicy: %v", err)
	}

	if got, want := composed.Allowlist(), seeded.Allowlist(); !equalStrings(got, want) {
		t.Errorf("allowlist = %v, want the seed's %v", got, want)
	}
	if got, want := composed.ExtraTerms(), seeded.ExtraTerms(); !equalStrings(got, want) {
		t.Errorf("extra terms = %v, want the seed's %v", got, want)
	}
}

// TestReAddingAfterARemovalTakesEffectAcrossARestart pins the documented way to
// undo a tombstone: an audited runtime addition, not a seed edit.
func TestReAddingAfterARemovalTakesEffectAcrossARestart(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	cfg := config.BlocklistConfig{AllowEntries: []string{"Admin"}}
	ov := newFakeOverrides()
	sink := &recordingSink{}

	first := boot(t, cfg, ov, sink)
	if err := first.svc.RemoveAllowlistEntry(ctx, activeAdminID, "Admin"); err != nil {
		t.Fatalf("RemoveAllowlistEntry: %v", err)
	}

	second := boot(t, cfg, ov, sink)
	if err := second.svc.AddAllowlistEntry(ctx, activeAdminID, "Admin"); err != nil {
		t.Fatalf("AddAllowlistEntry: %v", err)
	}

	third := boot(t, cfg, ov, sink)
	if third.blocked(t, "Admin") {
		t.Error("an audited re-addition did not survive the restart")
	}
}

// TestReplayDoesNotDuplicateASeededEntry pins that a present override matching a
// seed entry composes to one entry. Two entries sharing a skeleton are refused
// by the setters, so a duplicate would fail the whole install rather than being
// harmlessly ignored.
func TestReplayDoesNotDuplicateASeededEntry(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ov := newFakeOverrides()
	sink := &recordingSink{}

	// Added at runtime while absent from the seed...
	first := boot(t, config.BlocklistConfig{}, ov, sink)
	if err := first.svc.AddAllowlistEntry(ctx, activeAdminID, "Admin"); err != nil {
		t.Fatalf("AddAllowlistEntry: %v", err)
	}

	// ...then the operator adds the same entry to the seed as well.
	cfg := config.BlocklistConfig{AllowEntries: []string{"Admin"}}
	second := boot(t, cfg, ov, sink)
	if got := second.matcher.Allowlist(); len(got) != 1 {
		t.Errorf("allowlist = %v, want exactly one entry", got)
	}
}

// TestLoadPolicyRefusesAMalformedSeed covers the other direction of the abort
// rule: LoadPolicy must fail startup on an unreadable seed exactly as ApplySeed
// does, and must not install the overrides on their own. Replaying tombstones
// over a seed that never loaded would compose a policy from half its inputs --
// an operator would see their runtime edits in force and silently lose every
// term the seed file was supposed to block.
func TestLoadPolicyRefusesAMalformedSeed(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	ov := newFakeOverrides()
	if err := ov.Put(ctx, &domain.ListOverride{
		List:      domain.ListKindBlocklistTerm,
		Skeleton:  blocklist.Skeleton("runtime"),
		Entry:     "runtime",
		State:     domain.ListOverridePresent,
		ActorID:   activeAdminID,
		UpdatedAt: testNow,
	}); err != nil {
		t.Fatalf("seed the override: %v", err)
	}

	m := seedMatcher(t)
	path := writeSeed(t, "extra_entries:\n  - good\n  - [unclosed\n")

	err := LoadPolicy(ctx, m, config.BlocklistConfig{SeedFile: path}, ov)
	if err == nil {
		t.Fatal("LoadPolicy accepted a malformed seed file")
	}
	if !strings.Contains(err.Error(), "parse blocklist seed file") {
		t.Errorf("error = %v, want it to mention the seed parse failure", err)
	}

	if got := m.ExtraTerms(); len(got) != 0 {
		t.Errorf("extra terms = %v after a failed load, want none applied", got)
	}
	if got := m.Allowlist(); len(got) != 0 {
		t.Errorf("allowlist = %v after a failed load, want none applied", got)
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
