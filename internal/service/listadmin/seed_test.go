package listadmin

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/blocklist"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/config"
)

// writeSeed writes a seed document to a temporary file and returns its path.
func writeSeed(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "seed.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write seed file: %v", err)
	}
	return path
}

// seedMatcher builds a matcher with one curated term, so a test can tell a
// seeded term apart from a shipped one.
func seedMatcher(t *testing.T) *blocklist.Matcher {
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

func TestApplySeedFromFile(t *testing.T) {
	t.Parallel()
	m := seedMatcher(t)

	path := writeSeed(t, `
extra_entries:
  - sadeq
allow_entries:
  - scunthorpe
`)
	if err := ApplySeed(m, config.BlocklistConfig{SeedFile: path}); err != nil {
		t.Fatalf("ApplySeed: %v", err)
	}

	if res := m.Check("sadeq"); !res.Blocked() {
		t.Error("a seeded blocklist term is not in force")
	}
	if res := m.Check("scunthorpe"); res.Blocked() {
		t.Error("a seeded allowlist entry is not in force")
	}
	// The curated list is untouched by seeding.
	if res := m.Check("admin"); !res.Blocked() {
		t.Error("seeding disabled a curated term")
	}
}

func TestApplySeedFromConfigWithoutAFile(t *testing.T) {
	t.Parallel()
	m := seedMatcher(t)

	err := ApplySeed(m, config.BlocklistConfig{
		ExtraEntries: []string{"sadeq"},
		AllowEntries: []string{"scunthorpe"},
	})
	if err != nil {
		t.Fatalf("ApplySeed: %v", err)
	}
	if res := m.Check("sadeq"); !res.Blocked() {
		t.Error("an inline blocklist term is not in force")
	}
	if res := m.Check("scunthorpe"); res.Blocked() {
		t.Error("an inline allowlist entry is not in force")
	}
}

func TestApplySeedMergesFileAndConfig(t *testing.T) {
	t.Parallel()
	m := seedMatcher(t)

	path := writeSeed(t, "extra_entries:\n  - fromfile\nallow_entries:\n  - allowfile\n")
	err := ApplySeed(m, config.BlocklistConfig{
		SeedFile:     path,
		ExtraEntries: []string{"fromconfig"},
		AllowEntries: []string{"allowconfig"},
	})
	if err != nil {
		t.Fatalf("ApplySeed: %v", err)
	}

	for _, term := range []string{"fromfile", "fromconfig"} {
		if res := m.Check(term); !res.Blocked() {
			t.Errorf("%q is not blocked; the two sources were not merged", term)
		}
	}
	for _, entry := range []string{"allowfile", "allowconfig"} {
		if res := m.Check(entry); res.Blocked() {
			t.Errorf("%q is blocked; the two allowlist sources were not merged", entry)
		}
	}
}

// TestMalformedSeedFileFailsWithoutApplyingAnything is the trust-boundary test.
// A malformed document must fail startup rather than leave the matcher holding
// a partial policy: the entries that happened to parse before the failure are a
// set nobody chose.
func TestMalformedSeedFileFailsWithoutApplyingAnything(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		content string
		wantIn  string
	}{
		{
			// Well-formed YAML up to the point it breaks, with a valid entry
			// first. A loader that applied as it parsed would leave "good"
			// installed.
			name:    "truncated document",
			content: "extra_entries:\n  - good\n  - [unclosed\n",
			wantIn:  "parse blocklist seed file",
		},
		{
			// A typo'd key is the dangerous case: it decodes to nothing, so a
			// permissive loader would start with a policy the operator believes
			// is in force and is not.
			name:    "unknown key",
			content: "extra_entires:\n  - good\n",
			wantIn:  "parse blocklist seed file",
		},
		{
			name:    "wrong type",
			content: "extra_entries: notalist\n",
			wantIn:  "parse blocklist seed file",
		},
		{
			// An entry with no comparable content cannot be compiled, and the
			// whole seed is refused rather than the entry being dropped.
			name:    "uncompilable entry",
			content: "extra_entries:\n  - good\n  - \"---\"\n",
			wantIn:  "seed blocklist terms",
		},
		{
			name:    "duplicate skeletons in the allowlist",
			content: "allow_entries:\n  - admin\n  - adm1n\n",
			wantIn:  "seed allowlist entries",
		},
		{
			// Several documents in one file: honoring only the first would let
			// an operator's later edits sit in a file nothing reads.
			name:    "multiple documents",
			content: "extra_entries:\n  - one\n---\nextra_entries:\n  - two\n",
			wantIn:  "more than one document",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			m := seedMatcher(t)
			path := writeSeed(t, tc.content)

			err := ApplySeed(m, config.BlocklistConfig{SeedFile: path})
			if err == nil {
				t.Fatal("ApplySeed accepted a malformed seed file")
			}
			if !strings.Contains(err.Error(), tc.wantIn) {
				t.Errorf("error = %v, want it to mention %q", err, tc.wantIn)
			}

			// Nothing may have been installed: not the entries that parsed, and
			// not a cleared list either.
			if got := m.ExtraTerms(); len(got) != 0 {
				t.Errorf("extra terms = %v after a failed seed, want none applied", got)
			}
			if got := m.Allowlist(); len(got) != 0 {
				t.Errorf("allowlist = %v after a failed seed, want none applied", got)
			}
			if res := m.Check("good"); res.Blocked() {
				t.Error("a failed seed partially applied its blocklist terms")
			}
		})
	}
}

// TestMalformedAllowlistDoesNotLeaveTermsApplied is the cross-list case for the
// same property. The extra terms compile and the allowlist does not; neither
// may be installed, or the matcher would hold a state that is neither the old
// policy nor the new one.
func TestMalformedAllowlistDoesNotLeaveTermsApplied(t *testing.T) {
	t.Parallel()
	m := seedMatcher(t)

	path := writeSeed(t, "extra_entries:\n  - sadeq\nallow_entries:\n  - admin\n  - adm1n\n")
	if err := ApplySeed(m, config.BlocklistConfig{SeedFile: path}); err == nil {
		t.Fatal("ApplySeed accepted a seed whose allowlist does not compile")
	}

	if got := m.ExtraTerms(); len(got) != 0 {
		t.Errorf("extra terms = %v, want none: the valid list must not be applied alone", got)
	}
	if res := m.Check("sadeq"); res.Blocked() {
		t.Error("the blocklist half of a failed seed took effect")
	}
}

func TestMissingSeedFileIsAnError(t *testing.T) {
	t.Parallel()
	m := seedMatcher(t)

	// A configured path that does not exist is a deployment mistake, not an
	// empty policy. Treating it as empty would start the service with no
	// blocklist additions and no indication anything was wrong.
	err := ApplySeed(m, config.BlocklistConfig{
		SeedFile: filepath.Join(t.TempDir(), "absent.yaml"),
	})
	if err == nil {
		t.Fatal("ApplySeed accepted a missing seed file")
	}
	if !strings.Contains(err.Error(), "open blocklist seed file") {
		t.Errorf("error = %v, want it to name the open step", err)
	}
}

func TestEmptySeedFileIsValid(t *testing.T) {
	t.Parallel()
	m := seedMatcher(t)

	// An empty file is a policy an operator may legitimately have written
	// down: no additions, no exemptions.
	if err := ApplySeed(m, config.BlocklistConfig{SeedFile: writeSeed(t, "")}); err != nil {
		t.Fatalf("ApplySeed on an empty file: %v", err)
	}
	if got := m.Allowlist(); len(got) != 0 {
		t.Errorf("allowlist = %v, want empty", got)
	}
	if res := m.Check("admin"); !res.Blocked() {
		t.Error("an empty seed disabled a curated term")
	}
}

func TestOversizedSeedFileIsRefused(t *testing.T) {
	t.Parallel()
	m := seedMatcher(t)

	// Built as a valid document so the refusal is attributable to the size
	// bound rather than to a parse failure.
	big := "extra_entries:\n" + strings.Repeat("  - "+strings.Repeat("a", 60)+"\n", 20000)
	if len(big) <= maxSeedFileBytes {
		t.Fatalf("test fixture is %d bytes, want more than %d", len(big), maxSeedFileBytes)
	}

	err := ApplySeed(m, config.BlocklistConfig{SeedFile: writeSeed(t, big)})
	if err == nil {
		t.Fatal("ApplySeed accepted an oversized seed file")
	}
	if !strings.Contains(err.Error(), "exceeds") {
		t.Errorf("error = %v, want it to name the size bound", err)
	}
}

func TestApplySeedRejectsANilMatcher(t *testing.T) {
	t.Parallel()
	if err := ApplySeed(nil, config.BlocklistConfig{}); err == nil {
		t.Error("ApplySeed accepted a nil matcher")
	}
}

func TestApplySeedRejectsAnUnbuiltMatcher(t *testing.T) {
	t.Parallel()
	// A matcher that never went through NewMatcher cannot hold a policy, and a
	// seed that silently did nothing would leave the operator believing the
	// service was configured.
	if err := ApplySeed(&blocklist.Matcher{}, config.BlocklistConfig{
		ExtraEntries: []string{"sadeq"},
	}); err == nil {
		t.Error("ApplySeed accepted an unbuilt matcher")
	}
}

// TestSeededAllowlistIsReplacedByRuntimeEdits pins how the two management
// levels compose: a seeded entry is ordinary list content that an administrator
// can then withdraw at runtime.
func TestSeededAllowlistIsReplacedByRuntimeEdits(t *testing.T) {
	t.Parallel()
	h := newHarness(t)

	if err := ApplySeed(h.matcher, config.BlocklistConfig{
		AllowEntries: []string{"admin"},
	}); err != nil {
		t.Fatalf("ApplySeed: %v", err)
	}
	if res := h.matcher.Check("admin"); res.Blocked() {
		t.Fatal("precondition failed: the seeded entry is not in force")
	}

	if err := h.svc.RemoveAllowlistEntry(t.Context(), activeAdminID, "admin"); err != nil {
		t.Fatalf("RemoveAllowlistEntry: %v", err)
	}
	if res := h.matcher.Check("admin"); !res.Blocked() {
		t.Error("a seeded entry survived an administrator's removal")
	}
}

// TestUnreadableSeedFileIsAnError covers the read failure that is distinct from
// the open failure: a directory opens successfully and then cannot be read.
func TestUnreadableSeedFileIsAnError(t *testing.T) {
	t.Parallel()
	m := seedMatcher(t)

	err := ApplySeed(m, config.BlocklistConfig{SeedFile: t.TempDir()})
	if err == nil {
		t.Fatal("ApplySeed accepted a directory as a seed file")
	}
	if got := m.ExtraTerms(); len(got) != 0 {
		t.Errorf("extra terms = %v after a failed read, want none", got)
	}
}
