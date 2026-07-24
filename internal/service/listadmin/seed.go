package listadmin

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"

	"gopkg.in/yaml.v3"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/blocklist"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/config"
)

// maxSeedFileBytes bounds a seed file. The file is operator-supplied and read
// at startup, so the bound is not about ordinary files being large; it is so a
// wrong path pointed at a huge or endless file fails fast with a clear error
// instead of exhausting memory before the service has started.
const maxSeedFileBytes = 1 << 20 // 1 MiB

// seedFile is the on-disk seed document. Its keys mirror the blocklist section
// of the main configuration, so an operator moving entries from one to the
// other does not have to rewrite them.
type seedFile struct {
	ExtraEntries []string `yaml:"extra_entries"`
	AllowEntries []string `yaml:"allow_entries"`
}

// ApplySeed loads the configured seed file, merges it with the entries given
// inline in the configuration, and installs the result on m.
//
// # Seeding is a trust boundary and this function fails loudly
//
// The seed file decides which identifiers the service will refuse and, through
// the allowlist, which it will stop refusing. A file that is missing,
// unreadable, malformed, or carries an entry the engine cannot compile is a
// deployment that nobody has actually reviewed the policy of, so every one of
// those is an error the caller is expected to treat as fatal at startup.
//
// A parse error must never yield an empty or partial list. Empty would be worst
// for the extra terms -- the service would start with less blocking than the
// operator wrote down and no indication of it -- and partial would be worst for
// the allowlist, because the holes that happened to parse before the failure
// would be open and nobody chose that set. Both are avoided the same way: the
// whole document is read, both lists are compiled against a scratch matcher,
// and nothing is installed on m until every entry in both lists is known to be
// good.
//
// An empty SeedFile path means no file, which is valid: a deployment may
// legitimately configure its entries inline or carry none at all.
// ApplySeed installs the seed ALONE, with no persisted runtime edits replayed
// over it.
//
// Production startup must call LoadPolicy instead. Seeding without replaying
// the overrides re-opens exactly the gap the override table exists to close: a
// removal an administrator made at runtime is not in the seed, so seed-only
// composition silently restores the entry they removed. For the allowlist that
// direction is fail-open. This function remains because a caller may
// legitimately want the seed by itself -- validating an operator's file, or
// composing the base a replay is then applied to -- and because LoadPolicy is
// built from the same parts.
func ApplySeed(m *blocklist.Matcher, cfg config.BlocklistConfig) error {
	if m == nil {
		return fmt.Errorf("listadmin: seed applied to a nil matcher")
	}

	extra, allow, err := seedLists(cfg)
	if err != nil {
		return err
	}
	return install(m, extra, allow)
}

// seedLists resolves the seed into its two lists without touching any matcher,
// so a caller that needs to compose something over the seed can obtain it
// without a partially-installed intermediate state.
func seedLists(cfg config.BlocklistConfig) (extra, allow []string, err error) {
	extra = cfg.ExtraEntries
	allow = cfg.AllowEntries

	if cfg.SeedFile != "" {
		fromFile, ferr := readSeedFile(cfg.SeedFile)
		if ferr != nil {
			return nil, nil, ferr
		}
		// Config-inline entries first, then the file's, so a listing reads in a
		// predictable order. Neither source overrides the other: both are
		// operator intent and the union is what was asked for. A duplicate
		// between them is refused on install rather than silently collapsed, so
		// an operator who has the same entry in two places is told about it.
		extra = append(append([]string{}, extra...), fromFile.ExtraEntries...)
		allow = append(append([]string{}, allow...), fromFile.AllowEntries...)
	}
	return extra, allow, nil
}

// install validates both lists against a throwaway matcher before touching m.
//
// This is what makes the operation all-or-nothing across the two lists:
// installing the extra terms and then discovering the allowlist is malformed
// would leave m in a state that is neither the old policy nor the new one.
func install(m *blocklist.Matcher, extra, allow []string) error {
	scratch, err := blocklist.NewMatcher()
	if err != nil {
		return fmt.Errorf("listadmin: build a scratch matcher to validate the policy: %w", err)
	}
	if err := applyBoth(scratch, extra, allow); err != nil {
		return err
	}
	return applyBoth(m, extra, allow)
}

// applyBoth installs the two lists on m, extra terms first.
//
// The order matters only for the failure case, and only on the scratch matcher
// where a failure is expected: validating the terms before the exemptions means
// a malformed document is reported against the list that is easier to get
// wrong. On m both are already known to compile.
func applyBoth(m *blocklist.Matcher, extra, allow []string) error {
	if err := m.SetExtraTerms(extra); err != nil {
		return fmt.Errorf("listadmin: seed blocklist terms: %w", err)
	}
	if err := m.SetAllowlist(allow); err != nil {
		return fmt.Errorf("listadmin: seed allowlist entries: %w", err)
	}
	return nil
}

// readSeedFile reads and strictly decodes the seed document.
//
// Decoding is strict about unknown keys, matching the main configuration
// loader. A typo'd key is a policy the operator believes is in force and is
// not, which is precisely the silent failure this whole function exists to
// prevent -- an "allow_entires" that decodes to nothing would leave every name
// the operator meant to permit still refused, or worse, a mistyped
// "extra_entries" would leave names they meant to refuse still available.
func readSeedFile(path string) (*seedFile, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("listadmin: open blocklist seed file: %w", err)
	}
	defer func() { _ = f.Close() }()

	// Bound the read before decoding, so an oversized file is refused rather
	// than consumed.
	limited := io.LimitReader(f, maxSeedFileBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("listadmin: read blocklist seed file: %w", err)
	}
	if len(data) > maxSeedFileBytes {
		return nil, fmt.Errorf("listadmin: blocklist seed file %s exceeds %d bytes", path, maxSeedFileBytes)
	}

	var out seedFile
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&out); err != nil {
		// An empty file decodes to io.EOF and is valid: it carries no entries,
		// which is a policy an operator may legitimately have written down.
		if errors.Is(err, io.EOF) {
			return &seedFile{}, nil
		}
		return nil, fmt.Errorf("listadmin: parse blocklist seed file %s: %w", path, err)
	}

	// A second document in the stream is refused. YAML permits several per
	// file, and silently honoring only the first would let an operator's later
	// edits sit in a file the service never reads.
	var extraDoc seedFile
	if err := dec.Decode(&extraDoc); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf(
			"listadmin: blocklist seed file %s holds more than one document", path)
	}

	return &out, nil
}
