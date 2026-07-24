package listadmin

import (
	"context"
	"fmt"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/blocklist"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/config"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/repository"
)

// LoadPolicy composes the reserved-identifier lists that are actually in force
// and installs them on m. It is the startup entry point: the seed is the base,
// and the durable record of runtime edits is replayed over it.
//
// # Why replay exists at all
//
// Runtime edits live in the matcher's atomic.Value, which does not survive a
// restart. Without replay, every restart reverts to the seed, so an entry an
// administrator removed at runtime comes back while the audit log still records
// the removal -- the audit trail would describe a policy that is not in force.
// Removing an allowlist entry means re-blocking a term, so the resurrection
// re-permits an identifier somebody deliberately refused. That is fail-open,
// which is why replay is part of composition rather than an optional extra.
//
// # A nil repository is refused
//
// Composing from the seed alone is precisely the bug, so it cannot be reached
// by omitting an argument. A caller that genuinely wants the seed by itself
// calls ApplySeed and says so.
//
// # All-or-nothing
//
// Nothing is installed on m until the fully composed policy is known to
// compile, so a malformed override cannot leave the matcher holding a partial
// set of holes nobody approved.
func LoadPolicy(
	ctx context.Context,
	m *blocklist.Matcher,
	cfg config.BlocklistConfig,
	overrides repository.ListOverrideRepository,
) error {
	if m == nil {
		return fmt.Errorf("listadmin: policy loaded onto a nil matcher")
	}
	if overrides == nil {
		return fmt.Errorf("listadmin: policy load requires an override repository")
	}

	extra, allow, err := seedLists(cfg)
	if err != nil {
		return err
	}

	// A failed read aborts startup rather than falling back to the seed.
	// Falling back would be the resurrection bug reached through an error path
	// instead of a missing feature, and a database hiccup at boot must not
	// quietly re-open a hole an administrator closed.
	rows, err := overrides.List(ctx)
	if err != nil {
		return fmt.Errorf("listadmin: read the persisted list overrides: %w", err)
	}

	return install(m,
		replay(extra, rows, domain.ListKindBlocklistTerm),
		replay(allow, rows, domain.ListKindAllowlist))
}

// replay applies the overrides of one kind over that list's seed entries.
//
// # A tombstone outranks the seed
//
// This is the function's reason to exist. A removed entry is dropped from the
// composed list even when the seed supplies it, so a seed file that gains an
// entry somebody removed at runtime does NOT resurrect it. That outcome is
// deliberate and explicit rather than incidental: the alternative -- recording
// removals as absence and letting the seed refill them -- is the fail-open
// behavior this whole mechanism exists to eliminate. An operator who wants a
// tombstoned entry back adds it at runtime, which is audited and names who
// decided it; editing the seed file is not a way to reverse another
// administrator's removal without a record.
//
// Comparison is on the SKELETON throughout, because that is what the matcher
// enforces. Matching a tombstone by raw spelling would let a seed entry spelled
// "adm1n" survive a removal recorded for "admin", even though the two are one
// rule to the engine -- the hole would be reachable by exactly the confusable
// spellings the folding exists to catch.
//
// A present override that the seed already supplies is not appended twice: the
// setters refuse two entries sharing a skeleton, so a duplicate would fail the
// whole install rather than being harmlessly ignored.
func replay(seed []string, rows []domain.ListOverride, kind domain.ListKind) []string {
	tombstoned := make(map[string]bool)
	added := make(map[string]string)
	for _, o := range rows {
		if o.List != kind {
			continue
		}
		switch o.State {
		case domain.ListOverrideRemoved:
			tombstoned[o.Skeleton] = true
		case domain.ListOverridePresent:
			added[o.Skeleton] = o.Entry
		}
	}

	// Nothing to do, and returning seed unchanged keeps the no-override case
	// byte-identical to what ApplySeed would have installed.
	if len(tombstoned) == 0 && len(added) == 0 {
		return seed
	}

	out := make([]string, 0, len(seed)+len(added))
	present := make(map[string]bool, len(seed))
	for _, raw := range seed {
		sk := blocklist.Skeleton(raw)
		if tombstoned[sk] {
			continue
		}
		out = append(out, raw)
		present[sk] = true
	}

	// Appended in the repository's order, which is sorted by skeleton, so the
	// composed list is identical across calls, processes, and engines.
	for _, o := range rows {
		if o.List != kind || o.State != domain.ListOverridePresent {
			continue
		}
		if present[o.Skeleton] {
			continue
		}
		out = append(out, added[o.Skeleton])
		present[o.Skeleton] = true
	}
	return out
}
