package main

import (
	"context"
	"fmt"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/blocklist"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/config"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/nameguard"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/repository"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/service/listadmin"
)

// namePolicy is the composed reserved-identifier policy in force for this
// process: one blocklist.Matcher and a nameguard.Guard built over it.
//
// # Why the matcher and the guard travel together
//
// The whole point of Fb4 is that the enforcement choke point and the runtime
// editor act on the SAME matcher. nameguard.Guard reads the matcher on every
// Check; listadmin.Service edits it through the matcher's own atomic swappers
// (SetAllowlist/SetExtraTerms). Because those swaps store through a pointer the
// Guard already holds, a runtime edit reaches the Guard with no re-wiring --
// see blocklist.Matcher.SetAllowlist for the pointer-stability contract this
// relies on. Handing both out from one constructor is what keeps a caller from
// accidentally giving the guard one matcher and the editor another, which would
// silently reopen the disconnected-matcher seam (#36) this closes.
//
// Matcher is exported on the struct so the composition root can hand the SAME
// instance to listadmin.New; Guard is what every create/rename path consults.
type namePolicy struct {
	Matcher *blocklist.Matcher
	Guard   *nameguard.Guard
}

// newNamePolicy composes the reserved-identifier lists that are actually in
// force -- the curated defaults, the operator's seed, and the durable runtime
// overrides replayed over it -- and returns the shared matcher plus a guard
// over it.
//
// It fails startup rather than degrading. A matcher that cannot be built, a
// seed that cannot be read, or overrides that cannot be replayed each leave the
// policy in a state nobody reviewed; the one direction that must never happen
// silently is a guard enforcing less than the operator wrote down, so every one
// of those is a fatal error here. LoadPolicy -- not ApplySeed -- is used on
// purpose: seeding without replaying the overrides would resurrect an entry an
// administrator removed at runtime, which for the allowlist is the fail-open
// direction (see listadmin.LoadPolicy).
func newNamePolicy(
	ctx context.Context, cfg *config.Config, overrides repository.ListOverrideRepository,
) (*namePolicy, error) {
	// A FRESH matcher over the curated lists, not blocklist.DefaultMatcher().
	// DefaultMatcher returns a process-wide singleton, and this matcher is
	// mutated at runtime through SetAllowlist/SetExtraTerms: installing the
	// operator seed and replaying overrides onto the shared singleton would
	// entangle this composed, editable policy with every other DefaultMatcher()
	// reader (nameguard.Default in the handle sweep, for one), so a runtime
	// admin edit here would silently change a matcher those readers hold. A
	// private matcher keeps the runtime-editable policy isolated to the guard
	// and the editor that share THIS instance.
	m, err := blocklist.NewMatcher(blocklist.DefaultLists()...)
	if err != nil {
		return nil, fmt.Errorf("name policy: build matcher: %w", err)
	}
	if err := listadmin.LoadPolicy(ctx, m, cfg.Blocklist, overrides); err != nil {
		return nil, fmt.Errorf("name policy: load composed lists: %w", err)
	}
	return &namePolicy{Matcher: m, Guard: nameguard.New(m)}, nil
}
