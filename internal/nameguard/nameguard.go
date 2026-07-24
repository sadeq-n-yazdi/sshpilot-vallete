// Package nameguard is the single choke point every user-chosen identifier
// must pass before it is created or renamed into (ADR-0017, Fb4).
//
// # Why one package rather than a check at each call site
//
// The blocklist engine in internal/blocklist is only worth what its callers
// enforce; an engine nothing calls is a policy nobody has. The failure mode a
// scattered check invites is drift: five call sites agree on the day they are
// written and disagree a year later, and the one that drifted is the one an
// attacker finds. Concentrating the decision here means there is exactly one
// place to audit and exactly one place a future create or rename path has to
// be wired into.
//
// # What a check is
//
// A check is a syntax verdict followed by a blocklist verdict, in that order.
// Both must pass. Callers get an error or nil; they are never handed the
// blocklist Result, so no caller can accidentally render which curated term
// fired (see blocklist.Result).
//
// # Fail closed
//
// Every path that cannot reach a definite "allowed" refuses: a nil Guard, a
// nil or unbuilt matcher, an unknown Kind, an unknown Op. This direction is
// not a style preference. An identifier is claimed once and then lives
// indefinitely in a global namespace, so a name let through during a
// transient fault is not recoverable the way a dropped request is -- there is
// no retry that un-claims it, and the owner who now holds "support" has a URL
// other people have already saved. Refusing during a fault costs a legitimate
// user one retry.
package nameguard

import (
	"fmt"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/blocklist"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
)

// Kind selects which syntax rule applies to an identifier. The blocklist
// applies to every Kind; only the syntax rule differs.
type Kind uint8

const (
	// KindInvalid is the zero value and is always refused, so a Kind left
	// unset by a caller cannot be mistaken for a real identifier class.
	KindInvalid Kind = iota

	// KindHandle is a handle: the global, publicly routable name (ADR-0004).
	KindHandle

	// KindKeySetName is a key-set name, the second segment of
	// /{handle}/{set} (ADR-0016).
	KindKeySetName

	// KindDeviceName is a device's display label (ADR-0017 includes device
	// names).
	//
	// Both device create paths are now wired: device.Service.Register (the
	// HTTP-reachable one) and bootstrap.AddKey (the CLI one). The seam this
	// comment used to describe is closed.
	//
	// Device names are the Kind where confusable folding earns the most:
	// unlike handles and set names, they permit non-ASCII, so a homoglyph
	// reaches the blocklist here instead of being stopped by the charset rule.
	KindDeviceName
)

// String names the Kind for logs. It never contains user input.
func (k Kind) String() string {
	switch k {
	case KindHandle:
		return "handle"
	case KindKeySetName:
		return "set name"
	case KindDeviceName:
		return "device name"
	case KindInvalid:
		return "invalid"
	default:
		return "unknown"
	}
}

// Op is the operation an identifier is being checked for.
//
// The verdict does not depend on Op -- a name blocked at create is blocked at
// rename, and any rule that differed between them would be a way to land on a
// blocked name by creating a permitted one first and renaming afterwards. Op
// exists so the call site states which path it is, so that an audit record and
// a reviewer can both tell create from rename, and so that a rename path that
// forgot to call this package is visible by the absence of an OpRename caller.
type Op uint8

const (
	// OpInvalid is the zero value and is always refused.
	OpInvalid Op = iota
	// OpCreate is claiming a name that the actor does not yet hold.
	OpCreate
	// OpRename is moving an existing entity onto a different name. It is
	// checked identically to OpCreate; see Op.
	OpRename
)

// String names the Op for logs.
func (o Op) String() string {
	switch o {
	case OpCreate:
		return "create"
	case OpRename:
		return "rename"
	case OpInvalid:
		return "invalid"
	default:
		return "unknown"
	}
}

// Guard holds the compiled blocklist and answers checks. It is immutable after
// New and safe for concurrent use, because blocklist.Matcher is.
type Guard struct {
	matcher *blocklist.Matcher
}

// New returns a Guard backed by the given matcher.
//
// A nil matcher is accepted rather than rejected, and yields a Guard that
// refuses everything. That is deliberate: the alternative is returning an
// error a caller might ignore and then proceed with no guard at all, which is
// the bypass this package exists to prevent. A useless Guard is safe; a
// missing one is not.
func New(m *blocklist.Matcher) *Guard { return &Guard{matcher: m} }

// Default returns a Guard over the default curated lists (blocklist.DefaultLists).
//
// It returns an error only if the built-in lists fail to compile, which is a
// programming error in the list data rather than a runtime condition. A caller
// that gets an error MUST NOT proceed with a nil Guard -- but if it does, the
// nil Guard still refuses; see Check.
func Default() (*Guard, error) { return newFrom(blocklist.DefaultMatcher) }

// newFrom builds a Guard from a matcher constructor. It exists so the failure
// path -- unreachable through Default, because the built-in lists are known to
// compile -- is still exercised by a test. The invariant it protects is that a
// build failure yields NO guard: returning a half-built one alongside an error
// would let a caller that ignores the error proceed with something that looks
// usable.
func newFrom(build func() (*blocklist.Matcher, error)) (*Guard, error) {
	m, err := build()
	if err != nil {
		return nil, fmt.Errorf("nameguard: build matcher: %w", err)
	}
	return &Guard{matcher: m}, nil
}

// Check reports whether name may be used as the given Kind for the given Op.
// It returns nil only when the name is both syntactically valid and permitted
// by the blocklist.
//
// # Order: syntax first, then blocklist
//
// Both rules must pass, so the order cannot create a bypass; it is chosen for
// two other reasons. A malformed name deserves the specific syntax error that
// tells the user what to fix, whereas a well-formed but blocked name must get
// the deliberately vague "unavailable" answer -- checking syntax first is what
// keeps those two messages from being swapped. It also means the skeleton is
// only computed for input that already passed a length and charset bound,
// rather than for arbitrary attacker-supplied bytes.
//
// # Errors
//
// A syntax failure wraps domain.ErrInvalidInput and describes the rule. A
// blocklist refusal wraps domain.ErrBlockedName and carries only
// blocklist.Result.PublicMessage -- never the matched term, the list it came
// from, the match mode, or the skeleton. The blocklist is a moving target, and
// an error that named the rule would let an attacker enumerate the curated
// impersonation list one rejected registration at a time.
//
// BOUNDARY OBLIGATION: domain.ErrBlockedName is distinguishable from
// domain.ErrConflict in Go, which is what an audit record needs. A transport
// layer MUST render the two identically, so that "reserved" and "already
// taken" are indistinguishable to the user; otherwise the API tells an
// attacker which names are being held back.
func (g *Guard) Check(k Kind, op Op, name string) error {
	// A nil Guard means a caller was constructed without one. Refuse rather
	// than no-op: a no-op nil receiver would turn "forgot to wire the guard"
	// into a silent, total bypass that no test of a wired path would catch.
	if g == nil {
		return fmt.Errorf("nameguard: no guard configured: %w", domain.ErrBlockedName)
	}
	if op != OpCreate && op != OpRename {
		return fmt.Errorf("nameguard: unknown operation %d: %w", op, domain.ErrInvalidInput)
	}
	if err := validateSyntax(k, name); err != nil {
		return err
	}

	// The matcher checks the normalized skeleton, not the raw string; that is
	// the entire point of the Fb1 normalization, and it is why "adm1n" and
	// "ad-min" are refused when "admin" is blocked. The result is consulted
	// through Blocked(), whose zero value is "blocked", so a Result that some
	// future refactor forgets to populate still refuses.
	res := g.matcher.Check(name)
	if res.Blocked() {
		return fmt.Errorf("nameguard: %s: %s: %w", k, res.PublicMessage(), domain.ErrBlockedName)
	}
	return nil
}

// validateSyntax applies the Kind's charset and length rule, reusing the
// domain validators so that "valid" and "not blocked" are judged against the
// same definition of an identifier that the rest of the system uses. An
// unknown Kind is refused; a new identifier class must opt in here explicitly
// rather than inherit whichever rule happens to be first.
func validateSyntax(k Kind, name string) error {
	switch k {
	case KindHandle:
		return domain.ValidateHandle(name)
	case KindKeySetName:
		return domain.ValidateSetName(name)
	case KindDeviceName:
		return domain.ValidateDeviceName(name)
	case KindInvalid:
		return fmt.Errorf("nameguard: identifier kind not set: %w", domain.ErrInvalidInput)
	default:
		return fmt.Errorf("nameguard: unknown identifier kind %d: %w", k, domain.ErrInvalidInput)
	}
}
