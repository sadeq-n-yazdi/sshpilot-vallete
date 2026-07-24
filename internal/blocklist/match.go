package blocklist

import (
	"fmt"
	"strings"
	"sync/atomic"
)

// ListVersion identifies the revision of the default word lists in lists.go.
//
// It is deliberately SEPARATE from TableVersion. TableVersion says which
// identifiers compare equal; ListVersion says which of those comparisons the
// system refuses. The two change for different reasons and are reviewed by
// different criteria -- a folding-table edit is a Unicode judgment, a word-list
// edit is a policy judgment -- so collapsing them into one number would make an
// audit unable to tell which kind of change it is looking at. Adding, removing
// or re-categorizing a default term MUST bump this; touching the folding tables
// MUST NOT.
//
// Version 1: initial routing, impersonation and offensive lists.
const ListVersion = 1

// MaxInputBytes bounds the input Check will consider. Anything longer is
// refused without being examined.
//
// The bound exists for two reasons. The substring scan is O(terms x length),
// and while this runs at create/rename rather than per request, an unbounded
// input still lets an unauthenticated caller choose how much work the server
// does. The second reason is that it costs nothing: handles and key-set names
// are capped at 64 characters by their own validation, so 256 bytes is already
// several times any legitimate identifier and no real user can reach it.
//
// Callers SHOULD apply their own length validation first, so that an
// over-length identifier is reported as too long rather than as blocked.
const MaxInputBytes = 256

// MatchMode selects how a list's terms are compared against a skeleton.
//
// The zero value is invalid on purpose. A List that reaches NewMatcher without
// an explicitly chosen mode is a programming error, and guessing a default for
// it would silently pick a policy nobody reviewed.
type MatchMode uint8

const (
	// MatchModeInvalid is the unusable zero value; see MatchMode.
	MatchModeInvalid MatchMode = iota

	// MatchWholeSkeleton blocks only when the entire skeleton equals a term.
	//
	// This is the "whole-token" mode ADR-0017 requires for routing and
	// impersonation terms, and the reason it is spelled "whole skeleton" is the
	// single most important thing to understand about this package.
	//
	// Skeleton deletes separators entirely. "a-d-m-i-n", "a.d.m.i.n" and
	// "admin" all reduce to "admin", which means a skeleton has no interior
	// token boundaries left to find: by construction it is exactly one token.
	// "Whole-token match on the skeleton" and "whole-skeleton equality" are
	// therefore the same operation, and equality is the honest way to write it.
	//
	// Rejected alternative -- tokenize the ORIGINAL input on its separators and
	// skeletonize each token. It fails in both directions. Used alone it misses
	// the evasion the package exists to stop: "a-d-m-i-n" tokenizes to five
	// single letters, none of which is a term, so the padded spelling of the
	// reserved word sails through. Layered on top of whole-skeleton equality as
	// an extra candidate set it does catch that, but it then blocks every
	// legitimate hyphenated handle containing a reserved word as one component
	// -- "help-desk", "root-cause", "api-docs", "security-blog" -- and handles
	// are drawn from a-z, 0-9 and hyphen, so multi-component names are the
	// normal case, not an edge case. Over-blocking real users is the worse
	// failure (see tables.go), and the brief for this category calls substring
	// behavior here catastrophic for false positives. Equality gets every
	// must-block case right, because they all reduce to exactly the term, and
	// costs no token machinery at all.
	//
	// Known and accepted gap: "admin123" and "admin-support" reduce to
	// "admin123" and "adminsupport", neither of which equals "admin", so both
	// are permitted. Narrowing that is a policy change belonging to the runtime
	// list editing of Fb3 or the enforcement layer of Fb4, not to the match
	// mode. Splitting on letter/digit boundaries was considered as a middle
	// road and rejected: it would block "root2689", an ordinary identifier that
	// already appears as a fuzz seed.
	MatchWholeSkeleton

	// MatchSubstring blocks when a term appears anywhere inside the skeleton.
	//
	// This is the mode for offensive terms, where the harm is the word being
	// visible in a public URL at all; hiding it inside a longer name does not
	// make it less visible. The cost is the Scunthorpe problem, which is real
	// and which ADR-0017 answers with the administrator allowlist built in Fb3.
	// The defense available here is list curation: see lists.go, where terms
	// that are substrings of ordinary words are deliberately left out.
	MatchSubstring
)

// String renders the mode for logs. It names the mode only and never any term,
// so it is safe to include anywhere a Result is logged.
func (m MatchMode) String() string {
	switch m {
	case MatchWholeSkeleton:
		return "whole-skeleton"
	case MatchSubstring:
		return "substring"
	case MatchModeInvalid:
		return "invalid"
	default:
		return "unknown"
	}
}

// Reason records why Check returned the verdict it did.
type Reason uint8

const (
	// ReasonEngineUnavailable is the zero value, and it means blocked.
	//
	// Pairing the zero Reason with the zero Result -- which is also blocked,
	// see Result -- is what makes an uninitialized or partially-constructed
	// verdict fail closed instead of silently permitting the identifier.
	ReasonEngineUnavailable Reason = iota

	// ReasonAllowed: the skeleton matched no term in any list.
	ReasonAllowed

	// ReasonEmptySkeleton: the input reduced to nothing.
	//
	// Skeleton's contract requires callers to reject this rather than treat it
	// as matching no term. An identifier made entirely of separators, combining
	// marks or zero-width characters carries no comparable content, so no
	// blocklist can ever speak to it, and permitting it would let an attacker
	// register an identifier that no future list entry can reach.
	ReasonEmptySkeleton

	// ReasonTooLong: the input exceeded MaxInputBytes and was not examined.
	ReasonTooLong

	// ReasonBlockedTerm: the skeleton matched List/Term under Mode.
	ReasonBlockedTerm

	// ReasonTooAmbiguous: the skeleton held more ambiguous runes than
	// maxAmbiguousRunes, so the candidate set could not be built in full and
	// the identifier was refused unexamined.
	//
	// This is a fail-closed verdict and the direction is not arbitrary. The
	// engine cannot enumerate everything such an input might read as, so it
	// cannot show that none of those readings is a reserved word. Allowing it
	// would hand an attacker the bypass directly: pad an identifier with enough
	// ambiguous runes to blow the bound and it is permitted without ever being
	// compared. Refusing costs a legitimate user nothing, because no legitimate
	// identifier reaches the bound; see maxAmbiguousRunes.
	//
	// Appended after ReasonBlockedTerm on purpose: these values are recorded
	// alongside persisted decisions, so inserting one in the middle would
	// renumber the existing reasons and silently change what an old record
	// means.
	ReasonTooAmbiguous

	// ReasonAllowlisted: an administrator exempted this exact identifier, so
	// the blocklist was not consulted.
	//
	// It is a distinct reason from ReasonAllowed, not a reuse of it, because an
	// identifier that was permitted by a deliberate exemption and one that
	// simply matched no term are different facts about the system. The first is
	// a hole somebody opened and is accountable for; the second is the ordinary
	// case. An audit trail that rendered them identically could not answer
	// "which live identifiers exist only because of an allowlist entry?", which
	// is the question ADR-0017's flag-for-review process is built on.
	//
	// Appended last, for the renumbering reason given on ReasonTooAmbiguous.
	ReasonAllowlisted
)

// String renders the reason for logs. Like MatchMode.String it names no term.
func (r Reason) String() string {
	switch r {
	case ReasonAllowed:
		return "allowed"
	case ReasonEmptySkeleton:
		return "empty-skeleton"
	case ReasonTooLong:
		return "too-long"
	case ReasonBlockedTerm:
		return "blocked-term"
	case ReasonTooAmbiguous:
		return "too-ambiguous"
	case ReasonAllowlisted:
		return "allowlisted"
	case ReasonEngineUnavailable:
		return "engine-unavailable"
	default:
		return "unknown"
	}
}

// Result is the verdict for one identifier.
//
// # The field is Allowed, not Blocked
//
// This is a security decision, not a style one. The zero Result must mean
// "blocked", because a zero Result is what a caller holds after a path that
// forgot to assign one, after a struct built by a future refactor that missed a
// field, or after any decode that failed halfway. With a Blocked field the zero
// value would read as "not blocked" and every such mistake would become a
// silent bypass. With Allowed, every one of them fails closed.
//
// # Reporting without leaking the list
//
// List and Term say which curated entry fired. That is what an audit log and an
// administrator need, and it is exactly what an end user must not receive: the
// blocklist is a moving target an attacker would otherwise get to enumerate one
// rejected registration at a time. Result therefore deliberately has NO Error
// or String method. Nothing about it is safe to hand to fmt.Errorf("%v") or to
// return up an HTTP handler by accident; a caller wanting user-facing text must
// call PublicMessage and must reach past a field boundary to get anything more.
//
// Result also does not carry the skeleton. Skeletons are comparison-only and
// must never be stored or displayed, and the surest way to keep one out of a
// log line is to never put it in the value that gets logged.
type Result struct {
	// Allowed is true only when the identifier may be used.
	Allowed bool

	// Reason is why. Always set by Check.
	Reason Reason

	// List and Term are populated only when Reason is ReasonBlockedTerm. Term
	// is the curated list entry in its original human-readable spelling, never
	// the user's input and never a skeleton.
	List string
	Term string

	// Mode is the match mode that fired, set with List and Term.
	Mode MatchMode
}

// Blocked reports whether the identifier must be refused. It is the negation of
// Allowed and exists so calling code reads as a refusal check without anyone
// being tempted to add a Blocked field and reintroduce the zero-value problem
// described on Result.
func (r Result) Blocked() bool { return !r.Allowed }

// PublicMessage returns text safe to show the user who supplied the identifier.
//
// It is deliberately uninformative and identical for every blocked term. Saying
// which word matched, or even which category it came from, turns each rejected
// registration into one bit of the blocklist and lets an attacker map the list
// by brute force. Detail belongs in the audit log, from the Result fields.
func (r Result) PublicMessage() string {
	if r.Allowed {
		return "identifier is available"
	}
	return "this identifier is not available; please choose another"
}

// List is one curated set of terms sharing a match mode.
//
// Terms are held in their original, human-readable spelling and are skeletonized
// once by NewMatcher. Storing "admin" rather than its skeleton is what keeps
// lists.go reviewable -- a reviewer approving a policy change must be able to
// read the word being banned -- while comparison still happens skeleton against
// skeleton. It is also what lets Fb3 accept an administrator's term as typed.
//
// List is plain data with no behavior so that Fb3 can add an allowlist and
// runtime edits by supplying different Lists to NewMatcher, without the engine
// changing shape.
type List struct {
	// Name identifies the list in a Result and in audit records.
	Name string

	// Mode is how Terms are compared; see MatchMode.
	Mode MatchMode

	// Terms is ordered, and the order is part of the contract: see Matcher for
	// why determinism depends on it.
	Terms []string
}

// compiledTerm pairs a term's skeleton with the spelling to report.
type compiledTerm struct {
	skeleton string
	raw      string
}

// compiledList is a List with its skeletons precomputed.
type compiledList struct {
	name string
	mode MatchMode

	// whole indexes MatchWholeSkeleton terms by skeleton. A map is safe here
	// precisely because the lookup is equality: a given skeleton finds at most
	// one entry, so which entry is found cannot depend on iteration order. The
	// map is never ranged over.
	whole map[string]compiledTerm

	// substrings holds MatchSubstring terms in the order they were declared,
	// as a slice and never a map. Several terms can match one skeleton at
	// once, so the scan has to choose among them, and ranging a map to choose
	// would make the reported term vary run to run under Go's randomized map
	// iteration -- the blocked/allowed boolean would stay stable while the
	// audit record and the tests silently did not.
	substrings []compiledTerm
}

// Matcher checks identifiers against a fixed set of Lists.
//
// # Determinism
//
// The same input yields the same Result, including the same List and Term, on
// every run of every process. Lists are consulted in the order given to
// NewMatcher; within a list, whole-skeleton matching is an equality lookup with
// at most one answer and substring matching walks the declared term order and
// stops at the first hit. No map is ever iterated. This matters because the
// verdict is written to an audit log an administrator later reasons about; a
// record that names a different term each time it is regenerated is evidence of
// nothing.
//
// # Precedence
//
// Whole-skeleton lists are consulted before substring lists, regardless of the
// order they were supplied in. An identifier that is exactly a reserved word is
// most usefully reported as impersonation even if it happens to contain an
// offensive fragment too, and fixing the precedence means the report does not
// depend on how the caller happened to order its arguments.
//
// # Fail closed
//
// A Matcher that was not built by NewMatcher -- the zero value, or a nil
// pointer -- blocks everything. See Check.
//
// # Mutability
//
// A Matcher's LISTS are immutable after construction. Its ALLOWLIST is not:
// ADR-0017 gives an administrator a runtime allowlist for false positives, and
// that edit has to reach callers that already hold this *Matcher. The allowlist
// therefore lives behind an atomic pointer swapped by SetAllowlist, so the
// pointer identity of a Matcher never changes while its exemptions do. A
// Matcher is safe for concurrent use, including concurrent Check and
// SetAllowlist.
//
// A Matcher must not be copied after construction; the atomic pointer makes a
// copy meaningless. NewMatcher hands out a pointer for this reason.
type Matcher struct {
	// ready is set only by NewMatcher, and only after every list has been
	// validated. It is what distinguishes a usable Matcher from a zero one;
	// without it the zero Matcher would hold no lists, match nothing, and
	// therefore allow everything, which is the exact failure mode this package
	// must not have.
	ready bool

	lists []compiledList

	// allow holds the current compiled allowlist, or nil when none has been
	// set. Nil means NOTHING is exempt, which is why a matcher whose allowlist
	// failed to load behaves as though the allowlist were empty: an unavailable
	// allowlist must block more, never less. See allowlisted.
	allow atomic.Pointer[allowSet]

	// extra holds the administrator-added blocklist terms, or nil when none
	// have been set. Nil means the curated lists alone apply. See
	// SetExtraTerms.
	extra atomic.Pointer[compiledList]
}

// NewMatcher compiles lists into a Matcher, or reports why it cannot.
//
// Every term is skeletonized once here rather than on every check. The
// validation is strict and the errors are fatal by design: a malformed list is
// a bug in curated data or in an administrator's input, and the safe response
// is to refuse to build an engine whose behavior nobody can predict, not to
// build one that quietly ignores the bad entry.
//
// Refused, and why each would be dangerous rather than merely untidy:
//
//   - A list with no name, because a Result naming no list is unauditable.
//   - A mode outside the two defined ones, because there is no safe guess.
//   - Two lists sharing a name, because a Result could then not be traced back
//     to the entry that produced it.
//   - A term whose skeleton is empty. This one is the serious one: the empty
//     string is a substring of every string, so an empty-skeleton term in a
//     substring list blocks every identifier in the system, and in a
//     whole-skeleton list it blocks exactly the empty skeleton, which Check
//     already refuses on its own grounds. Neither is what an author writing
//     down a word intended.
//   - Two terms in one list sharing a skeleton, because they are the same term
//     to this engine and only one of them could ever be reported. Rejecting
//     forces the duplicate to be resolved in the data, where a reviewer can
//     see it, instead of one spelling silently shadowing the other.
//
// An empty list, or no lists at all, is accepted: a deployment may legitimately
// carry an empty allowlist, and Fb3 needs that to stay true.
func NewMatcher(lists ...List) (*Matcher, error) {
	compiled := make([]compiledList, 0, len(lists))
	seenNames := make(map[string]struct{}, len(lists))

	for _, l := range lists {
		if l.Name == "" {
			return nil, fmt.Errorf("blocklist: list has no name")
		}
		if _, dup := seenNames[l.Name]; dup {
			return nil, fmt.Errorf("blocklist: duplicate list name %q", l.Name)
		}
		seenNames[l.Name] = struct{}{}

		if l.Mode != MatchWholeSkeleton && l.Mode != MatchSubstring {
			return nil, fmt.Errorf("blocklist: list %q has invalid match mode %d", l.Name, l.Mode)
		}

		cl := compiledList{name: l.Name, mode: l.Mode}
		if l.Mode == MatchWholeSkeleton {
			cl.whole = make(map[string]compiledTerm, len(l.Terms))
		} else {
			cl.substrings = make([]compiledTerm, 0, len(l.Terms))
		}

		seenSkeletons := make(map[string]string, len(l.Terms))
		for _, raw := range l.Terms {
			sk := Skeleton(raw)
			if sk == "" {
				return nil, fmt.Errorf("blocklist: list %q term %q has an empty skeleton", l.Name, raw)
			}
			if prev, dup := seenSkeletons[sk]; dup {
				return nil, fmt.Errorf(
					"blocklist: list %q terms %q and %q share a skeleton", l.Name, prev, raw)
			}
			seenSkeletons[sk] = raw

			term := compiledTerm{skeleton: sk, raw: raw}
			if l.Mode == MatchWholeSkeleton {
				cl.whole[sk] = term
			} else {
				cl.substrings = append(cl.substrings, term)
			}
		}
		compiled = append(compiled, cl)
	}

	// Fix the precedence described on Matcher once, here, rather than on every
	// check. A stable partition keeps each mode's lists in the caller's
	// relative order, so the caller still controls ties within a mode.
	ordered := make([]compiledList, 0, len(compiled))
	for _, cl := range compiled {
		if cl.mode == MatchWholeSkeleton {
			ordered = append(ordered, cl)
		}
	}
	for _, cl := range compiled {
		if cl.mode == MatchSubstring {
			ordered = append(ordered, cl)
		}
	}

	return &Matcher{ready: true, lists: ordered}, nil
}

// Check returns the verdict for a user-supplied identifier.
//
// The input is the original string as the user typed it. Check does the
// skeletonising itself; callers must not pre-normalize, both because a skeleton
// is not something to be passed around and because doing it twice is exactly
// how a caller ends up comparing the wrong thing.
//
// Every path that is not a positive decision to allow returns blocked:
//
//   - a nil or unbuilt Matcher, so a wiring mistake refuses identifiers rather
//     than admitting them;
//   - input longer than MaxInputBytes, refused unexamined;
//   - input whose skeleton is empty, per Skeleton's contract;
//   - input too ambiguous to expand within maxAmbiguousRunes, refused because
//     the engine cannot enumerate what it might read as.
//
// The skeleton is not compared only as itself. Runes that draw a glyph with
// more than one reading are expanded into a set of candidate skeletons, and a
// match against ANY candidate blocks; see candidateSkeletons.
//
// Only a completed walk of every list against every candidate with no hit
// returns Allowed.
func (m *Matcher) Check(input string) Result {
	if m == nil || !m.ready {
		return Result{Allowed: false, Reason: ReasonEngineUnavailable}
	}
	if len(input) > MaxInputBytes {
		return Result{Allowed: false, Reason: ReasonTooLong}
	}

	skeleton := Skeleton(input)
	if skeleton == "" {
		return Result{Allowed: false, Reason: ReasonEmptySkeleton}
	}

	// The allowlist is consulted HERE, and the position is load-bearing in both
	// directions.
	//
	// It is after normalization because it must exempt the same form the
	// blocklist blocks. Comparing the raw input instead would let the exempted
	// set and the blocked set be different sets, and the difference would be
	// reachable by the confusable and leetspeak spellings the folding exists to
	// catch.
	//
	// It is after the length and empty-skeleton guards because those are
	// fail-closed refusals about the input being unexaminable, not policy
	// judgments about a word. An allowlist entry says "this identifier is not
	// the offensive word it looks like"; it does not say "skip the bounds".
	// Consulting the allowlist first would let an entry exempt an over-length
	// or empty-skeleton input from checks that exist to stop inputs no list can
	// ever speak to -- which is a bypass of the engine, not an exemption from a
	// term.
	//
	// It is before the candidate expansion because an exempted identifier must
	// not then be blocked by an alternative reading of itself; that is the
	// whole point of the entry. See allowlisted for why the expansion is not
	// applied to the allowlist lookup itself.
	if entry, exempt := m.allowlisted(skeleton); exempt {
		return Result{
			Allowed: true,
			Reason:  ReasonAllowlisted,
			List:    AllowlistName,
			Term:    entry,
		}
	}

	candidates, ok := candidateSkeletons(skeleton)
	if !ok {
		return Result{Allowed: false, Reason: ReasonTooAmbiguous}
	}

	// Administrator-added terms are consulted before the curated lists, so a
	// term added at runtime takes effect immediately and is reported under its
	// own list name. They are whole-skeleton, so they share the precedence the
	// Matcher documentation gives that mode; placing them first within it means
	// a runtime decision is the one reported when it overlaps a default.
	//
	// The candidate expansion applies here exactly as it does to the curated
	// lists: an administrator who blocks a word must get its evasive spellings
	// blocked too, or the entry would be worth less than the one in lists.go.
	if extra := m.extra.Load(); extra != nil {
		for _, candidate := range candidates {
			if term, hit := extra.whole[candidate]; hit {
				return blockedBy(*extra, term)
			}
		}
	}

	// Lists stay the outer loop, so the precedence documented on Matcher --
	// whole-skeleton lists before substring lists, caller order within a mode
	// -- is unchanged by the expansion. Candidates come next, ahead of the
	// terms, because candidates[0] is the skeleton itself: an exact match is
	// found and reported before any alternative reading is even tried.
	for _, cl := range m.lists {
		if cl.mode == MatchWholeSkeleton {
			for _, candidate := range candidates {
				if term, ok := cl.whole[candidate]; ok {
					return blockedBy(cl, term)
				}
			}
			continue
		}
		for _, candidate := range candidates {
			for _, term := range cl.substrings {
				if strings.Contains(candidate, term.skeleton) {
					return blockedBy(cl, term)
				}
			}
		}
	}

	return Result{Allowed: true, Reason: ReasonAllowed}
}

// candidateSkeletons returns every skeleton sk might be a reading of, and
// reports whether it could do so within maxAmbiguousRunes.
//
// A rune whose glyph carries two readings cannot be folded to one output
// without losing the other, so Skeleton returns one reading and this restores
// the rest; see ambiguousReadings in tables.go for why the ambiguity is keyed
// on the fold's output and why the expansion is one-way.
//
// Contract, all three parts relied on by Check:
//
//   - The first element is always sk itself, unmodified. Check walks candidates
//     in order, so an identifier that is exactly a reserved word is reported
//     against that word rather than against whatever an alternative reading of
//     it happens to hit.
//   - The order is fixed: positions ascend, and within a position the readings
//     follow their declared order in ambiguousReadings. The table is looked up,
//     never ranged, so Go's randomized map iteration cannot reach the result.
//     Two runs of two processes produce the same slice, which is what makes the
//     reported term in an audit record mean something.
//   - ok is false when sk holds more than maxAmbiguousRunes ambiguous
//     positions, or when those positions would expand past
//     maxCandidateSkeletons. The candidate set is then NOT partially returned: a truncated
//     set is worse than none, because Check would walk it, find no match, and
//     allow the identifier on the strength of an expansion it never finished.
//     Callers MUST treat false as blocked.
//
// The scan is byte-wise, which ambiguousReadings' ASCII-only invariant makes
// exact: every byte of a multi-byte rune is >= 0x80 and so matches no key, and
// substituting one ASCII byte for another leaves every other offset in place.
func candidateSkeletons(sk string) ([]string, bool) {
	return expandCandidates(sk, ambiguousReadings)
}

// expandCandidates is candidateSkeletons with the table injected.
//
// The table is a parameter solely so that a test can exercise the ceiling
// against a hypothetical multi-reading entry without writing to the package
// variable. Check runs concurrently in this package's own tests, so a test that
// swapped the global would be a data race rather than a test. Production code
// has exactly one table and must call candidateSkeletons.
func expandCandidates(sk string, table map[byte][]byte) ([]string, bool) {
	// Count first, expand second. Finding the bound broken before allocating
	// anything is what stops the denial-of-service case from being paid for on
	// the way to refusing it.
	positions := make([]int, 0, maxAmbiguousRunes)
	for i := 0; i < len(sk); i++ {
		if _, ok := table[sk[i]]; !ok {
			continue
		}
		if len(positions) == maxAmbiguousRunes {
			return nil, false
		}
		positions = append(positions, i)
	}

	// Size the set exactly, and make maxCandidateSkeletons a real ceiling
	// rather than one that happens to hold. Each position multiplies the set by
	// 1 + len(readings) -- the unmodified reading plus its alternatives -- so
	// 1<<len(positions) is only the right answer while every entry has exactly
	// one alternative, which is true today and is not a property this function
	// should depend on. A future two-reading entry would otherwise expand 3^k,
	// silently overshoot the ceiling the bound is documented to enforce, and
	// grow the slice past its hint on the way. Computing the product checks the
	// ceiling before allocating and fails closed against it.
	total := 1
	for _, pos := range positions {
		total *= 1 + len(table[sk[pos]])
		if total > maxCandidateSkeletons {
			return nil, false
		}
	}

	candidates := make([]string, 1, total)
	candidates[0] = sk

	for _, pos := range positions {
		readings := table[sk[pos]]
		grown := make([]string, 0, len(candidates)*(1+len(readings)))
		// The unmodified set first, so candidates[0] survives every round as
		// sk itself.
		grown = append(grown, candidates...)
		for _, reading := range readings {
			for _, c := range candidates {
				b := []byte(c)
				b[pos] = reading
				grown = append(grown, string(b))
			}
		}
		candidates = grown
	}
	return candidates, true
}

// blockedBy builds the refusal for a term that matched.
func blockedBy(cl compiledList, term compiledTerm) Result {
	return Result{
		Allowed: false,
		Reason:  ReasonBlockedTerm,
		List:    cl.name,
		Term:    term.raw,
		Mode:    cl.mode,
	}
}
