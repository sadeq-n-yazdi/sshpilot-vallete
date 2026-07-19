// Package audit is the service-side entry point for recording
// access-affecting events in the append-only audit log (ADR-0007).
//
// Callers construct an Emitter over a repository.AuditAppender — the
// insert-only port — and call Emit. The Emitter mints the record ID, stamps the
// timestamp, validates the event, and appends it. Nothing here can read,
// rewrite, or delete audit content, because the only port it holds cannot.
//
// # Keeping secrets out of the audit trail
//
// An audit trail is the most widely copied data in the system: it is shipped to
// a SIEM, retained far longer than the data it describes, and read by people who
// were never entitled to the underlying records. A secret that reaches it is
// therefore not merely logged, it is broadcast and archived. Keeping secrets out
// is the single most important property of this package.
//
// The design makes storing a secret awkward rather than merely discouraged:
//
//   - Free-form metadata is not reachable. domain.AuditRecord.Metadata is a
//     map[string]string, but callers never populate it directly; they build a
//     Details value whose keys must come from the allowlist in details.go.
//     There is no "token" or "password" key, so a secret has no natural home,
//     and adding one is a visible edit to a reviewed list rather than an
//     incidental string literal at a call site.
//   - Every value is screened for credential shapes — PEM blocks, bearer
//     tokens, authorization headers, JWTs, and SSH private keys — and rejected.
//   - A value that arrived as a redacted secret is rejected outright. The
//     secrets package renders a Redacted as "[REDACTED]" through every
//     formatting path, so the realistic accidental route (formatting a struct
//     that holds a resolved secret) produces that marker rather than the secret.
//     Seeing it here means a caller wired a secret into an audit call, so Emit
//     fails loudly instead of recording the near miss.
//
// secrets.Redacted is deliberately not used as a field type on the record
// itself. Redacted exists to keep a live secret out of logs while it is held in
// memory, and every one of its rendering paths yields "[REDACTED]"; a persisted
// Redacted field would therefore either store that useless marker or force a
// Reveal at the storage boundary, which is exactly the leak it exists to
// prevent. The right answer for a durable record is not to redact a secret but
// to never accept one, which is what the allowlist and the screens above do.
//
// # What a record captures
//
// Who (actor type and ID), what (action), to what (target type and ID), when
// (OccurredAt), and bounded non-secret context (Details). It deliberately does
// not capture the content of the change: an audit record says "this key was
// added to this set by this owner", identifying the key by its fingerprint,
// never by its bytes. The log is a record of access-affecting decisions, not a
// second copy of the data those decisions were about.
package audit

import (
	"context"
	"crypto/rand"
	"fmt"
	"regexp"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/repository"
)

// actionRe constrains an action to dotted lowercase segments, matching the
// AuditAction constants in package domain (for example "key.added"). The action
// vocabulary is deliberately open — tracks add their own actions — so the
// format is validated rather than the value allowlisted.
var actionRe = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$`)

// maxIDLen bounds actor and target identifiers. They are opaque IDs, not free
// text; the bound stops an unbounded string from riding into the log through
// an identifier field.
const maxIDLen = 256

// Event describes an access-affecting action to record. It carries no ID and no
// timestamp: Emit mints both, so a caller cannot backdate a record or choose its
// identifier.
type Event struct {
	// ActorType and ActorID identify who acted. ActorID is empty only for
	// ActorTypeSystem, which has no principal behind it.
	ActorType domain.ActorType
	ActorID   string

	// Action names what happened, as dotted lowercase segments.
	Action domain.AuditAction

	// TargetType and TargetID identify what was affected.
	TargetType domain.TargetType
	TargetID   string

	// Details is the bounded, allowlisted, non-secret context for the event.
	// The zero value carries no context, which is valid.
	Details Details
}

// Clock returns the current time. Emit stamps OccurredAt from it.
type Clock func() time.Time

// Emitter appends events to the audit log. It is safe for concurrent use if the
// underlying appender is.
type Emitter struct {
	sink  repository.AuditAppender
	now   Clock
	newID func() string
}

// Option customizes an Emitter.
type Option func(*Emitter)

// WithClock overrides the clock used to stamp OccurredAt. It exists for tests
// and for callers that already hold a coordinated clock.
func WithClock(c Clock) Option {
	return func(e *Emitter) {
		if c != nil {
			e.now = c
		}
	}
}

// withIDFunc overrides the record ID generator. It is unexported because
// production code must not choose audit record IDs; only tests substitute it.
func withIDFunc(f func() string) Option {
	return func(e *Emitter) {
		if f != nil {
			e.newID = f
		}
	}
}

// NewEmitter returns an Emitter appending to sink. A nil sink is a programming
// error and returns domain.ErrInvalidInput rather than deferring the failure to
// the first event, which would be the worst moment to discover the audit log
// was never wired up.
func NewEmitter(sink repository.AuditAppender, opts ...Option) (*Emitter, error) {
	if sink == nil {
		return nil, fmt.Errorf("audit: nil appender: %w", domain.ErrInvalidInput)
	}
	e := &Emitter{sink: sink, now: time.Now, newID: newRecordID}
	for i, opt := range opts {
		// A nil option is rejected rather than skipped. Skipping it would
		// silently drop whatever the caller meant to configure -- a substituted
		// clock, say -- and leave an Emitter that looks configured and is not.
		// It is the same class of caller error as a nil sink above and gets the
		// same answer, for the same reason: the worst moment to discover the
		// audit log is misconfigured is the first event it fails to record.
		if opt == nil {
			return nil, fmt.Errorf("audit: nil option at index %d: %w", i, domain.ErrInvalidInput)
		}
		opt(e)
	}
	return e, nil
}

// newRecordID returns a fresh, unguessable audit record ID. crypto/rand.Text
// yields 26 base32 characters (~130 bits), matching the identifier convention
// used elsewhere in the codebase. A CSPRNG rather than a counter means the IDs
// leak nothing about event volume or ordering and cannot be predicted and
// pre-poisoned into the log.
func newRecordID() string {
	return rand.Text()
}

// Emit validates ev, stamps it, and appends it to the audit log.
//
// The returned error MUST NOT be ignored. An access-affecting change whose
// audit record failed to persist is a change with no accountability, so a
// caller should fail the operation rather than proceed unrecorded.
func (e *Emitter) Emit(ctx context.Context, ev Event) error {
	rec, err := e.record(ev)
	if err != nil {
		return err
	}
	return e.sink.Append(ctx, rec)
}

// record validates ev and builds the domain record Emit appends. It is split
// out so the validation is testable without a sink.
func (e *Emitter) record(ev Event) (*domain.AuditRecord, error) {
	if err := ev.validate(); err != nil {
		return nil, err
	}
	metadata, err := ev.Details.metadata()
	if err != nil {
		return nil, err
	}
	return &domain.AuditRecord{
		ID:         domain.AuditRecordID(e.newID()),
		ActorType:  ev.ActorType,
		ActorID:    ev.ActorID,
		Action:     ev.Action,
		TargetType: ev.TargetType,
		TargetID:   ev.TargetID,
		// UTC so the stored value is unambiguous regardless of the process's
		// local zone; the storage layer encodes UTC anyway, and normalizing here
		// keeps the in-memory record consistent with what is persisted.
		OccurredAt: e.now().UTC(),
		Metadata:   metadata,
	}, nil
}

// validate rejects a malformed event. Every failure wraps
// domain.ErrInvalidInput; none of them echo a value back, so a rejected event
// cannot smuggle its contents into an error string that is itself logged.
func (ev Event) validate() error {
	if !ev.ActorType.IsValid() {
		return fmt.Errorf("audit: unknown actor type: %w", domain.ErrInvalidInput)
	}
	if !ev.TargetType.IsValid() {
		return fmt.Errorf("audit: unknown target type: %w", domain.ErrInvalidInput)
	}
	if !actionRe.MatchString(string(ev.Action)) {
		return fmt.Errorf("audit: malformed action: %w", domain.ErrInvalidInput)
	}

	// The system actor has no principal behind it, so it alone may have an empty
	// ActorID. Every other actor type must name who acted, or the record cannot
	// answer the question the audit log exists to answer.
	switch {
	case ev.ActorType == domain.ActorTypeSystem:
		if ev.ActorID != "" && len(ev.ActorID) > maxIDLen {
			return fmt.Errorf("audit: actor id too long: %w", domain.ErrInvalidInput)
		}
	case ev.ActorID == "":
		return fmt.Errorf("audit: missing actor id: %w", domain.ErrInvalidInput)
	case len(ev.ActorID) > maxIDLen:
		return fmt.Errorf("audit: actor id too long: %w", domain.ErrInvalidInput)
	}

	if ev.TargetID == "" {
		return fmt.Errorf("audit: missing target id: %w", domain.ErrInvalidInput)
	}
	if len(ev.TargetID) > maxIDLen {
		return fmt.Errorf("audit: target id too long: %w", domain.ErrInvalidInput)
	}

	// Identifiers are opaque tokens, never free text, so they are screened for
	// credential shapes too: an ID field is a plausible place for a caller to
	// pass "the thing that identified the caller", which may be a token.
	if err := screenValue("actor id", ev.ActorID); err != nil {
		return err
	}
	return screenValue("target id", ev.TargetID)
}
