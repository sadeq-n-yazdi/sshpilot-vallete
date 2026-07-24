package audit

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/repository"
)

var testClock = time.Date(2026, 7, 19, 10, 0, 0, 0, time.UTC)

// fakeSink captures appended records. It implements only the insert-only port,
// which is the whole surface the emitter is allowed to hold.
type fakeSink struct {
	records []domain.AuditRecord
	err     error
}

var _ repository.AuditAppender = (*fakeSink)(nil)

func (f *fakeSink) Append(_ context.Context, r *domain.AuditRecord) error {
	if f.err != nil {
		return f.err
	}
	f.records = append(f.records, *r)
	return nil
}

// newTestEmitter returns an emitter with a fixed clock and deterministic IDs.
func newTestEmitter(t *testing.T) (*Emitter, *fakeSink) {
	t.Helper()
	sink := &fakeSink{}
	n := 0
	e, err := NewEmitter(sink,
		WithClock(func() time.Time { return testClock }),
		withIDFunc(func() string { n++; return fmt.Sprintf("aud-%d", n) }),
	)
	if err != nil {
		t.Fatalf("NewEmitter: %v", err)
	}
	return e, sink
}

// validEvent returns an event that passes validation.
func validEvent() Event {
	return Event{
		ActorType:  domain.ActorTypeOwner,
		ActorID:    "owner-a",
		Action:     domain.AuditActionKeyAdded,
		TargetType: domain.TargetTypePublicKey,
		TargetID:   "key-1",
	}
}

func TestEmitAppendsRecord(t *testing.T) {
	t.Parallel()
	e, sink := newTestEmitter(t)

	ev := validEvent()
	ev.Details = Details{}.
		Set(DetailFingerprint, "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").
		Set(DetailDeviceName, "laptop")

	if err := e.Emit(context.Background(), ev); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if len(sink.records) != 1 {
		t.Fatalf("appended %d records, want 1", len(sink.records))
	}

	got := sink.records[0]
	if got.ID != "aud-1" {
		t.Errorf("ID = %q, want the emitter-minted aud-1", got.ID)
	}
	if !got.OccurredAt.Equal(testClock) {
		t.Errorf("OccurredAt = %v, want %v", got.OccurredAt, testClock)
	}
	if got.OccurredAt.Location() != time.UTC {
		t.Errorf("OccurredAt location = %v, want UTC", got.OccurredAt.Location())
	}
	if got.ActorType != ev.ActorType || got.ActorID != ev.ActorID || got.Action != ev.Action {
		t.Errorf("actor/action = %+v, want %+v", got, ev)
	}
	if got.TargetType != ev.TargetType || got.TargetID != ev.TargetID {
		t.Errorf("target = %+v, want %+v", got, ev)
	}
	want := map[string]string{
		"fingerprint": "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		"device_name": "laptop",
	}
	if !reflect.DeepEqual(got.Metadata, want) {
		t.Errorf("Metadata = %v, want %v", got.Metadata, want)
	}
	if got.Pseudonymized {
		t.Error("Pseudonymized = true, want false on a freshly emitted record")
	}
}

// TestEmitToUsesTheSuppliedSink is the load-bearing check behind the durable-
// release fix: EmitTo must append to the sink it is GIVEN, never the emitter's
// own. The two sinks here stand in for the transaction-bound r.Audit and the
// auto-commit e.sink; a record written to the latter would auto-commit on its
// own and defeat the atomicity the caller reached for EmitTo to get. The record
// must still be minted and stamped exactly as Emit does it.
func TestEmitToUsesTheSuppliedSink(t *testing.T) {
	t.Parallel()
	e, own := newTestEmitter(t)
	txSink := &fakeSink{}

	if err := e.EmitTo(context.Background(), txSink, validEvent()); err != nil {
		t.Fatalf("EmitTo: %v", err)
	}
	if len(own.records) != 0 {
		t.Fatalf("EmitTo wrote %d records to the emitter's own sink, want 0: it "+
			"must append only to the supplied sink", len(own.records))
	}
	if len(txSink.records) != 1 {
		t.Fatalf("supplied sink got %d records, want 1", len(txSink.records))
	}
	got := txSink.records[0]
	if got.ID != "aud-1" {
		t.Errorf("ID = %q, want the emitter-minted aud-1", got.ID)
	}
	if !got.OccurredAt.Equal(testClock) || got.OccurredAt.Location() != time.UTC {
		t.Errorf("OccurredAt = %v, want %v in UTC", got.OccurredAt, testClock)
	}
}

// TestEmitToStillValidatesAndScreens confirms EmitTo shares Emit's record path,
// so the credential screen and validation are not bypassed by routing a record
// to a different sink. A rejected event must reach neither sink.
func TestEmitToStillValidatesAndScreens(t *testing.T) {
	t.Parallel()
	e, own := newTestEmitter(t)
	txSink := &fakeSink{}

	bad := validEvent()
	bad.ActorID = "" // a non-system actor with no id fails validation
	if err := e.EmitTo(context.Background(), txSink, bad); !errors.Is(err, domain.ErrInvalidInput) {
		t.Fatalf("EmitTo(invalid) = %v, want ErrInvalidInput", err)
	}
	if len(txSink.records) != 0 || len(own.records) != 0 {
		t.Fatal("a rejected event was appended to a sink")
	}

	if err := e.EmitTo(context.Background(), nil, validEvent()); !errors.Is(err, domain.ErrInvalidInput) {
		t.Fatalf("EmitTo(nil sink) = %v, want ErrInvalidInput", err)
	}
}

// TestEmitMintsIDAndTimestamp confirms the caller cannot choose either: Event
// has no field for them, so a caller can neither backdate a record nor pick an
// ID that collides with an existing one to force an append failure.
func TestEmitMintsIDAndTimestamp(t *testing.T) {
	t.Parallel()

	evType := reflect.TypeOf(Event{})
	for _, forbidden := range []string{"ID", "OccurredAt", "Pseudonymized"} {
		if _, ok := evType.FieldByName(forbidden); ok {
			t.Errorf("Event has a %q field: the emitter must own it, not the caller", forbidden)
		}
	}

	e, sink := newTestEmitter(t)
	for range 2 {
		if err := e.Emit(context.Background(), validEvent()); err != nil {
			t.Fatalf("Emit: %v", err)
		}
	}
	if sink.records[0].ID == sink.records[1].ID {
		t.Error("two emitted records share an ID")
	}
}

func TestNewRecordIDIsUnguessable(t *testing.T) {
	t.Parallel()

	seen := make(map[string]bool, 100)
	for range 100 {
		id := newRecordID()
		if len(id) != 26 {
			t.Fatalf("record id %q has length %d, want 26", id, len(id))
		}
		if seen[id] {
			t.Fatalf("record id %q repeated", id)
		}
		seen[id] = true
	}
}

func TestNewEmitterRejectsNilSink(t *testing.T) {
	t.Parallel()
	if _, err := NewEmitter(nil); !errors.Is(err, domain.ErrInvalidInput) {
		t.Errorf("NewEmitter(nil) = %v, want ErrInvalidInput", err)
	}
}

func TestNewEmitterIgnoresNilOptions(t *testing.T) {
	t.Parallel()
	e, err := NewEmitter(&fakeSink{}, WithClock(nil), withIDFunc(nil))
	if err != nil {
		t.Fatalf("NewEmitter: %v", err)
	}
	if e.now == nil || e.newID == nil {
		t.Error("a nil option overwrote a default")
	}
}

// TestNewEmitterRejectsANilOption covers the case the test above does not:
// WithClock(nil) is a non-nil Option carrying a nil value, whereas a nil Option
// is a nil func that would panic when applied.
//
// It is rejected rather than skipped. Skipping would silently discard whatever
// the caller meant to configure and hand back an Emitter that looks configured
// and is not -- the failure would surface as a missing or mis-stamped audit
// record long after the call that caused it.
func TestNewEmitterRejectsANilOption(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		opts []Option
	}{
		{name: "only a nil option", opts: []Option{nil}},
		{name: "nil after a valid option", opts: []Option{WithClock(nil), nil}},
		{name: "nil before a valid option", opts: []Option{nil, WithClock(nil)}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			e, err := NewEmitter(&fakeSink{}, tc.opts...)
			if !errors.Is(err, domain.ErrInvalidInput) {
				t.Errorf("NewEmitter = %v, want ErrInvalidInput", err)
			}
			if e != nil {
				t.Error("a rejected construction must not return an Emitter")
			}
		})
	}
}

func TestEmitPropagatesSinkError(t *testing.T) {
	t.Parallel()
	sentinel := errors.New("sink down")
	sink := &fakeSink{err: sentinel}
	e, err := NewEmitter(sink)
	if err != nil {
		t.Fatalf("NewEmitter: %v", err)
	}
	if err := e.Emit(context.Background(), validEvent()); !errors.Is(err, sentinel) {
		t.Errorf("Emit = %v, want the sink error", err)
	}
}

func TestEmitRejectsInvalidEvents(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		mutid func(*Event)
	}{
		{"unknown actor type", func(e *Event) { e.ActorType = "intruder" }},
		{"empty actor type", func(e *Event) { e.ActorType = "" }},
		{"unknown target type", func(e *Event) { e.TargetType = "shadow" }},
		{"empty target type", func(e *Event) { e.TargetType = "" }},
		{"empty action", func(e *Event) { e.Action = "" }},
		{"undotted action", func(e *Event) { e.Action = "keyadded" }},
		{"uppercase action", func(e *Event) { e.Action = "Key.Added" }},
		{"action with spaces", func(e *Event) { e.Action = "key added" }},
		{"missing actor id", func(e *Event) { e.ActorID = "" }},
		{"missing target id", func(e *Event) { e.TargetID = "" }},
		{"overlong actor id", func(e *Event) { e.ActorID = strings.Repeat("a", maxIDLen+1) }},
		{"overlong target id", func(e *Event) { e.TargetID = strings.Repeat("a", maxIDLen+1) }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			e, sink := newTestEmitter(t)
			ev := validEvent()
			tc.mutid(&ev)
			if err := e.Emit(context.Background(), ev); !errors.Is(err, domain.ErrInvalidInput) {
				t.Errorf("Emit = %v, want ErrInvalidInput", err)
			}
			if len(sink.records) != 0 {
				t.Errorf("a rejected event was still appended: %+v", sink.records)
			}
		})
	}
}

// TestEmitAllowsSystemActorWithoutID covers the one actor type that legitimately
// has no principal behind it.
func TestEmitAllowsSystemActorWithoutID(t *testing.T) {
	t.Parallel()
	e, sink := newTestEmitter(t)

	ev := validEvent()
	ev.ActorType = domain.ActorTypeSystem
	ev.ActorID = ""
	if err := e.Emit(context.Background(), ev); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if len(sink.records) != 1 {
		t.Fatalf("appended %d records, want 1", len(sink.records))
	}

	// A system actor may still name itself, but not without bound.
	ev.ActorID = strings.Repeat("a", maxIDLen+1)
	if err := e.Emit(context.Background(), ev); !errors.Is(err, domain.ErrInvalidInput) {
		t.Errorf("overlong system actor id = %v, want ErrInvalidInput", err)
	}
}

func TestEmitAcceptsEveryValidActorAndTargetType(t *testing.T) {
	t.Parallel()

	actors := []domain.ActorType{
		domain.ActorTypeOwner, domain.ActorTypeAdministrator, domain.ActorTypeSystem,
	}
	targets := []domain.TargetType{
		domain.TargetTypeOwner, domain.TargetTypeHandle, domain.TargetTypeDevice,
		domain.TargetTypePublicKey, domain.TargetTypeKeySet, domain.TargetTypeAccessKey,
		domain.TargetTypeRefreshCredential, domain.TargetTypeBlocklistEntry,
		domain.TargetTypeAllowlistEntry,
	}
	e, sink := newTestEmitter(t)
	for _, at := range actors {
		for _, tt := range targets {
			ev := validEvent()
			ev.ActorType, ev.TargetType = at, tt
			if err := e.Emit(context.Background(), ev); err != nil {
				t.Errorf("Emit(%s -> %s): %v", at, tt, err)
			}
		}
	}
	if want := len(actors) * len(targets); len(sink.records) != want {
		t.Errorf("appended %d records, want %d", len(sink.records), want)
	}
}

// TestEmitterHoldsOnlyTheAppendOnlyPort is the capability test for the emitter:
// the field it stores must be the insert-only interface, so no amount of
// service-layer code can reach a read, rewrite, or delete through it.
func TestEmitterHoldsOnlyTheAppendOnlyPort(t *testing.T) {
	t.Parallel()

	field, ok := reflect.TypeOf(Emitter{}).FieldByName("sink")
	if !ok {
		t.Fatal("Emitter has no sink field")
	}
	want := reflect.TypeOf((*repository.AuditAppender)(nil)).Elem()
	if field.Type != want {
		t.Errorf("Emitter.sink is %v, want %v: the emitter must not hold a port "+
			"that can read, rewrite, or delete audit content", field.Type, want)
	}

	// And the emitter must expose no operation beyond appending. EmitTo is
	// allowed because it is still append-only: its sink parameter is the
	// insert-only repository.AuditAppender, so like Emit it can add a record and
	// can neither read, rewrite, nor delete one — it only changes which appender
	// the record lands on.
	allowed := map[string]bool{"Emit": true, "EmitTo": true}
	et := reflect.TypeOf(&Emitter{})
	for i := range et.NumMethod() {
		if name := et.Method(i).Name; !allowed[name] {
			t.Errorf("Emitter exposes unexpected method %q; it may only append", name)
		}
	}
}
