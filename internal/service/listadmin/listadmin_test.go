package listadmin

import (
	"context"
	"errors"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/audit"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/blocklist"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/repository"
)

// testNow is the fixed instant the harness stamps persisted overrides with, so
// an assertion about a recorded timestamp cannot pass by comparing two zero
// values.
var testNow = time.Date(2026, 7, 20, 11, 0, 0, 0, time.UTC)

// fakeOverrides is an in-memory ListOverrideRepository. It keys on
// (list, skeleton) exactly as the real table's primary key does, so a test
// cannot accidentally observe two rows where production would hold one.
type fakeOverrides struct {
	mu     sync.Mutex
	rows   map[string]domain.ListOverride
	putErr error
	putN   int
}

func newFakeOverrides() *fakeOverrides {
	return &fakeOverrides{rows: make(map[string]domain.ListOverride)}
}

func overrideKey(kind domain.ListKind, skeleton string) string {
	return string(kind) + "\x00" + skeleton
}

func (f *fakeOverrides) Put(_ context.Context, o *domain.ListOverride) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.putN++
	if f.putErr != nil {
		return f.putErr
	}
	f.rows[overrideKey(o.List, o.Skeleton)] = *o
	return nil
}

func (f *fakeOverrides) List(_ context.Context) ([]domain.ListOverride, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.rows) == 0 {
		return nil, nil
	}
	keys := make([]string, 0, len(f.rows))
	for k := range f.rows {
		keys = append(keys, k)
	}
	// Sorted, matching the adapter's ORDER BY list, skeleton. The key's NUL
	// separator makes the string order agree with the column order.
	sort.Strings(keys)
	out := make([]domain.ListOverride, 0, len(keys))
	for _, k := range keys {
		out = append(out, f.rows[k])
	}
	return out, nil
}

// get returns the stored override for an entry, for assertions.
func (f *fakeOverrides) get(kind domain.ListKind, entry string) (domain.ListOverride, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	o, ok := f.rows[overrideKey(kind, blocklist.Skeleton(entry))]
	return o, ok
}

var _ repository.ListOverrideRepository = (*fakeOverrides)(nil)

// fakeAdmins is an in-memory AdministratorRepository. Only Get is exercised by
// this package; the rest satisfy the port.
type fakeAdmins struct {
	mu      sync.Mutex
	byID    map[domain.AdministratorID]*domain.Administrator
	getErr  error
	nilOnly bool
}

func newFakeAdmins(admins ...*domain.Administrator) *fakeAdmins {
	f := &fakeAdmins{byID: make(map[domain.AdministratorID]*domain.Administrator)}
	for _, a := range admins {
		f.byID[a.ID] = a
	}
	return f
}

func (f *fakeAdmins) Get(_ context.Context, id domain.AdministratorID) (*domain.Administrator, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.getErr != nil {
		return nil, f.getErr
	}
	// nilOnly reproduces a repository that violates its own contract by
	// returning no administrator and no error.
	if f.nilOnly {
		return nil, nil
	}
	a, ok := f.byID[id]
	if !ok {
		return nil, domain.ErrNotFound
	}
	return a, nil
}

func (f *fakeAdmins) Create(context.Context, *domain.Administrator) error { return nil }
func (f *fakeAdmins) List(context.Context) ([]domain.Administrator, error) {
	return nil, nil
}

func (f *fakeAdmins) SetLabel(context.Context, domain.AdministratorID, string, time.Time) error {
	return nil
}

func (f *fakeAdmins) UpdateStatus(
	context.Context, domain.AdministratorID, domain.AdminStatus, time.Time,
) error {
	return nil
}

var _ repository.AdministratorRepository = (*fakeAdmins)(nil)

// recordingSink captures emitted audit records so a test can assert on them.
type recordingSink struct {
	mu      sync.Mutex
	records []*domain.AuditRecord
	err     error
}

func (s *recordingSink) Append(_ context.Context, r *domain.AuditRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return s.err
	}
	s.records = append(s.records, r)
	return nil
}

func (s *recordingSink) all() []*domain.AuditRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slicesClone(s.records)
}

func slicesClone(in []*domain.AuditRecord) []*domain.AuditRecord {
	out := make([]*domain.AuditRecord, len(in))
	copy(out, in)
	return out
}

const (
	activeAdminID   = domain.AdministratorID("adm-active")
	disabledAdminID = domain.AdministratorID("adm-disabled")
)

func activeAdmin() *domain.Administrator {
	return &domain.Administrator{ID: activeAdminID, Status: domain.AdminStatusActive}
}

func disabledAdmin() *domain.Administrator {
	return &domain.Administrator{ID: disabledAdminID, Status: domain.AdminStatusDisabled}
}

type harness struct {
	svc       *Service
	sink      *recordingSink
	admins    *fakeAdmins
	matcher   *blocklist.Matcher
	overrides *fakeOverrides
}

// newHarness wires a Service over a real matcher. The matcher is real, not a
// fake, so a test that says an identifier is exempt is exercising the actual
// match engine rather than a stub that agrees with the test.
func newHarness(t *testing.T) *harness {
	t.Helper()

	m, err := blocklist.NewMatcher(
		blocklist.List{
			Name:  "impersonation",
			Mode:  blocklist.MatchWholeSkeleton,
			Terms: []string{"admin", "root"},
		},
		blocklist.List{
			Name:  "offensive",
			Mode:  blocklist.MatchSubstring,
			Terms: []string{"cunt"},
		},
	)
	if err != nil {
		t.Fatalf("NewMatcher: %v", err)
	}

	sink := &recordingSink{}
	em, err := audit.NewEmitter(sink)
	if err != nil {
		t.Fatalf("NewEmitter: %v", err)
	}
	admins := newFakeAdmins(activeAdmin(), disabledAdmin())
	overrides := newFakeOverrides()

	svc, err := New(Params{
		Admins:    admins,
		Overrides: overrides,
		Emitter:   em,
		Matcher:   m,
		Now:       func() time.Time { return testNow },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return &harness{svc: svc, sink: sink, admins: admins, matcher: m, overrides: overrides}
}

func TestNewRequiresEveryDependency(t *testing.T) {
	t.Parallel()
	m, err := blocklist.NewMatcher(
		blocklist.List{Name: "l", Mode: blocklist.MatchWholeSkeleton, Terms: []string{"admin"}})
	if err != nil {
		t.Fatalf("NewMatcher: %v", err)
	}
	em, err := audit.NewEmitter(&recordingSink{})
	if err != nil {
		t.Fatalf("NewEmitter: %v", err)
	}

	full := func() Params {
		return Params{
			Admins:    newFakeAdmins(),
			Overrides: newFakeOverrides(),
			Emitter:   em,
			Matcher:   m,
		}
	}
	cases := map[string]func(*Params){
		"nil administrator repository": func(p *Params) { p.Admins = nil },
		"nil override repository":      func(p *Params) { p.Overrides = nil },
		"nil emitter":                  func(p *Params) { p.Emitter = nil },
		"nil matcher":                  func(p *Params) { p.Matcher = nil },
	}
	for name, drop := range cases {
		p := full()
		drop(&p)
		if _, err := New(p); err == nil {
			t.Errorf("New accepted a %s", name)
		}
	}

	// A nil clock is the one optional field: it has a single correct default
	// and is not a security decision the way a missing repository is.
	if _, err := New(full()); err != nil {
		t.Errorf("New rejected a nil clock: %v", err)
	}
}

// TestAllowlistedIdentifierPassesTheRealMatcher is the end-to-end property the
// feature exists for: after an authorized edit, the real match engine permits
// the identifier it previously refused, and a non-allowlisted one is still
// refused.
func TestAllowlistedIdentifierPassesTheRealMatcher(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	ctx := context.Background()

	if res := h.matcher.Check("scunthorpe"); !res.Blocked() {
		t.Fatal("precondition failed: \"scunthorpe\" was not blocked")
	}

	if err := h.svc.AddAllowlistEntry(ctx, activeAdminID, "scunthorpe"); err != nil {
		t.Fatalf("AddAllowlistEntry: %v", err)
	}

	if res := h.matcher.Check("scunthorpe"); res.Blocked() {
		t.Error("the allowlisted identifier is still refused by the matcher")
	}
	// A different blocked identifier must remain blocked, or the entry would be
	// a switch that disables the control rather than a hole in it.
	if res := h.matcher.Check("admin"); !res.Blocked() {
		t.Error("allowlisting one identifier exempted another")
	}
}

// TestNonAdministratorCannotEditEitherList is the authorization test, exercised
// at the service layer rather than through a handler: every caller reaching
// this API is refused unless it names an active administrator, whatever
// transport it came from.
func TestNonAdministratorCannotEditEitherList(t *testing.T) {
	t.Parallel()

	actors := []struct {
		name    string
		actor   domain.AdministratorID
		wantErr error
	}{
		{"no actor named", "", domain.ErrUnauthorized},
		{"unknown administrator", "adm-ghost", domain.ErrUnauthorized},
		{"disabled administrator", disabledAdminID, domain.ErrForbidden},
	}

	edits := []struct {
		name string
		call func(*Service, context.Context, domain.AdministratorID) error
	}{
		{"add allowlist", func(s *Service, ctx context.Context, a domain.AdministratorID) error {
			return s.AddAllowlistEntry(ctx, a, "scunthorpe")
		}},
		{"remove allowlist", func(s *Service, ctx context.Context, a domain.AdministratorID) error {
			return s.RemoveAllowlistEntry(ctx, a, "scunthorpe")
		}},
		{"add blocklist", func(s *Service, ctx context.Context, a domain.AdministratorID) error {
			return s.AddBlocklistTerm(ctx, a, "sadeq")
		}},
		{"remove blocklist", func(s *Service, ctx context.Context, a domain.AdministratorID) error {
			return s.RemoveBlocklistTerm(ctx, a, "sadeq")
		}},
	}

	for _, actor := range actors {
		for _, edit := range edits {
			t.Run(actor.name+"/"+edit.name, func(t *testing.T) {
				t.Parallel()
				h := newHarness(t)
				ctx := context.Background()

				err := edit.call(h.svc, ctx, actor.actor)
				if !errors.Is(err, actor.wantErr) {
					t.Fatalf("error = %v, want %v", err, actor.wantErr)
				}

				// The refusal must leave no trace in either list.
				if got := h.svc.Allowlist(); len(got) != 0 {
					t.Errorf("allowlist = %v after a refused edit, want empty", got)
				}
				if got := h.svc.BlocklistTerms(); len(got) != 0 {
					t.Errorf("blocklist terms = %v after a refused edit, want empty", got)
				}
				// And it must not append to the audit log: an unauthorized
				// caller must not be able to write records by submitting edits
				// it was never allowed to make.
				if recs := h.sink.all(); len(recs) != 0 {
					t.Errorf("a refused edit emitted %d audit records, want 0", len(recs))
				}
				// The matcher must be unchanged.
				if res := h.matcher.Check("scunthorpe"); !res.Blocked() {
					t.Error("a refused edit reached the matcher")
				}
			})
		}
	}
}

// TestAdministratorCheckFailureRefusesTheEdit is the fail-closed case. An
// administrator lookup that could not be performed is not evidence of
// authority, so the edit must be refused rather than allowed through.
func TestAdministratorCheckFailureRefusesTheEdit(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	ctx := context.Background()

	storeErr := errors.New("database unavailable")
	h.admins.getErr = storeErr

	err := h.svc.AddAllowlistEntry(ctx, activeAdminID, "scunthorpe")
	if err == nil {
		t.Fatal("an unavailable administrator store permitted the edit")
	}
	if !errors.Is(err, storeErr) {
		t.Errorf("error = %v, want it to wrap the store error", err)
	}
	// It must not be reported as an ordinary authorization refusal: an operator
	// needs to tell "somebody lacked authority" from "authority could not be
	// evaluated".
	if errors.Is(err, domain.ErrUnauthorized) || errors.Is(err, domain.ErrForbidden) {
		t.Error("a store failure was reported as an authorization decision")
	}

	if res := h.matcher.Check("scunthorpe"); !res.Blocked() {
		t.Error("the edit reached the matcher despite the store failure")
	}
	if recs := h.sink.all(); len(recs) != 0 {
		t.Errorf("a refused edit emitted %d audit records, want 0", len(recs))
	}
}

// TestAdministratorLookupReturningNothingRefusesTheEdit covers a repository
// that violates its contract by returning neither an administrator nor an
// error. An authorization decision must never depend on a value nobody
// promised.
func TestAdministratorLookupReturningNothingRefusesTheEdit(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.admins.nilOnly = true

	err := h.svc.AddAllowlistEntry(context.Background(), activeAdminID, "scunthorpe")
	if !errors.Is(err, domain.ErrUnauthorized) {
		t.Fatalf("error = %v, want ErrUnauthorized", err)
	}
}

// TestAuditNamesTheActorEntryAndDirection covers the record's content for both
// directions on both lists. Without the actor the record cannot answer who
// opened the hole, which is the question the audit exists for.
func TestAuditNamesTheActorEntryAndDirection(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	ctx := context.Background()

	if err := h.svc.AddAllowlistEntry(ctx, activeAdminID, "scunthorpe"); err != nil {
		t.Fatalf("AddAllowlistEntry: %v", err)
	}
	if err := h.svc.RemoveAllowlistEntry(ctx, activeAdminID, "scunthorpe"); err != nil {
		t.Fatalf("RemoveAllowlistEntry: %v", err)
	}
	if err := h.svc.AddBlocklistTerm(ctx, activeAdminID, "sadeq"); err != nil {
		t.Fatalf("AddBlocklistTerm: %v", err)
	}
	if err := h.svc.RemoveBlocklistTerm(ctx, activeAdminID, "sadeq"); err != nil {
		t.Fatalf("RemoveBlocklistTerm: %v", err)
	}

	want := []struct {
		action domain.AuditAction
		target domain.TargetType
		id     string
	}{
		{domain.AuditActionAllowlistEntryAdded, domain.TargetTypeAllowlistEntry, "scunthorpe"},
		{domain.AuditActionAllowlistEntryRemoved, domain.TargetTypeAllowlistEntry, "scunthorpe"},
		{domain.AuditActionBlocklistEntryAdded, domain.TargetTypeBlocklistEntry, "sadeq"},
		{domain.AuditActionBlocklistEntryRemoved, domain.TargetTypeBlocklistEntry, "sadeq"},
	}

	recs := h.sink.all()
	if len(recs) != len(want) {
		t.Fatalf("emitted %d records, want %d", len(recs), len(want))
	}
	for i, w := range want {
		got := recs[i]
		if got.ActorType != domain.ActorTypeAdministrator {
			t.Errorf("record %d ActorType = %q, want administrator", i, got.ActorType)
		}
		if got.ActorID != string(activeAdminID) {
			t.Errorf("record %d ActorID = %q, want %q", i, got.ActorID, activeAdminID)
		}
		if got.Action != w.action {
			t.Errorf("record %d Action = %q, want %q", i, got.Action, w.action)
		}
		if got.TargetType != w.target {
			t.Errorf("record %d TargetType = %q, want %q", i, got.TargetType, w.target)
		}
		if got.TargetID != w.id {
			t.Errorf("record %d TargetID = %q, want %q", i, got.TargetID, w.id)
		}
	}
}

// TestAuditFailureAbortsTheEdit is the ordering guarantee. The record is
// written before the change takes effect, so a failed write must leave the
// lists untouched -- there must be no path that produces an applied change with
// no record of it.
func TestAuditFailureAbortsTheEdit(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	ctx := context.Background()

	h.sink.err = errors.New("audit sink unavailable")

	err := h.svc.AddAllowlistEntry(ctx, activeAdminID, "scunthorpe")
	if err == nil {
		t.Fatal("the edit proceeded despite an audit failure")
	}

	if got := h.svc.Allowlist(); len(got) != 0 {
		t.Errorf("allowlist = %v after a failed audit, want empty", got)
	}
	// The matcher is the thing that matters: an unrecorded hole here would be
	// invisible to every later review.
	if res := h.matcher.Check("scunthorpe"); !res.Blocked() {
		t.Error("an unaudited allowlist entry took effect")
	}
}

// TestRemovingAnEntryRestoresTheBlock pins the removal direction end to end.
func TestRemovingAnEntryRestoresTheBlock(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	ctx := context.Background()

	if err := h.svc.AddAllowlistEntry(ctx, activeAdminID, "admin"); err != nil {
		t.Fatalf("AddAllowlistEntry: %v", err)
	}
	if res := h.matcher.Check("admin"); res.Blocked() {
		t.Fatal("precondition failed: the entry did not take effect")
	}

	if err := h.svc.RemoveAllowlistEntry(ctx, activeAdminID, "admin"); err != nil {
		t.Fatalf("RemoveAllowlistEntry: %v", err)
	}
	if res := h.matcher.Check("admin"); !res.Blocked() {
		t.Error("the identifier is still exempt after its entry was removed")
	}
}

// TestRemovalMatchesOnTheSkeleton pins that an entry can be withdrawn by any
// spelling that folds to it. Deciding membership on the raw string would leave
// an administrator unable to remove a hole they can plainly see listed.
func TestRemovalMatchesOnTheSkeleton(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	ctx := context.Background()

	if err := h.svc.AddAllowlistEntry(ctx, activeAdminID, "admin"); err != nil {
		t.Fatalf("AddAllowlistEntry: %v", err)
	}
	if err := h.svc.RemoveAllowlistEntry(ctx, activeAdminID, "adm1n"); err != nil {
		t.Fatalf("RemoveAllowlistEntry by a folded spelling: %v", err)
	}
	if got := h.svc.Allowlist(); len(got) != 0 {
		t.Errorf("allowlist = %v, want empty", got)
	}
}

// TestNoOpEditsAreRefused pins that a change which changes nothing is an error
// rather than a silent success: auditing it would put a false event in the
// record.
func TestNoOpEditsAreRefused(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	ctx := context.Background()

	if err := h.svc.AddAllowlistEntry(ctx, activeAdminID, "admin"); err != nil {
		t.Fatalf("AddAllowlistEntry: %v", err)
	}
	// Adding it again, including by a spelling that folds to the same entry.
	if err := h.svc.AddAllowlistEntry(ctx, activeAdminID, "adm1n"); !errors.Is(err, domain.ErrConflict) {
		t.Errorf("duplicate add error = %v, want ErrConflict", err)
	}
	if err := h.svc.RemoveAllowlistEntry(ctx, activeAdminID, "root"); !errors.Is(err, domain.ErrNotFound) {
		t.Errorf("absent removal error = %v, want ErrNotFound", err)
	}
	if err := h.svc.RemoveBlocklistTerm(ctx, activeAdminID, "sadeq"); !errors.Is(err, domain.ErrNotFound) {
		t.Errorf("absent term removal error = %v, want ErrNotFound", err)
	}

	// A refused no-op must emit exactly the one record for the successful add.
	if recs := h.sink.all(); len(recs) != 1 {
		t.Errorf("emitted %d records, want 1", len(recs))
	}
}

func TestInvalidEntriesAreRefusedBeforeAuthorization(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	ctx := context.Background()

	cases := []struct {
		name  string
		entry string
	}{
		{"empty", ""},
		{"too long", strings.Repeat("a", maxEntryLen+1)},
		// Separators only: no comparable content, so the entry could never
		// match any identifier.
		{"no skeleton", "---"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := h.svc.AddAllowlistEntry(ctx, activeAdminID, tc.entry)
			if !errors.Is(err, domain.ErrInvalidInput) {
				t.Fatalf("error = %v, want ErrInvalidInput", err)
			}
		})
	}
}

// TestBlocklistTermTakesEffectThroughTheService is the blocklist-side end to
// end: an authorized add makes the real matcher refuse an identifier it
// previously permitted.
func TestBlocklistTermTakesEffectThroughTheService(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	ctx := context.Background()

	if res := h.matcher.Check("sadeq"); res.Blocked() {
		t.Fatal("precondition failed: \"sadeq\" was already blocked")
	}
	if err := h.svc.AddBlocklistTerm(ctx, activeAdminID, "sadeq"); err != nil {
		t.Fatalf("AddBlocklistTerm: %v", err)
	}
	if res := h.matcher.Check("sadeq"); !res.Blocked() {
		t.Error("the added term did not reach the matcher")
	}

	if err := h.svc.RemoveBlocklistTerm(ctx, activeAdminID, "sadeq"); err != nil {
		t.Fatalf("RemoveBlocklistTerm: %v", err)
	}
	if res := h.matcher.Check("sadeq"); res.Blocked() {
		t.Error("the term still applies after removal")
	}
}

// TestConcurrentEditsDoNotLoseEntries exercises the serialization. Two
// concurrent adds that both read the same starting set would each write a set
// missing the other's entry, and the loser's change would vanish while its
// audit record claimed it had been applied.
func TestConcurrentEditsDoNotLoseEntries(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	ctx := context.Background()

	entries := []string{"alpha", "bravo", "charlie", "delta", "echo", "foxtrot"}
	var wg sync.WaitGroup
	for _, e := range entries {
		wg.Add(1)
		go func(entry string) {
			defer wg.Done()
			if err := h.svc.AddAllowlistEntry(ctx, activeAdminID, entry); err != nil {
				t.Errorf("AddAllowlistEntry(%q): %v", entry, err)
			}
		}(e)
	}
	wg.Wait()

	if got := h.svc.Allowlist(); len(got) != len(entries) {
		t.Errorf("allowlist = %v (%d entries), want %d", got, len(got), len(entries))
	}
	if recs := h.sink.all(); len(recs) != len(entries) {
		t.Errorf("emitted %d records, want %d", len(recs), len(entries))
	}
}

// TestApplyFailureIsReportedAfterTheAuditRecord covers the last branch of an
// edit: the change is authorized and recorded, and then the swap itself fails.
//
// The scenario is a Service built over a matcher that was never compiled by
// NewMatcher. It is the ordering's over-recording direction made visible: a
// record exists for a change that did not take effect. That is the safe side of
// the trade -- an investigator reconciling the record against the list finds a
// discrepancy -- and the test pins that the failure is surfaced rather than
// swallowed, because a caller told the edit succeeded would believe a hole was
// open when it is not.
func TestApplyFailureIsReportedAfterTheAuditRecord(t *testing.T) {
	t.Parallel()

	sink := &recordingSink{}
	em, err := audit.NewEmitter(sink)
	if err != nil {
		t.Fatalf("NewEmitter: %v", err)
	}
	// A zero Matcher is not ready, so every SetAllowlist on it fails.
	svc, err := New(Params{
		Admins:    newFakeAdmins(activeAdmin()),
		Overrides: newFakeOverrides(),
		Emitter:   em,
		Matcher:   &blocklist.Matcher{},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	err = svc.AddAllowlistEntry(context.Background(), activeAdminID, "scunthorpe")
	if err == nil {
		t.Fatal("an edit against an unbuilt matcher reported success")
	}
	if !strings.Contains(err.Error(), "apply the edit") {
		t.Errorf("error = %v, want it to name the apply step", err)
	}

	// The record was written first, so it exists even though the change did not
	// land. This is the intended direction.
	if recs := sink.all(); len(recs) != 1 {
		t.Errorf("emitted %d records, want 1 written before the failed apply", len(recs))
	}
}
