package onboarding_test

import (
	"context"
	"database/sql"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/audit"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/auth"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/migrate"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/nameguard"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/repository"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/schema"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/secrets"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/service/onboarding"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/storage/sqlite"
)

// These tests drive the REAL SQLite adapter, not a fake repository. The
// invariant most worth protecting — that owner, handle, and default key set are
// created atomically, or not at all — is enforced by the transaction and the
// schema's foreign keys, not by any line of Go in the service. A fake would
// honor those by construction and pass just as happily with the atomicity gone.
//
// The auditor is the REAL *audit.Emitter for the same reason: an owner-created
// record that persisted the enrollment code would be a leak this fixture must
// be able to see, so it emits through production code and reads the row back.

const (
	activeAdmin   domain.AdministratorID = "admin-active"
	disabledAdmin domain.AdministratorID = "admin-disabled"
)

// deviceCodeSecret is the fixed enrollment code the fake minter returns; the
// audit test asserts this exact string appears in no persisted detail value.
const deviceCodeSecret = "device-code-secret"

var fixedNow = time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)

// recordingMinter stands in for auth.EnrollmentService.MintInto. It records the
// arguments it was called with — so a test can prove the new owner id and the
// full-owner scope reach the minter — and returns a fixed grant, or an error.
type recordingMinter struct {
	mu      sync.Mutex
	calls   int
	sawTx   bool
	ownerID domain.OwnerID
	label   string
	scopes  []domain.Scope
	grant   *auth.Grant
	err     error
}

func (m *recordingMinter) MintInto(_ context.Context, r repository.Repos, ownerID domain.OwnerID, label string, scopes []domain.Scope) (*auth.Grant, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls++
	// The mint must run through the transaction-bound repos, not the ambient
	// store — a non-nil handle here is what makes the provision atomic.
	m.sawTx = r.Owners != nil
	m.ownerID = ownerID
	m.label = label
	m.scopes = slices.Clone(scopes)
	if m.err != nil {
		return nil, m.err
	}
	return m.grant, nil
}

func newMinter() *recordingMinter {
	return &recordingMinter{grant: &auth.Grant{
		PairingID:  "pairing-1",
		DeviceCode: secrets.NewRedacted(deviceCodeSecret),
		ExpiresAt:  fixedNow.Add(15 * time.Minute),
	}}
}

// failingAuditor satisfies onboarding.Auditor and always fails, so a test can
// prove the provisioning transaction rolls back when the record cannot be
// written.
type failingAuditor struct{ err error }

func (a failingAuditor) EmitTo(context.Context, repository.AuditAppender, audit.Event) error {
	return a.err
}

// fixture is one test's world.
type fixture struct {
	t      *testing.T
	store  repository.Store
	svc    *onboarding.Service
	minter *recordingMinter
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	store := newStore(t)
	minter := newMinter()
	emitter, err := audit.NewEmitter(store.Repos().Audit)
	if err != nil {
		t.Fatalf("audit.NewEmitter: %v", err)
	}
	svc := mustService(t, onboarding.Params{
		Store:   store,
		Guard:   mustGuard(t),
		Minter:  minter,
		Auditor: emitter,
		Now:     func() time.Time { return fixedNow },
	})
	return &fixture{t: t, store: store, svc: svc, minter: minter}
}

func newStore(t *testing.T) repository.Store {
	t.Helper()
	db, err := sqlite.Open(sqlite.Options{Path: ":memory:"})
	if err != nil {
		t.Fatalf("sqlite.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	migrateUp(t, db)
	store := sqlite.NewStore(db)
	seedAdmin(t, store, activeAdmin, domain.AdminStatusActive)
	seedAdmin(t, store, disabledAdmin, domain.AdminStatusDisabled)
	return store
}

func mustService(t *testing.T, p onboarding.Params) *onboarding.Service {
	t.Helper()
	svc, err := onboarding.New(p)
	if err != nil {
		t.Fatalf("onboarding.New: %v", err)
	}
	return svc
}

func migrateUp(t *testing.T, db *sql.DB) {
	t.Helper()
	reg, err := schema.Registry()
	if err != nil {
		t.Fatalf("schema.Registry: %v", err)
	}
	runner, err := migrate.NewRunner(sqlite.NewMigrateDB(db), migrate.EngineSQLite, reg)
	if err != nil {
		t.Fatalf("migrate.NewRunner: %v", err)
	}
	if _, err := runner.Up(context.Background()); err != nil {
		t.Fatalf("migrate Up: %v", err)
	}
}

func seedAdmin(t *testing.T, store repository.Store, id domain.AdministratorID, status domain.AdminStatus) {
	t.Helper()
	if err := store.Repos().Admins.Create(context.Background(), &domain.Administrator{
		ID: id, Label: string(id), Status: status,
		CreatedAt: fixedNow, UpdatedAt: fixedNow,
	}); err != nil {
		t.Fatalf("Admins.Create(%s): %v", id, err)
	}
}

func mustGuard(t *testing.T) *nameguard.Guard {
	t.Helper()
	g, err := nameguard.Default()
	if err != nil {
		t.Fatalf("nameguard.Default(): %v", err)
	}
	return g
}

// records returns every persisted audit record, newest first.
func (f *fixture) records() []domain.AuditRecord {
	f.t.Helper()
	recs, _, err := f.store.Repos().Audit.List(context.Background(), repository.AuditQuery{}, repository.Page{})
	if err != nil {
		f.t.Fatalf("Audit.List: %v", err)
	}
	return recs
}

func wantErr(t *testing.T, got, want error, what string) {
	t.Helper()
	if !errors.Is(got, want) {
		t.Fatalf("%s: error = %v, want %v", what, got, want)
	}
}

// TestProvisionOwnerHappyPath proves the whole slice: an active admin gets an
// owner with an active handle and a public default key set, all persisted, and
// the returned enrollment code is the minter's device code.
func TestProvisionOwnerHappyPath(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	res, err := f.svc.ProvisionOwner(ctx, activeAdmin, onboarding.Request{Handle: "alice"})
	if err != nil {
		t.Fatalf("ProvisionOwner: %v", err)
	}

	if res.OwnerID == "" {
		t.Fatal("owner id is empty")
	}
	if res.Handle != "alice" {
		t.Fatalf("handle = %q, want alice", res.Handle)
	}
	if res.SetName != onboarding.DefaultSetName {
		t.Fatalf("set name = %q, want %q", res.SetName, onboarding.DefaultSetName)
	}
	if res.EnrollmentCode.Reveal() != deviceCodeSecret {
		t.Fatalf("enrollment code = %q, want the minter's device code", res.EnrollmentCode.Reveal())
	}
	if res.PairingID != "pairing-1" {
		t.Fatalf("pairing id = %q, want pairing-1", res.PairingID)
	}

	owner, err := f.store.Repos().Owners.Get(ctx, res.OwnerID)
	if err != nil {
		t.Fatalf("Owners.Get: %v", err)
	}
	if owner.Status != domain.OwnerStatusActive {
		t.Fatalf("owner status = %q, want active", owner.Status)
	}

	h, err := f.store.Repos().Handles.GetByName(ctx, "alice")
	if err != nil {
		t.Fatalf("Handles.GetByName: %v", err)
	}
	if h.OwnerID != res.OwnerID {
		t.Fatalf("handle owner = %q, want %q", h.OwnerID, res.OwnerID)
	}

	sets, err := f.store.Repos().KeySets.ListByOwner(ctx, res.OwnerID)
	if err != nil {
		t.Fatalf("KeySets.ListByOwner: %v", err)
	}
	if len(sets) != 1 {
		t.Fatalf("owner has %d sets, want 1", len(sets))
	}
	if !sets[0].IsDefault || sets[0].Visibility != domain.VisibilityPublic {
		t.Fatalf("default set = %+v, want default+public", sets[0])
	}

	if f.minter.ownerID != res.OwnerID {
		t.Fatalf("minter owner = %q, want %q", f.minter.ownerID, res.OwnerID)
	}
	if len(f.minter.scopes) != 1 || f.minter.scopes[0].Kind != domain.ScopeFullOwner {
		t.Fatalf("minter scopes = %+v, want one full-owner", f.minter.scopes)
	}
}

// TestProvisionOwnerAuditRecordCarriesNoCredential proves an owner.created
// record is persisted with the handle and set name, and that the enrollment
// code appears in NO detail value — a credential must never reach the audit log.
func TestProvisionOwnerAuditRecordCarriesNoCredential(t *testing.T) {
	f := newFixture(t)

	res, err := f.svc.ProvisionOwner(context.Background(), activeAdmin, onboarding.Request{Handle: "bob"})
	if err != nil {
		t.Fatalf("ProvisionOwner: %v", err)
	}

	recs := f.records()
	if len(recs) != 1 {
		t.Fatalf("persisted %d audit records, want 1", len(recs))
	}
	rec := recs[0]
	if rec.Action != domain.AuditActionOwnerCreated {
		t.Fatalf("action = %q, want %q", rec.Action, domain.AuditActionOwnerCreated)
	}
	if rec.ActorType != domain.ActorTypeAdministrator || rec.ActorID != string(activeAdmin) {
		t.Fatalf("actor = %q/%q, want administrator/%s", rec.ActorType, rec.ActorID, activeAdmin)
	}
	if rec.TargetType != domain.TargetTypeOwner || rec.TargetID != string(res.OwnerID) {
		t.Fatalf("target = %q/%q, want owner/%s", rec.TargetType, rec.TargetID, res.OwnerID)
	}
	if rec.Metadata[string(audit.DetailHandle)] != "bob" {
		t.Fatalf("handle detail = %q, want bob", rec.Metadata[string(audit.DetailHandle)])
	}
	for k, v := range rec.Metadata {
		if v == deviceCodeSecret {
			t.Fatalf("detail %q leaked the enrollment code", k)
		}
	}
}

// TestProvisionOwnerRejectsReservedHandle proves the COMPOSED guard's blocklist
// refuses a reserved handle, and that nothing was written when it does.
func TestProvisionOwnerRejectsReservedHandle(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	_, err := f.svc.ProvisionOwner(ctx, activeAdmin, onboarding.Request{Handle: "admin"})
	wantErr(t, err, domain.ErrBlockedName, "reserved handle")

	if _, err := f.store.Repos().Handles.GetByName(ctx, "admin"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("handle lookup after refusal: err = %v, want ErrNotFound", err)
	}
	if f.minter.calls != 0 {
		t.Fatalf("minter called %d times after a refused handle, want 0", f.minter.calls)
	}
}

// TestProvisionOwnerRejectsBlockedSetName proves an explicitly supplied set name
// is checked against the blocklist too.
func TestProvisionOwnerRejectsBlockedSetName(t *testing.T) {
	f := newFixture(t)

	_, err := f.svc.ProvisionOwner(context.Background(), activeAdmin, onboarding.Request{
		Handle: "carol", SetName: "admin",
	})
	wantErr(t, err, domain.ErrBlockedName, "reserved set name")
}

// TestProvisionOwnerRejectsInvalidHandle proves a syntactically invalid handle
// is refused before any write.
func TestProvisionOwnerRejectsInvalidHandle(t *testing.T) {
	f := newFixture(t)

	_, err := f.svc.ProvisionOwner(context.Background(), activeAdmin, onboarding.Request{Handle: "A B"})
	if err == nil {
		t.Fatal("invalid handle was accepted")
	}
	if !errors.Is(err, domain.ErrInvalidInput) && !errors.Is(err, domain.ErrBlockedName) {
		t.Fatalf("invalid handle: err = %v, want invalid-input or blocked-name", err)
	}
}

// TestProvisionOwnerDuplicateHandleConflicts proves a second claim on a taken
// handle is a conflict, not a silent overwrite.
func TestProvisionOwnerDuplicateHandleConflicts(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	if _, err := f.svc.ProvisionOwner(ctx, activeAdmin, onboarding.Request{Handle: "dave"}); err != nil {
		t.Fatalf("first ProvisionOwner: %v", err)
	}
	_, err := f.svc.ProvisionOwner(ctx, activeAdmin, onboarding.Request{Handle: "dave"})
	wantErr(t, err, domain.ErrConflict, "duplicate handle")
}

// TestProvisionOwnerRejectsUnknownAdministrator proves an actor that names no
// administrator is refused, fail-closed, before any write.
func TestProvisionOwnerRejectsUnknownAdministrator(t *testing.T) {
	f := newFixture(t)

	_, err := f.svc.ProvisionOwner(context.Background(), "ghost", onboarding.Request{Handle: "erin"})
	wantErr(t, err, domain.ErrUnauthorized, "unknown administrator")
	if f.minter.calls != 0 {
		t.Fatalf("minter called for an unauthorized actor")
	}
}

// TestProvisionOwnerRejectsEmptyActor proves "no administrator named" is refused.
func TestProvisionOwnerRejectsEmptyActor(t *testing.T) {
	f := newFixture(t)

	_, err := f.svc.ProvisionOwner(context.Background(), "", onboarding.Request{Handle: "erin"})
	wantErr(t, err, domain.ErrUnauthorized, "empty actor")
}

// TestProvisionOwnerRejectsDisabledAdministrator proves a disabled admin's
// still-identifiable id cannot provision — the check that transport signature
// verification alone would miss.
func TestProvisionOwnerRejectsDisabledAdministrator(t *testing.T) {
	f := newFixture(t)

	_, err := f.svc.ProvisionOwner(context.Background(), disabledAdmin, onboarding.Request{Handle: "erin"})
	wantErr(t, err, domain.ErrForbidden, "disabled administrator")
}

// TestProvisionOwnerMintFailureRollsBackWholeProvision proves the provision is
// all-or-nothing: because the credential mint runs INSIDE the owner-create
// transaction (MintInto), a mint failure rolls the owner, handle, key set and
// audit record back with it. No owner is stranded with a claimed handle and no
// way to enroll, and the handle is immediately reclaimable by a retry.
func TestProvisionOwnerMintFailureRollsBackWholeProvision(t *testing.T) {
	f := newFixture(t)
	f.minter.err = errors.New("mint boom")
	ctx := context.Background()

	_, err := f.svc.ProvisionOwner(ctx, activeAdmin, onboarding.Request{Handle: "frank"})
	if err == nil {
		t.Fatal("mint failure did not surface")
	}
	if !f.minter.sawTx {
		t.Fatal("mint did not run through the transaction-bound repos; the provision is not atomic")
	}
	// Nothing committed: no handle, and (the audit record only commits with the
	// owner) no owner.created record.
	if _, err := f.store.Repos().Handles.GetByName(ctx, "frank"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("handle survived a rolled-back provision: err = %v, want ErrNotFound", err)
	}
	if recs := f.records(); len(recs) != 0 {
		t.Fatalf("audit record survived a rolled-back provision: %d records", len(recs))
	}

	// The handle is reclaimable — a fresh provision with a working minter succeeds
	// on the very same handle, proving the first attempt left no trace.
	f.minter.err = nil
	res, err := f.svc.ProvisionOwner(ctx, activeAdmin, onboarding.Request{Handle: "frank"})
	if err != nil {
		t.Fatalf("retry after rollback failed: %v", err)
	}
	if _, err := f.store.Repos().Owners.Get(ctx, res.OwnerID); err != nil {
		t.Fatalf("retry did not create the owner: %v", err)
	}
}

// TestProvisionOwnerAuditFailureRollsBack proves a failed audit write aborts the
// whole provision: with the record un-writable, no owner is left behind.
func TestProvisionOwnerAuditFailureRollsBack(t *testing.T) {
	store := newStore(t)
	svc := mustService(t, onboarding.Params{
		Store:   store,
		Guard:   mustGuard(t),
		Minter:  newMinter(),
		Auditor: failingAuditor{err: errors.New("audit boom")},
		Now:     func() time.Time { return fixedNow },
	})
	ctx := context.Background()

	_, err := svc.ProvisionOwner(ctx, activeAdmin, onboarding.Request{Handle: "grace"})
	if err == nil {
		t.Fatal("audit failure did not surface")
	}
	if _, err := store.Repos().Handles.GetByName(ctx, "grace"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("handle survived a rolled-back provision: err = %v, want ErrNotFound", err)
	}
}

// TestNewRefusesNilDependencies proves the service refuses to construct without
// each required dependency — a nil guard is refused here, not silently tolerated
// into a total blocklist bypass.
func TestNewRefusesNilDependencies(t *testing.T) {
	store := newStore(t)
	emitter, err := audit.NewEmitter(store.Repos().Audit)
	if err != nil {
		t.Fatalf("audit.NewEmitter: %v", err)
	}
	good := onboarding.Params{
		Store:   store,
		Guard:   mustGuard(t),
		Minter:  newMinter(),
		Auditor: emitter,
	}

	cases := map[string]func(onboarding.Params) onboarding.Params{
		"nil store":   func(p onboarding.Params) onboarding.Params { p.Store = nil; return p },
		"nil guard":   func(p onboarding.Params) onboarding.Params { p.Guard = nil; return p },
		"nil minter":  func(p onboarding.Params) onboarding.Params { p.Minter = nil; return p },
		"nil auditor": func(p onboarding.Params) onboarding.Params { p.Auditor = nil; return p },
	}
	for name, mangle := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := onboarding.New(mangle(good)); !errors.Is(err, domain.ErrInvalidInput) {
				t.Fatalf("New(%s): err = %v, want ErrInvalidInput", name, err)
			}
		})
	}
}
