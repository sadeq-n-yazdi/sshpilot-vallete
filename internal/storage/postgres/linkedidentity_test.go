package postgres

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/repository"
)

// newLinkedIdentity returns a fully populated linked identity. email is
// optional so the nullable column can be exercised in both states.
func newLinkedIdentity(id, ownerID, provider, subject string, email *string) *domain.LinkedIdentity {
	return &domain.LinkedIdentity{
		ID:        domain.LinkedIdentityID(id),
		OwnerID:   domain.OwnerID(ownerID),
		Provider:  provider,
		Subject:   subject,
		Email:     email,
		CreatedAt: testClock,
		UpdatedAt: testClock,
	}
}

// mustCreateLinkedIdentity creates a linked identity through the auto-commit
// repos, failing the test on error.
func mustCreateLinkedIdentity(t *testing.T, s *Store, li *domain.LinkedIdentity) *domain.LinkedIdentity {
	t.Helper()
	if err := s.Repos().LinkedIdentities.Create(context.Background(), li); err != nil {
		t.Fatalf("create linked identity %q: %v", li.ID, err)
	}
	return li
}

func strptr(s string) *string { return &s }

func TestLinkedIdentityCreateAndGetRoundTrips(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	mustCreateOwner(t, s, "o-1")

	want := mustCreateLinkedIdentity(t, s, newLinkedIdentity("li-1", "o-1", "github", "sub-1", strptr("a@example.test")))

	got, err := s.Repos().LinkedIdentities.GetByProviderSubject(ctx, "github", "sub-1")
	if err != nil {
		t.Fatalf("GetByProviderSubject: %v", err)
	}
	if got.ID != want.ID || got.OwnerID != want.OwnerID {
		t.Errorf("identity = %q/%q, want %q/%q", got.ID, got.OwnerID, want.ID, want.OwnerID)
	}
	if got.Provider != "github" || got.Subject != "sub-1" {
		t.Errorf("provider/subject = %q/%q, want github/sub-1", got.Provider, got.Subject)
	}
	if got.Email == nil || *got.Email != "a@example.test" {
		t.Errorf("email = %v, want a@example.test", got.Email)
	}
	if !got.CreatedAt.Equal(testClock) || !got.UpdatedAt.Equal(testClock) {
		t.Errorf("timestamps = %v/%v, want %v", got.CreatedAt, got.UpdatedAt, testClock)
	}
	if got.CreatedAt.Location() != time.UTC {
		t.Errorf("CreatedAt location = %v, want UTC", got.CreatedAt.Location())
	}
}

// A timestamp presented in a non-UTC zone must come back as the same instant in
// UTC: encTime normalizes before formatting, so the stored text is zone-free.
func TestLinkedIdentityTimestampsRoundTripFromNonUTCZone(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	mustCreateOwner(t, s, "o-1")

	zone := time.FixedZone("UTC+5", 5*60*60)
	li := newLinkedIdentity("li-tz", "o-1", "github", "sub-tz", nil)
	li.CreatedAt = testClock.In(zone)
	li.UpdatedAt = testClock.In(zone).Add(90 * time.Minute)
	mustCreateLinkedIdentity(t, s, li)

	got, err := s.Repos().LinkedIdentities.GetByProviderSubject(ctx, "github", "sub-tz")
	if err != nil {
		t.Fatalf("GetByProviderSubject: %v", err)
	}
	if !got.CreatedAt.Equal(testClock) {
		t.Errorf("CreatedAt = %v, want the same instant as %v", got.CreatedAt, testClock)
	}
	if !got.UpdatedAt.Equal(testClock.Add(90 * time.Minute)) {
		t.Errorf("UpdatedAt = %v, want %v", got.UpdatedAt, testClock.Add(90*time.Minute))
	}
	if got.CreatedAt.Location() != time.UTC || got.UpdatedAt.Location() != time.UTC {
		t.Errorf("locations = %v/%v, want UTC", got.CreatedAt.Location(), got.UpdatedAt.Location())
	}
}

func TestLinkedIdentityNilEmailRoundTrips(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	mustCreateOwner(t, s, "o-1")
	mustCreateLinkedIdentity(t, s, newLinkedIdentity("li-1", "o-1", "github", "sub-1", nil))

	got, err := s.Repos().LinkedIdentities.GetByProviderSubject(ctx, "github", "sub-1")
	if err != nil {
		t.Fatalf("GetByProviderSubject: %v", err)
	}
	if got.Email != nil {
		t.Errorf("email = %v, want nil", got.Email)
	}
}

// An empty string is a value, not an absence: it must round-trip as an empty
// string rather than collapsing into SQL NULL.
func TestLinkedIdentityEmptyEmailIsNotNull(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	mustCreateOwner(t, s, "o-1")
	mustCreateLinkedIdentity(t, s, newLinkedIdentity("li-1", "o-1", "github", "sub-1", strptr("")))

	got, err := s.Repos().LinkedIdentities.GetByProviderSubject(ctx, "github", "sub-1")
	if err != nil {
		t.Fatalf("GetByProviderSubject: %v", err)
	}
	if got.Email == nil {
		t.Fatalf("email = nil, want an empty string")
	}
	if *got.Email != "" {
		t.Errorf("email = %q, want empty", *got.Email)
	}
}

func TestLinkedIdentityCreateRejectsNil(t *testing.T) {
	t.Parallel()
	s := newStore(t)

	err := s.Repos().LinkedIdentities.Create(context.Background(), nil)
	if !errors.Is(err, domain.ErrInvalidInput) {
		t.Fatalf("Create(nil) = %v, want ErrInvalidInput", err)
	}
}

// A duplicate primary key is SQLSTATE 23505, which mapError turns into the same
// domain.ErrConflict the SQLite adapter derives from its extended codes.
func TestLinkedIdentityCreateRejectsDuplicateID(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	mustCreateOwner(t, s, "o-1")
	mustCreateLinkedIdentity(t, s, newLinkedIdentity("li-1", "o-1", "github", "sub-1", nil))

	err := s.Repos().LinkedIdentities.Create(ctx, newLinkedIdentity("li-1", "o-1", "gitlab", "sub-2", nil))
	if !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("duplicate id = %v, want ErrConflict", err)
	}
}

// The (provider, subject) unique index is what stops one external subject from
// being bound to a second owner.
func TestLinkedIdentityRejectsSameSubjectForAnotherOwner(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	mustCreateOwner(t, s, "o-1")
	mustCreateOwner(t, s, "o-2")
	mustCreateLinkedIdentity(t, s, newLinkedIdentity("li-1", "o-1", "github", "sub-1", nil))

	err := s.Repos().LinkedIdentities.Create(ctx, newLinkedIdentity("li-2", "o-2", "github", "sub-1", nil))
	if !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("cross-owner subject rebind = %v, want ErrConflict", err)
	}

	got, err := s.Repos().LinkedIdentities.GetByProviderSubject(ctx, "github", "sub-1")
	if err != nil {
		t.Fatalf("GetByProviderSubject: %v", err)
	}
	if got.OwnerID != "o-1" {
		t.Errorf("subject now bound to %q, want o-1", got.OwnerID)
	}
}

// The same subject string from a different provider is a different identity;
// the unique index covers the pair, not the subject alone.
func TestLinkedIdentityAllowsSameSubjectAcrossProviders(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	mustCreateOwner(t, s, "o-1")
	mustCreateLinkedIdentity(t, s, newLinkedIdentity("li-1", "o-1", "github", "sub-1", nil))

	if err := s.Repos().LinkedIdentities.Create(ctx, newLinkedIdentity("li-2", "o-1", "gitlab", "sub-1", nil)); err != nil {
		t.Fatalf("same subject on another provider: %v", err)
	}
}

func TestLinkedIdentityGetByProviderSubjectMissing(t *testing.T) {
	t.Parallel()
	s := newStore(t)

	_, err := s.Repos().LinkedIdentities.GetByProviderSubject(context.Background(), "github", "nobody")
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("missing identity = %v, want ErrNotFound", err)
	}
}

// Both halves of the pair are part of the predicate: a matching provider with
// the wrong subject, or the reverse, resolves to nothing.
func TestLinkedIdentityGetRequiresBothProviderAndSubject(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	mustCreateOwner(t, s, "o-1")
	mustCreateLinkedIdentity(t, s, newLinkedIdentity("li-1", "o-1", "github", "sub-1", nil))

	if _, err := s.Repos().LinkedIdentities.GetByProviderSubject(ctx, "github", "sub-2"); !errors.Is(err, domain.ErrNotFound) {
		t.Errorf("wrong subject = %v, want ErrNotFound", err)
	}
	if _, err := s.Repos().LinkedIdentities.GetByProviderSubject(ctx, "gitlab", "sub-1"); !errors.Is(err, domain.ErrNotFound) {
		t.Errorf("wrong provider = %v, want ErrNotFound", err)
	}
}

func TestLinkedIdentityListByOwnerIsScopedAndOrdered(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	mustCreateOwner(t, s, "o-1")
	mustCreateOwner(t, s, "o-2")

	// Same creation timestamp on purpose, so the id tiebreak is what makes the
	// order total.
	mustCreateLinkedIdentity(t, s, newLinkedIdentity("li-b", "o-1", "github", "sub-b", nil))
	mustCreateLinkedIdentity(t, s, newLinkedIdentity("li-a", "o-1", "gitlab", "sub-a", nil))
	mustCreateLinkedIdentity(t, s, newLinkedIdentity("li-z", "o-2", "github", "sub-z", nil))

	got, err := s.Repos().LinkedIdentities.ListByOwner(ctx, "o-1")
	if err != nil {
		t.Fatalf("ListByOwner: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2 (other owner's identity must not appear)", len(got))
	}
	if got[0].ID != "li-a" || got[1].ID != "li-b" {
		t.Errorf("order = %q,%q, want li-a,li-b", got[0].ID, got[1].ID)
	}
	for _, li := range got {
		if li.OwnerID != "o-1" {
			t.Errorf("identity %q belongs to %q, want o-1", li.ID, li.OwnerID)
		}
	}
}

// Owner B listing must return exactly what an owner id that was never created
// returns: nothing. The two answers being identical is the isolation property.
func TestLinkedIdentityListByOwnerIsIndistinguishableFromInventedOwner(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	mustCreateOwner(t, s, "o-1")
	mustCreateOwner(t, s, "o-2")
	mustCreateLinkedIdentity(t, s, newLinkedIdentity("li-1", "o-1", "github", "sub-1", nil))

	other, err := s.Repos().LinkedIdentities.ListByOwner(ctx, "o-2")
	if err != nil {
		t.Fatalf("ListByOwner(o-2): %v", err)
	}
	invented, err := s.Repos().LinkedIdentities.ListByOwner(ctx, "o-never-created")
	if err != nil {
		t.Fatalf("ListByOwner(invented): %v", err)
	}
	if other != nil || invented != nil {
		t.Errorf("lists = %v / %v, want nil / nil", other, invented)
	}
}

// An owner with nothing linked gets a nil slice, matching the package
// convention that an empty list is nil rather than an allocated empty slice.
func TestLinkedIdentityListByOwnerEmptyIsNil(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	mustCreateOwner(t, s, "o-1")

	got, err := s.Repos().LinkedIdentities.ListByOwner(ctx, "o-1")
	if err != nil {
		t.Fatalf("ListByOwner: %v", err)
	}
	if got != nil {
		t.Errorf("list = %v, want nil", got)
	}
}

func TestLinkedIdentityDelete(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	mustCreateOwner(t, s, "o-1")
	mustCreateLinkedIdentity(t, s, newLinkedIdentity("li-1", "o-1", "github", "sub-1", nil))

	if err := s.Repos().LinkedIdentities.Delete(ctx, "o-1", "li-1"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := s.Repos().LinkedIdentities.GetByProviderSubject(ctx, "github", "sub-1"); !errors.Is(err, domain.ErrNotFound) {
		t.Errorf("identity still present after delete: %v", err)
	}
}

func TestLinkedIdentityDeleteMissing(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	mustCreateOwner(t, s, "o-1")

	err := s.Repos().LinkedIdentities.Delete(ctx, "o-1", "li-absent")
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("delete missing = %v, want ErrNotFound", err)
	}
}

// Deleting another owner's identity must fail as ErrNotFound — byte for byte
// the error an id that never existed produces, so the caller cannot tell the
// two apart — and must leave the row untouched.
func TestLinkedIdentityDeleteIsOwnerScoped(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	mustCreateOwner(t, s, "o-1")
	mustCreateOwner(t, s, "o-2")
	mustCreateLinkedIdentity(t, s, newLinkedIdentity("li-1", "o-1", "github", "sub-1", nil))

	crossOwner := s.Repos().LinkedIdentities.Delete(ctx, "o-2", "li-1")
	if !errors.Is(crossOwner, domain.ErrNotFound) {
		t.Fatalf("cross-owner delete = %v, want ErrNotFound", crossOwner)
	}
	invented := s.Repos().LinkedIdentities.Delete(ctx, "o-2", "li-never-existed")
	if crossOwner.Error() != invented.Error() {
		t.Errorf("cross-owner error %q differs from invented-id error %q; that difference is an existence oracle",
			crossOwner, invented)
	}

	got, err := s.Repos().LinkedIdentities.ListByOwner(ctx, "o-1")
	if err != nil {
		t.Fatalf("ListByOwner: %v", err)
	}
	if len(got) != 1 {
		t.Errorf("owner has %d identities after cross-owner delete, want 1", len(got))
	}
}

func TestLinkedIdentityDeleteByOwner(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	mustCreateOwner(t, s, "o-1")
	mustCreateOwner(t, s, "o-2")
	mustCreateLinkedIdentity(t, s, newLinkedIdentity("li-1", "o-1", "github", "sub-1", nil))
	mustCreateLinkedIdentity(t, s, newLinkedIdentity("li-2", "o-1", "gitlab", "sub-2", nil))
	mustCreateLinkedIdentity(t, s, newLinkedIdentity("li-3", "o-2", "github", "sub-3", nil))

	n, err := s.Repos().LinkedIdentities.DeleteByOwner(ctx, "o-1")
	if err != nil {
		t.Fatalf("DeleteByOwner: %v", err)
	}
	if n != 2 {
		t.Errorf("deleted = %d, want 2", n)
	}

	// The other owner's identity must survive an erasure sweep of o-1.
	survivors, err := s.Repos().LinkedIdentities.ListByOwner(ctx, "o-2")
	if err != nil {
		t.Fatalf("ListByOwner(o-2): %v", err)
	}
	if len(survivors) != 1 || survivors[0].ID != "li-3" {
		t.Errorf("o-2 identities = %v, want just li-3", survivors)
	}
}

// An owner with nothing linked is already in the requested state, so an erasure
// sweep reports zero rather than failing.
func TestLinkedIdentityDeleteByOwnerEmptyIsNotAnError(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	mustCreateOwner(t, s, "o-1")

	n, err := s.Repos().LinkedIdentities.DeleteByOwner(ctx, "o-1")
	if err != nil {
		t.Fatalf("DeleteByOwner: %v", err)
	}
	if n != 0 {
		t.Errorf("deleted = %d, want 0", n)
	}
}

// The repository composes into a caller-managed transaction: a rollback must
// discard the identity written inside it.
func TestLinkedIdentityTransactional(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	mustCreateOwner(t, s, "o-1")
	boom := errors.New("boom")

	err := s.WithTx(ctx, func(ctx context.Context, r repository.Repos) error {
		if cerr := r.LinkedIdentities.Create(ctx, newLinkedIdentity("li-tx", "o-1", "github", "sub-tx", nil)); cerr != nil {
			return cerr
		}
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatalf("WithTx = %v, want boom", err)
	}
	if _, err := s.Repos().LinkedIdentities.GetByProviderSubject(ctx, "github", "sub-tx"); !errors.Is(err, domain.ErrNotFound) {
		t.Errorf("identity survived rollback: %v", err)
	}
}

// A timestamp column holding text encTime never produced must surface as a
// decode error rather than a zero time silently standing in for a real instant.
func TestLinkedIdentityRejectsCorruptTimestamp(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	mustCreateOwner(t, s, "o-1")
	mustCreateLinkedIdentity(t, s, newLinkedIdentity("li-1", "o-1", "github", "sub-1", nil))

	if _, err := s.db.ExecContext(ctx,
		`UPDATE linked_identities SET created_at = $1 WHERE id = $2`, "not-a-timestamp", "li-1"); err != nil {
		t.Fatalf("corrupt row: %v", err)
	}

	if _, err := s.Repos().LinkedIdentities.GetByProviderSubject(ctx, "github", "sub-1"); err == nil {
		t.Error("corrupt created_at decoded without error")
	}
}

func TestDecNullText(t *testing.T) {
	t.Parallel()

	if got := decNullText(sql.NullString{}); got != nil {
		t.Errorf("decNullText(NULL) = %v, want nil", got)
	}
	got := decNullText(sql.NullString{String: "v", Valid: true})
	if got == nil || *got != "v" {
		t.Errorf("decNullText(v) = %v, want pointer to v", got)
	}
}

func TestEncNullText(t *testing.T) {
	t.Parallel()

	if got := encNullText(nil); got != nil {
		t.Errorf("encNullText(nil) = %v, want nil", got)
	}
	if got := encNullText(strptr("")); got != "" {
		t.Errorf("encNullText(\"\") = %v, want an empty string, not NULL", got)
	}
}
