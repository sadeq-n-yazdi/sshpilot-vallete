package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"testing"

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
}

// A nil email must round-trip as SQL NULL and decode back to nil, which is the
// post-crypto-erasure state as well as the no-address-released state.
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
		t.Errorf("email = %v, want nil", *got.Email)
	}
}

// An empty email must stay an empty string rather than collapsing into NULL,
// so "erased" (NULL) stays distinguishable from "present but empty".
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
		t.Fatalf("email = nil, want empty string")
	}
	if *got.Email != "" {
		t.Errorf("email = %q, want empty string", *got.Email)
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

func TestLinkedIdentityCreateRejectsDuplicateID(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	mustCreateOwner(t, s, "o-1")
	mustCreateLinkedIdentity(t, s, newLinkedIdentity("li-1", "o-1", "github", "sub-1", nil))

	err := s.Repos().LinkedIdentities.Create(ctx, newLinkedIdentity("li-1", "o-1", "gitlab", "sub-9", nil))
	if !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("duplicate id = %v, want ErrConflict", err)
	}
}

// The (provider, subject) unique index is the control that stops one external
// subject being bound to a second owner. A second link attempt must be refused
// even when it comes from a different owner — that is the account-takeover
// case, not merely a duplicate-row case.
func TestLinkedIdentityRejectsSameSubjectForAnotherOwner(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	mustCreateOwner(t, s, "o-1")
	mustCreateOwner(t, s, "o-2")
	mustCreateLinkedIdentity(t, s, newLinkedIdentity("li-1", "o-1", "github", "sub-1", nil))

	err := s.Repos().LinkedIdentities.Create(ctx, newLinkedIdentity("li-2", "o-2", "github", "sub-1", nil))
	if !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("cross-owner duplicate subject = %v, want ErrConflict", err)
	}

	// The original binding must be intact: the takeover attempt must not have
	// repointed the subject at the second owner.
	got, err := s.Repos().LinkedIdentities.GetByProviderSubject(ctx, "github", "sub-1")
	if err != nil {
		t.Fatalf("GetByProviderSubject: %v", err)
	}
	if got.OwnerID != "o-1" {
		t.Errorf("subject now bound to %q, want o-1", got.OwnerID)
	}
}

// The same subject string under a different provider is a different identity
// and must be allowed; the index is on the pair, not on subject alone.
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

	_, err := s.Repos().LinkedIdentities.GetByProviderSubject(context.Background(), "github", "absent")
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("missing identity = %v, want ErrNotFound", err)
	}
}

// A provider/subject mismatch must not resolve: a subject registered under one
// provider must never be returned for another provider, or a caller could
// present an identity asserted by a weaker issuer and log in as the owner.
func TestLinkedIdentityGetRequiresBothProviderAndSubject(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	mustCreateOwner(t, s, "o-1")
	mustCreateLinkedIdentity(t, s, newLinkedIdentity("li-1", "o-1", "github", "sub-1", nil))

	if _, err := s.Repos().LinkedIdentities.GetByProviderSubject(ctx, "gitlab", "sub-1"); !errors.Is(err, domain.ErrNotFound) {
		t.Errorf("wrong provider = %v, want ErrNotFound", err)
	}
	if _, err := s.Repos().LinkedIdentities.GetByProviderSubject(ctx, "github", "sub-2"); !errors.Is(err, domain.ErrNotFound) {
		t.Errorf("wrong subject = %v, want ErrNotFound", err)
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

// Deleting another owner's identity must fail as ErrNotFound — the same error
// as a missing row, so the caller cannot tell that the id exists — and must
// leave the row untouched.
func TestLinkedIdentityDeleteIsOwnerScoped(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	mustCreateOwner(t, s, "o-1")
	mustCreateOwner(t, s, "o-2")
	mustCreateLinkedIdentity(t, s, newLinkedIdentity("li-1", "o-1", "github", "sub-1", nil))

	err := s.Repos().LinkedIdentities.Delete(ctx, "o-2", "li-1")
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("cross-owner delete = %v, want ErrNotFound", err)
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

	// The erasure sweep must not reach across owners.
	other, err := s.Repos().LinkedIdentities.ListByOwner(ctx, "o-2")
	if err != nil {
		t.Fatalf("ListByOwner: %v", err)
	}
	if len(other) != 1 {
		t.Errorf("other owner has %d identities, want 1", len(other))
	}
}

// An owner with nothing linked is already in the requested state, so the
// erasure sweep reports zero and succeeds rather than failing ErrNotFound.
func TestLinkedIdentityDeleteByOwnerEmptyIsNotAnError(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	mustCreateOwner(t, s, "o-1")

	n, err := s.Repos().LinkedIdentities.DeleteByOwner(ctx, "o-1")
	if err != nil {
		t.Fatalf("DeleteByOwner on empty owner = %v, want nil", err)
	}
	if n != 0 {
		t.Errorf("deleted = %d, want 0", n)
	}
}

// A rolled-back transaction must leave no linked identity behind.
func TestLinkedIdentityTransactional(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	mustCreateOwner(t, s, "o-1")

	sentinel := errors.New("rollback")
	err := s.WithTx(ctx, func(ctx context.Context, r repository.Repos) error {
		if cerr := r.LinkedIdentities.Create(ctx, newLinkedIdentity("li-1", "o-1", "github", "sub-1", nil)); cerr != nil {
			return cerr
		}
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("WithTx = %v, want sentinel", err)
	}

	if _, err := s.Repos().LinkedIdentities.GetByProviderSubject(ctx, "github", "sub-1"); !errors.Is(err, domain.ErrNotFound) {
		t.Errorf("identity survived rollback: %v", err)
	}
}

func TestLinkedIdentitySurfacesDriverErrors(t *testing.T) {
	t.Parallel()
	repo := &linkedIdentityRepo{e: closedStore(t).db}
	ctx := context.Background()

	if err := repo.Create(ctx, newLinkedIdentity("li-1", "o-1", "github", "sub-1", nil)); err == nil {
		t.Error("Create on closed db = nil, want error")
	}
	if _, err := repo.GetByProviderSubject(ctx, "github", "sub-1"); err == nil {
		t.Error("GetByProviderSubject on closed db = nil, want error")
	}
	if _, err := repo.ListByOwner(ctx, "o-1"); err == nil {
		t.Error("ListByOwner on closed db = nil, want error")
	}
	if err := repo.Delete(ctx, "o-1", "li-1"); err == nil {
		t.Error("Delete on closed db = nil, want error")
	}
	if _, err := repo.DeleteByOwner(ctx, "o-1"); err == nil {
		t.Error("DeleteByOwner on closed db = nil, want error")
	}
}

// A RowsAffected failure must surface, not be reported as zero rows deleted —
// an erasure sweep that silently claims it removed nothing (or that a delete
// found no row) would hide a storage fault.
func TestLinkedIdentitySurfacesRowsAffectedErrors(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	mustCreateOwner(t, s, "o-1")
	mustCreateLinkedIdentity(t, s, newLinkedIdentity("li-1", "o-1", "github", "sub-1", nil))

	boom := errors.New("rows affected failed")
	repo := &linkedIdentityRepo{e: countErrExecer{execer: s.db, err: boom}}

	if err := repo.Delete(ctx, "o-1", "li-1"); !errors.Is(err, boom) {
		t.Errorf("Delete = %v, want %v", err, boom)
	}
	if _, err := repo.DeleteByOwner(ctx, "o-1"); !errors.Is(err, boom) {
		t.Errorf("DeleteByOwner = %v, want %v", err, boom)
	}
}

// A row whose stored timestamps are unparseable must fail loudly rather than
// decode into a zero time that downstream code would treat as a real instant.
func TestLinkedIdentityRejectsCorruptRows(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	mustCreateOwner(t, s, "o-1")

	insert := func(t *testing.T, id, createdAt, updatedAt string) {
		t.Helper()
		const q = `INSERT INTO linked_identities (id, owner_id, provider, subject, email, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?)`
		if _, err := s.db.ExecContext(ctx, q, id, "o-1", "github", id, nil, createdAt, updatedAt); err != nil {
			t.Fatalf("raw insert: %v", err)
		}
	}

	insert(t, "li-bad-created", "not-a-time", encTime(testClock))
	if _, err := s.Repos().LinkedIdentities.GetByProviderSubject(ctx, "github", "li-bad-created"); err == nil {
		t.Error("corrupt created_at = nil, want error")
	}

	insert(t, "li-bad-updated", encTime(testClock), "not-a-time")
	if _, err := s.Repos().LinkedIdentities.GetByProviderSubject(ctx, "github", "li-bad-updated"); err == nil {
		t.Error("corrupt updated_at = nil, want error")
	}

	// The same failure must propagate through the iterating list path, not just
	// the single-row read.
	if _, err := s.Repos().LinkedIdentities.ListByOwner(ctx, "o-1"); err == nil {
		t.Error("ListByOwner over corrupt rows = nil, want error")
	}
}

// decNullText is exercised indirectly above; this pins the NULL branch against
// a directly-constructed NullString so the mapping cannot silently invert.
func TestDecNullText(t *testing.T) {
	t.Parallel()

	if got := decNullText(sql.NullString{}); got != nil {
		t.Errorf("NULL = %q, want nil", *got)
	}
	got := decNullText(sql.NullString{String: "v", Valid: true})
	if got == nil || *got != "v" {
		t.Errorf("valid = %v, want v", got)
	}
}
