package postgres

import (
	"context"
	"errors"
	"testing"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/repository"
)

func TestKeySetDeleteRemovesMembershipButKeepsKeys(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	mustCreateKeySet(t, s, newKeySet("ks-1", "owner-a", "primary"))
	mustCreatePublicKey(t, s, newPublicKey("k-1", "owner-a", "d-1"))
	if err := s.Repos().KeySets.AddMember(ctx, "owner-a", "ks-1", "k-1", testClock); err != nil {
		t.Fatalf("AddMember: %v", err)
	}

	if err := s.Repos().KeySets.Delete(ctx, "owner-a", "ks-1"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := s.Repos().KeySets.Get(ctx, "owner-a", "ks-1"); !errors.Is(err, domain.ErrNotFound) {
		t.Errorf("Get after Delete = %v, want ErrNotFound", err)
	}
	// The public key itself must survive; only the membership is removed.
	if _, err := s.Repos().PublicKeys.Get(ctx, "owner-a", "k-1"); err != nil {
		t.Errorf("Delete removed the referenced public key: %v", err)
	}
}

// TestKeySetAddMemberHappyPathAndDuplicateConflicts pins both halves of the
// INSERT contract: a valid membership is written, and a second identical
// AddMember trips the composite primary key and maps to ErrConflict. It must
// NOT be silently ignored, which would report ErrNotFound instead and hide a
// real duplicate from the caller.
func TestKeySetAddMemberHappyPathAndDuplicateConflicts(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	mustCreateKeySet(t, s, newKeySet("ks-1", "owner-a", "primary"))
	mustCreatePublicKey(t, s, newPublicKey("k-1", "owner-a", "d-1"))

	if err := s.Repos().KeySets.AddMember(ctx, "owner-a", "ks-1", "k-1", testClock); err != nil {
		t.Fatalf("AddMember: %v", err)
	}
	members, err := s.Repos().KeySets.ListMembers(ctx, "owner-a", "ks-1")
	if err != nil {
		t.Fatalf("ListMembers: %v", err)
	}
	if len(members) != 1 || members[0].PublicKeyID != "k-1" || !members[0].AddedAt.Equal(testClock) {
		t.Fatalf("ListMembers = %+v, want one k-1 added at %v", members, testClock)
	}

	dup := s.Repos().KeySets.AddMember(ctx, "owner-a", "ks-1", "k-1", testClock)
	if !errors.Is(dup, domain.ErrConflict) {
		t.Fatalf("duplicate AddMember = %v, want ErrConflict", dup)
	}
	if errors.Is(dup, domain.ErrNotFound) {
		t.Error("duplicate AddMember was downgraded to ErrNotFound; the INSERT must not ignore conflicts")
	}
}

// TestKeySetAddMemberRejectsAnotherOwnersKey is the central confused-deputy
// guard. key_set_members has no owner_id column and its foreign keys only check
// that the rows EXIST, so nothing in the schema stops a membership that links
// owner A's set to owner B's key. The repository's two owner-scoped EXISTS
// clauses are the only thing preventing it, and this test is what holds them in
// place.
func TestKeySetAddMemberRejectsAnotherOwnersKey(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	mustCreateKeySet(t, s, newKeySet("ks-a", "owner-a", "primary"))
	mustCreatePublicKey(t, s, newPublicKey("k-b", "owner-b", "d-b"))

	// Owner A tries to add owner B's key to A's own set.
	err := s.Repos().KeySets.AddMember(ctx, "owner-a", "ks-a", "k-b", testClock)
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("AddMember with another owner's key = %v, want ErrNotFound", err)
	}
	// No row may have been written.
	members, lerr := s.Repos().KeySets.ListMembers(ctx, "owner-a", "ks-a")
	if lerr != nil {
		t.Fatalf("ListMembers: %v", lerr)
	}
	if len(members) != 0 {
		t.Fatalf("cross-owner membership was written: %+v", members)
	}
}

// TestKeySetAddMemberRejectsAnotherOwnersSet is the mirror case: owner B's key
// may not be attached to a set owned by someone else, addressed from the other
// direction.
func TestKeySetAddMemberRejectsAnotherOwnersSet(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	mustCreateKeySet(t, s, newKeySet("ks-a", "owner-a", "primary"))
	mustCreatePublicKey(t, s, newPublicKey("k-b", "owner-b", "d-b"))

	// Owner B tries to add its own key to owner A's set.
	err := s.Repos().KeySets.AddMember(ctx, "owner-b", "ks-a", "k-b", testClock)
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("AddMember into another owner's set = %v, want ErrNotFound", err)
	}
	members, lerr := s.Repos().KeySets.ListMembers(ctx, "owner-a", "ks-a")
	if lerr != nil {
		t.Fatalf("ListMembers: %v", lerr)
	}
	if len(members) != 0 {
		t.Fatalf("cross-owner membership was written: %+v", members)
	}
}

// TestKeySetAddMemberMissingSetAndKeyReturnNotFound pins that a miss on either
// EXISTS clause is reported identically to the cross-owner case above, so the
// error never distinguishes "does not exist" from "belongs to another owner".
func TestKeySetAddMemberMissingSetAndKeyReturnNotFound(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	mustCreateKeySet(t, s, newKeySet("ks-a", "owner-a", "primary"))
	mustCreatePublicKey(t, s, newPublicKey("k-a", "owner-a", "d-a"))
	mustCreatePublicKey(t, s, newPublicKey("k-b", "owner-b", "d-b"))

	missingSet := s.Repos().KeySets.AddMember(ctx, "owner-a", "ks-absent", "k-a", testClock)
	if !errors.Is(missingSet, domain.ErrNotFound) {
		t.Fatalf("AddMember with missing set = %v, want ErrNotFound", missingSet)
	}
	missingKey := s.Repos().KeySets.AddMember(ctx, "owner-a", "ks-a", "k-absent", testClock)
	if !errors.Is(missingKey, domain.ErrNotFound) {
		t.Fatalf("AddMember with missing key = %v, want ErrNotFound", missingKey)
	}

	// The wrong-owner error must be byte-identical to the missing-row error, or
	// a caller could probe for the existence of another owner's key.
	wrongOwnerKey := s.Repos().KeySets.AddMember(ctx, "owner-a", "ks-a", "k-b", testClock)
	if wrongOwnerKey == nil || wrongOwnerKey.Error() != missingKey.Error() {
		t.Errorf("wrong-owner error %q differs from missing-key error %q; existence leaks",
			wrongOwnerKey, missingKey)
	}
}

func TestKeySetRemoveMember(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	mustCreateKeySet(t, s, newKeySet("ks-1", "owner-a", "primary"))
	mustCreatePublicKey(t, s, newPublicKey("k-1", "owner-a", "d-1"))
	if err := s.Repos().KeySets.AddMember(ctx, "owner-a", "ks-1", "k-1", testClock); err != nil {
		t.Fatalf("AddMember: %v", err)
	}

	if err := s.Repos().KeySets.RemoveMember(ctx, "owner-a", "ks-1", "k-1"); err != nil {
		t.Fatalf("RemoveMember: %v", err)
	}
	members, err := s.Repos().KeySets.ListMembers(ctx, "owner-a", "ks-1")
	if err != nil {
		t.Fatalf("ListMembers: %v", err)
	}
	if len(members) != 0 {
		t.Errorf("ListMembers after RemoveMember = %+v, want empty", members)
	}
	// Removing again finds nothing and reports ErrNotFound.
	if err := s.Repos().KeySets.RemoveMember(ctx, "owner-a", "ks-1", "k-1"); !errors.Is(err, domain.ErrNotFound) {
		t.Errorf("second RemoveMember = %v, want ErrNotFound", err)
	}
	// The key itself survives.
	if _, err := s.Repos().PublicKeys.Get(ctx, "owner-a", "k-1"); err != nil {
		t.Errorf("RemoveMember removed the public key: %v", err)
	}
}

// TestKeySetRemoveMemberOtherOwnerReturnsNotFound pins that owner B cannot
// strip a key out of owner A's set.
func TestKeySetRemoveMemberOtherOwnerReturnsNotFound(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	mustCreateKeySet(t, s, newKeySet("ks-a", "owner-a", "primary"))
	mustCreatePublicKey(t, s, newPublicKey("k-a", "owner-a", "d-a"))
	if err := s.Repos().KeySets.AddMember(ctx, "owner-a", "ks-a", "k-a", testClock); err != nil {
		t.Fatalf("AddMember: %v", err)
	}
	mustCreateOwner(t, s, "owner-b")

	if err := s.Repos().KeySets.RemoveMember(ctx, "owner-b", "ks-a", "k-a"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("cross-owner RemoveMember = %v, want ErrNotFound", err)
	}
	members, err := s.Repos().KeySets.ListMembers(ctx, "owner-a", "ks-a")
	if err != nil {
		t.Fatalf("ListMembers: %v", err)
	}
	if len(members) != 1 {
		t.Errorf("owner A membership removed by owner B: %+v", members)
	}
}

func TestKeySetListMembersOrderedAndOwnerScoped(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	mustCreateKeySet(t, s, newKeySet("ks-1", "owner-a", "primary"))
	for _, id := range []string{"k-c", "k-a", "k-b"} {
		mustCreatePublicKey(t, s, newPublicKey(id, "owner-a", "d-1"))
		if err := s.Repos().KeySets.AddMember(ctx, "owner-a", "ks-1", domain.PublicKeyID(id), testClock); err != nil {
			t.Fatalf("AddMember %q: %v", id, err)
		}
	}
	mustCreateOwner(t, s, "owner-b")

	got, err := s.Repos().KeySets.ListMembers(ctx, "owner-a", "ks-1")
	if err != nil {
		t.Fatalf("ListMembers: %v", err)
	}
	want := []domain.PublicKeyID{"k-a", "k-b", "k-c"}
	if len(got) != len(want) {
		t.Fatalf("ListMembers returned %d rows, want %d", len(got), len(want))
	}
	for i, id := range want {
		if got[i].PublicKeyID != id {
			t.Errorf("ListMembers[%d].PublicKeyID = %q, want %q", i, got[i].PublicKeyID, id)
		}
	}

	// Owner B asking for A's set gets nothing rather than A's membership.
	if other, oerr := s.Repos().KeySets.ListMembers(ctx, "owner-b", "ks-1"); oerr != nil || len(other) != 0 {
		t.Fatalf("cross-owner ListMembers = (%v, %v), want (empty, nil)", other, oerr)
	}
}

func TestKeySetListSetsForKeyOrderedAndOwnerScoped(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	mustCreatePublicKey(t, s, newPublicKey("k-1", "owner-a", "d-1"))
	for _, id := range []string{"ks-c", "ks-a", "ks-b"} {
		mustCreateKeySet(t, s, newKeySet(id, "owner-a", "name-"+id))
		if err := s.Repos().KeySets.AddMember(ctx, "owner-a", domain.KeySetID(id), "k-1", testClock); err != nil {
			t.Fatalf("AddMember %q: %v", id, err)
		}
	}
	// A set the key is not a member of must not appear.
	mustCreateKeySet(t, s, newKeySet("ks-z", "owner-a", "unrelated"))
	mustCreateOwner(t, s, "owner-b")

	got, err := s.Repos().KeySets.ListSetsForKey(ctx, "owner-a", "k-1")
	if err != nil {
		t.Fatalf("ListSetsForKey: %v", err)
	}
	want := []domain.KeySetID{"ks-a", "ks-b", "ks-c"}
	if len(got) != len(want) {
		t.Fatalf("ListSetsForKey returned %d sets, want %d", len(got), len(want))
	}
	for i, id := range want {
		if got[i].ID != id {
			t.Errorf("ListSetsForKey[%d].ID = %q, want %q", i, got[i].ID, id)
		}
	}

	if other, oerr := s.Repos().KeySets.ListSetsForKey(ctx, "owner-b", "k-1"); oerr != nil || len(other) != 0 {
		t.Fatalf("cross-owner ListSetsForKey = (%v, %v), want (empty, nil)", other, oerr)
	}
}

func TestKeySetMembershipRunsInsideCallerTransaction(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	mustCreateKeySet(t, s, newKeySet("ks-1", "owner-a", "primary"))
	mustCreatePublicKey(t, s, newPublicKey("k-1", "owner-a", "d-1"))

	boom := errors.New("boom")
	err := s.WithTx(ctx, func(ctx context.Context, r repository.Repos) error {
		if aerr := r.KeySets.AddMember(ctx, "owner-a", "ks-1", "k-1", testClock); aerr != nil {
			return aerr
		}
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatalf("WithTx = %v, want boom", err)
	}
	members, lerr := s.Repos().KeySets.ListMembers(ctx, "owner-a", "ks-1")
	if lerr != nil {
		t.Fatalf("ListMembers: %v", lerr)
	}
	if len(members) != 0 {
		t.Errorf("membership survived a rolled-back transaction: %+v", members)
	}
}

// TestPublicKeyListActiveByKeySet pins the publish-path resolution query: only
// the owner's ACTIVE keys that are members of the set are returned, ordered by
// id.
func TestPublicKeyListActiveByKeySet(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	mustCreateKeySet(t, s, newKeySet("ks-1", "owner-a", "primary"))
	mustCreatePublicKey(t, s, newPublicKey("k-a", "owner-a", "d-1"))
	mustCreatePublicKey(t, s, newPublicKey("k-b", "owner-a", "d-1"))
	// A member that is revoked must not be published.
	revoked := newPublicKey("k-revoked", "owner-a", "d-1")
	revoked.Status = domain.KeyStatusRevoked
	mustCreatePublicKey(t, s, revoked)
	// An active key that is NOT a member must not be published either.
	mustCreatePublicKey(t, s, newPublicKey("k-nonmember", "owner-a", "d-1"))

	for _, id := range []domain.PublicKeyID{"k-a", "k-b", "k-revoked"} {
		if err := s.Repos().KeySets.AddMember(ctx, "owner-a", "ks-1", id, testClock); err != nil {
			t.Fatalf("AddMember %q: %v", id, err)
		}
	}

	got, err := s.Repos().PublicKeys.ListActiveByKeySet(ctx, "owner-a", "ks-1")
	if err != nil {
		t.Fatalf("ListActiveByKeySet: %v", err)
	}
	if len(got) != 2 || got[0].ID != "k-a" || got[1].ID != "k-b" {
		t.Fatalf("ListActiveByKeySet = %+v, want exactly active members k-a, k-b", got)
	}
}

// TestPublicKeyListActiveByKeySetIsOwnerScoped is the publish-path tenant
// isolation check: owner B asking for owner A's set must get nothing, never A's
// keys.
func TestPublicKeyListActiveByKeySetIsOwnerScoped(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	mustCreateKeySet(t, s, newKeySet("ks-a", "owner-a", "primary"))
	mustCreatePublicKey(t, s, newPublicKey("k-a", "owner-a", "d-1"))
	if err := s.Repos().KeySets.AddMember(ctx, "owner-a", "ks-a", "k-a", testClock); err != nil {
		t.Fatalf("AddMember: %v", err)
	}
	mustCreateOwner(t, s, "owner-b")

	got, err := s.Repos().PublicKeys.ListActiveByKeySet(ctx, "owner-b", "ks-a")
	if err != nil {
		t.Fatalf("ListActiveByKeySet: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("owner B resolved owner A's key set to %+v; publish path leaks across tenants", got)
	}
}
