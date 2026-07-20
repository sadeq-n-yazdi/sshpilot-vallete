package postgres

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
)

// newAccessKey returns a fully populated active access key owned by ownerID and
// resolving setID. Optional lifecycle fields are left nil, as they are on a key
// that has been neither rotated nor revoked.
func newAccessKey(id, ownerID, setID, name string) *domain.AccessKey {
	return &domain.AccessKey{
		ID:         domain.AccessKeyID(id),
		OwnerID:    domain.OwnerID(ownerID),
		KeySetID:   domain.KeySetID(setID),
		Name:       name,
		SecretHash: []byte("digest-" + id),
		Status:     domain.AccessKeyStatusActive,
		CreatedAt:  testClock,
	}
}

// mustCreateAccessKey creates the owner and key set (if needed) and the access
// key. access_keys carries NOT NULL foreign keys to both owners(id) and
// key_sets(id), which PostgreSQL enforces, so both parents must exist first.
func mustCreateAccessKey(t *testing.T, s *Store, k *domain.AccessKey) *domain.AccessKey {
	t.Helper()
	ctx := context.Background()
	if _, err := s.Repos().KeySets.Get(ctx, k.OwnerID, k.KeySetID); errors.Is(err, domain.ErrNotFound) {
		mustCreateKeySet(t, s, newKeySet(string(k.KeySetID), string(k.OwnerID), "set-"+string(k.KeySetID)))
	}
	if err := s.Repos().AccessKeys.Create(ctx, k); err != nil {
		t.Fatalf("Create access key %q: %v", k.ID, err)
	}
	return k
}

// accessKeyIDs projects a result slice to its ids, so an isolation assertion can
// name exactly what came back.
func accessKeyIDs(keys []domain.AccessKey) []domain.AccessKeyID {
	var ids []domain.AccessKeyID
	for _, k := range keys {
		ids = append(ids, k.ID)
	}
	return ids
}

func TestAccessKeyCreateAndGet(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	want := newAccessKey("ak-1", "owner-a", "ks-1", "ci-runner")
	mustCreateAccessKey(t, s, want)

	got, err := s.Repos().AccessKeys.Get(ctx, "owner-a", "ak-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.ID != want.ID || got.OwnerID != want.OwnerID || got.KeySetID != want.KeySetID {
		t.Errorf("identity = %q/%q/%q, want ak-1/owner-a/ks-1", got.ID, got.OwnerID, got.KeySetID)
	}
	// The digest must survive the BYTEA round trip byte for byte: it is what the
	// constant-time Bearer comparison outside this package is performed against.
	if !bytes.Equal(got.SecretHash, want.SecretHash) {
		t.Errorf("SecretHash = %x, want %x", got.SecretHash, want.SecretHash)
	}
	if got.Name != "ci-runner" || got.Status != domain.AccessKeyStatusActive {
		t.Errorf("name/status = %q/%q, want ci-runner/active", got.Name, got.Status)
	}
	if !got.CreatedAt.Equal(testClock) {
		t.Errorf("CreatedAt = %v, want %v", got.CreatedAt, testClock)
	}
	if got.RevokedAt != nil || got.GraceUntil != nil || got.ReplacedByID != nil {
		t.Errorf("lifecycle fields = %v/%v/%v, want all nil",
			got.RevokedAt, got.GraceUntil, got.ReplacedByID)
	}
}

// A nil entity is a caller bug, and the adapter must name it as one rather than
// dereference it into a panic.
func TestAccessKeyCreateRejectsNil(t *testing.T) {
	t.Parallel()
	s := newStore(t)

	err := s.Repos().AccessKeys.Create(context.Background(), nil)
	if !errors.Is(err, domain.ErrInvalidInput) {
		t.Fatalf("Create(nil) = %v, want ErrInvalidInput", err)
	}
}

func TestAccessKeyCreateDuplicateIDConflicts(t *testing.T) {
	t.Parallel()
	s := newStore(t)

	mustCreateAccessKey(t, s, newAccessKey("ak-dup", "owner-a", "ks-1", "first"))
	err := s.Repos().AccessKeys.Create(context.Background(),
		newAccessKey("ak-dup", "owner-a", "ks-1", "second"))
	if !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("duplicate Create = %v, want ErrConflict", err)
	}
}

// Get must not become an existence oracle: another owner's key and a key that
// was never written have to produce the same answer, or one owner learns that
// an id they cannot read is nonetheless in use.
func TestAccessKeyGetWrongOwnerIsIndistinguishableFromMissing(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	mustCreateAccessKey(t, s, newAccessKey("ak-a", "owner-a", "ks-a", "a"))
	mustCreateOwner(t, s, "owner-b")

	got, wrongOwner := s.Repos().AccessKeys.Get(ctx, "owner-b", "ak-a")
	if !errors.Is(wrongOwner, domain.ErrNotFound) {
		t.Fatalf("Get another owner's key = %v, want ErrNotFound", wrongOwner)
	}
	if got != nil {
		t.Errorf("Get another owner's key returned %+v, want nil", got)
	}

	_, missing := s.Repos().AccessKeys.Get(ctx, "owner-b", "ak-nonexistent")
	if !errors.Is(missing, domain.ErrNotFound) {
		t.Fatalf("Get missing key = %v, want ErrNotFound", missing)
	}
	// Same sentinel is necessary but not sufficient; the rendered text must not
	// differ either, since a caller can read that too.
	if wrongOwner.Error() != missing.Error() {
		t.Errorf("wrong-owner error %q differs from missing-key error %q",
			wrongOwner, missing)
	}
}

func TestAccessKeyListByOwnerIsolatesOwners(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	mustCreateAccessKey(t, s, newAccessKey("ak-a1", "owner-a", "ks-a", "a1"))
	mustCreateAccessKey(t, s, newAccessKey("ak-a2", "owner-a", "ks-a", "a2"))
	mustCreateAccessKey(t, s, newAccessKey("ak-b1", "owner-b", "ks-b", "b1"))

	got, err := s.Repos().AccessKeys.ListByOwner(ctx, "owner-a")
	if err != nil {
		t.Fatalf("ListByOwner: %v", err)
	}
	if ids := accessKeyIDs(got); len(ids) != 2 || ids[0] != "ak-a1" || ids[1] != "ak-a2" {
		t.Errorf("ListByOwner(owner-a) = %v, want [ak-a1 ak-a2]", ids)
	}
}

func TestAccessKeyListByOwnerEmptyReturnsNil(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	mustCreateOwner(t, s, "owner-empty")

	got, err := s.Repos().AccessKeys.ListByOwner(context.Background(), "owner-empty")
	if err != nil {
		t.Fatalf("ListByOwner: %v", err)
	}
	if got != nil {
		t.Errorf("ListByOwner with no keys = %v, want nil slice", got)
	}
}

// Two owners are given keys pointing at the SAME key set id. The schema does not
// enforce that a key set and a key referencing it share an owner, so the owner_id
// predicate is the only thing keeping the other owner's credential out of this
// result.
func TestAccessKeyListByKeySetIsolatesOwnersOnSharedSetID(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	mustCreateAccessKey(t, s, newAccessKey("ak-a1", "owner-a", "ks-shared", "a1"))
	mustCreateOwner(t, s, "owner-b")
	// owner-b's key reuses owner-a's key set id, which the plain (non-composite)
	// foreign key permits.
	if err := s.Repos().AccessKeys.Create(ctx,
		newAccessKey("ak-b1", "owner-b", "ks-shared", "b1")); err != nil {
		t.Fatalf("Create owner-b key on shared set: %v", err)
	}

	got, err := s.Repos().AccessKeys.ListByKeySet(ctx, "owner-a", "ks-shared")
	if err != nil {
		t.Fatalf("ListByKeySet: %v", err)
	}
	if ids := accessKeyIDs(got); len(ids) != 1 || ids[0] != "ak-a1" {
		t.Errorf("ListByKeySet(owner-a, ks-shared) = %v, want [ak-a1]", ids)
	}
}

func TestAccessKeyListByKeySetEmptyReturnsNil(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	mustCreateAccessKey(t, s, newAccessKey("ak-a1", "owner-a", "ks-a", "a1"))

	got, err := s.Repos().AccessKeys.ListByKeySet(ctx, "owner-a", "ks-other")
	if err != nil {
		t.Fatalf("ListByKeySet: %v", err)
	}
	if got != nil {
		t.Errorf("ListByKeySet with no matches = %v, want nil slice", got)
	}
}

func TestAccessKeyMarkRotatedMovesKeyToGrace(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	mustCreateAccessKey(t, s, newAccessKey("ak-old", "owner-a", "ks-a", "old"))
	deadline := testClock.Add(2 * time.Hour)

	if err := s.Repos().AccessKeys.MarkRotated(ctx, "owner-a", "ak-old", "ak-new", deadline); err != nil {
		t.Fatalf("MarkRotated: %v", err)
	}

	got, err := s.Repos().AccessKeys.Get(ctx, "owner-a", "ak-old")
	if err != nil {
		t.Fatalf("Get after MarkRotated: %v", err)
	}
	if got.Status != domain.AccessKeyStatusGrace {
		t.Errorf("status = %q, want grace", got.Status)
	}
	if got.GraceUntil == nil || !got.GraceUntil.Equal(deadline) {
		t.Errorf("GraceUntil = %v, want %v", got.GraceUntil, deadline)
	}
	if got.ReplacedByID == nil || *got.ReplacedByID != "ak-new" {
		t.Errorf("ReplacedByID = %v, want ak-new", got.ReplacedByID)
	}
}

// The owner predicate must be enforced by the statement, not by the caller: a
// rotation aimed at another owner's key has to report ErrNotFound AND leave that
// key exactly as it was.
func TestAccessKeyMarkRotatedCannotTouchAnotherOwnersKey(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	mustCreateAccessKey(t, s, newAccessKey("ak-a", "owner-a", "ks-a", "victim"))
	mustCreateOwner(t, s, "owner-b")

	err := s.Repos().AccessKeys.MarkRotated(ctx, "owner-b", "ak-a", "ak-attacker", testClock)
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("MarkRotated across owners = %v, want ErrNotFound", err)
	}

	victim, gerr := s.Repos().AccessKeys.Get(ctx, "owner-a", "ak-a")
	if gerr != nil {
		t.Fatalf("Get victim: %v", gerr)
	}
	if victim.Status != domain.AccessKeyStatusActive {
		t.Errorf("victim status = %q, want active (untouched)", victim.Status)
	}
	if victim.GraceUntil != nil || victim.ReplacedByID != nil {
		t.Errorf("victim grace/replacement = %v/%v, want nil/nil (untouched)",
			victim.GraceUntil, victim.ReplacedByID)
	}
}

// Revocation is terminal. Rotating a revoked key must not resurrect it into the
// grace state, and the refusal must look identical to a missing key so a revoked
// key is not distinguishable from one that never existed.
func TestAccessKeyMarkRotatedRefusesToReviveRevokedKey(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	mustCreateAccessKey(t, s, newAccessKey("ak-dead", "owner-a", "ks-a", "dead"))
	if err := s.Repos().AccessKeys.Revoke(ctx, "owner-a", "ak-dead", testClock); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	err := s.Repos().AccessKeys.MarkRotated(ctx, "owner-a", "ak-dead", "ak-new", testClock.Add(time.Hour))
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("MarkRotated on revoked key = %v, want ErrNotFound", err)
	}

	got, gerr := s.Repos().AccessKeys.Get(ctx, "owner-a", "ak-dead")
	if gerr != nil {
		t.Fatalf("Get after refused rotation: %v", gerr)
	}
	if got.Status != domain.AccessKeyStatusRevoked {
		t.Errorf("status = %q, want revoked (still dead)", got.Status)
	}
	if got.GraceUntil != nil || got.ReplacedByID != nil {
		t.Errorf("revoked key gained grace/replacement %v/%v, want nil/nil",
			got.GraceUntil, got.ReplacedByID)
	}
}

func TestAccessKeyRevokeClearsGraceState(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	mustCreateAccessKey(t, s, newAccessKey("ak-r", "owner-a", "ks-a", "r"))
	if err := s.Repos().AccessKeys.MarkRotated(ctx, "owner-a", "ak-r", "ak-next",
		testClock.Add(time.Hour)); err != nil {
		t.Fatalf("MarkRotated: %v", err)
	}

	revokedAt := testClock.Add(30 * time.Minute)
	if err := s.Repos().AccessKeys.Revoke(ctx, "owner-a", "ak-r", revokedAt); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	got, err := s.Repos().AccessKeys.Get(ctx, "owner-a", "ak-r")
	if err != nil {
		t.Fatalf("Get after Revoke: %v", err)
	}
	if got.Status != domain.AccessKeyStatusRevoked {
		t.Errorf("status = %q, want revoked", got.Status)
	}
	// A revoked key must carry no live deadline a later grace sweep could act on.
	if got.GraceUntil != nil || got.ReplacedByID != nil {
		t.Errorf("grace/replacement = %v/%v, want nil/nil after revoke",
			got.GraceUntil, got.ReplacedByID)
	}
	if got.RevokedAt == nil || !got.RevokedAt.Equal(revokedAt) {
		t.Errorf("RevokedAt = %v, want %v", got.RevokedAt, revokedAt)
	}
}

// revoked_at answers "from when was this credential dead". Anyone holding the
// token can call Revoke again, so a repeat must not walk that timestamp forward
// away from the compromise.
func TestAccessKeyRevokeKeepsFirstRevocationTimestamp(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	mustCreateAccessKey(t, s, newAccessKey("ak-r", "owner-a", "ks-a", "r"))
	first := testClock
	later := testClock.Add(72 * time.Hour)

	if err := s.Repos().AccessKeys.Revoke(ctx, "owner-a", "ak-r", first); err != nil {
		t.Fatalf("first Revoke: %v", err)
	}
	if err := s.Repos().AccessKeys.Revoke(ctx, "owner-a", "ak-r", later); err != nil {
		t.Fatalf("second Revoke: %v", err)
	}

	got, err := s.Repos().AccessKeys.Get(ctx, "owner-a", "ak-r")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.RevokedAt == nil || !got.RevokedAt.Equal(first) {
		t.Errorf("RevokedAt = %v, want the first revocation %v", got.RevokedAt, first)
	}
}

// A revoke aimed at another owner's key must report ErrNotFound and leave the
// victim usable — otherwise one owner can shut another's credentials down.
func TestAccessKeyRevokeCannotTouchAnotherOwnersKey(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	mustCreateAccessKey(t, s, newAccessKey("ak-a", "owner-a", "ks-a", "victim"))
	mustCreateOwner(t, s, "owner-b")

	err := s.Repos().AccessKeys.Revoke(ctx, "owner-b", "ak-a", testClock)
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("Revoke across owners = %v, want ErrNotFound", err)
	}

	victim, gerr := s.Repos().AccessKeys.Get(ctx, "owner-a", "ak-a")
	if gerr != nil {
		t.Fatalf("Get victim: %v", gerr)
	}
	if victim.Status != domain.AccessKeyStatusActive || victim.RevokedAt != nil {
		t.Errorf("victim status/RevokedAt = %q/%v, want active/nil (untouched)",
			victim.Status, victim.RevokedAt)
	}
}

// The sweep is UNSCOPED by contract, so it must see every owner's expired grace
// keys — and only those actually in the grace state with a passed deadline.
func TestAccessKeyListExpiredGraceSpansOwnersAndFiltersByState(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	mustCreateAccessKey(t, s, newAccessKey("ak-a", "owner-a", "ks-a", "a"))
	mustCreateAccessKey(t, s, newAccessKey("ak-b", "owner-b", "ks-b", "b"))
	mustCreateAccessKey(t, s, newAccessKey("ak-future", "owner-a", "ks-a", "future"))
	mustCreateAccessKey(t, s, newAccessKey("ak-active", "owner-a", "ks-a", "active"))

	now := testClock.Add(time.Hour)
	// ak-b's deadline is the older one, so it must sort first.
	rotate := func(id, owner string, at time.Time) {
		t.Helper()
		if err := s.Repos().AccessKeys.MarkRotated(ctx,
			domain.OwnerID(owner), domain.AccessKeyID(id), "ak-next", at); err != nil {
			t.Fatalf("MarkRotated %s: %v", id, err)
		}
	}
	rotate("ak-a", "owner-a", testClock.Add(30*time.Minute))
	rotate("ak-b", "owner-b", testClock)
	rotate("ak-future", "owner-a", now.Add(time.Hour))

	got, err := s.Repos().AccessKeys.ListExpiredGrace(ctx, now, 10)
	if err != nil {
		t.Fatalf("ListExpiredGrace: %v", err)
	}
	if ids := accessKeyIDs(got); len(ids) != 2 || ids[0] != "ak-b" || ids[1] != "ak-a" {
		t.Errorf("ListExpiredGrace = %v, want [ak-b ak-a] (oldest deadline first)", ids)
	}
}

func TestAccessKeyListExpiredGraceHonorsLimit(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	mustCreateAccessKey(t, s, newAccessKey("ak-1", "owner-a", "ks-a", "1"))
	mustCreateAccessKey(t, s, newAccessKey("ak-2", "owner-a", "ks-a", "2"))
	for _, id := range []domain.AccessKeyID{"ak-1", "ak-2"} {
		if err := s.Repos().AccessKeys.MarkRotated(ctx, "owner-a", id, "ak-next", testClock); err != nil {
			t.Fatalf("MarkRotated %s: %v", id, err)
		}
	}

	got, err := s.Repos().AccessKeys.ListExpiredGrace(ctx, testClock.Add(time.Hour), 1)
	if err != nil {
		t.Fatalf("ListExpiredGrace: %v", err)
	}
	if len(got) != 1 {
		t.Errorf("ListExpiredGrace with limit 1 returned %d rows, want 1", len(got))
	}
}

func TestAccessKeyListExpiredGraceEmptyReturnsNil(t *testing.T) {
	t.Parallel()
	s := newStore(t)

	got, err := s.Repos().AccessKeys.ListExpiredGrace(context.Background(), testClock, 10)
	if err != nil {
		t.Fatalf("ListExpiredGrace: %v", err)
	}
	if got != nil {
		t.Errorf("ListExpiredGrace with no matches = %v, want nil slice", got)
	}
}

// A zero limit reaching the query as "unbounded" would turn a caller's zero
// value into a full-table scan, which is the accident the batching exists to
// prevent.
func TestAccessKeyListExpiredGraceRejectsNonPositiveLimit(t *testing.T) {
	t.Parallel()
	s := newStore(t)

	for _, limit := range []int{0, -1} {
		_, err := s.Repos().AccessKeys.ListExpiredGrace(context.Background(), testClock, limit)
		if !errors.Is(err, domain.ErrInvalidInput) {
			t.Errorf("ListExpiredGrace(limit=%d) = %v, want ErrInvalidInput", limit, err)
		}
	}
}

// Timestamps are stored as fixed-width UTC text, so an instant handed in with a
// non-UTC offset must come back as the same instant in UTC — the grace sweep's
// lexical "<=" comparison depends on that encoding.
func TestAccessKeyTimestampsRoundTripFromNonUTCZone(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	zone := time.FixedZone("UTC-7", -7*60*60)
	k := newAccessKey("ak-tz", "owner-a", "ks-a", "tz")
	k.CreatedAt = testClock.In(zone)
	mustCreateAccessKey(t, s, k)

	got, err := s.Repos().AccessKeys.Get(ctx, "owner-a", "ak-tz")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !got.CreatedAt.Equal(testClock) {
		t.Errorf("CreatedAt = %v, want %v", got.CreatedAt, testClock)
	}
	if got.CreatedAt.Location() != time.UTC {
		t.Errorf("CreatedAt location = %v, want UTC", got.CreatedAt.Location())
	}
}
