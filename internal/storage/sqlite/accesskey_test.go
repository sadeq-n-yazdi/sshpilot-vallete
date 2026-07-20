package sqlite

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
)

// akPlaintext is the plaintext access key the tests pretend was shown once at
// creation. It is never handed to the repository; only its "digest" is. Tests
// assert this string never reaches the database.
const akPlaintext = "plaintext-access-key-value-never-stored"

// newAccessKey returns a fully populated active access key owned by ownerID and
// resolving setID. SecretHash stands in for a real digest: the repository is
// indifferent to how it was derived, only that it is not the plaintext.
func newAccessKey(id, ownerID, setID, name string) *domain.AccessKey {
	return &domain.AccessKey{
		ID:         domain.AccessKeyID(id),
		OwnerID:    domain.OwnerID(ownerID),
		KeySetID:   domain.KeySetID(setID),
		Name:       name,
		SecretHash: []byte("digest-of-" + id),
		Status:     domain.AccessKeyStatusActive,
		CreatedAt:  testClock,
	}
}

// mustCreateAccessKey creates the owner and key set the access key depends on
// (if absent) and then the key itself.
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

// rawAccessKeyRow reads the stored columns for id directly via SQL, bypassing
// the repository, so assertions about what is on disk do not depend on the code
// under test.
func rawAccessKeyRow(t *testing.T, s *Store, id string) (secretHash []byte, status string) {
	t.Helper()
	const q = `SELECT secret_hash, status FROM access_keys WHERE id = ?`
	if err := s.db.QueryRowContext(context.Background(), q, id).Scan(&secretHash, &status); err != nil {
		t.Fatalf("read raw access key %q: %v", id, err)
	}
	return secretHash, status
}

func TestAccessKeyCreateAndGetRoundTrip(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	want := mustCreateAccessKey(t, s, newAccessKey("ak-1", "owner-a", "ks-1", "ci-runner"))

	got, err := s.Repos().AccessKeys.Get(ctx, "owner-a", "ak-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.ID != want.ID || got.OwnerID != want.OwnerID || got.KeySetID != want.KeySetID {
		t.Errorf("identity round-trip = %+v", got)
	}
	if got.Name != "ci-runner" || got.Status != domain.AccessKeyStatusActive {
		t.Errorf("name/status = %q/%q", got.Name, got.Status)
	}
	if string(got.SecretHash) != string(want.SecretHash) {
		t.Errorf("SecretHash = %q, want %q", got.SecretHash, want.SecretHash)
	}
	if !got.CreatedAt.Equal(testClock) {
		t.Errorf("CreatedAt = %v, want %v", got.CreatedAt, testClock)
	}
	if got.RevokedAt != nil || got.GraceUntil != nil || got.ReplacedByID != nil {
		t.Errorf("optional fields = %v/%v/%v, want all nil", got.RevokedAt, got.GraceUntil, got.ReplacedByID)
	}
}

func TestAccessKeyCreateNilIsInvalidInput(t *testing.T) {
	t.Parallel()
	s := newStore(t)

	err := s.Repos().AccessKeys.Create(context.Background(), nil)
	if !errors.Is(err, domain.ErrInvalidInput) {
		t.Fatalf("Create(nil) = %v, want ErrInvalidInput", err)
	}
}

func TestAccessKeyCreateDuplicateIsConflict(t *testing.T) {
	t.Parallel()
	s := newStore(t)

	mustCreateAccessKey(t, s, newAccessKey("ak-1", "owner-a", "ks-1", "ci"))
	err := s.Repos().AccessKeys.Create(context.Background(), newAccessKey("ak-1", "owner-a", "ks-1", "ci"))
	if !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("duplicate Create = %v, want ErrConflict", err)
	}
}

// TestAccessKeyPlaintextIsNeverPersisted asserts the core secrecy property: the
// only secret-derived bytes on disk are the digest the caller supplied, and the
// plaintext appears in no column of the row.
func TestAccessKeyPlaintextIsNeverPersisted(t *testing.T) {
	t.Parallel()
	s := newStore(t)

	k := newAccessKey("ak-1", "owner-a", "ks-1", "ci")
	k.SecretHash = []byte("digest-not-the-plaintext")
	mustCreateAccessKey(t, s, k)

	storedHash, _ := rawAccessKeyRow(t, s, "ak-1")
	if string(storedHash) != "digest-not-the-plaintext" {
		t.Errorf("stored secret_hash = %q, want the supplied digest", storedHash)
	}

	// Scan the whole row as text: no column may contain the plaintext.
	const q = `SELECT id || '|' || owner_id || '|' || key_set_id || '|' || name ||
'|' || CAST(secret_hash AS TEXT) || '|' || status || '|' || created_at ||
'|' || COALESCE(revoked_at, '') || '|' || COALESCE(grace_until, '') ||
'|' || COALESCE(replaced_by_id, '') FROM access_keys WHERE id = ?`
	var row string
	if err := s.db.QueryRowContext(context.Background(), q, "ak-1").Scan(&row); err != nil {
		t.Fatalf("read row text: %v", err)
	}
	if strings.Contains(row, akPlaintext) {
		t.Errorf("stored row contains the plaintext access key: %q", row)
	}

	// The row cannot hold a plaintext because there is nowhere to put one: assert
	// the table's column set exactly, so adding a column that could carry
	// recoverable key material fails here rather than passing unnoticed. This
	// checks the mechanism, not just that this particular insert happened to
	// store a digest.
	rows, err := s.db.QueryContext(context.Background(), `SELECT name FROM pragma_table_info('access_keys') ORDER BY name`)
	if err != nil {
		t.Fatalf("read table info: %v", err)
	}
	defer func() { _ = rows.Close() }()
	var cols []string
	for rows.Next() {
		var name string
		if serr := rows.Scan(&name); serr != nil {
			t.Fatalf("scan column name: %v", serr)
		}
		cols = append(cols, name)
	}
	if rerr := rows.Err(); rerr != nil {
		t.Fatalf("iterate table info: %v", rerr)
	}
	want := "created_at,grace_until,id,key_set_id,name,owner_id,replaced_by_id,revoked_at,secret_hash,status"
	if got := strings.Join(cols, ","); got != want {
		t.Errorf("access_keys columns = %q, want %q", got, want)
	}
}

func TestAccessKeyListByOwnerAndKeySet(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	mustCreateAccessKey(t, s, newAccessKey("ak-1", "owner-a", "ks-1", "one"))
	mustCreateAccessKey(t, s, newAccessKey("ak-2", "owner-a", "ks-2", "two"))
	mustCreateAccessKey(t, s, newAccessKey("ak-3", "owner-a", "ks-1", "three"))

	all, err := s.Repos().AccessKeys.ListByOwner(ctx, "owner-a")
	if err != nil {
		t.Fatalf("ListByOwner: %v", err)
	}
	if len(all) != 3 || all[0].ID != "ak-1" || all[2].ID != "ak-3" {
		t.Errorf("ListByOwner = %d keys, want 3 ordered by id: %+v", len(all), all)
	}

	inSet, err := s.Repos().AccessKeys.ListByKeySet(ctx, "owner-a", "ks-1")
	if err != nil {
		t.Fatalf("ListByKeySet: %v", err)
	}
	if len(inSet) != 2 || inSet[0].ID != "ak-1" || inSet[1].ID != "ak-3" {
		t.Errorf("ListByKeySet(ks-1) = %+v, want ak-1 and ak-3", inSet)
	}
}

// TestAccessKeyEmptyListsAreNil pins the convention that an empty result is a
// nil slice rather than an allocated empty one.
func TestAccessKeyEmptyListsAreNil(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	mustCreateOwner(t, s, "owner-a")

	byOwner, err := s.Repos().AccessKeys.ListByOwner(ctx, "owner-a")
	if err != nil {
		t.Fatalf("ListByOwner: %v", err)
	}
	if byOwner != nil {
		t.Errorf("ListByOwner = %#v, want nil", byOwner)
	}

	bySet, err := s.Repos().AccessKeys.ListByKeySet(ctx, "owner-a", "ks-absent")
	if err != nil {
		t.Fatalf("ListByKeySet: %v", err)
	}
	if bySet != nil {
		t.Errorf("ListByKeySet = %#v, want nil", bySet)
	}

	expired, err := s.Repos().AccessKeys.ListExpiredGrace(ctx, testClock, 10)
	if err != nil {
		t.Fatalf("ListExpiredGrace: %v", err)
	}
	if expired != nil {
		t.Errorf("ListExpiredGrace = %#v, want nil", expired)
	}
}

func TestAccessKeyRevokeThenGet(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	mustCreateAccessKey(t, s, newAccessKey("ak-1", "owner-a", "ks-1", "ci"))
	// Rotate first, so grace_until and replaced_by_id are actually populated when
	// Revoke runs. Revoking a never-rotated key would leave them NULL anyway and
	// would not show that revocation clears them.
	if err := s.Repos().AccessKeys.MarkRotated(ctx, "owner-a", "ak-1", "ak-2", testClock.Add(48*time.Hour)); err != nil {
		t.Fatalf("MarkRotated: %v", err)
	}
	revokedAt := testClock.Add(time.Hour)
	if err := s.Repos().AccessKeys.Revoke(ctx, "owner-a", "ak-1", revokedAt); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	got, err := s.Repos().AccessKeys.Get(ctx, "owner-a", "ak-1")
	if err != nil {
		t.Fatalf("Get after Revoke: %v", err)
	}
	if got.Status != domain.AccessKeyStatusRevoked {
		t.Errorf("Status = %q, want revoked", got.Status)
	}
	if got.RevokedAt == nil || !got.RevokedAt.Equal(revokedAt) {
		t.Errorf("RevokedAt = %v, want %v", got.RevokedAt, revokedAt)
	}
	if got.GraceUntil != nil || got.ReplacedByID != nil {
		t.Errorf("revoked key retained grace state: %v/%v", got.GraceUntil, got.ReplacedByID)
	}
}

func TestAccessKeyRevokeMissingIsNotFound(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	mustCreateOwner(t, s, "owner-a")

	err := s.Repos().AccessKeys.Revoke(context.Background(), "owner-a", "ak-absent", testClock)
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("Revoke(absent) = %v, want ErrNotFound", err)
	}
}

// TestAccessKeyRevokeIsTerminal covers the revival hole: rotating a revoked key
// must not move it back into the grace state, because that would put a
// credential an operator shut down back into service.
func TestAccessKeyRevokeIsTerminal(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	mustCreateAccessKey(t, s, newAccessKey("ak-1", "owner-a", "ks-1", "ci"))
	if err := s.Repos().AccessKeys.Revoke(ctx, "owner-a", "ak-1", testClock); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	err := s.Repos().AccessKeys.MarkRotated(ctx, "owner-a", "ak-1", "ak-2", testClock.Add(time.Hour))
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("MarkRotated(revoked) = %v, want ErrNotFound", err)
	}

	_, status := rawAccessKeyRow(t, s, "ak-1")
	if status != string(domain.AccessKeyStatusRevoked) {
		t.Errorf("status after MarkRotated = %q, want it to stay revoked", status)
	}
}

func TestAccessKeyMarkRotated(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	mustCreateAccessKey(t, s, newAccessKey("ak-1", "owner-a", "ks-1", "old"))
	until := testClock.Add(24 * time.Hour)
	if err := s.Repos().AccessKeys.MarkRotated(ctx, "owner-a", "ak-1", "ak-2", until); err != nil {
		t.Fatalf("MarkRotated: %v", err)
	}

	got, err := s.Repos().AccessKeys.Get(ctx, "owner-a", "ak-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Status != domain.AccessKeyStatusGrace {
		t.Errorf("Status = %q, want grace", got.Status)
	}
	if got.GraceUntil == nil || !got.GraceUntil.Equal(until) {
		t.Errorf("GraceUntil = %v, want %v", got.GraceUntil, until)
	}
	if got.ReplacedByID == nil || *got.ReplacedByID != "ak-2" {
		t.Errorf("ReplacedByID = %v, want ak-2", got.ReplacedByID)
	}
}

func TestAccessKeyMarkRotatedMissingIsNotFound(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	mustCreateOwner(t, s, "owner-a")

	err := s.Repos().AccessKeys.MarkRotated(context.Background(), "owner-a", "ak-absent", "ak-2", testClock)
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("MarkRotated(absent) = %v, want ErrNotFound", err)
	}
}

// TestAccessKeyCrossOwnerIsolation is the cross-tenant assertion. Owner B must
// get exactly the same answer for owner A's key as for a key that was never
// created: ErrNotFound from Get, MarkRotated and Revoke, and no row at all from
// either list. Any divergence between the two columns of this table would tell
// owner B that an id they cannot reach nonetheless exists.
func TestAccessKeyCrossOwnerIsolation(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	mustCreateAccessKey(t, s, newAccessKey("ak-a", "owner-a", "ks-a", "a-key"))
	mustCreateOwner(t, s, "owner-b")
	repos := s.Repos()

	for _, id := range []domain.AccessKeyID{"ak-a", "ak-never-existed"} {
		if _, err := repos.AccessKeys.Get(ctx, "owner-b", id); !errors.Is(err, domain.ErrNotFound) {
			t.Errorf("Get(owner-b, %q) = %v, want ErrNotFound", id, err)
		}
		if err := repos.AccessKeys.Revoke(ctx, "owner-b", id, testClock); !errors.Is(err, domain.ErrNotFound) {
			t.Errorf("Revoke(owner-b, %q) = %v, want ErrNotFound", id, err)
		}
		err := repos.AccessKeys.MarkRotated(ctx, "owner-b", id, "ak-b", testClock)
		if !errors.Is(err, domain.ErrNotFound) {
			t.Errorf("MarkRotated(owner-b, %q) = %v, want ErrNotFound", id, err)
		}
	}

	byOwner, err := repos.AccessKeys.ListByOwner(ctx, "owner-b")
	if err != nil {
		t.Fatalf("ListByOwner(owner-b): %v", err)
	}
	if byOwner != nil {
		t.Errorf("ListByOwner(owner-b) = %+v, want nil", byOwner)
	}

	// Owner B naming owner A's key set id must still see nothing.
	bySet, err := repos.AccessKeys.ListByKeySet(ctx, "owner-b", "ks-a")
	if err != nil {
		t.Fatalf("ListByKeySet(owner-b, ks-a): %v", err)
	}
	if bySet != nil {
		t.Errorf("ListByKeySet(owner-b, ks-a) = %+v, want nil", bySet)
	}

	// Owner A's key must be untouched by everything owner B attempted.
	got, err := repos.AccessKeys.Get(ctx, "owner-a", "ak-a")
	if err != nil {
		t.Fatalf("Get(owner-a): %v", err)
	}
	if got.Status != domain.AccessKeyStatusActive {
		t.Errorf("owner-a key status = %q, want it still active", got.Status)
	}
}

func TestAccessKeyListExpiredGrace(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	repos := s.Repos()

	// Two keys of different owners rotated into grace, plus one still active.
	mustCreateAccessKey(t, s, newAccessKey("ak-a", "owner-a", "ks-a", "a"))
	mustCreateAccessKey(t, s, newAccessKey("ak-b", "owner-b", "ks-b", "b"))
	mustCreateAccessKey(t, s, newAccessKey("ak-c", "owner-a", "ks-a", "c"))

	early := testClock.Add(time.Hour)
	late := testClock.Add(2 * time.Hour)
	if err := repos.AccessKeys.MarkRotated(ctx, "owner-b", "ak-b", "ak-b2", early); err != nil {
		t.Fatalf("MarkRotated ak-b: %v", err)
	}
	if err := repos.AccessKeys.MarkRotated(ctx, "owner-a", "ak-a", "ak-a2", late); err != nil {
		t.Fatalf("MarkRotated ak-a: %v", err)
	}

	// A deadline in the future is not yet expired.
	got, err := repos.AccessKeys.ListExpiredGrace(ctx, testClock, 10)
	if err != nil {
		t.Fatalf("ListExpiredGrace(now): %v", err)
	}
	if got != nil {
		t.Errorf("ListExpiredGrace before any deadline = %+v, want nil", got)
	}

	// Past both deadlines the sweep sees both owners' keys, oldest first, and
	// never the active one.
	got, err = repos.AccessKeys.ListExpiredGrace(ctx, testClock.Add(3*time.Hour), 10)
	if err != nil {
		t.Fatalf("ListExpiredGrace(after): %v", err)
	}
	if len(got) != 2 || got[0].ID != "ak-b" || got[1].ID != "ak-a" {
		t.Fatalf("ListExpiredGrace = %+v, want ak-b then ak-a", got)
	}

	// limit bounds the batch.
	got, err = repos.AccessKeys.ListExpiredGrace(ctx, testClock.Add(3*time.Hour), 1)
	if err != nil {
		t.Fatalf("ListExpiredGrace(limit 1): %v", err)
	}
	if len(got) != 1 || got[0].ID != "ak-b" {
		t.Errorf("ListExpiredGrace(limit 1) = %+v, want just ak-b", got)
	}
}

// TestAccessKeyListExpiredGraceSkipsRevoked checks that revoking a key in its
// grace window takes it out of the sweep entirely: Revoke clears grace_until,
// so nothing is left for the expiry job to act on.
func TestAccessKeyListExpiredGraceSkipsRevoked(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	repos := s.Repos()

	mustCreateAccessKey(t, s, newAccessKey("ak-1", "owner-a", "ks-1", "ci"))
	if err := repos.AccessKeys.MarkRotated(ctx, "owner-a", "ak-1", "ak-2", testClock.Add(time.Hour)); err != nil {
		t.Fatalf("MarkRotated: %v", err)
	}
	if err := repos.AccessKeys.Revoke(ctx, "owner-a", "ak-1", testClock); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	got, err := repos.AccessKeys.ListExpiredGrace(ctx, testClock.Add(2*time.Hour), 10)
	if err != nil {
		t.Fatalf("ListExpiredGrace: %v", err)
	}
	if got != nil {
		t.Errorf("ListExpiredGrace = %+v, want nil for a revoked key", got)
	}
}

// TestAccessKeyListExpiredGraceRequiresGraceStatus covers the sweep's status
// predicate on its own. Revoke clears grace_until, so no row reachable through
// the repository has a past deadline in a non-grace state — which is exactly
// why the predicate needs testing directly: it is the defense-in-depth that
// keeps an anomalous row (a bad backfill, a future writer, a restored backup)
// out of a job that retires credentials. The row is inserted with raw SQL
// because the repository is correctly incapable of producing it.
func TestAccessKeyListExpiredGraceRequiresGraceStatus(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	mustCreateKeySet(t, s, newKeySet("ks-1", "owner-a", "set-one"))

	const q = `INSERT INTO access_keys (id, owner_id, key_set_id, name, secret_hash,
status, created_at, revoked_at, grace_until, replaced_by_id)
VALUES (?, ?, ?, ?, ?, ?, ?, NULL, ?, NULL)`
	past := encTime(testClock.Add(-time.Hour))
	for _, status := range []domain.AccessKeyStatus{
		domain.AccessKeyStatusActive,
		domain.AccessKeyStatusRevoked,
	} {
		id := "ak-" + string(status)
		if _, err := s.db.ExecContext(ctx, q, id, "owner-a", "ks-1", id,
			[]byte("digest"), string(status), encTime(testClock), past); err != nil {
			t.Fatalf("insert %s row: %v", status, err)
		}
	}

	got, err := s.Repos().AccessKeys.ListExpiredGrace(ctx, testClock, 10)
	if err != nil {
		t.Fatalf("ListExpiredGrace: %v", err)
	}
	if got != nil {
		t.Errorf("ListExpiredGrace = %+v, want nil: only grace rows may be swept", got)
	}
}

func TestAccessKeyListExpiredGraceRejectsNonPositiveLimit(t *testing.T) {
	t.Parallel()
	s := newStore(t)

	for _, limit := range []int{0, -1} {
		_, err := s.Repos().AccessKeys.ListExpiredGrace(context.Background(), testClock, limit)
		if !errors.Is(err, domain.ErrInvalidInput) {
			t.Errorf("ListExpiredGrace(limit %d) = %v, want ErrInvalidInput", limit, err)
		}
	}
}

// TestRevokeKeepsTheFirstRevocationTime pins revoked_at against being walked
// forward by a repeated revoke.
//
// Revocation is deliberately idempotent -- it converges rather than objecting,
// so incident response never fails at the moment an operator is shutting a
// credential down. That property is what makes the timestamp attackable: anyone
// still holding the token can call revoke again, and a plain assignment would
// move the recorded time away from the compromise, with every call returning
// success. The forensic question is "from when was this credential dead", so
// the first answer is the correct one to keep.
func TestRevokeKeepsTheFirstRevocationTime(t *testing.T) {
	t.Parallel()

	s := newStore(t)
	ctx := context.Background()

	mustCreateAccessKey(t, s, newAccessKey("ak-1", "owner-a", "ks-1", "ci"))

	first := testClock.Add(time.Hour)
	if err := s.Repos().AccessKeys.Revoke(ctx, "owner-a", "ak-1", first); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	// A day later, and long after the fact. The repeat still succeeds -- that is
	// the idempotence -- but it must not rewrite history.
	later := first.Add(24 * time.Hour)
	if err := s.Repos().AccessKeys.Revoke(ctx, "owner-a", "ak-1", later); err != nil {
		t.Fatalf("Revoke (repeat) = %v, want nil: revocation must stay idempotent", err)
	}

	got, err := s.Repos().AccessKeys.Get(ctx, "owner-a", "ak-1")
	if err != nil {
		t.Fatalf("Get after repeated Revoke: %v", err)
	}
	if got.RevokedAt == nil || !got.RevokedAt.Equal(first) {
		t.Errorf("RevokedAt = %v, want the first revocation time %v", got.RevokedAt, first)
	}
	if got.Status != domain.AccessKeyStatusRevoked {
		t.Errorf("Status = %q, want revoked", got.Status)
	}
}
