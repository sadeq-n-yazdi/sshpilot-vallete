package erasure_test

import (
	"context"
	"testing"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/audit"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/erasure"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/storage/sqlite"
)

// erasableDetails are the seven detail keys whose values name an owner and must
// be tombstoned by erasure. keptDetails are the seven structural keys that must
// survive byte-for-byte. Together they are the full fourteen-key allowlist, and
// this pair IS the authoritative classification from ADR-0024: a future edit
// that moves a key across the line makes the assertions below fail rather than
// silently changing what erasure erases.
var erasableDetails = map[audit.DetailKey]string{
	audit.DetailFingerprint: "SHA256:" + "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ",
	audit.DetailHandle:      "acme",
	audit.DetailDeviceName:  "my laptop",
	audit.DetailKeySetName:  "production",
	audit.DetailClientLabel: "ci runner",
	audit.DetailFrom:        "old-name",
	audit.DetailTo:          "new-name",
}

var keptDetails = map[audit.DetailKey]string{
	audit.DetailAlgorithm:  "ssh-ed25519",
	audit.DetailVisibility: "public",
	audit.DetailScope:      "read",
	audit.DetailReason:     "scheduled rotation",
	audit.DetailResult:     "allowed",
	audit.DetailRequestID:  "req-12345",
	audit.DetailCount:      "5",
}

// fullMetadata builds a metadata map covering every allowlisted key.
func fullMetadata() map[string]string {
	m := map[string]string{}
	for k, v := range erasableDetails {
		m[string(k)] = v
	}
	for k, v := range keptDetails {
		m[string(k)] = v
	}
	return m
}

// appendAudit inserts one audit record straight through the repository, so a
// test can seed metadata the request path's validators would otherwise shape.
func appendAudit(t *testing.T, s *sqlite.Store, id, actor, target string, meta map[string]string) {
	t.Helper()
	rec := &domain.AuditRecord{
		ID:         domain.AuditRecordID(id),
		ActorType:  domain.ActorTypeOwner,
		ActorID:    actor,
		Action:     domain.AuditActionKeySetRenamed,
		TargetType: domain.TargetTypeKeySet,
		TargetID:   target,
		OccurredAt: testClock,
		Metadata:   meta,
	}
	if err := s.Repos().Audit.Append(context.Background(), rec); err != nil {
		t.Fatalf("append audit %s: %v", id, err)
	}
}

func primitiveEraser(t *testing.T, s *sqlite.Store) *erasure.Eraser {
	t.Helper()
	e, err := erasure.New(s.Repos().Audit, s.Repos().OwnerSalts)
	if err != nil {
		t.Fatalf("erasure.New: %v", err)
	}
	return e
}

func getAudit(t *testing.T, s *sqlite.Store, id string) *domain.AuditRecord {
	t.Helper()
	rec, err := s.Repos().Audit.Get(context.Background(), domain.AuditRecordID(id))
	if err != nil {
		t.Fatalf("get audit %s: %v", id, err)
	}
	return rec
}

// TestEraseOwnerScrubsMetadataPerClassification is the whole-record erasure
// pin. It seeds one record carrying every allowlisted detail key, erases the
// owner, and asserts key by key that each identifying value became an
// irreversible tombstone while each structural value survived unchanged. It
// fails if a key is ever reclassified, so the policy cannot drift silently.
func TestEraseOwnerScrubsMetadataPerClassification(t *testing.T) {
	t.Parallel()
	_, store := newStore(t)
	ctx := context.Background()

	appendAudit(t, store, "aud-1", "owner-a", "set-1", fullMetadata())

	if _, err := primitiveEraser(t, store).EraseOwner(ctx, "owner-a", []string{"owner-a"}); err != nil {
		t.Fatalf("EraseOwner: %v", err)
	}

	got := getAudit(t, store, "aud-1")
	for key, original := range erasableDetails {
		v := got.Metadata[string(key)]
		if v == original {
			t.Errorf("erasable detail %q survived in the clear: %q", key, v)
		}
		if !erasure.IsTombstoneForTest(v) {
			t.Errorf("erasable detail %q = %q, want a tombstone", key, v)
		}
	}
	for key, original := range keptDetails {
		if v := got.Metadata[string(key)]; v != original {
			t.Errorf("structural detail %q = %q, want it preserved byte-for-byte %q", key, v, original)
		}
	}
}

// TestEraseOwnerScrubsRenameFromTo is the explicit statement that a rename
// record's before/after names are erased: they carry the owner's old and new
// display names and are as identifying as any other name.
func TestEraseOwnerScrubsRenameFromTo(t *testing.T) {
	t.Parallel()
	_, store := newStore(t)
	ctx := context.Background()

	appendAudit(t, store, "aud-1", "owner-a", "set-1", map[string]string{
		"from": "acme-old",
		"to":   "acme-new",
	})

	if _, err := primitiveEraser(t, store).EraseOwner(ctx, "owner-a", []string{"owner-a"}); err != nil {
		t.Fatalf("EraseOwner: %v", err)
	}

	got := getAudit(t, store, "aud-1")
	for _, key := range []string{"from", "to"} {
		v := got.Metadata[key]
		if v == "acme-old" || v == "acme-new" || !erasure.IsTombstoneForTest(v) {
			t.Errorf("rename detail %q = %q, want a tombstone", key, v)
		}
	}
}

// TestEraseOwnerMetadataTombstonesAreConsistent proves the count/lineage
// property: the same value in two different records erases to the SAME
// tombstone, so a reader can still see the two events involved one thing.
func TestEraseOwnerMetadataTombstonesAreConsistent(t *testing.T) {
	t.Parallel()
	_, store := newStore(t)
	ctx := context.Background()

	appendAudit(t, store, "aud-1", "owner-a", "set-1", map[string]string{"handle": "acme"})
	appendAudit(t, store, "aud-2", "owner-a", "set-2", map[string]string{"handle": "acme"})

	if _, err := primitiveEraser(t, store).EraseOwner(ctx, "owner-a", []string{"owner-a"}); err != nil {
		t.Fatalf("EraseOwner: %v", err)
	}

	a := getAudit(t, store, "aud-1").Metadata["handle"]
	b := getAudit(t, store, "aud-2").Metadata["handle"]
	if a == "acme" || !erasure.IsTombstoneForTest(a) {
		t.Fatalf("handle not tombstoned: %q", a)
	}
	if a != b {
		t.Errorf("equal handles erased to different tombstones %q and %q: lineage is broken", a, b)
	}
}

// TestEraseOwnerMetadataIsIrreversible proves the scrub inherits the primitive's
// irreversibility: once the salt is destroyed, the tombstone in the metadata
// cannot be recomputed from the value, so no one can confirm what it was.
func TestEraseOwnerMetadataIsIrreversible(t *testing.T) {
	t.Parallel()
	_, store := newStore(t)
	ctx := context.Background()

	appendAudit(t, store, "aud-1", "owner-a", "set-1", map[string]string{"handle": "acme"})

	if _, err := primitiveEraser(t, store).EraseOwner(ctx, "owner-a", []string{"owner-a"}); err != nil {
		t.Fatalf("EraseOwner: %v", err)
	}
	tomb := getAudit(t, store, "aud-1").Metadata["handle"]

	// The salt is gone.
	if _, err := store.Repos().OwnerSalts.Get(ctx, "owner-a"); err == nil {
		t.Fatal("salt survived erasure: the metadata tombstone is still reversible")
	}
	// A fresh salt cannot reproduce the destroyed salt's tombstone, so holding
	// the record and the candidate value learns nothing.
	fresh, err := store.Repos().OwnerSalts.Ensure(ctx, "owner-a")
	if err != nil {
		t.Fatalf("ensure fresh salt: %v", err)
	}
	if erasure.Verify(fresh, "acme", tomb) {
		t.Error("a fresh salt reproduced the destroyed salt's metadata tombstone")
	}
}

// TestEraseOwnerMetadataScrubIsIdempotent re-runs the whole erasure and asserts
// the metadata tombstone is stable, not re-tombstoned under the fresh salt the
// second pass mints. isTombstone recognizing the already-erased value is what
// makes this hold.
func TestEraseOwnerMetadataScrubIsIdempotent(t *testing.T) {
	t.Parallel()
	_, store := newStore(t)
	ctx := context.Background()

	appendAudit(t, store, "aud-1", "owner-a", "set-1", map[string]string{"handle": "acme"})

	e := primitiveEraser(t, store)
	if _, err := e.EraseOwner(ctx, "owner-a", []string{"owner-a"}); err != nil {
		t.Fatalf("first EraseOwner: %v", err)
	}
	first := getAudit(t, store, "aud-1").Metadata["handle"]

	if _, err := e.EraseOwner(ctx, "owner-a", []string{"owner-a"}); err != nil {
		t.Fatalf("second EraseOwner: %v", err)
	}
	second := getAudit(t, store, "aud-1").Metadata["handle"]

	if first != second {
		t.Errorf("metadata tombstone drifted across runs: %q then %q", first, second)
	}
}
