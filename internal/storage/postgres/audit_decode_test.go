package postgres

import (
	"context"
	"testing"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/repository"
)

// insertRawAudit writes an audit row straight through the handle, bypassing the
// adapter's encoders, so the decode paths can be exercised against values the
// adapter itself would never produce.
func insertRawAudit(t *testing.T, s *Store, id, occurredAt, metadata string) {
	t.Helper()
	const q = `INSERT INTO audit_records
(id, actor_type, actor_id, action, target_type, target_id, occurred_at, metadata, pseudonymized)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`
	if _, err := s.db.ExecContext(context.Background(), q,
		id, string(domain.ActorTypeOwner), "owner-a", string(domain.AuditActionKeyAdded),
		string(domain.TargetTypePublicKey), "key-1", occurredAt, metadata, false); err != nil {
		t.Fatalf("insert raw audit row %q: %v", id, err)
	}
}

// TestAuditGetRejectsCorruptRow covers both decode branches in scanAuditRecord:
// an unparseable timestamp and unparseable metadata JSON.
func TestAuditGetRejectsCorruptRow(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	_, repo := auditSink(t, s)

	insertRawAudit(t, s, "aud-bad-time", "not-a-timestamp", "{}")
	insertRawAudit(t, s, "aud-bad-meta", encTime(testClock), `{"a":`)

	for _, id := range []string{"aud-bad-time", "aud-bad-meta"} {
		if _, err := repo.Get(ctx, domain.AuditRecordID(id)); err == nil {
			t.Errorf("Get(%q) on a corrupt row = nil error, want a decode failure", id)
		}
	}
}

// TestAuditListRejectsCorruptRow drives the same decode failure through the
// iterating path in collectAuditRecords rather than the single-row path.
func TestAuditListRejectsCorruptRow(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	_, repo := auditSink(t, s)

	insertRawAudit(t, s, "aud-bad-time", "not-a-timestamp", "{}")

	if _, _, err := repo.List(context.Background(), repository.AuditQuery{}, repository.Page{}); err == nil {
		t.Error("List over a corrupt row = nil error, want a decode failure")
	}
}

// TestAuditNullMetadataDecodesToNil covers the JSON-null metadata branch: a
// literal "null" unmarshals to a nil map and must surface as nil, not as an
// empty map, matching the nil-collection convention.
func TestAuditNullMetadataDecodesToNil(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	_, repo := auditSink(t, s)

	insertRawAudit(t, s, "aud-null-meta", encTime(testClock), "null")

	got, err := repo.Get(context.Background(), "aud-null-meta")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Metadata != nil {
		t.Errorf("Metadata = %#v, want nil", got.Metadata)
	}
}

func TestAuditEmptyMetadataColumnDecodesToNil(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	_, repo := auditSink(t, s)

	insertRawAudit(t, s, "aud-empty-meta", encTime(testClock), "")

	got, err := repo.Get(context.Background(), "aud-empty-meta")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Metadata != nil {
		t.Errorf("Metadata = %#v, want nil", got.Metadata)
	}
}

// TestAuditQueryErrorsAreMapped covers the query-failure branches by driving
// both reads with an already-canceled context.
func TestAuditQueryErrorsAreMapped(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	sink, repo := auditSink(t, s)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, _, err := repo.List(ctx, repository.AuditQuery{}, repository.Page{}); err == nil {
		t.Error("List with a canceled context = nil error, want failure")
	}
	if _, err := repo.Get(ctx, "aud-1"); err == nil {
		t.Error("Get with a canceled context = nil error, want failure")
	}
	if err := sink.Append(ctx, newAuditRecord("aud-1", "owner-a", "key-1", testClock)); err == nil {
		t.Error("Append with a canceled context = nil error, want failure")
	}
}
