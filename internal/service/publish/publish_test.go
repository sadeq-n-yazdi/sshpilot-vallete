package publish

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/repository"
)

func TestResolveDefaultSet(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	owner := f.seedOwner("alice")
	f.addKey(owner.OwnerID, owner.KeySetID, "alice@laptop")

	// An empty set name must reach the same set as naming it explicitly;
	// otherwise /{handle} and /{handle}/default would publish different things.
	byDefault := f.resolve("alice", "")
	byName := f.resolve("alice", "default")

	if byDefault != byName {
		t.Errorf("default resolution differs from named:\n default: %q\n named:   %q", byDefault, byName)
	}
	if got := lines(byDefault); len(got) != 1 {
		t.Fatalf("got %d lines, want 1: %q", len(got), byDefault)
	}
	if !strings.HasSuffix(byDefault, "\n") {
		t.Errorf("body does not end in a newline: %q", byDefault)
	}
}

func TestResolveOutputIsValidAuthorizedKeys(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	owner := f.seedOwner("alice")
	f.addKey(owner.OwnerID, owner.KeySetID, "alice@laptop")
	f.addKey(owner.OwnerID, owner.KeySetID, "")

	body := f.resolve("alice", "")

	// Parse every line the way sshd would. This is the property that matters:
	// the body is not merely well-shaped text, it is a file sshd will accept.
	for _, line := range lines(body) {
		_, comment, options, rest, err := ssh.ParseAuthorizedKey([]byte(line))
		if err != nil {
			t.Fatalf("line does not parse as an authorized_keys entry: %v", err)
		}
		if len(options) != 0 {
			t.Errorf("line carries options %v; published keys must never have any", options)
		}
		if len(rest) != 0 {
			t.Errorf("line has trailing content %q, so it holds more than one entry", rest)
		}
		if strings.ContainsAny(comment, "\n\r") {
			t.Errorf("comment %q contains a line break", comment)
		}
	}
}

func TestResolveOrderingIsDeterministic(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	owner := f.seedOwner("alice")

	// Identifiers are random, so insertion order almost never matches id order.
	// That is exactly what makes this assertion meaningful: it fails if the
	// output ever follows insertion order instead of the promised id order.
	var ids []domain.PublicKeyID
	for range 6 {
		ids = append(ids, f.addKey(owner.OwnerID, owner.KeySetID, ""))
	}
	slices.Sort(ids)

	body := f.resolve("alice", "")
	got := lines(body)
	if len(got) != len(ids) {
		t.Fatalf("got %d lines, want %d", len(got), len(ids))
	}

	// Map each published line back to the key it came from by fingerprint, then
	// assert the sequence matches ascending id order.
	repos := f.store.Repos()
	for i, wantID := range ids {
		key, err := repos.PublicKeys.Get(context.Background(), owner.OwnerID, wantID)
		if err != nil {
			t.Fatalf("get key %s: %v", wantID, err)
		}
		pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(got[i]))
		if err != nil {
			t.Fatalf("parse line %d: %v", i, err)
		}
		if fp := ssh.FingerprintSHA256(pub); fp != key.Fingerprint {
			t.Errorf("line %d is key %s, want %s (ordering is not by id)", i, fp, key.Fingerprint)
		}
	}

	// Repeated resolution must be byte-identical, or the ETag would change
	// under a client that had not missed a single update.
	for range 5 {
		if again := f.resolve("alice", ""); again != body {
			t.Fatalf("repeated resolution differs:\n first: %q\n again: %q", body, again)
		}
	}
}

func TestResolvePublishesOnlyActiveKeys(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	owner := f.seedOwner("alice")
	keep := f.addKey(owner.OwnerID, owner.KeySetID, "keep")
	revoke := f.addKey(owner.OwnerID, owner.KeySetID, "revoked")

	repos := f.store.Repos()
	if err := repos.PublicKeys.Revoke(context.Background(), owner.OwnerID, revoke, testNow); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	revoked, err := repos.PublicKeys.Get(context.Background(), owner.OwnerID, revoke)
	if err != nil {
		t.Fatalf("get revoked key: %v", err)
	}
	kept, err := repos.PublicKeys.Get(context.Background(), owner.OwnerID, keep)
	if err != nil {
		t.Fatalf("get kept key: %v", err)
	}

	body := f.resolve("alice", "")

	// A revoked key appearing here is the failure that lets a decommissioned
	// laptop keep logging in, so assert on the fingerprint rather than a count.
	if strings.Contains(body, base64Of(t, revoked.Blob)) {
		t.Error("revoked key is published")
	}
	if !strings.Contains(body, base64Of(t, kept.Blob)) {
		t.Error("active key is missing from the published body")
	}
	if got := lines(body); len(got) != 1 {
		t.Errorf("got %d lines, want only the active key", len(got))
	}
}

func TestResolveNeverPublishesAnotherOwnersKey(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	alice := f.seedOwner("alice")
	bob := f.seedOwner("bob")

	aliceKey := f.addKey(alice.OwnerID, alice.KeySetID, "alice@laptop")
	bobKey := f.addKey(bob.OwnerID, bob.KeySetID, "bob@laptop")

	// Forge the membership row the repository would refuse to write: bob's key
	// listed as a member of alice's set. The publish query's pk.owner_id
	// predicate is what must still exclude it, and this is the only way to
	// prove that predicate is load-bearing rather than incidental.
	f.exec(
		`INSERT INTO key_set_members (key_set_id, public_key_id, added_at) VALUES (?, ?, ?)`,
		string(alice.KeySetID), string(bobKey), testNow.Format(sqliteTimeLayout),
	)

	repos := f.store.Repos()
	bobStored, err := repos.PublicKeys.Get(context.Background(), bob.OwnerID, bobKey)
	if err != nil {
		t.Fatalf("get bob's key: %v", err)
	}
	aliceStored, err := repos.PublicKeys.Get(context.Background(), alice.OwnerID, aliceKey)
	if err != nil {
		t.Fatalf("get alice's key: %v", err)
	}

	body := f.resolve("alice", "")

	if strings.Contains(body, base64Of(t, bobStored.Blob)) {
		t.Error("another owner's key was published through a forged membership row")
	}
	if !strings.Contains(body, base64Of(t, aliceStored.Blob)) {
		t.Error("the owner's own key is missing")
	}
}

// TestResolveNotFoundCases covers every input that must be indistinguishable
// from every other. They are asserted together, in one table, because the
// property under test is that they all produce the SAME sentinel — splitting
// them into separate tests would let one drift into its own error unnoticed.
func TestResolveNotFoundCases(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		setup   func(f *fixture)
		handle  string
		setName string
	}{
		{
			name:   "unknown handle",
			setup:  func(f *fixture) { f.seedOwner("alice") },
			handle: "nobody",
		},
		{
			name:   "malformed handle",
			setup:  func(f *fixture) { f.seedOwner("alice") },
			handle: "Not A Handle!",
		},
		{
			name:    "malformed set name",
			setup:   func(f *fixture) { f.seedOwner("alice") },
			handle:  "alice",
			setName: "../etc/passwd",
		},
		{
			name:    "unknown set",
			setup:   func(f *fixture) { f.seedOwner("alice") },
			handle:  "alice",
			setName: "nosuchset",
		},
		{
			name: "set belonging to another owner",
			setup: func(f *fixture) {
				f.seedOwner("alice")
				bob := f.seedOwner("bob")
				// Give bob a distinctly named set and ask for it under alice.
				f.exec(`UPDATE key_sets SET name = 'bobsecrets' WHERE id = ?`, string(bob.KeySetID))
			},
			handle:  "alice",
			setName: "bobsecrets",
		},
		{
			name: "protected set",
			setup: func(f *fixture) {
				alice := f.seedOwner("alice")
				f.addKey(alice.OwnerID, alice.KeySetID, "")
				f.exec(`UPDATE key_sets SET visibility = 'protected' WHERE id = ?`, string(alice.KeySetID))
			},
			handle: "alice",
		},
		{
			name: "quarantined handle",
			setup: func(f *fixture) {
				f.seedOwner("alice")
				f.exec(`UPDATE handles SET state = 'quarantined' WHERE name = 'alice'`)
			},
			handle: "alice",
		},
		{
			name: "retired handle",
			setup: func(f *fixture) {
				f.seedOwner("alice")
				f.exec(`UPDATE handles SET state = 'retired' WHERE name = 'alice'`)
			},
			handle: "alice",
		},
		{
			name: "quarantined set",
			setup: func(f *fixture) {
				alice := f.seedOwner("alice")
				f.exec(`UPDATE key_sets SET state = 'quarantined' WHERE id = ?`, string(alice.KeySetID))
			},
			handle: "alice",
		},
		{
			name: "suspended owner",
			setup: func(f *fixture) {
				alice := f.seedOwner("alice")
				f.exec(`UPDATE owners SET status = 'suspended' WHERE id = ?`, string(alice.OwnerID))
			},
			handle: "alice",
		},
		{
			name: "soft-deleted owner",
			setup: func(f *fixture) {
				alice := f.seedOwner("alice")
				f.exec(`UPDATE owners SET deleted_at = ? WHERE id = ?`,
					testNow.Format(sqliteTimeLayout), string(alice.OwnerID))
			},
			handle: "alice",
		},
		{
			name: "owner with no default set",
			setup: func(f *fixture) {
				alice := f.seedOwner("alice")
				f.exec(`UPDATE key_sets SET is_default = 0 WHERE id = ?`, string(alice.KeySetID))
			},
			handle: "alice",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newFixture(t)
			tc.setup(f)

			body, err := f.svc.Resolve(context.Background(), tc.handle, tc.setName)
			if !errors.Is(err, ErrNotFound) {
				t.Fatalf("Resolve(%q, %q) error = %v, want ErrNotFound", tc.handle, tc.setName, err)
			}
			if body != nil {
				t.Errorf("body = %q, want nil; a 404 path must return no key data", body)
			}
		})
	}
}

func TestResolveEmptyPublicSetSucceeds(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	f.seedOwner("alice")

	// A public set with no keys is not a 404: the set exists and is public by
	// its owner's declaration, and an empty authorized_keys file is the honest
	// representation of "this set publishes nothing". Answering 404 would also
	// make a legitimately empty set look like a nonexistent one to sshd.
	body, err := f.svc.Resolve(context.Background(), "alice", "")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(body) != 0 {
		t.Errorf("body = %q, want empty", body)
	}
}

func TestNewRejectsIncompleteRepos(t *testing.T) {
	t.Parallel()

	// A partially wired service must fail at construction, not nil-panic on the
	// first live request.
	if _, err := New(repository.Repos{}); !errors.Is(err, ErrMissingRepository) {
		t.Errorf("New(empty) error = %v, want ErrMissingRepository", err)
	}
}

// base64Of returns the base64 of a stored blob as it appears in an
// authorized_keys line, so tests can assert on key identity within a body.
func base64Of(t *testing.T, blob []byte) string {
	t.Helper()

	pub, err := ssh.ParsePublicKey(blob)
	if err != nil {
		t.Fatalf("ssh.ParsePublicKey: %v", err)
	}
	fields := strings.Fields(string(ssh.MarshalAuthorizedKey(pub)))
	if len(fields) < 2 {
		t.Fatalf("unexpected authorized key form: %q", fields)
	}
	return fields[1]
}
