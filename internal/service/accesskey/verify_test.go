package accesskey

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/secrets"
)

// TestVerifyAcceptsMintedToken is the positive control. Every test below asserts
// a refusal, and a refusal is only meaningful if the same setup accepted.
func TestVerifyAcceptsMintedToken(t *testing.T) {
	f := newFixture(t)
	owner := f.seedOwner("alice")
	k, token := f.mint(owner.OwnerID, owner.KeySetID, "ci")

	got, err := f.svc.Verify(context.Background(), owner.OwnerID, owner.KeySetID, token)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got.ID != k.ID {
		t.Fatalf("Verify resolved %q, want %q", got.ID, k.ID)
	}
}

// TestVerifyRejectsTokenForAnotherSet is the set-scope invariant. The token is
// genuine, its owner is right, and its secret is right; only the set differs.
// The repository's Get is scoped by owner and id and NOT by key set, so if
// Verify drops its KeySetID comparison this call succeeds and a credential for
// a public set opens a protected one.
func TestVerifyRejectsTokenForAnotherSet(t *testing.T) {
	f := newFixture(t)
	owner := f.seedOwner("alice")
	other := f.seedSet(owner.OwnerID, "prod", domain.NameStateActive)

	_, token := f.mint(owner.OwnerID, owner.KeySetID, "ci")

	_, err := f.svc.Verify(context.Background(), owner.OwnerID, other, token)
	denied(t, "Verify with a token for a different set", err)
}

// TestVerifyRejectsAnotherOwnersToken is the cross-owner invariant, which lives
// in the SQL predicate rather than in this package. Bob's genuine token, whose
// id is real, must not resolve under Alice.
func TestVerifyRejectsAnotherOwnersToken(t *testing.T) {
	f := newFixture(t)
	alice := f.seedOwner("alice")
	bob := f.seedOwner("bob")

	_, token := f.mint(bob.OwnerID, bob.KeySetID, "ci")

	_, err := f.svc.Verify(context.Background(), alice.OwnerID, alice.KeySetID, token)
	denied(t, "Verify with another owner's token", err)
}

// TestVerifyRejectsWrongSecret keeps the id genuine and changes only the secret,
// so what it exercises is the digest comparison and nothing else. A compare that
// always returned true — or one that compared the wrong operands — passes every
// other test in this file and fails this one.
func TestVerifyRejectsWrongSecret(t *testing.T) {
	f := newFixture(t)
	owner := f.seedOwner("alice")
	k, _ := f.mint(owner.OwnerID, owner.KeySetID, "ci")

	forged := secrets.NewRedacted(tokenPrefix + string(k.ID) + tokenSeparator + strings.Repeat("A", 43))

	_, err := f.svc.Verify(context.Background(), owner.OwnerID, owner.KeySetID, forged)
	denied(t, "Verify with a wrong secret", err)
}

// TestVerifyRejectsSwappedSecret presents one credential's id with another
// credential's secret. Both halves are genuine and neither belongs to the other,
// which is the case a digest that did not bind the id into its message would
// accept.
func TestVerifyRejectsSwappedSecret(t *testing.T) {
	f := newFixture(t)
	owner := f.seedOwner("alice")
	first, _ := f.mint(owner.OwnerID, owner.KeySetID, "ci")
	_, secondToken := f.mint(owner.OwnerID, owner.KeySetID, "deploy")

	_, secondSecret, ok := parseToken(secondToken.Reveal())
	if !ok {
		t.Fatalf("parseToken of a freshly minted token failed")
	}
	swapped := secrets.NewRedacted(tokenPrefix + string(first.ID) + tokenSeparator + secondSecret)

	_, err := f.svc.Verify(context.Background(), owner.OwnerID, owner.KeySetID, swapped)
	denied(t, "Verify with a swapped secret", err)
}

// TestVerifyRejectsRevoked asserts revocation is terminal even for a token whose
// secret is correct. The status check runs before the digest comparison, which
// is the whole meaning of revocation.
func TestVerifyRejectsRevoked(t *testing.T) {
	f := newFixture(t)
	owner := f.seedOwner("alice")
	k, token := f.mint(owner.OwnerID, owner.KeySetID, "ci")

	if err := f.svc.Revoke(context.Background(), owner.OwnerID, k.ID, "req-2"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	_, err := f.svc.Verify(context.Background(), owner.OwnerID, owner.KeySetID, token)
	denied(t, "Verify with a revoked token", err)
}

// TestVerifyGraceBoundary pins the deadline on both sides of the exact instant.
// The window is INCLUSIVE: a credential is honored at its deadline and refused
// one nanosecond later. An off-by-one in either direction — > for >=, or
// Before for After — fails one of these two subtests.
func TestVerifyGraceBoundary(t *testing.T) {
	deadline := fixedNow.Add(time.Hour)

	for _, tc := range []struct {
		name string
		now  time.Time
		want bool
	}{
		{"before the deadline", deadline.Add(-time.Second), true},
		{"at the deadline", deadline, true},
		{"one nanosecond past the deadline", deadline.Add(time.Nanosecond), false},
		{"long past the deadline", deadline.Add(time.Hour), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			owner := f.seedOwner("alice")
			k, token := f.mint(owner.OwnerID, owner.KeySetID, "ci")

			if err := f.store.Repos().AccessKeys.MarkRotated(context.Background(), owner.OwnerID, k.ID, "replacement", deadline); err != nil {
				t.Fatalf("MarkRotated: %v", err)
			}

			f.now = tc.now
			_, err := f.svc.Verify(context.Background(), owner.OwnerID, owner.KeySetID, token)
			switch {
			case tc.want && err != nil:
				t.Fatalf("Verify at %v: %v, want acceptance", tc.now, err)
			case !tc.want:
				denied(t, "Verify at "+tc.now.String(), err)
			}
		})
	}
}

// TestVerifyRejectsGraceWithoutDeadline covers the row the write path never
// produces: grace status with a NULL grace_until. A missing deadline must not
// read as "no expiry", which would make the credential immortal.
func TestVerifyRejectsGraceWithoutDeadline(t *testing.T) {
	f := newFixture(t)
	owner := f.seedOwner("alice")
	k, token := f.mint(owner.OwnerID, owner.KeySetID, "ci")

	f.exec(`UPDATE access_keys SET status = 'grace', grace_until = NULL WHERE id = ?`, string(k.ID))

	_, err := f.svc.Verify(context.Background(), owner.OwnerID, owner.KeySetID, token)
	denied(t, "Verify with a grace key holding no deadline", err)
}

// TestVerifyRejectsMalformedTokens walks the shapes the parser must refuse. None
// may panic, and every one must produce the same verdict a wrong secret gets, so
// that a caller cannot use the parser as an oracle for which shapes are close.
func TestVerifyRejectsMalformedTokens(t *testing.T) {
	f := newFixture(t)
	owner := f.seedOwner("alice")
	k, _ := f.mint(owner.OwnerID, owner.KeySetID, "ci")
	id := string(k.ID)

	for _, tc := range []struct {
		name  string
		token string
	}{
		{"empty", ""},
		{"prefix only", tokenPrefix},
		{"no prefix", id + tokenSeparator + "secret"},
		{"wrong prefix", "bearer_" + id + tokenSeparator + "secret"},
		{"no separator", tokenPrefix + id},
		{"empty id", tokenPrefix + tokenSeparator + "secret"},
		{"empty secret", tokenPrefix + id + tokenSeparator},
		{"extra separator", tokenPrefix + id + tokenSeparator + "a" + tokenSeparator + "b"},
		{"separator only", tokenPrefix + tokenSeparator},
		{"oversized", tokenPrefix + id + tokenSeparator + strings.Repeat("A", maxTokenLen)},
		{"unknown id", tokenPrefix + strings.Repeat("Z", 26) + tokenSeparator + strings.Repeat("A", 43)},
		{"nul bytes", tokenPrefix + id + tokenSeparator + "\x00\x00"},
		{"whitespace", "   "},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := f.svc.Verify(context.Background(), owner.OwnerID, owner.KeySetID, secrets.NewRedacted(tc.token))
			denied(t, "Verify("+tc.name+")", err)
		})
	}
}

// TestVerifyRejectsEmptyIdentifiers covers a caller that failed to resolve the
// handle or the set. It is answered with the verdict rather than an
// invalid-input error, because this is the unauthenticated path and a second
// distinguishable outcome on it is a second signal to read.
func TestVerifyRejectsEmptyIdentifiers(t *testing.T) {
	f := newFixture(t)
	owner := f.seedOwner("alice")
	_, token := f.mint(owner.OwnerID, owner.KeySetID, "ci")

	_, err := f.svc.Verify(context.Background(), "", owner.KeySetID, token)
	denied(t, "Verify with no owner", err)

	_, err = f.svc.Verify(context.Background(), owner.OwnerID, "", token)
	denied(t, "Verify with no key set", err)
}

// TestUsableRejectsUnknownStatus covers a status this code does not recognize.
// The database's CHECK constraint makes such a row unreachable through storage
// today, which is exactly why the case is exercised against the decision
// function directly: the constraint is not what makes the answer safe, the
// explicit default is, and a future status added to the domain must not become
// usable by omission.
func TestUsableRejectsUnknownStatus(t *testing.T) {
	f := newFixture(t)

	if f.svc.usable(&domain.AccessKey{Status: domain.AccessKeyStatus("pending")}) {
		t.Fatal("usable accepted an unrecognized status")
	}
	if f.svc.usable(&domain.AccessKey{Status: ""}) {
		t.Fatal("usable accepted an empty status")
	}
}

// TestVerifyPropagatesStorageFailure asserts a storage fault is NOT collapsed
// into the negative verdict. A database that could not be read has not decided
// the caller is unauthorized, and answering 404 for an outage makes it look
// exactly like normal operation.
func TestVerifyPropagatesStorageFailure(t *testing.T) {
	f := newFixture(t)
	owner := f.seedOwner("alice")
	_, token := f.mint(owner.OwnerID, owner.KeySetID, "ci")

	if err := f.db.Close(); err != nil {
		t.Fatalf("db.Close: %v", err)
	}

	_, err := f.svc.Verify(context.Background(), owner.OwnerID, owner.KeySetID, token)
	if err == nil {
		t.Fatal("Verify against a closed database succeeded")
	}
	if errors.Is(err, ErrNotFound) {
		t.Fatalf("storage failure collapsed into the negative verdict: %v", err)
	}
}

// TestHashBindsIDAndSecret asserts the digest is meaningful for exactly one
// credential. Both properties are checked directly on the hasher because
// neither is reachable through the write path: mint never produces two rows
// sharing a secret, so a digest that attested only to "this secret is valid"
// would pass every end-to-end test here while allowing a stored hash to be
// moved between rows — including to a row for a different key set — and still
// verify.
func TestHashBindsIDAndSecret(t *testing.T) {
	f := newFixture(t)
	h := f.svc.hasher

	if string(h.hash("id-one", "secret")) == string(h.hash("id-two", "secret")) {
		t.Fatal("one secret digests identically under two key ids")
	}
	// The separator must make the message unambiguous: ("ab", "c") and
	// ("a", "bc") concatenate to the same bytes without it.
	if string(h.hash("ab", "c")) == string(h.hash("a", "bc")) {
		t.Fatal("the id and secret boundary is ambiguous in the digested message")
	}
	if string(h.hash("id", "secret")) == string(h.hash("id", "secrets")) {
		t.Fatal("two secrets digest identically under one id")
	}
}

// TestHashIsKeyedByThePepper asserts an attacker holding only the database
// cannot compute a valid digest: two services differing solely in their pepper
// produce different hashes for the same credential, and a token minted under
// one does not verify under the other.
func TestHashIsKeyedByThePepper(t *testing.T) {
	f := newFixture(t)
	owner := f.seedOwner("alice")
	k, token := f.mint(owner.OwnerID, owner.KeySetID, "ci")

	repos := f.store.Repos()
	other, err := New(repos.AccessKeys, repos.KeySets, f.audit, []byte("ffffffffffffffffffffffffffffffff"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if string(other.hasher.hash(k.ID, "secret")) == string(f.svc.hasher.hash(k.ID, "secret")) {
		t.Fatal("the digest does not depend on the pepper")
	}

	_, err = other.Verify(context.Background(), owner.OwnerID, owner.KeySetID, token)
	denied(t, "Verify under a different pepper", err)
}
