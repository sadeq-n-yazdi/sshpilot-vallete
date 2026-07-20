package auth_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/auth"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/secrets"
)

// TestReuseOfConsumedTokenRevokesTheWholeLineage is the reuse-theft property.
// Presenting a consumed token means it was captured; since victim and attacker
// are indistinguishable, every credential in the lineage dies -- including the
// sibling the legitimate holder is still using, which is the whole point.
func TestReuseOfConsumedTokenRevokesTheWholeLineage(t *testing.T) {
	store, svc := newService(t)
	first := issue(t, svc, baseTime)
	// Two further rotations, so the lineage has a consumed root, a consumed
	// middle, and a live tip. A test with only two credentials cannot tell
	// "revoked the presented one" from "revoked the lineage".
	second := exchange(t, svc, first.RefreshToken, baseTime.Add(time.Hour))
	third := exchange(t, svc, second.RefreshToken, baseTime.Add(2*time.Hour))

	// The attacker replays the captured first token.
	got, err := svc.Exchange(context.Background(), first.RefreshToken, baseTime.Add(3*time.Hour))
	denied(t, got, err)

	rows := store.all()
	if len(rows) != 3 {
		t.Fatalf("lineage holds %d credentials, want 3", len(rows))
	}
	for _, c := range rows {
		if c.Status != domain.CredentialStatusRevoked {
			t.Fatalf("credential %q has status %q, want revoked -- the whole lineage must die, not only the presented token", c.ID, c.Status)
		}
		if c.RevokedAt == nil || !c.RevokedAt.Equal(baseTime.Add(3*time.Hour)) {
			t.Fatalf("credential %q RevokedAt = %v, want the presentation time", c.ID, c.RevokedAt)
		}
	}

	// The sibling the legitimate holder still has must now be dead too. This is
	// the assertion that separates "revoked the lineage" from "revoked the
	// replayed token".
	got, err = svc.Exchange(context.Background(), third.RefreshToken, baseTime.Add(4*time.Hour))
	denied(t, got, err)
}

// TestReuseWithWrongSecretDoesNotRevokeTheLineage guards the ordering that
// makes reuse detection safe to have at all. If the lineage died on the
// identifier alone, anyone who read an identifier out of a log or a backup
// could log any user out at will -- a denial-of-service handed to whoever sees
// a non-secret value. Possession of the secret is what makes "this was
// captured" the right conclusion.
func TestReuseWithWrongSecretDoesNotRevokeTheLineage(t *testing.T) {
	store, svc := newService(t)
	first := issue(t, svc, baseTime)
	second := exchange(t, svc, first.RefreshToken, baseTime.Add(time.Hour))

	// The identifier of the consumed credential, with a secret the attacker
	// made up.
	forged := forgeSecret(t, first.RefreshToken)

	got, err := svc.Exchange(context.Background(), forged, baseTime.Add(2*time.Hour))
	denied(t, got, err)

	for _, c := range store.all() {
		if c.Status == domain.CredentialStatusRevoked {
			t.Fatalf("credential %q was revoked by a presentation that never proved possession of the secret", c.ID)
		}
	}
	// And the legitimate holder is unaffected.
	exchange(t, svc, second.RefreshToken, baseTime.Add(3*time.Hour))
}

// TestAbsoluteCapIsNotExtendableByRotation is the classic bug in this design:
// a lineage that keeps rotating quietly becomes permanent. The lineage is
// rotated repeatedly right up to the cap, and then rejected past it -- with a
// fresh lineage rotated successfully at the same absolute instant, so the test
// cannot pass merely because everything is being rejected.
func TestAbsoluteCapIsNotExtendableByRotation(t *testing.T) {
	store, svc := newService(t)
	deadline := baseTime.Add(auth.RefreshLineageLifetime)

	current := issue(t, svc, baseTime)
	rootID := store.all()[0].ID
	// Rotate every ten days for the life of the lineage. Each rotation is the
	// event that would extend the deadline if the child re-based it on now.
	for at := baseTime.Add(10 * 24 * time.Hour); at.Before(deadline); at = at.Add(10 * 24 * time.Hour) {
		current = exchange(t, svc, current.RefreshToken, at)
		if !current.RefreshExpiresAt.Equal(deadline) {
			t.Fatalf("after rotating at %v the deadline moved to %v, want the original %v", at, current.RefreshExpiresAt, deadline)
		}
	}

	// Rotated seconds ago, and dead all the same.
	got, err := svc.Exchange(context.Background(), current.RefreshToken, deadline)
	denied(t, got, err)
	got, err = svc.Exchange(context.Background(), current.RefreshToken, deadline.Add(24*time.Hour))
	denied(t, got, err)

	// The control: a lineage issued recently rotates fine at the very instant
	// the old one is refused. Without this, the assertions above would pass for
	// a mutant that rejects every exchange.
	fresh := issue(t, svc, deadline.Add(-time.Hour))
	exchange(t, svc, fresh.RefreshToken, deadline.Add(24*time.Hour))

	// Every credential in the capped lineage is now beyond use, and none of
	// them was rewritten with a later deadline.
	for _, c := range store.all() {
		if c.LineageID != domain.LineageID(rootID) {
			continue
		}
		if !c.ExpiresAt.Equal(deadline) {
			t.Fatalf("credential %q has ExpiresAt %v, want the lineage deadline %v", c.ID, c.ExpiresAt, deadline)
		}
	}
}

// TestExpiryBoundaryOfALineage pins the exact instant a lineage stops
// rotating: valid up to but excluding the deadline.
func TestExpiryBoundaryOfALineage(t *testing.T) {
	_, svc := newService(t)
	deadline := baseTime.Add(auth.RefreshLineageLifetime)

	first := issue(t, svc, baseTime)
	// One nanosecond before the deadline the exchange still succeeds.
	second := exchange(t, svc, first.RefreshToken, deadline.Add(-time.Nanosecond))
	// Exactly at the deadline it does not.
	got, err := svc.Exchange(context.Background(), second.RefreshToken, deadline)
	denied(t, got, err)
}

// TestExpiredLineageIsNotRevoked separates natural expiry from theft. An
// expired credential is refused, but nothing about presenting it is evidence of
// capture, so the lineage is left alone rather than marked revoked.
func TestExpiredLineageIsNotRevoked(t *testing.T) {
	store, svc := newService(t)
	first := issue(t, svc, baseTime)

	got, err := svc.Exchange(context.Background(), first.RefreshToken, baseTime.Add(auth.RefreshLineageLifetime))
	denied(t, got, err)

	if s := store.all()[0].Status; s != domain.CredentialStatusActive {
		t.Fatalf("status after presenting an expired credential = %q, want it left untouched", s)
	}
}

func TestExchangeDeniesUnusableCredentials(t *testing.T) {
	tests := []struct {
		name  string
		setup func(t *testing.T, store *fakeStore, first *auth.Issued) secrets.Redacted
	}{
		{
			name: "malformed token",
			setup: func(*testing.T, *fakeStore, *auth.Issued) secrets.Redacted {
				return secrets.NewRedacted("not-a-token")
			},
		},
		{
			name: "unknown credential",
			setup: func(t *testing.T, _ *fakeStore, first *auth.Issued) secrets.Redacted {
				return retarget(t, first.RefreshToken, "AAAAAAAAAAAAAAAAAAAAAA")
			},
		},
		{
			name: "wrong secret",
			setup: func(t *testing.T, _ *fakeStore, first *auth.Issued) secrets.Redacted {
				return forgeSecret(t, first.RefreshToken)
			},
		},
		{
			name: "storage fault on lookup",
			setup: func(_ *testing.T, store *fakeStore, first *auth.Issued) secrets.Redacted {
				store.getByIDErr = errStore
				return first.RefreshToken
			},
		},
		{
			name: "store returns a nil row with no error",
			setup: func(_ *testing.T, store *fakeStore, first *auth.Issued) secrets.Redacted {
				store.nilRow = true
				return first.RefreshToken
			},
		},
		{
			name: "store returns a different credential",
			setup: func(_ *testing.T, store *fakeStore, first *auth.Issued) secrets.Redacted {
				row := store.all()[0]
				row.ID = "some-other-credential"
				store.override = &row
				return first.RefreshToken
			},
		},
		{
			name: "credential row has no owner",
			setup: func(_ *testing.T, store *fakeStore, first *auth.Issued) secrets.Redacted {
				row := store.all()[0]
				row.OwnerID = ""
				store.override = &row
				return first.RefreshToken
			},
		},
		{
			name: "credential row has no lineage",
			setup: func(_ *testing.T, store *fakeStore, first *auth.Issued) secrets.Redacted {
				row := store.all()[0]
				row.LineageID = ""
				store.override = &row
				return first.RefreshToken
			},
		},
		{
			name: "credential row has an unusable scope set",
			setup: func(_ *testing.T, store *fakeStore, first *auth.Issued) secrets.Redacted {
				row := store.all()[0]
				row.Scopes = []domain.Scope{{Kind: domain.ScopeKind("nonsense")}}
				store.override = &row
				return first.RefreshToken
			},
		},
		{
			name: "owner is unknown",
			setup: func(_ *testing.T, store *fakeStore, first *auth.Issued) secrets.Redacted {
				store.owners.rows = map[domain.OwnerID]*domain.Owner{}
				return first.RefreshToken
			},
		},
		{
			name: "owner lookup faults",
			setup: func(_ *testing.T, store *fakeStore, first *auth.Issued) secrets.Redacted {
				store.owners.err = errStore
				return first.RefreshToken
			},
		},
		{
			name: "owner store returns a nil row with no error",
			setup: func(_ *testing.T, store *fakeStore, first *auth.Issued) secrets.Redacted {
				store.owners.nilRow = true
				return first.RefreshToken
			},
		},
		{
			name: "owner store returns a different owner",
			setup: func(_ *testing.T, store *fakeStore, first *auth.Issued) secrets.Redacted {
				store.owners.override = activeOwner("someone-else")
				return first.RefreshToken
			},
		},
		{
			name: "owner is suspended",
			setup: func(_ *testing.T, store *fakeStore, first *auth.Issued) secrets.Redacted {
				store.owners.rows[testOwner].Status = domain.OwnerStatusSuspended
				return first.RefreshToken
			},
		},
		{
			name: "owner is soft deleted",
			setup: func(_ *testing.T, store *fakeStore, first *auth.Issued) secrets.Redacted {
				deleted := baseTime
				store.owners.rows[testOwner].DeletedAt = &deleted
				return first.RefreshToken
			},
		},
		{
			name: "consuming the credential faults",
			setup: func(_ *testing.T, store *fakeStore, first *auth.Issued) secrets.Redacted {
				store.markRotatedErr = errStore
				return first.RefreshToken
			},
		},
		{
			name: "creating the successor faults",
			setup: func(_ *testing.T, store *fakeStore, first *auth.Issued) secrets.Redacted {
				store.createErr = errStore
				return first.RefreshToken
			},
		},
		{
			name: "the transaction itself faults",
			setup: func(_ *testing.T, store *fakeStore, first *auth.Issued) secrets.Redacted {
				store.withTxErr = errStore
				return first.RefreshToken
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store, svc := newService(t)
			first := issue(t, svc, baseTime)
			tok := tt.setup(t, store, first)

			got, err := svc.Exchange(context.Background(), tok, baseTime.Add(time.Hour))
			denied(t, got, err)
		})
	}
}

// TestFailedExchangeLeavesNoSuccessor proves the exchange is atomic: when
// creating the successor fails, the credential that was consumed on the way is
// rolled back with it, so a storage hiccup cannot destroy a working credential
// without issuing its replacement.
func TestFailedExchangeLeavesNoSuccessor(t *testing.T) {
	store, svc := newService(t)
	first := issue(t, svc, baseTime)
	rootID := store.all()[0].ID

	store.createErr = errStore
	got, err := svc.Exchange(context.Background(), first.RefreshToken, baseTime.Add(time.Hour))
	denied(t, got, err)

	if n := len(store.all()); n != 1 {
		t.Fatalf("store holds %d credentials after a failed exchange, want 1", n)
	}
	if s := store.snapshotOf(rootID).Status; s != domain.CredentialStatusActive {
		t.Fatalf("the presented credential was left %q after a rolled-back exchange, want active", s)
	}

	// And with the fault cleared, the original token still works: the failure
	// cost the caller nothing.
	store.createErr = nil
	exchange(t, svc, first.RefreshToken, baseTime.Add(2*time.Hour))
}

// TestReuseRevocationSurvivesTheDenial proves the lineage revocation is
// committed even though the exchange it happened during was refused. Detecting
// a theft and then rolling the detection back would leave the attacker holding
// a live lineage.
func TestReuseRevocationSurvivesTheDenial(t *testing.T) {
	store, svc := newService(t)
	first := issue(t, svc, baseTime)
	exchange(t, svc, first.RefreshToken, baseTime.Add(time.Hour))

	got, err := svc.Exchange(context.Background(), first.RefreshToken, baseTime.Add(2*time.Hour))
	denied(t, got, err)

	for _, c := range store.all() {
		if c.Status != domain.CredentialStatusRevoked {
			t.Fatalf("credential %q survived reuse detection with status %q", c.ID, c.Status)
		}
	}
}

// TestReuseRevocationFailureDeniesAndRollsBack covers the storage fault during
// the revocation itself: the caller is still denied, and nothing half-revoked
// is left behind.
func TestReuseRevocationFailureDeniesAndRollsBack(t *testing.T) {
	store, svc := newService(t)
	first := issue(t, svc, baseTime)
	exchange(t, svc, first.RefreshToken, baseTime.Add(time.Hour))
	store.revokeLineageErr = errStore

	got, err := svc.Exchange(context.Background(), first.RefreshToken, baseTime.Add(2*time.Hour))
	denied(t, got, err)
}

// TestConcurrentExchangeOfOneTokenYieldsOneSuccess drives the same token from
// many goroutines. Exactly one may win; every other presentation is a second
// use of a single-use token and must be treated as one, killing the lineage.
//
// The atomicity this relies on is the port's: MarkRotated is a conditional
// transition. The guarantee proven here is against the in-memory store, which
// implements that contract; it is not evidence about any real database engine.
func TestConcurrentExchangeOfOneTokenYieldsOneSuccess(t *testing.T) {
	store, svc := newService(t)
	first := issue(t, svc, baseTime)

	const n = 16
	var (
		wg        sync.WaitGroup
		mu        sync.Mutex
		successes int
	)
	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, err := svc.Exchange(context.Background(), first.RefreshToken, baseTime.Add(time.Hour))
			mu.Lock()
			defer mu.Unlock()
			if err == nil && got != nil {
				successes++
				return
			}
			if !errors.Is(err, auth.ErrAuthFailed) {
				t.Errorf("error = %v, want ErrAuthFailed", err)
			}
		}()
	}
	wg.Wait()

	if successes != 1 {
		t.Fatalf("%d concurrent presentations of one token produced %d successes, want exactly 1", n, successes)
	}
	// The losers were reuses, so the lineage is dead.
	for _, c := range store.all() {
		if c.Status != domain.CredentialStatusRevoked {
			t.Fatalf("credential %q has status %q after a concurrent double-use, want revoked", c.ID, c.Status)
		}
	}
}

// TestIssuedIsRedactedEverywhere proves neither raw token can escape through
// any formatting, marshaling, or logging path.
func TestIssuedIsRedactedEverywhere(t *testing.T) {
	_, svc := newService(t)
	got := issue(t, svc, baseTime)
	needles := []string{got.RefreshToken.Reveal(), got.AccessToken.Reveal()}

	var textLog, jsonLog bytes.Buffer
	slog.New(slog.NewTextHandler(&textLog, nil)).Info("issued", "tokens", got)
	slog.New(slog.NewJSONHandler(&jsonLog, nil)).Info("issued", "tokens", *got)

	blob, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	text, err := got.MarshalText()
	if err != nil {
		t.Fatalf("MarshalText: %v", err)
	}

	renderings := map[string]string{
		"String":     got.String(),
		"GoString":   got.GoString(),
		"%v":         fmt.Sprintf("%v", got),
		"%s":         fmt.Sprintf("%s", got),
		"%q":         fmt.Sprintf("%q", got),
		"%+v":        fmt.Sprintf("%+v", *got),
		"%#v":        fmt.Sprintf("%#v", *got),
		"nested":     fmt.Sprintf("%+v", struct{ I auth.Issued }{*got}),
		"json":       string(blob),
		"text":       string(text),
		"slog text":  textLog.String(),
		"slog json":  jsonLog.String(),
		"slog value": got.LogValue().String(),
	}
	for name, r := range renderings {
		for _, needle := range needles {
			if strings.Contains(r, needle) {
				t.Fatalf("%s leaked a raw token: %s", name, r)
			}
		}
		if !strings.Contains(r, "[REDACTED]") {
			t.Fatalf("%s does not show the redaction marker: %s", name, r)
		}
	}
}

// TestVerifyDelegatesToTheSigner confirms the service's Verify accepts a token
// it issued and refuses one signed by another key.
func TestVerifyDelegatesToTheSigner(t *testing.T) {
	_, svc := newService(t)
	got := issue(t, svc, baseTime)

	if _, err := svc.Verify(got.AccessToken, baseTime); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if _, err := svc.Verify(got.AccessToken, baseTime.Add(auth.AccessTokenLifetime)); !errors.Is(err, auth.ErrAuthFailed) {
		t.Fatalf("expired token: error = %v, want ErrAuthFailed", err)
	}

	other := newSigner(t, 99)
	foreign, err := other.Issue(sampleAccess(baseTime))
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if _, err := svc.Verify(foreign, baseTime); !errors.Is(err, auth.ErrAuthFailed) {
		t.Fatalf("foreign token: error = %v, want ErrAuthFailed", err)
	}
}

// TestConcurrentConsumeConflictIsTreatedAsReuse covers the branch that a
// serializing store never reaches but a real engine at read-committed
// isolation does: two exchanges both read the credential as active, and the
// conditional MarkRotated refuses the second. The loser has presented a token
// that was consumed underneath it, which is a double use of a single-use
// credential, so it is handled exactly like any other reuse -- the lineage
// dies. Silently treating the conflict as "try again" would hand the attacker
// in a genuine race a retry loop.
func TestConcurrentConsumeConflictIsTreatedAsReuse(t *testing.T) {
	store, svc := newService(t)
	first := issue(t, svc, baseTime)
	store.markRotatedErr = domain.ErrConflict

	got, err := svc.Exchange(context.Background(), first.RefreshToken, baseTime.Add(time.Hour))
	denied(t, got, err)

	for _, c := range store.all() {
		if c.Status != domain.CredentialStatusRevoked {
			t.Fatalf("credential %q has status %q after a losing race, want revoked", c.ID, c.Status)
		}
	}
}

// TestConsumeConflictRevocationFailureStillDenies covers the storage fault
// during the revocation that the conflict triggered.
func TestConsumeConflictRevocationFailureStillDenies(t *testing.T) {
	store, svc := newService(t)
	first := issue(t, svc, baseTime)
	store.markRotatedErr = domain.ErrConflict
	store.revokeLineageErr = errStore

	got, err := svc.Exchange(context.Background(), first.RefreshToken, baseTime.Add(time.Hour))
	denied(t, got, err)
}

// TestExchangeSeparatesDenialFromStorageFault pins a distinction that is
// invisible from outside and must stay that way.
//
// A denial and a storage fault give the caller the same answer -- both are
// ErrAuthFailed, because a client must never learn whether a credential
// exists. They are not the same event to an operator. A denial has written
// nothing and lets the transaction close; a fault must roll back and reach
// logs and monitoring, exactly as the MarkRotated, Create and mint paths in
// the same function already do. Swallowing it made a database outage read as
// a flood of unknown tokens.
func TestExchangeSeparatesDenialFromStorageFault(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		injected     error
		wantRollback bool
	}{
		{
			name:         "unknown credential is a denial",
			injected:     domain.ErrNotFound,
			wantRollback: false,
		},
		{
			name:         "storage fault must not be swallowed",
			injected:     errors.New("dial tcp: connection refused"),
			wantRollback: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store, svc := newService(t)
			first := issue(t, svc, baseTime)
			store.getByIDErr = tc.injected

			got, err := svc.Exchange(context.Background(), first.RefreshToken, baseTime.Add(time.Minute))
			if got != nil {
				t.Fatalf("Exchange returned %v, want nil", got)
			}
			// The caller half must not regress while the operator half is
			// being improved.
			if !errors.Is(err, auth.ErrAuthFailed) {
				t.Fatalf("error = %v, want auth.ErrAuthFailed", err)
			}
			if store.rolledBack != tc.wantRollback {
				t.Errorf("rolledBack = %v, want %v", store.rolledBack, tc.wantRollback)
			}
		})
	}
}
