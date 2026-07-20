package auth_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/auth"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/secrets"
)

// TestVerifyDeniesARevokedCredential is the whole point of the denylist: a
// signed, unexpired access token stops being accepted the moment the credential
// it came from is listed, rather than fifteen minutes later.
func TestVerifyDeniesARevokedCredential(t *testing.T) {
	_, svc, f := newServiceWithDenylist(t)
	ctx := context.Background()
	got := issue(t, svc, baseTime)

	claims, err := svc.Verify(ctx, got.AccessToken, baseTime)
	if err != nil {
		t.Fatalf("a freshly issued token was rejected: %v", err)
	}

	if err := f.dl.RevokeCredential(ctx, claims.RefreshCredentialID); err != nil {
		t.Fatalf("RevokeCredential: %v", err)
	}

	// Same token, same instant, well inside its own expiry.
	_, err = svc.Verify(ctx, got.AccessToken, baseTime)
	if !errors.Is(err, auth.ErrAuthFailed) {
		t.Fatalf("a revoked token was accepted: err = %v", err)
	}
	if errors.Unwrap(err) != nil {
		t.Fatalf("denial %v carries a cause, which tells a caller why it was denied", err)
	}
}

// TestVerifyFailsClosedWhenTheDenylistIsDown is the fail-closed test at the
// service boundary: a valid, unrevoked token must be refused when the denylist
// store cannot answer. Admitting it instead would mean a store outage silently
// disables revocation for everyone.
func TestVerifyFailsClosedWhenTheDenylistIsDown(t *testing.T) {
	ctx := context.Background()

	// Issue against a working denylist, so the token under test is genuinely
	// valid and genuinely not revoked.
	_, working, _ := newServiceWithDenylist(t)
	got := issue(t, working, baseTime)
	if _, err := working.Verify(ctx, got.AccessToken, baseTime); err != nil {
		t.Fatalf("the token must be valid before the store is broken: %v", err)
	}

	// The same token through a service whose denylist store is unreachable.
	dl, err := auth.NewDenylist(&failingStore{getErr: errors.New("dial tcp: connection refused")})
	if err != nil {
		t.Fatalf("NewDenylist: %v", err)
	}
	broken, err := auth.NewTokenService(newFakeStore(&fakeOwners{}), newSigner(t, 1), dl)
	if err != nil {
		t.Fatalf("NewTokenService: %v", err)
	}

	claims, err := broken.Verify(ctx, got.AccessToken, baseTime)
	if !errors.Is(err, auth.ErrAuthFailed) {
		t.Fatalf("a token was accepted while the denylist was unreachable: err = %v", err)
	}
	if claims != nil {
		t.Fatal("a denied verification still returned claims")
	}
	// The reason stays inside the server: to a client this is the same denial
	// as a forged token.
	if errors.Unwrap(err) != nil {
		t.Fatalf("denial %v leaks that the denylist store is down", err)
	}
}

// TestLineageRevocationDeniesEveryAccessTokenInTheLineage is the end-to-end
// case ADR-0018 names. A stolen refresh token is replayed, B2 detects the reuse
// and revokes the lineage in storage, and every access token already minted
// from that lineage must stop being accepted immediately -- not when its own
// fifteen minutes run out, which is the window the thief would otherwise still
// hold the account for.
func TestLineageRevocationDeniesEveryAccessTokenInTheLineage(t *testing.T) {
	_, svc, _ := newServiceWithDenylist(t)
	ctx := context.Background()

	// A lineage that has rotated twice, so there are three access tokens alive
	// from three different credentials in one lineage.
	first := issue(t, svc, baseTime)
	second := exchange(t, svc, first.RefreshToken, baseTime.Add(time.Minute))
	third := exchange(t, svc, second.RefreshToken, baseTime.Add(2*time.Minute))

	live := []struct {
		name string
		tok  *auth.Issued
	}{
		{"first", first},
		{"second", second},
		{"third", third},
	}
	at := baseTime.Add(3 * time.Minute)
	for _, c := range live {
		if _, err := svc.Verify(ctx, c.tok.AccessToken, at); err != nil {
			t.Fatalf("%s access token rejected before revocation: %v", c.name, err)
		}
	}

	// The theft: the already-spent first refresh token is presented again.
	// B2 revokes the lineage; B3 must make that reach the access tokens.
	replayed, err := svc.Exchange(ctx, first.RefreshToken, at)
	denied(t, replayed, err)

	for _, c := range live {
		// Every one of them is still inside its own fifteen-minute lifetime, so
		// only the denylist can be refusing them.
		if _, err := svc.Verify(ctx, c.tok.AccessToken, at); !errors.Is(err, auth.ErrAuthFailed) {
			t.Fatalf("%s access token survived lineage revocation: err = %v", c.name, err)
		}
	}

	// A token from an unrelated lineage is untouched: revocation is scoped to
	// the lineage, not applied to everything the service has issued.
	other := issue(t, svc, at)
	if _, err := svc.Verify(ctx, other.AccessToken, at); err != nil {
		t.Fatalf("an unrelated lineage was revoked too: %v", err)
	}
}

// TestLineageRevocationSurvivesADenylistFailure states the ordering rule the
// other way round. The durable revocation in storage is authoritative; a
// denylist that cannot be written must not roll it back, because un-revoking a
// lineage that was just detected as stolen to keep a fifteen-minute cache
// consistent is the wrong trade by a wide margin.
func TestLineageRevocationSurvivesADenylistFailure(t *testing.T) {
	ctx := context.Background()
	store := newFakeStore(&fakeOwners{rows: map[domain.OwnerID]*domain.Owner{
		testOwner: activeOwner(testOwner),
	}})
	dl, err := auth.NewDenylist(&failingStore{incErr: errors.New("connection refused")})
	if err != nil {
		t.Fatalf("NewDenylist: %v", err)
	}
	svc, err := auth.NewTokenService(store, newSigner(t, 1), dl)
	if err != nil {
		t.Fatalf("NewTokenService: %v", err)
	}

	first := issue(t, svc, baseTime)
	second := exchange(t, svc, first.RefreshToken, baseTime.Add(time.Minute))

	replayed, err := svc.Exchange(ctx, first.RefreshToken, baseTime.Add(2*time.Minute))
	denied(t, replayed, err)

	// The refresh side is revoked in storage regardless of the denylist.
	if _, err := svc.Exchange(ctx, second.RefreshToken, baseTime.Add(3*time.Minute)); !errors.Is(err, auth.ErrAuthFailed) {
		t.Fatalf("the lineage was not revoked in storage: err = %v", err)
	}
	for _, c := range store.creds {
		if c.Status == domain.CredentialStatusActive {
			t.Fatalf("credential %q is still active after the lineage was revoked", c.ID)
		}
	}
}

// TestVerifyChecksTheSignatureBeforeTheDenylist pins the ordering. An
// unauthenticated caller must not be able to make the service touch the
// denylist store by sending garbage, or the revocation store becomes a free
// amplification target for anyone who can send a request.
func TestVerifyChecksTheSignatureBeforeTheDenylist(t *testing.T) {
	ctx := context.Background()
	// A store that fails every read: if the denylist were consulted at all, the
	// error would come back wrapped rather than as the bare sentinel, and any
	// read at all would show up as a call.
	store := &failingStore{getErr: errors.New("connection refused")}
	dl, err := auth.NewDenylist(store)
	if err != nil {
		t.Fatalf("NewDenylist: %v", err)
	}
	svc, err := auth.NewTokenService(newFakeStore(&fakeOwners{}), newSigner(t, 1), dl)
	if err != nil {
		t.Fatalf("NewTokenService: %v", err)
	}

	for _, tt := range []struct {
		name string
		raw  string
	}{
		{"not a token", "hello"},
		{"wrong prefix", "svr_abc.def"},
		{"forged mac", "sva_eyJ2IjoxfQ.AAAA"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := svc.Verify(ctx, secrets.NewRedacted(tt.raw), baseTime); !errors.Is(err, auth.ErrAuthFailed) {
				t.Fatalf("err = %v, want ErrAuthFailed", err)
			}
		})
	}
	if store.gets != 0 {
		t.Fatalf("the denylist store was read %d times for tokens that failed the stateless checks", store.gets)
	}
}

// TestExpiredTokenIsRejectedWithoutTheDenylist covers the same ordering for the
// commonest rejection of all. An expired token must cost nothing to refuse.
func TestExpiredTokenIsRejectedWithoutTheDenylist(t *testing.T) {
	ctx := context.Background()
	_, working, _ := newServiceWithDenylist(t)
	got := issue(t, working, baseTime)

	store := &failingStore{getErr: errors.New("connection refused")}
	dl, err := auth.NewDenylist(store)
	if err != nil {
		t.Fatalf("NewDenylist: %v", err)
	}
	svc, err := auth.NewTokenService(newFakeStore(&fakeOwners{}), newSigner(t, 1), dl)
	if err != nil {
		t.Fatalf("NewTokenService: %v", err)
	}

	if _, err := svc.Verify(ctx, got.AccessToken, baseTime.Add(auth.AccessTokenLifetime)); !errors.Is(err, auth.ErrAuthFailed) {
		t.Fatalf("an expired token was accepted: %v", err)
	}
	if store.gets != 0 {
		t.Fatal("the denylist was consulted for a token that had already expired")
	}
}
