package auth_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/auth"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/counter"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/secrets"
)

// enrollHarness wires a real EnrollmentService over in-memory doubles. The
// doubles that matter -- the conditional pairing transitions and the counter
// store -- have real behavior, so the invariants under test can actually fail.
type enrollHarness struct {
	svc      *auth.EnrollmentService
	pairings *fakePairings
	creds    *fakeStore
	links    *fakeLinkStore
	tokens   *auth.TokenService
	counters *counter.MemoryStore
	clock    *testTime
}

// testTime is a settable clock. Every expiry decision in the service takes its
// time from here, so a boundary is tested by assignment rather than by sleeping.
type testTime struct {
	mu sync.Mutex
	t  time.Time
}

func (c *testTime) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *testTime) set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = t
}

func (c *testTime) advance(d time.Duration) { c.set(c.now().Add(d)) }

func newEnrollHarness(t *testing.T) *enrollHarness {
	t.Helper()
	clock := &testTime{t: testClock}
	owners := &fakeOwners{rows: map[domain.OwnerID]*domain.Owner{
		"owner-1": {ID: "owner-1", Status: domain.OwnerStatusActive},
		"owner-2": {ID: "owner-2", Status: domain.OwnerStatusActive},
	}}
	pairings := newFakePairings()
	creds := newFakeStore(owners)
	links := newFakeLinkStore()
	creds.pairings = pairings
	creds.links = links

	provider, err := auth.NewAPITokenProvider(pairings, clock.now)
	if err != nil {
		t.Fatalf("building the provider: %v", err)
	}
	reg, err := auth.NewRegistry(provider)
	if err != nil {
		t.Fatalf("building the registry: %v", err)
	}
	authenticator, err := auth.NewAuthenticator(reg, links, owners)
	if err != nil {
		t.Fatalf("building the authenticator: %v", err)
	}
	counters, err := counter.NewMemoryStore(clock.now)
	if err != nil {
		t.Fatalf("building the counter store: %v", err)
	}
	denylist, err := auth.NewDenylist(counters)
	if err != nil {
		t.Fatalf("building the denylist: %v", err)
	}
	tokens, err := auth.NewTokenService(creds, newSigner(t, 0x11), denylist)
	if err != nil {
		t.Fatalf("building the token service: %v", err)
	}
	svc, err := auth.NewEnrollmentService(creds, authenticator, tokens, denylist, counters, clock.now)
	if err != nil {
		t.Fatalf("building the enrollment service: %v", err)
	}
	return &enrollHarness{
		svc: svc, pairings: pairings, creds: creds, links: links,
		tokens: tokens, counters: counters, clock: clock,
	}
}

// fullOwner is the default grant a paired management client receives.
func fullOwner() []domain.Scope { return []domain.Scope{{Kind: domain.ScopeFullOwner}} }

func TestNewEnrollmentServiceRejectsMissingDependencies(t *testing.T) {
	h := newEnrollHarness(t)
	// Each nil is a control the service would silently skip: no limiter is an
	// unbounded guessing budget against a 40-bit code, no denylist is a revoked
	// device that keeps its live tokens.
	for _, tt := range []struct {
		name string
		call func() error
	}{
		{"nil store", func() error {
			_, err := auth.NewEnrollmentService(nil, nil, nil, nil, nil, nil)
			return err
		}},
		{"nil limiter", func() error {
			_, err := auth.NewEnrollmentService(h.creds, nil, nil, nil, nil, h.clock.now)
			return err
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.call(); !errors.Is(err, domain.ErrInvalidInput) {
				t.Fatalf("error = %v, want ErrInvalidInput", err)
			}
		})
	}
}

// TestMintStoresOnlyHashes is the storage invariant for the manual-paste flow:
// the row that comes back from the store must not contain the code that was
// handed to the caller.
func TestMintStoresOnlyHashes(t *testing.T) {
	h := newEnrollHarness(t)
	grant, err := h.svc.Mint(context.Background(), "owner-1", "laptop", fullOwner())
	if err != nil {
		t.Fatalf("minting: %v", err)
	}

	row := h.pairings.snapshotOf(grant.PairingID)
	if row == nil {
		t.Fatal("mint returned a grant without storing a pairing")
	}
	if string(row.DeviceCodeHash) == grant.DeviceCode.Reveal() {
		t.Fatal("the stored device code hash IS the device code; the credential is stored in plaintext")
	}
	// The strongest form of the check: the secret half must not appear anywhere
	// in the row's digest, whatever encoding it was written in.
	_, secret, err := splitDeviceCode(grant.DeviceCode)
	if err != nil {
		t.Fatalf("splitting the device code: %v", err)
	}
	if bytesContain(row.DeviceCodeHash, secret) {
		t.Fatal("the stored digest contains the device code secret")
	}
	if row.OwnerID != "owner-1" {
		t.Fatalf("stored OwnerID = %q, want owner-1", row.OwnerID)
	}
	if row.Status != domain.PairingStatusApproved {
		t.Fatalf("a minted pairing is %q, want approved: the owner minting it is the approval", row.Status)
	}
	// A manually minted pairing has no second party to authorize it, so there
	// is no short secret to defend.
	if len(row.UserCodeHash) != 0 || grant.UserCode != "" {
		t.Fatal("a manually minted pairing carries a user code, which is a short secret nobody needs")
	}
	// The grant is redaction-safe: printing it must not spill either code.
	if containsSecret(grant.String(), grant.DeviceCode.Reveal()) {
		t.Fatalf("a Grant rendered its device code when printed: %s", grant.String())
	}
}

// TestMintCreatesTheLink checks that the pairing's principal is resolvable to
// the minting owner, and to nobody else.
func TestMintCreatesTheLink(t *testing.T) {
	h := newEnrollHarness(t)
	grant, err := h.svc.Mint(context.Background(), "owner-1", "laptop", fullOwner())
	if err != nil {
		t.Fatalf("minting: %v", err)
	}
	li := h.links.get(auth.APITokenProviderID.String(), string(grant.PairingID))
	if li == nil {
		t.Fatal("mint created no LinkedIdentity, so the device code would verify and resolve to nobody")
	}
	if li.OwnerID != "owner-1" {
		t.Fatalf("link owner = %q, want owner-1", li.OwnerID)
	}
}

func TestMintRejectsInvalidInput(t *testing.T) {
	h := newEnrollHarness(t)
	ctx := context.Background()
	tests := []struct {
		name  string
		owner domain.OwnerID
		label string
		scope []domain.Scope
	}{
		{name: "empty owner", owner: "", label: "laptop", scope: fullOwner()},
		// An empty scope set must never be read as full access.
		{name: "no scopes", owner: "owner-1", label: "laptop", scope: nil},
		{name: "control character in label", owner: "owner-1", label: "lap\x00top", scope: fullOwner()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := h.svc.Mint(ctx, tt.owner, tt.label, tt.scope); !errors.Is(err, domain.ErrInvalidInput) {
				t.Fatalf("error = %v, want ErrInvalidInput", err)
			}
		})
	}
}

// TestRedeemIssuesForTheBoundOwner is the happy path end to end: a minted
// pairing redeems to a credential pair for the owner that minted it.
func TestRedeemIssuesForTheBoundOwner(t *testing.T) {
	h := newEnrollHarness(t)
	ctx := context.Background()
	grant, err := h.svc.Mint(ctx, "owner-1", "laptop", fullOwner())
	if err != nil {
		t.Fatalf("minting: %v", err)
	}

	issued, err := h.svc.Redeem(ctx, grant.DeviceCode)
	if err != nil {
		t.Fatalf("redeeming: %v", err)
	}
	if issued.OwnerID != "owner-1" {
		t.Fatalf("issued for %q, want owner-1", issued.OwnerID)
	}
	if issued.LineageID == "" {
		t.Fatal("no lineage was reported, so revoking this device could never reach its tokens")
	}
	// The label and scopes travel from the pairing onto the credential, so the
	// authority a device gets is the one the owner decided up front.
	if len(issued.Scopes) != 1 || issued.Scopes[0].Kind != domain.ScopeFullOwner {
		t.Fatalf("issued scopes = %+v, want the pairing's", issued.Scopes)
	}

	row := h.pairings.snapshotOf(grant.PairingID)
	if row.Status != domain.PairingStatusRedeemed {
		t.Fatalf("pairing status after redemption = %q, want redeemed", row.Status)
	}
	if row.LineageID != issued.LineageID {
		t.Fatalf("pairing lineage = %q, want %q: revocation could not reach the device's tokens",
			row.LineageID, issued.LineageID)
	}
	if row.RedeemedAt == nil {
		t.Fatal("a redeemed pairing has no RedeemedAt stamp")
	}
}

// TestRedeemIsSingleUse is the invariant stated serially. The second
// presentation of a device code must fail, whatever else is true.
func TestRedeemIsSingleUse(t *testing.T) {
	h := newEnrollHarness(t)
	ctx := context.Background()
	grant, err := h.svc.Mint(ctx, "owner-1", "laptop", fullOwner())
	if err != nil {
		t.Fatalf("minting: %v", err)
	}
	if _, err := h.svc.Redeem(ctx, grant.DeviceCode); err != nil {
		t.Fatalf("first redemption: %v", err)
	}

	second, err := h.svc.Redeem(ctx, grant.DeviceCode)
	requireBareAuthFailed(t, err, "second redemption of one device code")
	if second != nil {
		t.Fatal("a device code was redeemed twice, so one pairing installed two credentials")
	}
}

// TestRedeemConcurrentlyYieldsExactlyOneCredential is the invariant stated
// under -race, which is the only form that proves it. A read-then-write
// consume passes the serial test above and fails this one.
func TestRedeemConcurrentlyYieldsExactlyOneCredential(t *testing.T) {
	h := newEnrollHarness(t)
	ctx := context.Background()
	grant, err := h.svc.Mint(ctx, "owner-1", "laptop", fullOwner())
	if err != nil {
		t.Fatalf("minting: %v", err)
	}

	const racers = 16
	var wins atomic.Int64
	var lineages sync.Map
	var wg sync.WaitGroup
	start := make(chan struct{})
	for range racers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			issued, err := h.svc.Redeem(ctx, grant.DeviceCode)
			if err == nil && issued != nil {
				wins.Add(1)
				lineages.Store(issued.LineageID, struct{}{})
			}
		}()
	}
	close(start)
	wg.Wait()

	if got := wins.Load(); got != 1 {
		t.Fatalf("%d of %d concurrent redemptions succeeded, want exactly 1: the consume "+
			"is not a conditional single statement", got, racers)
	}

	// Every lineage a loser minted before losing the race must be dead, or the
	// pairing has installed credentials nobody can see or revoke.
	winner := h.pairings.snapshotOf(grant.PairingID).LineageID
	for _, c := range h.creds.all() {
		if c.LineageID == winner {
			continue
		}
		if c.Status != domain.CredentialStatusRevoked {
			t.Fatalf("a losing redemption left credential %q in lineage %q live at status %q",
				c.ID, c.LineageID, c.Status)
		}
	}
}

// TestRedeemDenials covers the reasons a device code is refused at the service
// level, all with the same bare sentinel.
func TestRedeemDenials(t *testing.T) {
	tests := []struct {
		name    string
		prepare func(t *testing.T, h *enrollHarness, g *auth.Grant) secrets.Redacted
	}{
		{
			name: "malformed code",
			prepare: func(*testing.T, *enrollHarness, *auth.Grant) secrets.Redacted {
				return secrets.NewRedacted("svd_nonsense")
			},
		},
		{
			name: "expired pairing",
			prepare: func(_ *testing.T, h *enrollHarness, g *auth.Grant) secrets.Redacted {
				h.clock.advance(auth.PairingLifetime)
				return g.DeviceCode
			},
		},
		{
			name: "revoked pairing",
			prepare: func(t *testing.T, h *enrollHarness, g *auth.Grant) secrets.Redacted {
				if err := h.svc.Revoke(context.Background(), "owner-1", g.PairingID); err != nil {
					t.Fatalf("revoking: %v", err)
				}
				return g.DeviceCode
			},
		},
		{
			name: "owner suspended after the pairing was minted",
			prepare: func(_ *testing.T, h *enrollHarness, g *auth.Grant) secrets.Redacted {
				// The pairing outlives the account's good standing, so the
				// owner's status is re-checked by Authenticator on redemption.
				h.creds.owners.rows["owner-1"].Status = domain.OwnerStatusSuspended
				return g.DeviceCode
			},
		},
		{
			name: "link removed after the pairing was minted",
			prepare: func(_ *testing.T, h *enrollHarness, g *auth.Grant) secrets.Redacted {
				h.links.remove(auth.APITokenProviderID.String(), string(g.PairingID))
				return g.DeviceCode
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newEnrollHarness(t)
			ctx := context.Background()
			grant, err := h.svc.Mint(ctx, "owner-1", "laptop", fullOwner())
			if err != nil {
				t.Fatalf("minting: %v", err)
			}
			issued, err := h.svc.Redeem(ctx, tt.prepare(t, h, grant))
			requireBareAuthFailed(t, err, tt.name)
			if issued != nil {
				t.Fatal("credentials were issued alongside a denial")
			}
		})
	}
}

// TestRedeemRefusesACrossOwnerLink is the defense in depth that Redeem's second
// read exists for. The link says one owner and the pairing row says another,
// which is what a tampered row or a lookup that returned a neighbor looks like.
// Pairing a device into an account that never approved it is the outcome being
// prevented.
func TestRedeemRefusesACrossOwnerLink(t *testing.T) {
	h := newEnrollHarness(t)
	ctx := context.Background()
	grant, err := h.svc.Mint(ctx, "owner-1", "laptop", fullOwner())
	if err != nil {
		t.Fatalf("minting: %v", err)
	}
	// Repoint the link at a second, entirely legitimate owner.
	h.links.setOwner(auth.APITokenProviderID.String(), string(grant.PairingID), "owner-2")

	issued, err := h.svc.Redeem(ctx, grant.DeviceCode)
	requireBareAuthFailed(t, err, "cross-owner redemption")
	if issued != nil {
		t.Fatalf("a pairing approved by owner-1 issued credentials for %q", issued.OwnerID)
	}
	if h.pairings.snapshotOf(grant.PairingID).Status == domain.PairingStatusRedeemed {
		t.Fatal("a refused cross-owner redemption still consumed the pairing")
	}
}

// TestRevokeDeniesLiveAccessTokens is requirement six: withdrawing a device
// must reach the tokens it is already holding, not just stop future ones.
func TestRevokeDeniesLiveAccessTokens(t *testing.T) {
	h := newEnrollHarness(t)
	ctx := context.Background()
	grant, err := h.svc.Mint(ctx, "owner-1", "laptop", fullOwner())
	if err != nil {
		t.Fatalf("minting: %v", err)
	}
	issued, err := h.svc.Redeem(ctx, grant.DeviceCode)
	if err != nil {
		t.Fatalf("redeeming: %v", err)
	}

	// The access token is good before the revocation and dead immediately
	// after, well inside its fifteen-minute lifetime.
	tokens := h.tokens
	if _, err := tokens.Verify(ctx, issued.AccessToken, h.clock.now()); err != nil {
		t.Fatalf("the freshly issued access token did not verify: %v", err)
	}
	if err := h.svc.Revoke(ctx, "owner-1", grant.PairingID); err != nil {
		t.Fatalf("revoking: %v", err)
	}
	if _, err := tokens.Verify(ctx, issued.AccessToken, h.clock.now()); err == nil {
		t.Fatal("a revoked device's access token still verified; revocation waits out the TTL")
	}
	// The refresh credential is dead too, so the device cannot rotate its way
	// back into the account.
	if _, err := tokens.Exchange(ctx, issued.RefreshToken, h.clock.now()); err == nil {
		t.Fatal("a revoked device exchanged its refresh token for a new credential")
	}
}

// TestRevokeIsOwnerScoped checks that one owner cannot revoke another's
// pairing, and that the refusal does not distinguish "not yours" from "no such
// pairing".
func TestRevokeIsOwnerScoped(t *testing.T) {
	h := newEnrollHarness(t)
	ctx := context.Background()
	grant, err := h.svc.Mint(ctx, "owner-1", "laptop", fullOwner())
	if err != nil {
		t.Fatalf("minting: %v", err)
	}

	otherErr := h.svc.Revoke(ctx, "owner-2", grant.PairingID)
	if !errors.Is(otherErr, domain.ErrNotFound) {
		t.Fatalf("cross-owner revoke error = %v, want ErrNotFound", otherErr)
	}
	missingErr := h.svc.Revoke(ctx, "owner-2", "dGhpcy1kb2VzLW5vdC1leA")
	if !errors.Is(missingErr, domain.ErrNotFound) {
		t.Fatalf("missing pairing revoke error = %v, want ErrNotFound", missingErr)
	}
	// Still redeemable by its real owner: the refused revocation changed nothing.
	if h.pairings.snapshotOf(grant.PairingID).Status != domain.PairingStatusApproved {
		t.Fatal("a cross-owner revoke modified the pairing")
	}
	if _, err := h.svc.Redeem(ctx, grant.DeviceCode); err != nil {
		t.Fatalf("the pairing stopped working after a refused cross-owner revoke: %v", err)
	}
}

func bytesContain(haystack, needle []byte) bool {
	if len(needle) == 0 || len(needle) > len(haystack) {
		return false
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if string(haystack[i:i+len(needle)]) == string(needle) {
			return true
		}
	}
	return false
}

func containsSecret(rendered, secret string) bool {
	return secret != "" && len(rendered) >= len(secret) && bytesContain([]byte(rendered), []byte(secret))
}
