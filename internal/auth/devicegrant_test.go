package auth_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/auth"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/secrets"
)

// startGrant begins a device-authorization grant and fails the test if it does
// not produce both codes.
func startGrant(t *testing.T, h *enrollHarness) *auth.Grant {
	t.Helper()
	g, err := h.svc.StartDeviceGrant(context.Background(), "laptop", fullOwner())
	if err != nil {
		t.Fatalf("starting a device grant: %v", err)
	}
	if g.DeviceCode == "" || g.UserCode == "" {
		t.Fatal("a device grant must produce both a device code and a user code")
	}
	return g
}

// TestStartDeviceGrantIsUnbound is the shape of the flow: the client starting a
// grant has not authenticated as anybody, so the pairing must carry no owner
// and must not be redeemable.
func TestStartDeviceGrantIsUnbound(t *testing.T) {
	h := newEnrollHarness(t)
	grant := startGrant(t, h)

	row := h.pairings.snapshotOf(grant.PairingID)
	if row.OwnerID != "" {
		t.Fatalf("a pending pairing is already bound to %q", row.OwnerID)
	}
	if row.Status != domain.PairingStatusPending {
		t.Fatalf("status = %q, want pending", row.Status)
	}
	// No link exists yet either: linking is the explicitly authorized act that
	// approval performs, and never something a client's request creates.
	if h.links.get(auth.APITokenProviderID.String(), string(grant.PairingID)) != nil {
		t.Fatal("starting a grant created a LinkedIdentity, which links an identity to an owner nobody approved")
	}
	// Neither code is stored, and the row's digests are not the codes.
	if string(row.UserCodeHash) == grant.UserCode.Reveal() {
		t.Fatal("the stored user code hash IS the user code")
	}
	if strings.Contains(grant.String(), grant.UserCode.Reveal()) {
		t.Fatalf("a Grant rendered its user code when printed: %s", grant.String())
	}

	issued, err := h.svc.Redeem(context.Background(), grant.DeviceCode)
	requireBareAuthFailed(t, err, "redeeming an unapproved pairing")
	if issued != nil {
		t.Fatal("an unapproved pairing issued credentials")
	}
}

// TestApproveBindsTheApprovingOwner walks the whole grant: start, approve,
// redeem.
func TestApproveBindsTheApprovingOwner(t *testing.T) {
	h := newEnrollHarness(t)
	ctx := context.Background()
	grant := startGrant(t, h)

	if err := h.svc.Approve(ctx, "owner-1", grant.UserCode.Reveal()); err != nil {
		t.Fatalf("approving: %v", err)
	}
	row := h.pairings.snapshotOf(grant.PairingID)
	if row.OwnerID != "owner-1" {
		t.Fatalf("approved pairing is bound to %q, want owner-1", row.OwnerID)
	}
	if row.ApprovedAt == nil {
		t.Fatal("an approved pairing has no ApprovedAt stamp")
	}
	if h.links.get(auth.APITokenProviderID.String(), string(grant.PairingID)) == nil {
		t.Fatal("approval created no LinkedIdentity, so the device code would resolve to nobody")
	}

	issued, err := h.svc.Redeem(ctx, grant.DeviceCode)
	if err != nil {
		t.Fatalf("redeeming an approved pairing: %v", err)
	}
	if issued.OwnerID != "owner-1" {
		t.Fatalf("issued for %q, want the approving owner", issued.OwnerID)
	}
}

// TestApproveAcceptsATranscribedCode checks the forms a person actually types.
// A code that only works in its canonical rendering is a code users cannot use.
func TestApproveAcceptsATranscribedCode(t *testing.T) {
	forms := map[string]func(string) string{
		"as displayed": func(s string) string { return s },
		"ungrouped":    func(s string) string { return strings.ReplaceAll(s, "-", "") },
		"lowercased":   strings.ToLower,
		"spaced":       func(s string) string { return strings.ReplaceAll(s, "-", " ") },
	}
	for name, transform := range forms {
		t.Run(name, func(t *testing.T) {
			h := newEnrollHarness(t)
			grant := startGrant(t, h)
			if err := h.svc.Approve(context.Background(), "owner-1", transform(grant.UserCode.Reveal())); err != nil {
				t.Fatalf("approving a code typed %s: %v", name, err)
			}
		})
	}
}

// TestApproveIsSingleUse covers the transition that stops a second approval
// from re-pointing a pairing another owner already claimed.
func TestApproveIsSingleUse(t *testing.T) {
	h := newEnrollHarness(t)
	ctx := context.Background()
	grant := startGrant(t, h)
	if err := h.svc.Approve(ctx, "owner-1", grant.UserCode.Reveal()); err != nil {
		t.Fatalf("first approval: %v", err)
	}

	// A second owner presenting the same user code must not take the pairing
	// over. The device is already waiting on owner-1's approval and would
	// otherwise hand its credentials to whoever approved last.
	err := h.svc.Approve(ctx, "owner-2", grant.UserCode.Reveal())
	requireBareAuthFailed(t, err, "second approval by another owner")
	if got := h.pairings.snapshotOf(grant.PairingID).OwnerID; got != "owner-1" {
		t.Fatalf("the pairing was re-pointed to %q by a second approval", got)
	}
}

// TestApproveConcurrentlyBindsOneOwner is the same invariant under -race. A
// read-then-write approval passes the serial test above and fails this one.
func TestApproveConcurrentlyBindsOneOwner(t *testing.T) {
	h := newEnrollHarness(t)
	grant := startGrant(t, h)
	code := grant.UserCode.Reveal()

	const racers = 8
	var wins atomic.Int64
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range racers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			owner := domain.OwnerID("owner-1")
			if i%2 == 1 {
				owner = "owner-2"
			}
			<-start
			if err := h.svc.Approve(context.Background(), owner, code); err == nil {
				wins.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()

	if got := wins.Load(); got != 1 {
		t.Fatalf("%d of %d concurrent approvals succeeded, want exactly 1: the binding "+
			"is not a conditional single statement", got, racers)
	}
	if got := h.pairings.snapshotOf(grant.PairingID).OwnerID; got != "owner-1" && got != "owner-2" {
		t.Fatalf("the pairing ended up bound to %q", got)
	}
}

// TestApproveDenials walks every refusal on the approval path. They are all the
// same bare sentinel, and that is the property that keeps this method from
// being a guessing oracle: "that code exists but is already used" would confirm
// a guess just as well as a success.
func TestApproveDenials(t *testing.T) {
	tests := []struct {
		name    string
		prepare func(t *testing.T, h *enrollHarness, g *auth.Grant) (domain.OwnerID, string)
	}{
		{
			name: "unknown code",
			prepare: func(*testing.T, *enrollHarness, *auth.Grant) (domain.OwnerID, string) {
				return "owner-1", "ABCD-EFGH"
			},
		},
		{
			name: "malformed code",
			prepare: func(*testing.T, *enrollHarness, *auth.Grant) (domain.OwnerID, string) {
				return "owner-1", "not a code"
			},
		},
		{
			name: "empty owner",
			prepare: func(_ *testing.T, _ *enrollHarness, g *auth.Grant) (domain.OwnerID, string) {
				return "", g.UserCode.Reveal()
			},
		},
		{
			name: "expired pairing",
			prepare: func(_ *testing.T, h *enrollHarness, g *auth.Grant) (domain.OwnerID, string) {
				h.clock.advance(auth.PairingLifetime)
				return "owner-1", g.UserCode.Reveal()
			},
		},
		{
			name: "pairing expiring exactly now",
			prepare: func(_ *testing.T, h *enrollHarness, g *auth.Grant) (domain.OwnerID, string) {
				h.clock.set(h.pairings.snapshotOf(g.PairingID).ExpiresAt)
				return "owner-1", g.UserCode.Reveal()
			},
		},
		{
			name: "storage fault on the lookup",
			prepare: func(_ *testing.T, h *enrollHarness, g *auth.Grant) (domain.OwnerID, string) {
				// Fails closed: this path binds an owner to a device, so there
				// is no tolerable way to fail other than denied.
				h.pairings.getByUserErr = errors.New("database is down")
				return "owner-1", g.UserCode.Reveal()
			},
		},
		{
			name: "storage fault on the binding write",
			prepare: func(_ *testing.T, h *enrollHarness, g *auth.Grant) (domain.OwnerID, string) {
				h.pairings.approveErr = errors.New("database is down")
				return "owner-1", g.UserCode.Reveal()
			},
		},
		{
			name: "the link cannot be created",
			prepare: func(_ *testing.T, h *enrollHarness, g *auth.Grant) (domain.OwnerID, string) {
				h.links.err = errors.New("database is down")
				return "owner-1", g.UserCode.Reveal()
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newEnrollHarness(t)
			grant := startGrant(t, h)
			owner, code := tt.prepare(t, h, grant)
			requireBareAuthFailed(t, h.svc.Approve(context.Background(), owner, code), tt.name)
		})
	}
}

// TestApproveIsRateLimited is what the user code's forty bits actually rest on.
// Without a limit, an authenticated attacker works through the space at
// whatever rate the server answers.
func TestApproveIsRateLimited(t *testing.T) {
	h := newEnrollHarness(t)
	ctx := context.Background()
	grant := startGrant(t, h)

	// Spend the budget on wrong guesses.
	for i := range auth.MaxApprovalAttempts {
		requireBareAuthFailed(t, h.svc.Approve(ctx, "owner-1", "ABCD-EFGH"), "guess")
		_ = i
	}
	// The next attempt is refused even though the code is correct, which is the
	// proof that the limiter runs before the lookup rather than only counting
	// failures after it.
	requireBareAuthFailed(t, h.svc.Approve(ctx, "owner-1", grant.UserCode.Reveal()), "attempt past the budget")
	if h.pairings.snapshotOf(grant.PairingID).Status != domain.PairingStatusPending {
		t.Fatal("an approval past the rate limit still bound the pairing")
	}

	// The limit is per owner, so one owner exhausting its budget must not lock
	// another owner out.
	if err := h.svc.Approve(ctx, "owner-2", grant.UserCode.Reveal()); err != nil {
		t.Fatalf("a second owner was blocked by the first owner's spent budget: %v", err)
	}
}

// TestApproveFailsClosedWhenTheLimiterIsUnavailable checks the direction the
// limiter fails in. Failing open would remove the limit exactly when an
// attacker able to disturb the store would want it gone.
func TestApproveFailsClosedWhenTheLimiterIsUnavailable(t *testing.T) {
	h := newEnrollHarness(t)
	grant := startGrant(t, h)
	h.limiter.down.Store(true)

	requireBareAuthFailed(t, h.svc.Approve(context.Background(), "owner-1", grant.UserCode.Reveal()),
		"approval with an unavailable limiter")
	if h.pairings.snapshotOf(grant.PairingID).Status != domain.PairingStatusPending {
		t.Fatal("an approval went through while the rate limiter could not be consulted")
	}
}

// TestPollReportsPendingThenReady covers the one deliberate exception to
// indistinguishable denials, and the interval enforcement that goes with it.
func TestPollReportsPendingThenReady(t *testing.T) {
	h := newEnrollHarness(t)
	ctx := context.Background()
	grant := startGrant(t, h)

	err := h.svc.Poll(ctx, grant.DeviceCode)
	if !auth.PollPending(err) {
		t.Fatalf("polling an unapproved pairing = %v, want pending", err)
	}

	// Polling again immediately is refused: the interval is enforced, not just
	// advertised, so a client without backoff slows itself down.
	err = h.svc.Poll(ctx, grant.DeviceCode)
	if auth.PollPending(err) {
		t.Fatal("a poll inside the interval was served; a client with no backoff is not throttled")
	}
	requireBareAuthFailed(t, err, "poll inside the interval")

	h.clock.advance(grant.PollInterval)
	if err := h.svc.Approve(ctx, "owner-1", grant.UserCode.Reveal()); err != nil {
		t.Fatalf("approving: %v", err)
	}
	if err := h.svc.Poll(ctx, grant.DeviceCode); err != nil {
		t.Fatalf("polling an approved pairing = %v, want ready", err)
	}
}

// TestPollDenials confirms the pending signal is available only to the holder
// of the device code, and never for a terminal or expired pairing.
func TestPollDenials(t *testing.T) {
	tests := []struct {
		name    string
		prepare func(t *testing.T, h *enrollHarness, g *auth.Grant) secrets.Redacted
	}{
		{
			name: "malformed device code",
			prepare: func(*testing.T, *enrollHarness, *auth.Grant) secrets.Redacted {
				return secrets.NewRedacted("svd_nope")
			},
		},
		{
			name: "unknown pairing",
			prepare: func(t *testing.T, _ *enrollHarness, _ *auth.Grant) secrets.Redacted {
				return deviceCodeFor(randomID(t), randomSecret(t))
			},
		},
		{
			name: "wrong device code secret",
			prepare: func(t *testing.T, _ *enrollHarness, g *auth.Grant) secrets.Redacted {
				// The pending signal must not be available to a caller that
				// merely guessed a pairing id.
				return deviceCodeFor(g.PairingID, randomSecret(t))
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
			name: "already redeemed pairing",
			prepare: func(t *testing.T, h *enrollHarness, g *auth.Grant) secrets.Redacted {
				ctx := context.Background()
				if err := h.svc.Approve(ctx, "owner-1", g.UserCode.Reveal()); err != nil {
					t.Fatalf("approving: %v", err)
				}
				if _, err := h.svc.Redeem(ctx, g.DeviceCode); err != nil {
					t.Fatalf("redeeming: %v", err)
				}
				return g.DeviceCode
			},
		},
		{
			name: "storage fault on the throttle write",
			prepare: func(_ *testing.T, h *enrollHarness, g *auth.Grant) secrets.Redacted {
				h.pairings.touchErr = errors.New("database is down")
				return g.DeviceCode
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newEnrollHarness(t)
			grant := startGrant(t, h)
			err := h.svc.Poll(context.Background(), tt.prepare(t, h, grant))
			if auth.PollPending(err) {
				t.Fatalf("%s: reported pending, which is a signal only the device code holder earns", tt.name)
			}
			requireBareAuthFailed(t, err, tt.name)
		})
	}
}
