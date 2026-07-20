package auth_test

import (
	"context"
	"encoding"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/auth"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
)

// The tests in this file cover the paths that only a fault can reach: a
// dependency that is missing at wiring time, a store that is down, a write that
// loses a race, and the rendering paths a leak would travel. They are separated
// from the flow tests so that each file stays about one thing.

// TestStartDeviceGrantRejectsInvalidInput checks the two values a client
// controls are validated before a row is written.
func TestStartDeviceGrantRejectsInvalidInput(t *testing.T) {
	h := newEnrollHarness(t)
	ctx := context.Background()
	if _, err := h.svc.StartDeviceGrant(ctx, "laptop", nil); !errors.Is(err, domain.ErrInvalidInput) {
		t.Fatalf("empty scope set: error = %v, want ErrInvalidInput", err)
	}
	if _, err := h.svc.StartDeviceGrant(ctx, strings.Repeat("x", auth.MaxClientLabelLen+1), fullOwner()); !errors.Is(err, domain.ErrInvalidInput) {
		t.Fatalf("oversized label: error = %v, want ErrInvalidInput", err)
	}
}

// TestStartDeviceGrantReportsStorageFaults checks that a failed write is not
// reported as a usable grant.
func TestStartDeviceGrantReportsStorageFaults(t *testing.T) {
	h := newEnrollHarness(t)
	h.pairings.createErr = errors.New("database is down")
	if _, err := h.svc.StartDeviceGrant(context.Background(), "laptop", fullOwner()); err == nil {
		t.Fatal("a grant was returned for a pairing that was never stored")
	}
	if _, err := h.svc.Mint(context.Background(), "owner-1", "laptop", fullOwner()); err == nil {
		t.Fatal("a minted grant was returned for a pairing that was never stored")
	}
}

// TestMintReportsALinkFailure checks that a pairing whose link could not be
// written is reported as a failure rather than handed back as a working code.
func TestMintReportsALinkFailure(t *testing.T) {
	h := newEnrollHarness(t)
	h.links.err = errors.New("database is down")
	if _, err := h.svc.Mint(context.Background(), "owner-1", "laptop", fullOwner()); err == nil {
		t.Fatal("a device code was returned for a pairing that resolves to no owner")
	}
}

// TestGrantRedactionSurvivesEveryFormattingPath is the leak check. The
// realistic path is a Grant printed as part of a surrounding value, which is
// why Format is implemented and why it is asserted here alongside the others.
func TestGrantRedactionSurvivesEveryFormattingPath(t *testing.T) {
	h := newEnrollHarness(t)
	grant := startGrant(t, h)
	device, user := grant.DeviceCode.Reveal(), grant.UserCode.Reveal()

	renders := map[string]string{
		"%v":     fmtOf("%v", *grant),
		"%+v":    fmtOf("%+v", *grant),
		"%#v":    fmtOf("%#v", *grant),
		"%s":     fmtOf("%s", *grant),
		"nested": fmtOf("%+v", struct{ G auth.Grant }{*grant}),
		"json":   mustJSON(t, *grant),
		"text":   mustText(t, *grant),
		"slog":   grant.LogValue().String(),
	}
	for name, rendered := range renders {
		if strings.Contains(rendered, device) {
			t.Fatalf("%s rendered the device code: %s", name, rendered)
		}
		if strings.Contains(rendered, user) {
			t.Fatalf("%s rendered the user code: %s", name, rendered)
		}
		if !strings.Contains(rendered, "REDACTED") {
			t.Fatalf("%s produced %q, which does not announce that it was redacted", name, rendered)
		}
	}
	// PairingID is not a secret and must stay legible, or an operator cannot
	// correlate a grant with an audit record.
	if !strings.Contains(renders["%v"], string(grant.PairingID)) {
		t.Fatal("the pairing id was redacted; it is a lookup key, not a secret")
	}
	// The expiry and interval are ordinary values a client needs.
	if grant.PollInterval != auth.PairingPollInterval {
		t.Fatalf("PollInterval = %v, want %v", grant.PollInterval, auth.PairingPollInterval)
	}
	if want := h.clock.now().Add(auth.PairingLifetime); !grant.ExpiresAt.Equal(want) {
		t.Fatalf("ExpiresAt = %v, want %v", grant.ExpiresAt, want)
	}
}

// fmtOf renders v with the given verb.
func fmtOf(verb string, v any) string { return fmt.Sprintf(verb, v) }

// mustJSON marshals v, failing the test if it cannot.
func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshaling: %v", err)
	}
	return string(b)
}

// mustText marshals v as text, failing the test if it cannot.
func mustText(t *testing.T, v encoding.TextMarshaler) string {
	t.Helper()
	b, err := v.MarshalText()
	if err != nil {
		t.Fatalf("marshaling text: %v", err)
	}
	return string(b)
}

// TestNewEnrollmentServiceRejectsEveryMissingDependency walks each dependency
// in turn. Each nil is a control the service would otherwise skip silently
// while still answering as though it had run.
func TestNewEnrollmentServiceRejectsEveryMissingDependency(t *testing.T) {
	h := newEnrollHarness(t)
	full := func() (*fakeStore, *auth.Authenticator, *auth.TokenService, *auth.Denylist, *faultyCounters, func() time.Time) {
		a, err := auth.NewAuthenticator(mustRegistry(t), h.links, h.creds.owners)
		if err != nil {
			t.Fatalf("building an authenticator: %v", err)
		}
		d, err := auth.NewDenylist(h.counters)
		if err != nil {
			t.Fatalf("building a denylist: %v", err)
		}
		return h.creds, a, h.tokens, d, h.limiter, h.clock.now
	}
	tests := map[string]func() error{
		"nil store": func() error {
			_, a, tk, d, l, n := full()
			_, err := auth.NewEnrollmentService(nil, a, tk, d, l, n)
			return err
		},
		"nil authenticator": func() error {
			st, _, tk, d, l, n := full()
			_, err := auth.NewEnrollmentService(st, nil, tk, d, l, n)
			return err
		},
		"nil token service": func() error {
			st, a, _, d, l, n := full()
			_, err := auth.NewEnrollmentService(st, a, nil, d, l, n)
			return err
		},
		"nil denylist": func() error {
			st, a, tk, _, l, n := full()
			_, err := auth.NewEnrollmentService(st, a, tk, nil, l, n)
			return err
		},
		"nil limiter": func() error {
			st, a, tk, d, _, n := full()
			_, err := auth.NewEnrollmentService(st, a, tk, d, nil, n)
			return err
		},
		"nil clock": func() error {
			st, a, tk, d, l, _ := full()
			_, err := auth.NewEnrollmentService(st, a, tk, d, l, nil)
			return err
		},
	}
	for name, call := range tests {
		t.Run(name, func(t *testing.T) {
			if err := call(); !errors.Is(err, domain.ErrInvalidInput) {
				t.Fatalf("error = %v, want ErrInvalidInput", err)
			}
		})
	}
	// The fully wired call must still succeed, or the table above would pass
	// for the wrong reason.
	st, a, tk, d, l, n := full()
	if _, err := auth.NewEnrollmentService(st, a, tk, d, l, n); err != nil {
		t.Fatalf("a fully wired service was refused: %v", err)
	}
}

func mustRegistry(t *testing.T) *auth.Registry {
	t.Helper()
	p, err := auth.NewAPITokenProvider(newFakePairings(), func() time.Time { return testClock })
	if err != nil {
		t.Fatalf("building a provider: %v", err)
	}
	reg, err := auth.NewRegistry(p)
	if err != nil {
		t.Fatalf("building a registry: %v", err)
	}
	return reg
}

// TestGrantGoStringRedacts covers the method directly. Format takes precedence
// over GoString for every verb, so %#v never reaches it -- but a caller can,
// and it must redact too.
func TestGrantGoStringRedacts(t *testing.T) {
	h := newEnrollHarness(t)
	grant := startGrant(t, h)
	got := grant.GoString()
	if strings.Contains(got, grant.DeviceCode.Reveal()) || strings.Contains(got, grant.UserCode.Reveal()) {
		t.Fatalf("GoString rendered a code: %s", got)
	}
	if !strings.Contains(got, "REDACTED") {
		t.Fatalf("GoString produced %q", got)
	}
}

// TestRedeemRefusesAnUnusableStoredScopeSet checks that a scope set which no
// longer validates is refused rather than carried into a credential. Both
// creation paths validated it, so a row like this was written by something else.
func TestRedeemRefusesAnUnusableStoredScopeSet(t *testing.T) {
	h := newEnrollHarness(t)
	ctx := context.Background()
	grant, err := h.svc.Mint(ctx, "owner-1", "laptop", fullOwner())
	if err != nil {
		t.Fatalf("minting: %v", err)
	}
	// An empty set must never be read as full access.
	h.pairings.rows[grant.PairingID].Scopes = nil

	issued, err := h.svc.Redeem(ctx, grant.DeviceCode)
	requireBareAuthFailed(t, err, "redeeming a pairing with no scopes")
	if issued != nil {
		t.Fatal("credentials were issued for a pairing whose grant does not validate")
	}
}

// TestRedeemDeniesWhenIssuanceFails checks that a failure to mint credentials
// does not consume the pairing, so the client can retry.
func TestRedeemDeniesWhenIssuanceFails(t *testing.T) {
	h := newEnrollHarness(t)
	ctx := context.Background()
	grant, err := h.svc.Mint(ctx, "owner-1", "laptop", fullOwner())
	if err != nil {
		t.Fatalf("minting: %v", err)
	}
	h.creds.createErr = errors.New("database is down")

	_, err = h.svc.Redeem(ctx, grant.DeviceCode)
	requireBareAuthFailed(t, err, "redemption with a failing credential store")
	if got := h.pairings.snapshotOf(grant.PairingID).Status; got != domain.PairingStatusApproved {
		t.Fatalf("pairing status = %q after a failed issuance, want approved so the client can retry", got)
	}
}

// TestRevokeRejectsInvalidInput checks the arguments are validated before an
// empty value is used as a query key.
func TestRevokeRejectsInvalidInput(t *testing.T) {
	h := newEnrollHarness(t)
	ctx := context.Background()
	if err := h.svc.Revoke(ctx, "", "abc"); !errors.Is(err, domain.ErrInvalidInput) {
		t.Fatalf("empty owner: error = %v, want ErrInvalidInput", err)
	}
	if err := h.svc.Revoke(ctx, "owner-1", ""); !errors.Is(err, domain.ErrInvalidInput) {
		t.Fatalf("empty pairing id: error = %v, want ErrInvalidInput", err)
	}
}

// TestRevokeSurvivesADegradedDenylist is the failure direction that matters.
// The pairing revocation is durable and authoritative; the denylist is a
// fifteen-minute cache in front of it, so a failure there must not undo the
// revocation, only degrade immediate withdrawal to TTL expiry.
func TestRevokeSurvivesADegradedDenylist(t *testing.T) {
	faults := map[string]func(h *enrollHarness){
		"the lineage cannot be revoked": func(h *enrollHarness) {
			h.creds.revokeLineageErr = errors.New("database is down")
		},
		"the revoked lineage cannot be read back": func(h *enrollHarness) {
			h.creds.listByLineageErr = errors.New("database is down")
		},
		"the denylist cannot be written": func(h *enrollHarness) {
			h.limiter.down.Store(true)
		},
	}
	for name, inject := range faults {
		t.Run(name, func(t *testing.T) {
			h := newEnrollHarness(t)
			ctx := context.Background()
			grant, err := h.svc.Mint(ctx, "owner-1", "laptop", fullOwner())
			if err != nil {
				t.Fatalf("minting: %v", err)
			}
			if _, err := h.svc.Redeem(ctx, grant.DeviceCode); err != nil {
				t.Fatalf("redeeming: %v", err)
			}
			inject(h)

			if err := h.svc.Revoke(ctx, "owner-1", grant.PairingID); err != nil {
				t.Fatalf("revoke reported %v; the durable revocation must not be undone "+
					"to keep a fifteen-minute cache consistent", err)
			}
			if got := h.pairings.snapshotOf(grant.PairingID).Status; got != domain.PairingStatusRevoked {
				t.Fatalf("pairing status = %q, want revoked", got)
			}
			// The device code is dead either way, which is the part that does
			// not depend on the denylist at all.
			if _, err := h.svc.Redeem(ctx, grant.DeviceCode); err == nil {
				t.Fatal("a revoked pairing still redeemed")
			}
		})
	}
}

// TestRevokeReportsAStorageFault checks that a failure to read or write the
// pairing row is reported rather than swallowed as success.
func TestRevokeReportsAStorageFault(t *testing.T) {
	h := newEnrollHarness(t)
	ctx := context.Background()
	grant, err := h.svc.Mint(ctx, "owner-1", "laptop", fullOwner())
	if err != nil {
		t.Fatalf("minting: %v", err)
	}
	h.pairings.revokeErr = errors.New("database is down")
	if err := h.svc.Revoke(ctx, "owner-1", grant.PairingID); err == nil {
		t.Fatal("a failed revocation was reported as success")
	}
}

// TestRedeemLosingTheConsumeRevokesItsLineage is the compensating write stated
// deterministically. The concurrency test exercises this path only when the
// timing lands there; injecting the conflict makes it unconditional.
func TestRedeemLosingTheConsumeRevokesItsLineage(t *testing.T) {
	h := newEnrollHarness(t)
	ctx := context.Background()
	grant, err := h.svc.Mint(ctx, "owner-1", "laptop", fullOwner())
	if err != nil {
		t.Fatalf("minting: %v", err)
	}
	h.pairings.markErr = domain.ErrConflict

	issued, err := h.svc.Redeem(ctx, grant.DeviceCode)
	requireBareAuthFailed(t, err, "redemption that lost the consume")
	if issued != nil {
		t.Fatal("credentials were returned by a redemption that did not consume the pairing")
	}
	// The lineage minted before losing must be dead, or the pairing has
	// installed a credential nobody can see or revoke.
	all := h.creds.all()
	if len(all) == 0 {
		t.Fatal("no credential was minted, so this test is not exercising the compensating revoke")
	}
	for _, c := range all {
		if c.Status != domain.CredentialStatusRevoked {
			t.Fatalf("credential %q in lineage %q was left live at status %q after a lost consume",
				c.ID, c.LineageID, c.Status)
		}
	}
}

// TestRevokeTreatsAPortViolationAsAbsent checks the (nil, nil) contract
// violation is read as "no such pairing" rather than dereferenced.
func TestRevokeTreatsAPortViolationAsAbsent(t *testing.T) {
	h := newEnrollHarness(t)
	ctx := context.Background()
	grant, err := h.svc.Mint(ctx, "owner-1", "laptop", fullOwner())
	if err != nil {
		t.Fatalf("minting: %v", err)
	}
	h.pairings.nilOwnedRow = true

	if err := h.svc.Revoke(ctx, "owner-1", grant.PairingID); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("error = %v, want ErrNotFound", err)
	}
}

// TestRedeemRefusesARowFromAnotherOwner exercises the owner comparison Redeem
// makes for itself, by handing it a store that ignored the owner filter. A
// LIKE that reached production, a cache keyed on the id alone, or a query
// missing its WHERE clause each look exactly like this, and each would
// otherwise pair a device into an account that never approved it.
func TestRedeemRefusesARowFromAnotherOwner(t *testing.T) {
	h := newEnrollHarness(t)
	ctx := context.Background()
	grant, err := h.svc.Mint(ctx, "owner-1", "laptop", fullOwner())
	if err != nil {
		t.Fatalf("minting: %v", err)
	}
	stolen := h.pairings.snapshotOf(grant.PairingID)
	stolen.OwnerID = "owner-2"
	h.pairings.overrideOwned = stolen

	issued, err := h.svc.Redeem(ctx, grant.DeviceCode)
	requireBareAuthFailed(t, err, "redemption against a row the store returned for the wrong owner")
	if issued != nil {
		t.Fatalf("credentials were issued for %q from owner-1's pairing", issued.OwnerID)
	}
}

// TestRedeemRefusesARowWithTheWrongID is the other half of the same check: a
// store that returned a neighboring pairing rather than the one asked for.
func TestRedeemRefusesARowWithTheWrongID(t *testing.T) {
	h := newEnrollHarness(t)
	ctx := context.Background()
	grant, err := h.svc.Mint(ctx, "owner-1", "laptop", fullOwner())
	if err != nil {
		t.Fatalf("minting: %v", err)
	}
	neighbor := h.pairings.snapshotOf(grant.PairingID)
	neighbor.ID = "c29tZS1vdGhlci1pZA"
	h.pairings.overrideOwned = neighbor

	issued, err := h.svc.Redeem(ctx, grant.DeviceCode)
	requireBareAuthFailed(t, err, "redemption against a neighboring row")
	if issued != nil {
		t.Fatal("credentials were issued from a pairing nobody asked for")
	}
}

// TestRevokeRefusesARowFromAnotherOwner is the same defense on the revocation
// path. Without the caller's own comparison, a store that ignored the owner
// filter would let one owner revoke another's device.
func TestRevokeRefusesARowFromAnotherOwner(t *testing.T) {
	h := newEnrollHarness(t)
	ctx := context.Background()
	grant, err := h.svc.Mint(ctx, "owner-1", "laptop", fullOwner())
	if err != nil {
		t.Fatalf("minting: %v", err)
	}
	stolen := h.pairings.snapshotOf(grant.PairingID)
	stolen.OwnerID = "owner-1"
	h.pairings.overrideOwned = stolen

	// owner-2 asks to revoke, and the store hands back owner-1's row.
	if err := h.svc.Revoke(ctx, "owner-2", grant.PairingID); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("error = %v, want ErrNotFound: one owner revoked another's device", err)
	}
	// The refusal must happen on the read, before any write is attempted. A
	// caller that relied on the write to re-check the owner would still be
	// wrong: it would have committed to revoking a row it had not verified,
	// and any store whose filter is weaker than the fake's would go through.
	if got := h.pairings.revokeCalls.Load(); got != 0 {
		t.Fatalf("a revocation write was attempted %d times against another owner's row; "+
			"the owner check must short-circuit before it", got)
	}
}
