package auth_test

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/auth"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/secrets"
)

// The helpers below build device codes and digests directly from the wire
// format and the domain separation tag, as literals. As with the refresh token
// tests, the format is restated here rather than derived from the package's own
// constants, so a change to either is caught by these tests rather than
// silently tracked by them.
const (
	devicePrefix  = "svd_"
	deviceHashTag = "vallet.auth.pairing.device.v1\x00"
)

var testClock = time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)

// deviceCodeFor builds a device code for id carrying secret, independently of
// the package under test.
func deviceCodeFor(id domain.PairingID, secret []byte) secrets.Redacted {
	return secrets.NewRedacted(devicePrefix + string(id) + "." + base64.RawURLEncoding.EncodeToString(secret))
}

// deviceDigest computes what the row must store for secret.
func deviceDigest(secret []byte) []byte {
	sum := sha256.Sum256(append([]byte(deviceHashTag), secret...))
	return sum[:]
}

func randomID(t *testing.T) domain.PairingID {
	t.Helper()
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("reading random bytes: %v", err)
	}
	return domain.PairingID(base64.RawURLEncoding.EncodeToString(b))
}

func randomSecret(t *testing.T) []byte {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("reading random bytes: %v", err)
	}
	return b
}

// approvedPairing stores an approved, unexpired pairing owned by ownerID and
// returns its id and device code.
func approvedPairing(t *testing.T, f *fakePairings, ownerID domain.OwnerID) (domain.PairingID, secrets.Redacted) {
	t.Helper()
	id := randomID(t)
	secret := randomSecret(t)
	approved := testClock.Add(-time.Minute)
	if err := f.Create(context.Background(), &domain.DevicePairing{
		ID:             id,
		OwnerID:        ownerID,
		DeviceCodeHash: deviceDigest(secret),
		Scopes:         []domain.Scope{{Kind: domain.ScopeFullOwner}},
		ClientLabel:    "laptop",
		Status:         domain.PairingStatusApproved,
		CreatedAt:      approved,
		ExpiresAt:      testClock.Add(9 * time.Minute),
		ApprovedAt:     &approved,
	}); err != nil {
		t.Fatalf("seeding a pairing: %v", err)
	}
	return id, deviceCodeFor(id, secret)
}

func newTestProvider(t *testing.T, f *fakePairings) *auth.APITokenProvider {
	t.Helper()
	p, err := auth.NewAPITokenProvider(f, func() time.Time { return testClock })
	if err != nil {
		t.Fatalf("building the provider: %v", err)
	}
	return p
}

// requireBareAuthFailed asserts the strictest form of the package's denial
// contract: exactly ErrAuthFailed, with nothing wrapped that errors.As could
// pull a cause out of.
func requireBareAuthFailed(t *testing.T, err error, context string) {
	t.Helper()
	if !errors.Is(err, auth.ErrAuthFailed) {
		t.Fatalf("%s: error = %v, want ErrAuthFailed", context, err)
	}
	if err.Error() != auth.ErrAuthFailed.Error() {
		t.Fatalf("%s: error %q wraps a cause, which reinstates the distinction "+
			"the sentinel exists to erase", context, err)
	}
}

func TestNewAPITokenProviderRejectsMissingDependencies(t *testing.T) {
	if _, err := auth.NewAPITokenProvider(nil, func() time.Time { return testClock }); !errors.Is(err, domain.ErrInvalidInput) {
		t.Fatalf("nil repository: error = %v, want ErrInvalidInput", err)
	}
	// A nil clock would leave the expiry check with nothing to compare against,
	// which is a provider that cannot expire a pairing.
	if _, err := auth.NewAPITokenProvider(newFakePairings(), nil); !errors.Is(err, domain.ErrInvalidInput) {
		t.Fatalf("nil clock: error = %v, want ErrInvalidInput", err)
	}
}

func TestAPITokenProviderID(t *testing.T) {
	p := newTestProvider(t, newFakePairings())
	if got := p.ID(); got != auth.APITokenProviderID {
		t.Fatalf("ID() = %q, want %q", got, auth.APITokenProviderID)
	}
	// The id is part of every identity key this provider mints, so it has to
	// satisfy the same rules Authenticator enforces on any provider.
	if err := p.ID().Validate(); err != nil {
		t.Fatalf("the provider's own id is malformed: %v", err)
	}
}

func TestAPITokenProviderAuthenticates(t *testing.T) {
	f := newFakePairings()
	id, code := approvedPairing(t, f, "owner-1")

	identity, err := newTestProvider(t, f).Authenticate(context.Background(), auth.Credential{Secret: code})
	if err != nil {
		t.Fatalf("authenticating a valid device code: %v", err)
	}
	if identity.Provider != auth.APITokenProviderID {
		t.Fatalf("Provider = %q, want %q", identity.Provider, auth.APITokenProviderID)
	}
	// The principal is the pairing id, which is what the approval linked to an
	// owner. The provider itself must not have reported an owner anywhere.
	if identity.Principal != auth.Principal(id) {
		t.Fatalf("Principal = %q, want %q", identity.Principal, id)
	}
	if err := identity.Validate(); err != nil {
		t.Fatalf("the returned identity is malformed: %v", err)
	}
}

// TestAPITokenProviderDenials walks every reason a device code is refused. All
// of them return the same bare sentinel, which is the point of the table: a
// caller cannot use the error to learn which pairings exist or what state one
// is in.
func TestAPITokenProviderDenials(t *testing.T) {
	tests := []struct {
		name string
		// setup mutates the seeded pairing and returns the code to present.
		setup func(t *testing.T, f *fakePairings, id domain.PairingID, code secrets.Redacted) secrets.Redacted
	}{
		{
			name: "malformed code",
			setup: func(*testing.T, *fakePairings, domain.PairingID, secrets.Redacted) secrets.Redacted {
				return secrets.NewRedacted("not-a-device-code")
			},
		},
		{
			name: "unknown pairing id",
			setup: func(t *testing.T, _ *fakePairings, _ domain.PairingID, _ secrets.Redacted) secrets.Redacted {
				return deviceCodeFor(randomID(t), randomSecret(t))
			},
		},
		{
			name: "wrong secret for a real pairing",
			setup: func(t *testing.T, _ *fakePairings, id domain.PairingID, _ secrets.Redacted) secrets.Redacted {
				// What an attacker who learned an identifier, and nothing else,
				// is able to present.
				return deviceCodeFor(id, randomSecret(t))
			},
		},
		{
			name: "pending pairing, not yet approved",
			setup: func(_ *testing.T, f *fakePairings, id domain.PairingID, code secrets.Redacted) secrets.Redacted {
				f.rows[id].Status = domain.PairingStatusPending
				f.rows[id].OwnerID = ""
				return code
			},
		},
		{
			name: "already redeemed pairing",
			setup: func(_ *testing.T, f *fakePairings, id domain.PairingID, code secrets.Redacted) secrets.Redacted {
				f.rows[id].Status = domain.PairingStatusRedeemed
				return code
			},
		},
		{
			name: "revoked pairing",
			setup: func(_ *testing.T, f *fakePairings, id domain.PairingID, code secrets.Redacted) secrets.Redacted {
				f.rows[id].Status = domain.PairingStatusRevoked
				return code
			},
		},
		{
			name: "expired pairing",
			setup: func(_ *testing.T, f *fakePairings, id domain.PairingID, code secrets.Redacted) secrets.Redacted {
				f.rows[id].ExpiresAt = testClock.Add(-time.Second)
				return code
			},
		},
		{
			name: "pairing expiring exactly now",
			setup: func(_ *testing.T, f *fakePairings, id domain.PairingID, code secrets.Redacted) secrets.Redacted {
				// The boundary is exclusive: a pairing is dead AT its expiry.
				f.rows[id].ExpiresAt = testClock
				return code
			},
		},
		{
			name: "approved pairing with no owner",
			setup: func(_ *testing.T, f *fakePairings, id domain.PairingID, code secrets.Redacted) secrets.Redacted {
				f.rows[id].OwnerID = ""
				return code
			},
		},
		{
			name: "store returns a nil row and a nil error",
			setup: func(_ *testing.T, f *fakePairings, _ domain.PairingID, code secrets.Redacted) secrets.Redacted {
				f.nilRow = true
				return code
			},
		},
		{
			name: "store returns a different pairing than asked for",
			setup: func(t *testing.T, f *fakePairings, _ domain.PairingID, code secrets.Redacted) secrets.Redacted {
				// A loosely keyed cache or a case-insensitive collation would do
				// exactly this. Accepting the row would authenticate a device
				// code against a neighbor's pairing.
				other := copyPairing(f.rows[randomIDOf(t, f)])
				other.ID = randomID(t)
				f.override = other
				return code
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFakePairings()
			id, code := approvedPairing(t, f, "owner-1")
			presented := tt.setup(t, f, id, code)

			identity, err := newTestProvider(t, f).Authenticate(context.Background(), auth.Credential{Secret: presented})
			requireBareAuthFailed(t, err, tt.name)
			if identity != (auth.Identity{}) {
				t.Fatalf("%s: returned an identity alongside a denial: %+v", tt.name, identity)
			}
		})
	}
}

// randomIDOf returns the id of the single seeded pairing.
func randomIDOf(t *testing.T, f *fakePairings) domain.PairingID {
	t.Helper()
	for id := range f.rows {
		return id
	}
	t.Fatal("no pairing seeded")
	return ""
}

// TestAPITokenProviderWrongSecretIsIndistinguishableFromUnknown is the
// enumeration guarantee stated as a byte comparison: a caller that guessed a
// real pairing id gets exactly the answer a caller that guessed a nonexistent
// one gets.
func TestAPITokenProviderWrongSecretIsIndistinguishableFromUnknown(t *testing.T) {
	f := newFakePairings()
	id, _ := approvedPairing(t, f, "owner-1")
	p := newTestProvider(t, f)

	_, wrongSecretErr := p.Authenticate(context.Background(),
		auth.Credential{Secret: deviceCodeFor(id, randomSecret(t))})
	_, unknownErr := p.Authenticate(context.Background(),
		auth.Credential{Secret: deviceCodeFor(randomID(t), randomSecret(t))})

	if wrongSecretErr.Error() != unknownErr.Error() {
		t.Fatalf("a wrong secret for a real pairing (%v) is distinguishable from an "+
			"unknown pairing (%v); the pair of answers enumerates which ids exist",
			wrongSecretErr, unknownErr)
	}
	requireBareAuthFailed(t, wrongSecretErr, "wrong secret")
	requireBareAuthFailed(t, unknownErr, "unknown pairing")
}

// TestAPITokenProviderStorageFaultIsNotADenial checks the one error this
// provider is allowed to distinguish. An outage must be legible to an operator
// in the logs; Authenticator is what stops it reaching a client.
func TestAPITokenProviderStorageFaultIsNotADenial(t *testing.T) {
	f := newFakePairings()
	_, code := approvedPairing(t, f, "owner-1")
	boom := errors.New("database is down")
	f.getByIDErr = boom

	_, err := newTestProvider(t, f).Authenticate(context.Background(), auth.Credential{Secret: code})
	if errors.Is(err, auth.ErrAuthFailed) {
		t.Fatal("a storage fault was reported as an authentication failure, so an " +
			"outage is invisible to the operator")
	}
	if !errors.Is(err, boom) {
		t.Fatalf("error = %v, want it to wrap the storage fault", err)
	}
}

// TestAPITokenProviderNotFoundIsADenial is the other side of the same check: a
// missing row is an ordinary denial and must not be reported as an outage.
func TestAPITokenProviderNotFoundIsADenial(t *testing.T) {
	f := newFakePairings()
	_, code := approvedPairing(t, f, "owner-1")
	f.getByIDErr = domain.ErrNotFound

	_, err := newTestProvider(t, f).Authenticate(context.Background(), auth.Credential{Secret: code})
	requireBareAuthFailed(t, err, "not found")
}
