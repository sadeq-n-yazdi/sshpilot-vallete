package auth_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/auth"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/secrets"
)

// baseTime is a fixed instant. Every expiry decision in this package takes an
// explicit now, so no test sleeps and no test reads the clock.
var baseTime = time.Unix(1_700_000_000, 0).UTC()

// fullOwnerScopes is the scope set used wherever the grant itself is not what
// is under test.
func fullOwnerScopes() []domain.Scope {
	return []domain.Scope{{Kind: domain.ScopeFullOwner}}
}

// newService wires a token service over an in-memory store holding one active
// owner.
func newService(t *testing.T) (*fakeStore, *auth.TokenService) {
	t.Helper()
	store, svc, _ := newServiceWithDenylist(t)
	return store, svc
}

// newServiceWithDenylist is newService with the denylist exposed, for the tests
// that assert on revocation taking effect before a token's own expiry. The
// denylist's clock is wound to baseTime so its entry lifetimes line up with the
// timestamps the token tests use.
func newServiceWithDenylist(t *testing.T) (*fakeStore, *auth.TokenService, *denylistFixture) {
	t.Helper()
	store := newFakeStore(&fakeOwners{rows: map[domain.OwnerID]*domain.Owner{
		testOwner: activeOwner(testOwner),
	}})
	f := newDenylistFixture(t)
	f.now = baseTime
	svc, err := auth.NewTokenService(store, newSigner(t, 1), f.dl)
	if err != nil {
		t.Fatalf("NewTokenService: %v", err)
	}
	return store, svc, f
}

// issue mints a first credential pair for the standard owner.
func issue(t *testing.T, svc *auth.TokenService, now time.Time) *auth.Issued {
	t.Helper()
	got, err := svc.Issue(context.Background(), testOwner, fullOwnerScopes(), "laptop", now)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	return got
}

// exchange rotates a refresh token, requiring success.
func exchange(t *testing.T, svc *auth.TokenService, tok secrets.Redacted, now time.Time) *auth.Issued {
	t.Helper()
	got, err := svc.Exchange(context.Background(), tok, now)
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	return got
}

// denied asserts that an exchange failed with a bare ErrAuthFailed.
func denied(t *testing.T, got *auth.Issued, err error) {
	t.Helper()
	if !errors.Is(err, auth.ErrAuthFailed) {
		t.Fatalf("error = %v, want ErrAuthFailed", err)
	}
	if errors.Unwrap(err) != nil {
		t.Fatalf("denial %v carries a cause, which reinstates the distinction the sentinel erases", err)
	}
	if got != nil {
		t.Fatal("a denied exchange still returned tokens")
	}
}

func TestNewTokenServiceRejectsMissingDependencies(t *testing.T) {
	signer := newSigner(t, 1)
	store := newFakeStore(&fakeOwners{})

	dl := newDenylistFixture(t).dl

	if _, err := auth.NewTokenService(nil, signer, dl); !errors.Is(err, domain.ErrInvalidInput) {
		t.Fatalf("nil store: error = %v, want ErrInvalidInput", err)
	}
	if _, err := auth.NewTokenService(store, nil, dl); !errors.Is(err, domain.ErrInvalidInput) {
		t.Fatalf("nil signer: error = %v, want ErrInvalidInput", err)
	}
	// A service built without a denylist would verify revoked access tokens,
	// which is the failure the denylist exists to prevent. It is a wiring bug
	// and must stop the process, not degrade the check.
	if _, err := auth.NewTokenService(store, signer, nil); !errors.Is(err, domain.ErrInvalidInput) {
		t.Fatalf("nil denylist: error = %v, want ErrInvalidInput", err)
	}
}

// TestIssueNeverPersistsTheRawToken is the storage-side half of the "never
// store a raw token" rule: it asserts against the stored representation, not
// against what the code claims to store. Every field of the row is rendered and
// searched for the token, the secret half alone, and the raw secret bytes.
func TestIssueNeverPersistsTheRawToken(t *testing.T) {
	store, svc := newService(t)
	got := issue(t, svc, baseTime)

	raw := got.RefreshToken.Reveal()
	_, secretPart, _ := strings.Cut(strings.TrimPrefix(raw, "svr_"), tokenSep)
	secretBytes, err := tokenEnc.DecodeString(secretPart)
	if err != nil {
		t.Fatalf("decoding the secret half: %v", err)
	}

	rows := store.all()
	if len(rows) != 1 {
		t.Fatalf("stored %d credentials, want 1", len(rows))
	}
	row := rows[0]

	rendered := fmt.Sprintf("%+v", row)
	for _, needle := range []string{raw, secretPart} {
		if strings.Contains(rendered, needle) {
			t.Fatalf("the stored row contains the raw token material %q", needle)
		}
	}
	if bytes.Contains(row.SecretHash, secretBytes) {
		t.Fatal("the stored SecretHash contains the raw secret bytes")
	}
	if len(row.SecretHash) != 32 {
		t.Fatalf("SecretHash is %d bytes, want a 32-byte SHA-256 digest", len(row.SecretHash))
	}
	// The digest must actually be a digest of this secret, not of something
	// else that happens to be the right length.
	if !bytes.Equal(row.SecretHash, sha256Of(secretBytes)) {
		t.Fatal("SecretHash is not SHA-256 of the issued secret")
	}
}

func TestIssuePopulatesTheRootCredential(t *testing.T) {
	store, svc := newService(t)
	scopes := []domain.Scope{
		{Kind: domain.ScopeSingleSet, ResourceID: "ks-1"},
		{Kind: domain.ScopeSingleDevice, ResourceID: "dev-1"},
	}
	got, err := svc.Issue(context.Background(), testOwner, scopes, "ci runner", baseTime)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	rows := store.all()
	row := rows[0]
	switch {
	case row.OwnerID != testOwner:
		t.Fatalf("OwnerID = %q, want %q", row.OwnerID, testOwner)
	case row.LineageID != domain.LineageID(row.ID):
		t.Fatalf("LineageID = %q, want the root credential's own id %q", row.LineageID, row.ID)
	case row.RotatedFromID != nil:
		t.Fatal("the root credential claims to have been rotated from another")
	case row.Status != domain.CredentialStatusActive:
		t.Fatalf("Status = %q, want active", row.Status)
	case !row.IssuedAt.Equal(baseTime):
		t.Fatalf("IssuedAt = %v, want %v", row.IssuedAt, baseTime)
	case !row.ExpiresAt.Equal(baseTime.Add(auth.RefreshLineageLifetime)):
		t.Fatalf("ExpiresAt = %v, want %v", row.ExpiresAt, baseTime.Add(auth.RefreshLineageLifetime))
	case row.ClientLabel != "ci runner":
		t.Fatalf("ClientLabel = %q", row.ClientLabel)
	case len(row.Scopes) != 2:
		t.Fatalf("stored %d scopes, want 2", len(row.Scopes))
	}

	if !got.RefreshExpiresAt.Equal(row.ExpiresAt) {
		t.Fatalf("reported RefreshExpiresAt %v, stored %v", got.RefreshExpiresAt, row.ExpiresAt)
	}
	if !got.AccessExpiresAt.Equal(baseTime.Add(auth.AccessTokenLifetime)) {
		t.Fatalf("AccessExpiresAt = %v, want issuance plus %v", got.AccessExpiresAt, auth.AccessTokenLifetime)
	}
	// The access token must be usable and must carry the owner binding and the
	// scopes, which is what B5 will enforce against.
	claims, err := svc.Verify(context.Background(), got.AccessToken, baseTime)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if claims.OwnerID != testOwner || len(claims.Scopes) != 2 {
		t.Fatalf("access token claims = %+v", claims)
	}
}

// TestIssueScopesAreCopied proves the caller cannot widen a grant after it has
// been validated by mutating the slice it handed in.
func TestIssueScopesAreCopied(t *testing.T) {
	store, svc := newService(t)
	scopes := []domain.Scope{{Kind: domain.ScopeReadOnly}}
	if _, err := svc.Issue(context.Background(), testOwner, scopes, "", baseTime); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	scopes[0] = domain.Scope{Kind: domain.ScopeFullOwner}
	if got := store.all()[0].Scopes[0].Kind; got != domain.ScopeReadOnly {
		t.Fatalf("stored scope became %q after the caller mutated its slice", got)
	}
}

func TestIssueRejectsInvalidInput(t *testing.T) {
	_, svc := newService(t)
	tests := []struct {
		name  string
		owner domain.OwnerID
		scope []domain.Scope
		label string
	}{
		{name: "empty owner", owner: "", scope: fullOwnerScopes()},
		{name: "no scopes", owner: testOwner, scope: nil},
		{name: "invalid scope", owner: testOwner, scope: []domain.Scope{{Kind: domain.ScopeKind("nonsense")}}},
		{name: "bad label", owner: testOwner, scope: fullOwnerScopes(), label: "a\nb"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := svc.Issue(context.Background(), tt.owner, tt.scope, tt.label, baseTime)
			if !errors.Is(err, domain.ErrInvalidInput) {
				t.Fatalf("error = %v, want ErrInvalidInput", err)
			}
			if got != nil {
				t.Fatal("a rejected issuance still returned tokens")
			}
		})
	}
}

func TestIssueReportsStorageFailure(t *testing.T) {
	store, svc := newService(t)
	store.createErr = errStore
	got, err := svc.Issue(context.Background(), testOwner, fullOwnerScopes(), "", baseTime)
	if !errors.Is(err, errStore) {
		t.Fatalf("error = %v, want the store fault", err)
	}
	if got != nil {
		t.Fatal("a failed issuance still returned tokens")
	}
}

// TestRotationInvalidatesTheOldToken is the central rotation property: a
// refresh token is single-use, and the successor works.
func TestRotationInvalidatesTheOldToken(t *testing.T) {
	store, svc := newService(t)
	first := issue(t, svc, baseTime)
	firstID := store.all()[0].ID

	second := exchange(t, svc, first.RefreshToken, baseTime.Add(time.Hour))

	if second.RefreshToken.Reveal() == first.RefreshToken.Reveal() {
		t.Fatal("rotation returned the same refresh token")
	}
	if store.snapshotOf(firstID).Status != domain.CredentialStatusRotated {
		t.Fatal("the presented credential was not consumed")
	}

	// The successor must work...
	third := exchange(t, svc, second.RefreshToken, baseTime.Add(2*time.Hour))
	if third.RefreshToken.Reveal() == second.RefreshToken.Reveal() {
		t.Fatal("the second rotation returned the same refresh token")
	}
}

func TestRotationCarriesTheLineageForward(t *testing.T) {
	store, svc := newService(t)
	scopes := []domain.Scope{{Kind: domain.ScopeSingleSet, ResourceID: "ks-1"}}
	first, err := svc.Issue(context.Background(), testOwner, scopes, "laptop", baseTime)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	parent := store.all()[0]

	second := exchange(t, svc, first.RefreshToken, baseTime.Add(time.Hour))

	var child domain.RefreshCredential
	for _, c := range store.all() {
		if c.ID != parent.ID {
			child = c
		}
	}
	switch {
	case child.LineageID != parent.LineageID:
		t.Fatalf("child lineage %q, want %q -- a new lineage would put the successor beyond the reach of reuse revocation", child.LineageID, parent.LineageID)
	case child.RotatedFromID == nil || *child.RotatedFromID != parent.ID:
		t.Fatalf("child RotatedFromID = %v, want %q", child.RotatedFromID, parent.ID)
	case !child.IssuedAt.Equal(baseTime.Add(time.Hour)):
		t.Fatalf("child IssuedAt = %v", child.IssuedAt)
	case child.Status != domain.CredentialStatusActive:
		t.Fatalf("child Status = %q, want active", child.Status)
	case child.ClientLabel != "laptop":
		t.Fatalf("child ClientLabel = %q, want the parent's", child.ClientLabel)
	case len(child.Scopes) != 1 || child.Scopes[0] != scopes[0]:
		t.Fatalf("child scopes = %+v, want the parent's %+v", child.Scopes, scopes)
	}
	// Rotation must never widen a grant: the new access token carries exactly
	// the scopes the lineage was issued with.
	claims, err := svc.Verify(context.Background(), second.AccessToken, baseTime.Add(time.Hour))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if len(claims.Scopes) != 1 || claims.Scopes[0] != scopes[0] {
		t.Fatalf("rotated access token scopes = %+v, want %+v", claims.Scopes, scopes)
	}
}
