package auth

import (
	"errors"
	"testing"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
)

// TestMintRefusesAnUnusableCredential exercises the guard on the access-token
// half of a mint. Every caller validates before reaching it, so the branch is
// unreachable through the exported surface; it is covered here so that a future
// caller that forgets to validate is refused rather than handed a token for an
// empty owner.
func TestMintRefusesAnUnusableCredential(t *testing.T) {
	signer, err := NewAccessTokenSigner(make([]byte, MinSigningKeyLen))
	if err != nil {
		t.Fatalf("NewAccessTokenSigner: %v", err)
	}
	svc := &TokenService{signer: signer}

	got, err := svc.mint(&domain.RefreshCredential{
		ID:     newCredentialID(),
		Scopes: []domain.Scope{{Kind: domain.ScopeFullOwner}},
	}, randomBytes(refreshSecretBytes), baseTimeInternal)
	if !errors.Is(err, domain.ErrInvalidInput) {
		t.Fatalf("error = %v, want ErrInvalidInput", err)
	}
	if got != nil {
		t.Fatal("a refused mint still returned tokens")
	}
}

// baseTimeInternal mirrors the fixed instant used by the external tests.
var baseTimeInternal = time.Unix(1_700_000_000, 0).UTC()
