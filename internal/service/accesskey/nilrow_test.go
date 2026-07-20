package accesskey

import (
	"context"
	"errors"
	"testing"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/repository"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/secrets"
)

// The tests in this file are the exception to the fixture's rule of driving the
// real adapter. What is under test is the response to a repository that BREAKS
// its contract by returning a nil row and a nil error, and the real adapter
// cannot be made to do that -- which is the entire reason a fake belongs here.
//
// The assertion that matters in each case is not the error value. It is that
// the call returns at all: every one of these paths decides whether a caller
// may act, and Verify in particular runs on every request for a protected set,
// so a nil dereference on it is a remotely reachable process kill rather than
// one refused request.

// nilKeyRepo returns (nil, nil) from Get and delegates nothing else. The
// embedded interface is nil on purpose: any method these tests do not expect to
// be called panics if it is, which is a louder failure than a zero value.
type nilKeyRepo struct{ repository.AccessKeyRepository }

func (nilKeyRepo) Get(context.Context, domain.OwnerID, domain.AccessKeyID) (*domain.AccessKey, error) {
	return nil, nil
}

type nilKeySetRepo struct{ repository.KeySetRepository }

func (nilKeySetRepo) Get(context.Context, domain.OwnerID, domain.KeySetID) (*domain.KeySet, error) {
	return nil, nil
}

// serviceOverNilRows builds a service whose repositories both violate the port
// contract in the one way these tests care about.
func serviceOverNilRows(t *testing.T) *Service {
	t.Helper()
	s, err := New(nilKeyRepo{}, nilKeySetRepo{}, &fakeAuditor{}, testPepper)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s
}

func TestVerifyRefusesNilCredentialWithoutPanicking(t *testing.T) {
	s := serviceOverNilRows(t)

	k, err := s.Verify(context.Background(), "owner-1", "set-1", secrets.NewRedacted("vak_key-1.secret"))
	if k != nil {
		t.Errorf("Verify returned a credential %+v, want nil", k)
	}
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("Verify error = %v, want one wrapping ErrNotFound", err)
	}
}

func TestMintRefusesNilKeySetWithoutPanicking(t *testing.T) {
	s := serviceOverNilRows(t)

	k, secret, err := s.Mint(context.Background(), "owner-1", "set-1", "ci", "req-1")
	if k != nil {
		t.Errorf("Mint returned a credential %+v, want nil", k)
	}
	if secret.Reveal() != "" {
		t.Error("Mint returned a secret for a set it could not resolve")
	}
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("Mint error = %v, want one wrapping ErrNotFound", err)
	}
}

func TestRevokeRefusesNilCredentialWithoutPanicking(t *testing.T) {
	s := serviceOverNilRows(t)

	err := s.Revoke(context.Background(), "owner-1", "key-1", "req-1")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("Revoke error = %v, want one wrapping ErrNotFound", err)
	}
}
