package keyset

import (
	"errors"
	"testing"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
)

// TestLiveRefusesNilSetWithoutPanicking drives live() with the one repository
// answer that violates the port contract: no row and no error.
//
// The assertion that matters is not the error value but that the call returns
// at all. Rename and Delete both feed live() straight from a repository read,
// so a dereference here is reachable from a request and would end the process
// rather than the request. Removing the nil guard makes this test panic, which
// is exactly the failure it exists to pin.
func TestLiveRefusesNilSetWithoutPanicking(t *testing.T) {
	t.Parallel()

	set, err := live(nil, nil)
	if set != nil {
		t.Fatalf("live(nil, nil) set = %#v, want nil", set)
	}
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("live(nil, nil) err = %v, want ErrNotFound", err)
	}
	// The transport maps on the domain sentinel, so a contract violation must
	// reach it as the same negative verdict an unknown id gets.
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("live(nil, nil) err = %v, want it to wrap domain.ErrNotFound", err)
	}
}
