package nameguard

import (
	"errors"
	"testing"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/blocklist"
)

var errBuild = errors.New("list data did not compile")

// TestNewFromRefusesToReturnAHalfBuiltGuard covers the constructor failure
// path that Default cannot reach. A build failure must yield a nil Guard, so
// that a caller ignoring the error is left holding nothing rather than
// something that looks usable -- and a nil Guard refuses every Check anyway.
func TestNewFromRefusesToReturnAHalfBuiltGuard(t *testing.T) {
	t.Parallel()
	g, err := newFrom(func() (*blocklist.Matcher, error) { return nil, errBuild })
	if !errors.Is(err, errBuild) {
		t.Fatalf("newFrom() error = %v, want wrapped errBuild", err)
	}
	if g != nil {
		t.Fatalf("newFrom() guard = %#v, want nil on build failure", g)
	}
	// The nil guard the caller now holds still fails closed.
	if err := g.Check(KindHandle, OpCreate, "alice"); err == nil {
		t.Error("nil guard from failed build allowed a name")
	}
}
