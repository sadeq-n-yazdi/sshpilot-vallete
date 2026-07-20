package postgres

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
)

// TestHandleUniquenessHoldsUnderConcurrentRegisters is the PostgreSQL half of
// the uniqueness proof.
//
// A previous finding on this project established that a cap race was
// demonstrated only on SQLite and that PostgreSQL needed its own answer. The
// same caution applies here, so this is not assumed from the SQLite result: it
// runs the same race against a real PostgreSQL server. Unlike the cap, though,
// uniqueness is not a read-then-write pair — it is a UNIQUE index the engine
// enforces at insert time — so the two engines are expected to agree, and this
// test is what turns that expectation into evidence.
//
// Each goroutine uses its own owner, so ux_handles_owner_active cannot be what
// refuses the losers; only the name and fold indexes can.
func TestHandleUniquenessHoldsUnderConcurrentRegisters(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	const racers = 24

	for _, tc := range []struct {
		name    string
		nameFor func(i int) string
	}{
		// Same exact name: caught by ux_handles_name.
		{"identical names", func(int) string { return "contested" }},
		// Distinct valid slugs sharing one fold: caught only by
		// ux_handles_name_fold. Every one skeletons to "contested".
		{"look-alike names", func(i int) string {
			return []string{"contested", "c0ntested", "contest-ed", "c0ntest-ed"}[i%4]
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s := newStore(t)

			for i := range racers {
				mustCreateOwner(t, s, fmt.Sprintf("owner-%d", i))
			}

			var (
				start sync.WaitGroup
				done  sync.WaitGroup
				mu    sync.Mutex
				won   int
			)
			start.Add(1)
			for i := range racers {
				done.Add(1)
				go func() {
					defer done.Done()
					start.Wait()

					err := s.Repos().Handles.Register(ctx, newHandle(
						fmt.Sprintf("h-%d", i),
						fmt.Sprintf("owner-%d", i),
						tc.nameFor(i),
					))
					switch {
					case err == nil:
						mu.Lock()
						won++
						mu.Unlock()
					case errors.Is(err, domain.ErrConflict):
						// The expected loss.
					default:
						t.Errorf("Register: unexpected error %v", err)
					}
				}()
			}
			start.Done()
			done.Wait()

			if won != 1 {
				t.Fatalf("%d registrations succeeded, want exactly 1: the name "+
					"is claimable by more than one owner", won)
			}
		})
	}
}
