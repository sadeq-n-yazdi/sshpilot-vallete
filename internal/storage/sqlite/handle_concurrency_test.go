package sqlite

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
)

// TestHandleUniquenessHoldsUnderConcurrentRegisters is why handle uniqueness
// lives in the database rather than in a service-layer pre-check.
//
// A "does this name exist yet?" SELECT followed by an INSERT is raceable by
// construction: every goroutine reads "unclaimed", every one concludes it may
// proceed, and two owners end up holding the same public name. Because a handle
// is the first path segment of GET /{handle}/{set}, that is not a cosmetic
// duplicate — it is two parties able to serve keys for one address, which is the
// account-takeover shape this whole task exists to prevent. A UNIQUE index is
// enforced by the engine at insert time, so no interleaving can produce two
// winners.
//
// This runs on a FILE-BACKED store deliberately; newStore's in-memory database
// pins the pool to one connection, which serializes every statement and would
// let a raceable implementation pass for lack of any concurrency at all. Every
// goroutine waits on a barrier so the inserts genuinely overlap.
//
// ENGINE: proven on SQLite. The Postgres adapter carries the same DDL (the
// migration emits one index definition used by both engines), but this test
// exercises SQLite only; see the pull request for that caveat.
func TestHandleUniquenessHoldsUnderConcurrentRegisters(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	const racers = 24

	for _, tc := range []struct {
		name string
		// nameFor gives each racer the handle name it will attempt.
		nameFor func(i int) string
	}{
		// Same exact name: caught by ux_handles_name.
		{"identical names", func(int) string { return "contested" }},
		// Distinct valid slugs that share one fold: caught only by
		// ux_handles_name_fold. Every one of these skeletons to "contested".
		{"look-alike names", func(i int) string {
			return []string{"contested", "c0ntested", "contest-ed", "c0ntest-ed"}[i%4]
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s := newFileStore(t)

			// One owner per racer: the per-owner active-claim index must not be
			// what refuses these, or the test would pass without the name
			// indexes doing anything.
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

					h := newHandle(
						fmt.Sprintf("h-%d", i),
						fmt.Sprintf("owner-%d", i),
						tc.nameFor(i),
					)
					err := s.Repos().Handles.Register(ctx, h)
					switch {
					case err == nil:
						mu.Lock()
						won++
						mu.Unlock()
					case errors.Is(err, domain.ErrConflict):
						// The expected loss.
					default:
						// SQLITE_BUSY and friends are neither a win nor a
						// correctness failure; they simply did not insert.
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
