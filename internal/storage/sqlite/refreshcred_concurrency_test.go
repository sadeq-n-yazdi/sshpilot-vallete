package sqlite

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/migrate"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/schema"
)

// newFileStore opens a FILE-BACKED migrated store.
//
// The concurrency tests cannot use newStore: an in-memory database pins the
// pool to MaxOpenConns(1) to keep the single connection that owns the data
// alive, which serializes every statement. Under that pool a read-then-write
// MarkRotated would pass a race test by accident, because no two goroutines
// could ever be inside the transition at once. A file-backed handle gets the
// real 8-connection pool and therefore real contention.
func newFileStore(t *testing.T) *Store {
	t.Helper()

	db, err := Open(Options{Path: filepath.Join(t.TempDir(), "test.db")})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	reg, err := schema.Registry()
	if err != nil {
		t.Fatalf("schema.Registry: %v", err)
	}
	runner, err := migrate.NewRunner(NewMigrateDB(db), migrate.EngineSQLite, reg)
	if err != nil {
		t.Fatalf("migrate.NewRunner: %v", err)
	}
	if _, err := runner.Up(context.Background()); err != nil {
		t.Fatalf("migrate Up: %v", err)
	}
	return NewStore(db)
}

// TestRefreshCredMarkRotatedIsSingleUseUnderConcurrency is the test the whole
// design exists to satisfy.
//
// Each round releases racers goroutines from a barrier to rotate ONE active
// credential. Exactly one may succeed; every other must get ErrConflict. A
// read-then-write implementation loses here, because several goroutines read
// 'active' before any of them writes and all of them then report success — the
// token spent several times over with no signal that anything was wrong.
//
// Two details make this a real test rather than a hopeful one:
//
// It runs on a FILE-backed store. The in-memory store pins the pool to one
// connection to keep its data alive, which serializes every statement and would
// let a read-then-write implementation pass for lack of any concurrency at all.
//
// It runs many rounds. A single round is probabilistic: the winner sometimes
// finishes its read and its write before the other goroutines have read, so a
// broken implementation produces the correct-looking single success perhaps a
// third of the time. Measured against the read-then-write mutant, one round
// caught it in roughly 6 runs out of 10 — a flaky guard on the codebase's most
// security-critical transition. Independent rounds make the escape probability
// vanish (about a third per round, so ~1e-11 across 24) while every round still
// exercises nothing but the production path.
func TestRefreshCredMarkRotatedIsSingleUseUnderConcurrency(t *testing.T) {
	t.Parallel()
	s := newFileStore(t)
	ctx := context.Background()
	mustCreateOwner(t, s, "owner-a")

	const (
		rounds = 24
		racers = 8
	)

	for round := 0; round < rounds; round++ {
		id := domain.RefreshCredentialID(fmt.Sprintf("rc-%02d", round))
		if err := s.Repos().RefreshCredentials.Create(ctx, newCred(string(id), "owner-a", "lin-1")); err != nil {
			t.Fatalf("Create %q: %v", id, err)
		}

		var (
			start sync.WaitGroup
			done  sync.WaitGroup
			mu    sync.Mutex
		)
		start.Add(1)
		errs := make([]error, 0, racers)

		for i := 0; i < racers; i++ {
			done.Add(1)
			go func() {
				defer done.Done()
				start.Wait()
				err := s.Repos().RefreshCredentials.MarkRotated(ctx, "owner-a", id, testClock)
				mu.Lock()
				errs = append(errs, err)
				mu.Unlock()
			}()
		}
		start.Done()
		done.Wait()

		var succeeded, conflicted int
		for _, err := range errs {
			switch {
			case err == nil:
				succeeded++
			case errors.Is(err, domain.ErrConflict):
				conflicted++
			default:
				t.Fatalf("round %d: unexpected error from racing MarkRotated: %v", round, err)
			}
		}
		if succeeded != 1 {
			t.Fatalf("round %d: %d of %d rotations succeeded, want exactly 1 (the credential was spent more than once)",
				round, succeeded, racers)
		}
		if conflicted != racers-1 {
			t.Fatalf("round %d: %d conflicts, want %d", round, conflicted, racers-1)
		}
	}
}
