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

// Rounds and racers for the transition races.
//
// One round is not enough. Measured against a read-then-write mutant of the
// same transition, a single round detects the defect only some of the time, so
// a one-round test would be a flaky guard on exactly the transitions that most
// need a reliable one. Independent rounds, each with a fresh pairing and its
// own barrier, turn that into a near-certain catch.
const (
	pairingRaceRounds = 24
	pairingRaceRacers = 8
)

// newPairingFileStore opens a FILE-BACKED migrated store.
//
// The concurrency tests cannot use newStore: an in-memory database pins the
// pool to MaxOpenConns(1) to keep the single connection that owns the data
// alive, which serializes every statement. Under that pool a read-then-write
// transition would pass a race test by accident, because no two goroutines
// could ever be inside the transition at once. A file-backed handle gets the
// real 8-connection pool and therefore real contention.
//
// TODO: identical to newFileStore in the refresh-credential concurrency test,
// which is developed on a sibling branch. Fold onto one helper once it merges.
func newPairingFileStore(t *testing.T) *Store {
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

// raceOutcome tallies the results of one round of racing goroutines.
type raceOutcome struct {
	mu        sync.Mutex
	ok        int
	conflict  int
	notFound  int
	otherErrs []error
}

func (o *raceOutcome) record(err error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	switch {
	case err == nil:
		o.ok++
	case errors.Is(err, domain.ErrConflict):
		o.conflict++
	case errors.Is(err, domain.ErrNotFound):
		o.notFound++
	default:
		o.otherErrs = append(o.otherErrs, err)
	}
}

// runRace releases racers goroutines from a barrier and tallies their results.
func runRace(racers int, fn func(i int) error) *raceOutcome {
	var (
		out   raceOutcome
		wg    sync.WaitGroup
		start = make(chan struct{})
	)
	for i := range racers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			out.record(fn(i))
		}()
	}
	close(start)
	wg.Wait()
	return &out
}

// TestPairingApproveBindsExactlyOneOwnerUnderConcurrency is the reason Approve
// is a single conditional statement.
//
// Each round releases racers goroutines that each try to approve ONE pending
// pairing for a DIFFERENT owner. Exactly one must win; every other must be
// told ErrConflict and must not have rewritten owner_id. If Approve read the
// status and then wrote, several goroutines would observe the same pending row
// and the last writer would decide which account the enrolling device ends up
// bound to — a silent account takeover, since the device sees an ordinary
// success either way.
func TestPairingApproveBindsExactlyOneOwnerUnderConcurrency(t *testing.T) {
	t.Parallel()
	s := newPairingFileStore(t)
	ctx := context.Background()
	repo := s.Repos().DevicePairings

	for i := range pairingRaceRacers {
		mustCreateOwner(t, s, fmt.Sprintf("o-%d", i))
	}

	for round := range pairingRaceRounds {
		id := domain.PairingID(fmt.Sprintf("p-%d", round))
		mustCreatePairing(t, s, newPairing(string(id)))

		out := runRace(pairingRaceRacers, func(i int) error {
			return repo.Approve(ctx, id, domain.OwnerID(fmt.Sprintf("o-%d", i)), testClock)
		})

		if len(out.otherErrs) > 0 {
			t.Fatalf("round %d: unexpected errors: %v", round, out.otherErrs)
		}
		if out.ok != 1 {
			t.Fatalf("round %d: %d approvals succeeded, want exactly 1 (owner binding is not atomic)", round, out.ok)
		}
		if out.conflict != pairingRaceRacers-1 {
			t.Fatalf("round %d: %d conflicts, want %d", round, out.conflict, pairingRaceRacers-1)
		}

		// Whichever owner won, the row must name exactly one and be approved.
		got, err := repo.GetByID(ctx, id)
		if err != nil {
			t.Fatalf("round %d: GetByID: %v", round, err)
		}
		if got.Status != domain.PairingStatusApproved {
			t.Fatalf("round %d: status = %q, want approved", round, got.Status)
		}
		if got.OwnerID == "" {
			t.Fatalf("round %d: pairing approved but owner is empty", round)
		}
	}
}

// TestPairingMarkRedeemedIsSingleUseUnderConcurrency proves a device code is
// spent exactly once.
//
// Each round releases racers goroutines that all redeem ONE approved pairing,
// each presenting a different lineage id. Exactly one must win. Under a
// read-then-write implementation several would observe the same approved row
// and the pairing would install multiple independent credential lineages, only
// one of which the owner would ever see in a listing.
func TestPairingMarkRedeemedIsSingleUseUnderConcurrency(t *testing.T) {
	t.Parallel()
	s := newPairingFileStore(t)
	ctx := context.Background()
	repo := s.Repos().DevicePairings
	mustCreateOwner(t, s, "o-1")

	for round := range pairingRaceRounds {
		id := domain.PairingID(fmt.Sprintf("p-%d", round))
		mustCreatePairing(t, s, newPairing(string(id)))
		if err := repo.Approve(ctx, id, "o-1", testClock); err != nil {
			t.Fatalf("round %d: approve: %v", round, err)
		}

		out := runRace(pairingRaceRacers, func(i int) error {
			return repo.MarkRedeemed(ctx, "o-1", id, domain.LineageID(fmt.Sprintf("lin-%d", i)), testClock)
		})

		if len(out.otherErrs) > 0 {
			t.Fatalf("round %d: unexpected errors: %v", round, out.otherErrs)
		}
		if out.ok != 1 {
			t.Fatalf("round %d: %d redemptions succeeded, want exactly 1 (device code was spent %d times)", round, out.ok, out.ok)
		}
		if out.conflict != pairingRaceRacers-1 {
			t.Fatalf("round %d: %d conflicts, want %d", round, out.conflict, pairingRaceRacers-1)
		}

		// Exactly one lineage must be recorded, and the row must be terminal.
		got, err := repo.Get(ctx, "o-1", id)
		if err != nil {
			t.Fatalf("round %d: Get: %v", round, err)
		}
		if got.Status != domain.PairingStatusRedeemed {
			t.Fatalf("round %d: status = %q, want redeemed", round, got.Status)
		}
		if got.LineageID == "" {
			t.Fatalf("round %d: redeemed pairing has no lineage", round)
		}
	}
}

// TestPairingRevokeIsSingleTransitionUnderConcurrency proves the terminal
// guard holds under contention: concurrent revocations of one approved pairing
// must produce exactly one transition, so the recorded revoked_at is the moment
// the pairing actually ended rather than whichever writer happened to run last.
func TestPairingRevokeIsSingleTransitionUnderConcurrency(t *testing.T) {
	t.Parallel()
	s := newPairingFileStore(t)
	ctx := context.Background()
	repo := s.Repos().DevicePairings
	mustCreateOwner(t, s, "o-1")

	for round := range pairingRaceRounds {
		id := domain.PairingID(fmt.Sprintf("p-%d", round))
		mustCreatePairing(t, s, newPairing(string(id)))
		if err := repo.Approve(ctx, id, "o-1", testClock); err != nil {
			t.Fatalf("round %d: approve: %v", round, err)
		}

		out := runRace(pairingRaceRacers, func(int) error {
			return repo.Revoke(ctx, "o-1", id, testClock)
		})

		if len(out.otherErrs) > 0 {
			t.Fatalf("round %d: unexpected errors: %v", round, out.otherErrs)
		}
		if out.ok != 1 {
			t.Fatalf("round %d: %d revocations succeeded, want exactly 1", round, out.ok)
		}
		if out.conflict != pairingRaceRacers-1 {
			t.Fatalf("round %d: %d conflicts, want %d", round, out.conflict, pairingRaceRacers-1)
		}
	}
}
