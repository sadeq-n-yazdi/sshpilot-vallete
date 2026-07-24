package postgres

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
)

func newSaltRepo(t *testing.T) (*ownerSaltRepo, *Store) {
	t.Helper()
	s := newStore(t)
	return &ownerSaltRepo{e: s.db}, s
}

func TestOwnerSaltEnsureMintsAndIsStable(t *testing.T) {
	t.Parallel()
	repo, _ := newSaltRepo(t)
	ctx := context.Background()

	first, err := repo.Ensure(ctx, "owner-a")
	if err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if len(first) != saltLen {
		t.Fatalf("salt length = %d, want %d", len(first), saltLen)
	}
	if bytes.Equal(first, make([]byte, saltLen)) {
		t.Fatal("salt is all zero bytes: the entropy source produced nothing")
	}

	// Idempotent: a second Ensure must return the same salt, or tombstones
	// minted at different times for one owner would disagree.
	second, err := repo.Ensure(ctx, "owner-a")
	if err != nil {
		t.Fatalf("second Ensure: %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Error("Ensure minted a different salt on the second call")
	}

	// Distinct owners must get distinct salts, so one owner's tombstones say
	// nothing about another's.
	other, err := repo.Ensure(ctx, "owner-b")
	if err != nil {
		t.Fatalf("Ensure other owner: %v", err)
	}
	if bytes.Equal(first, other) {
		t.Error("two owners share a salt")
	}
}

func TestOwnerSaltGetAndDestroy(t *testing.T) {
	t.Parallel()
	repo, _ := newSaltRepo(t)
	ctx := context.Background()

	minted, err := repo.Ensure(ctx, "owner-a")
	if err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	got, err := repo.Get(ctx, "owner-a")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !bytes.Equal(minted, got) {
		t.Error("Get returned a different salt than Ensure minted")
	}

	if err := repo.Destroy(ctx, "owner-a"); err != nil {
		t.Fatalf("Destroy: %v", err)
	}
	if _, err := repo.Get(ctx, "owner-a"); !errors.Is(err, domain.ErrNotFound) {
		t.Errorf("Get after Destroy = %v, want ErrNotFound", err)
	}
}

// TestOwnerSaltIsScopedToItsOwner pins the owner predicate in the two queries
// that carry one. Reading or destroying under one owner's identifier must never
// reach another's row, and the placeholder binding it is what enforces that: a
// query whose owner_id parameter went missing or bound the wrong argument would
// return or delete a row that does not belong to the caller.
//
// Destroy is the dangerous half. A dropped predicate there is not a read leak,
// it is an unrelated owner's erasure key destroyed — silently, since Destroy
// reports success whether or not it matched anything.
func TestOwnerSaltIsScopedToItsOwner(t *testing.T) {
	t.Parallel()
	repo, _ := newSaltRepo(t)
	ctx := context.Background()

	saltA, err := repo.Ensure(ctx, "owner-a")
	if err != nil {
		t.Fatalf("Ensure owner-a: %v", err)
	}
	saltB, err := repo.Ensure(ctx, "owner-b")
	if err != nil {
		t.Fatalf("Ensure owner-b: %v", err)
	}

	// A read under one owner returns that owner's salt and no other's.
	got, err := repo.Get(ctx, "owner-b")
	if err != nil {
		t.Fatalf("Get owner-b: %v", err)
	}
	if !bytes.Equal(got, saltB) {
		t.Error("Get(owner-b) did not return owner-b's salt")
	}
	if bytes.Equal(got, saltA) {
		t.Error("Get(owner-b) returned owner-a's salt: the owner predicate is not binding")
	}

	// Destroying one owner's salt must leave every other owner's standing.
	if err := repo.Destroy(ctx, "owner-a"); err != nil {
		t.Fatalf("Destroy owner-a: %v", err)
	}
	survived, err := repo.Get(ctx, "owner-b")
	if err != nil {
		t.Fatalf("Get owner-b after destroying owner-a: %v", err)
	}
	if !bytes.Equal(survived, saltB) {
		t.Error("owner-b's salt changed when owner-a's was destroyed")
	}
	if _, err := repo.Get(ctx, "owner-a"); !errors.Is(err, domain.ErrNotFound) {
		t.Errorf("Get(owner-a) after Destroy = %v, want ErrNotFound", err)
	}
}

// TestOwnerSaltDestroyRemovesTheRow proves Destroy is a real DELETE and not a
// soft-delete that flags the row.
//
// The distinction is the entire erasure guarantee and it is invisible through
// the port: a soft-deleted salt makes Get return ErrNotFound just as a deleted
// one does, so every other test in this file would pass either way. The only
// way to tell them apart is to look at the table directly, which is what this
// test does. A surviving row means the key still exists, and every tombstone
// minted under it is still reversible by anyone who can read the database — the
// erasure would be a label rather than a fact.
func TestOwnerSaltDestroyRemovesTheRow(t *testing.T) {
	t.Parallel()
	repo, s := newSaltRepo(t)
	ctx := context.Background()

	if _, err := repo.Ensure(ctx, "owner-a"); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	// Sanity: the row is really there before the destroy, so a zero count
	// afterwards means something happened rather than nothing ever existing.
	countRows := func(t *testing.T) int {
		t.Helper()
		var n int
		if err := s.db.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM owner_erasure_salts WHERE owner_id = $1`, "owner-a").Scan(&n); err != nil {
			t.Fatalf("count rows: %v", err)
		}
		return n
	}
	if got := countRows(t); got != 1 {
		t.Fatalf("rows before Destroy = %d, want 1", got)
	}

	if err := repo.Destroy(ctx, "owner-a"); err != nil {
		t.Fatalf("Destroy: %v", err)
	}

	if got := countRows(t); got != 0 {
		t.Errorf("rows after Destroy = %d, want 0: the salt row survives, so it was flagged "+
			"rather than deleted and every tombstone minted under it is still reversible", got)
	}

	// The salt bytes must not be recoverable from the table under any column.
	var any int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM owner_erasure_salts`).Scan(&any); err != nil {
		t.Fatalf("count all rows: %v", err)
	}
	if any != 0 {
		t.Errorf("owner_erasure_salts holds %d rows after the only salt was destroyed", any)
	}
}

// TestOwnerSaltDestroyedAndAbsentAreIndistinguishable pins the existence-leak
// property: an owner whose salt was destroyed must look exactly like an owner
// that never had one. Reporting them differently would confirm the erased owner
// once existed.
func TestOwnerSaltDestroyedAndAbsentAreIndistinguishable(t *testing.T) {
	t.Parallel()
	repo, _ := newSaltRepo(t)
	ctx := context.Background()

	if _, err := repo.Ensure(ctx, "owner-erased"); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if err := repo.Destroy(ctx, "owner-erased"); err != nil {
		t.Fatalf("Destroy: %v", err)
	}

	_, erasedErr := repo.Get(ctx, "owner-erased")
	_, neverErr := repo.Get(ctx, "owner-never-existed")
	if erasedErr.Error() != neverErr.Error() {
		t.Errorf("destroyed = %v but absent = %v: the two are distinguishable", erasedErr, neverErr)
	}

	// A third owner that exists but is not the one asked about must also be
	// indistinguishable from absent: the answer may not reveal that some other
	// owner holds a salt.
	if _, err := repo.Ensure(ctx, "owner-other"); err != nil {
		t.Fatalf("Ensure other: %v", err)
	}
	_, stillNeverErr := repo.Get(ctx, "owner-never-existed")
	if stillNeverErr.Error() != erasedErr.Error() {
		t.Errorf("absent = %v differs from destroyed = %v once another owner exists",
			stillNeverErr, erasedErr)
	}
}

// TestOwnerSaltDestroyIsIdempotent: erasure must converge on retry, so
// destroying a salt that is already gone is success, not ErrNotFound.
func TestOwnerSaltDestroyIsIdempotent(t *testing.T) {
	t.Parallel()
	repo, _ := newSaltRepo(t)
	ctx := context.Background()

	if err := repo.Destroy(ctx, "never-existed"); err != nil {
		t.Errorf("Destroy of absent salt = %v, want nil", err)
	}
	if _, err := repo.Ensure(ctx, "owner-a"); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	for i := range 3 {
		if err := repo.Destroy(ctx, "owner-a"); err != nil {
			t.Errorf("Destroy #%d = %v, want nil", i, err)
		}
	}
}

// TestOwnerSaltEnsureAfterDestroyMintsFresh documents the intended consequence
// of erasure: a new salt is a different key, so tombstones minted after an
// erasure cannot be linked back to those minted before it.
func TestOwnerSaltEnsureAfterDestroyMintsFresh(t *testing.T) {
	t.Parallel()
	repo, _ := newSaltRepo(t)
	ctx := context.Background()

	before, err := repo.Ensure(ctx, "owner-a")
	if err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if err := repo.Destroy(ctx, "owner-a"); err != nil {
		t.Fatalf("Destroy: %v", err)
	}
	after, err := repo.Ensure(ctx, "owner-a")
	if err != nil {
		t.Fatalf("Ensure after Destroy: %v", err)
	}
	if bytes.Equal(before, after) {
		t.Error("the destroyed salt came back: erasure is reversible")
	}
}

// TestOwnerSaltEnsureIsRaceSafe runs concurrent Ensure calls for one owner. All
// must agree on a single salt: if two callers could each keep their own, one
// set of tombstones would be orphaned with no key able to verify it.
//
// On this engine the race is real rather than notional. SQLite serializes every
// writer behind one BEGIN IMMEDIATE lock, so its version of this test rarely
// reaches the conflict path; Postgres runs the transactions concurrently, so
// the losers genuinely take SQLSTATE 23505 and must adopt the winner's salt.
func TestOwnerSaltEnsureIsRaceSafe(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	const goroutines = 8
	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		results [][]byte
	)
	for range goroutines {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Each goroutine uses its own repo over the shared pool, as
			// separate request handlers would.
			repo := &ownerSaltRepo{e: s.db}
			salt, err := repo.Ensure(ctx, "owner-hot")
			if err != nil {
				t.Errorf("Ensure: %v", err)
				return
			}
			mu.Lock()
			results = append(results, salt)
			mu.Unlock()
		}()
	}
	wg.Wait()

	if len(results) == 0 {
		t.Fatal("no successful Ensure calls")
	}
	for i, got := range results {
		if !bytes.Equal(got, results[0]) {
			t.Fatalf("goroutine %d got a different salt: concurrent Ensure did not converge", i)
		}
	}
}

func TestOwnerSaltEnsureRejectsEmptyOwner(t *testing.T) {
	t.Parallel()
	repo, _ := newSaltRepo(t)

	if _, err := repo.Ensure(context.Background(), ""); !errors.Is(err, domain.ErrInvalidInput) {
		t.Errorf("Ensure(\"\") = %v, want ErrInvalidInput", err)
	}
}

func TestOwnerSaltSurfacesStorageErrors(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("ensure", func(t *testing.T) {
		t.Parallel()
		repo := &ownerSaltRepo{e: closedStore(t).db}
		if _, err := repo.Ensure(ctx, "owner-a"); err == nil {
			t.Error("Ensure on a closed db = nil error, want error")
		}
	})
	t.Run("get", func(t *testing.T) {
		t.Parallel()
		repo := &ownerSaltRepo{e: closedStore(t).db}
		if _, err := repo.Get(ctx, "owner-a"); err == nil {
			t.Error("Get on a closed db = nil error, want error")
		}
	})
	t.Run("destroy", func(t *testing.T) {
		t.Parallel()
		repo := &ownerSaltRepo{e: closedStore(t).db}
		if err := repo.Destroy(ctx, "owner-a"); err == nil {
			t.Error("Destroy on a closed db = nil error, want error")
		}
	})
	t.Run("insert", func(t *testing.T) {
		t.Parallel()
		// The transaction begins, then the INSERT fails because the table is
		// gone: the error must propagate rather than yield a zero salt.
		s := newStore(t)
		if _, err := s.db.ExecContext(ctx, `DROP TABLE owner_erasure_salts`); err != nil {
			t.Fatalf("drop table: %v", err)
		}
		repo := &ownerSaltRepo{e: s.db}
		if _, err := repo.Ensure(ctx, "owner-a"); err == nil {
			t.Error("Ensure against a missing table = nil error, want error")
		}
	})
}

// TestStoreExposesOwnerSalts pins the wiring: a maintenance job takes the salt
// store from Repos, and it must actually be populated.
func TestStoreExposesOwnerSalts(t *testing.T) {
	t.Parallel()
	s := newStore(t)

	if s.Repos().OwnerSalts == nil {
		t.Error("Repos().OwnerSalts is nil")
	}
	if s.Repos().Audit == nil {
		t.Error("Repos().Audit is nil")
	}
}

// TestEnsureOwnerSaltAdoptsRaceWinner drives the conflict path directly. It
// simulates a concurrent caller that committed between this caller's existence
// check and its insert: the check finds nothing, the insert then hits an
// existing row, and the salt already stored must be adopted rather than the
// losing caller keeping its own. If the loser kept its salt, the winner's
// tombstones would be left with no key able to verify them.
//
// The adoption is driven by ON CONFLICT DO NOTHING reporting zero rows
// affected, not by a raised error. Asserting that the write really did collide
// (raced) and that the returned salt is the winner's — rather than merely that
// the call succeeded — is what distinguishes adoption from a silent overwrite:
// a DO UPDATE would also return without error, but would return this caller's
// salt and orphan the winner's tombstones.
func TestEnsureOwnerSaltAdoptsRaceWinner(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	winner := &raceExecer{execer: s.db, seeder: s.db, ownerID: "owner-hot", t: t}
	got, err := ensureOwnerSalt(ctx, winner, "owner-hot")
	if err != nil {
		t.Fatalf("ensureOwnerSalt: %v", err)
	}
	if !winner.raced {
		t.Fatal("the insert never collided: the adoption path was not exercised")
	}
	if !bytes.Equal(got, winner.stored) {
		t.Errorf("adopted salt = %x, want the race winner's %x", got, winner.stored)
	}

	// The stored row must still be the winner's: the loser's INSERT must not
	// have overwritten it.
	stored, err := getOwnerSalt(ctx, s.db, "owner-hot")
	if err != nil {
		t.Fatalf("read stored salt: %v", err)
	}
	if !bytes.Equal(stored, winner.stored) {
		t.Errorf("stored salt = %x, want the winner's %x: the losing caller overwrote it",
			stored, winner.stored)
	}
}

// raceExecer inserts a competing salt row immediately before forwarding the
// caller's INSERT, so that INSERT collides with an already-present row.
//
// The competing row is written through seeder, which may be a different handle
// from the one under test. That separation is what lets a test place the
// winning row in a SEPARATE, already-committed transaction — the arrangement
// that a real concurrent caller produces.
type raceExecer struct {
	execer
	seeder  execer
	ownerID string
	t       *testing.T
	stored  []byte
	raced   bool
}

func (e *raceExecer) ExecContext(ctx context.Context, q string, args ...any) (sql.Result, error) {
	if !e.raced && strings.HasPrefix(q, "INSERT INTO owner_erasure_salts") {
		e.raced = true
		e.stored = newSalt()
		const ins = `INSERT INTO owner_erasure_salts (owner_id, salt, created_at) VALUES ($1, $2, $3)`
		if _, err := e.seeder.ExecContext(ctx, ins, e.ownerID, e.stored, encTime(testClock)); err != nil {
			e.t.Fatalf("seed racing row: %v", err)
		}
	}
	return e.execer.ExecContext(ctx, q, args...)
}

// TestEnsureOwnerSaltAdoptsRaceWinnerInsideTransaction is the deterministic
// regression test for the failure mode that makes this adapter differ from the
// SQLite one, and it is the reason the difference exists.
//
// Ensure runs its body inside a transaction. PostgreSQL aborts an entire
// transaction as soon as any statement in it raises an error: every later
// command, including the re-read that adopts the race winner's salt, then fails
// with SQLSTATE 25P02 until the transaction is rolled back. So a plain INSERT
// that lets the collision raise a uniqueness violation — the SQLite adapter's
// shape, transliterated — does not merely fail to adopt the winner's salt here.
// It fails outright, under precisely the concurrency the retry exists to
// survive, and an owner's erasure key cannot be established at all.
//
// The concurrent-goroutine test above can provoke this, but only when the
// scheduler happens to interleave two callers inside the window; it passed
// roughly half the time against the broken version. This test forces the
// interleaving instead of hoping for it: the winning row is committed on a
// separate connection while the transaction under test is open, so the
// collision is certain on every run.
func TestEnsureOwnerSaltAdoptsRaceWinnerInsideTransaction(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback() }()

	// execer is the open transaction; seeder is the pool, so the competing row
	// commits independently while this transaction is still in flight.
	race := &raceExecer{execer: tx, seeder: s.db, ownerID: "owner-hot", t: t}
	got, err := ensureOwnerSalt(ctx, race, "owner-hot")
	if err != nil {
		t.Fatalf("ensureOwnerSalt inside a transaction: %v "+
			"(a statement error aborted the transaction and the adopting re-read could not run)", err)
	}
	if !race.raced {
		t.Fatal("the insert never collided: the adoption path was not exercised")
	}
	if !bytes.Equal(got, race.stored) {
		t.Errorf("adopted salt = %x, want the race winner's %x", got, race.stored)
	}

	// The transaction must still be usable afterwards, which is the property a
	// raised-and-swallowed error would have destroyed.
	if _, err := getOwnerSalt(ctx, tx, "owner-hot"); err != nil {
		t.Errorf("transaction unusable after the collision: %v", err)
	}
}

// failInsertExecer forwards reads to a real database but fails every INSERT
// with a non-conflict error.
type failInsertExecer struct {
	execer
	err error
}

func (e failInsertExecer) ExecContext(ctx context.Context, q string, args ...any) (sql.Result, error) {
	if strings.HasPrefix(q, "INSERT") {
		return nil, e.err
	}
	return e.execer.ExecContext(ctx, q, args...)
}

// TestEnsureOwnerSaltSurfacesInsertError covers the non-conflict insert
// failure: the existence check succeeds and finds nothing, then the insert
// fails for a reason that is not a race. The error must surface rather than
// yielding a salt the caller would go on to mint tombstones with.
func TestEnsureOwnerSaltSurfacesInsertError(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	sentinel := errors.New("disk went away")

	got, err := ensureOwnerSalt(context.Background(),
		failInsertExecer{execer: s.db, err: sentinel}, "owner-a")
	if !errors.Is(err, sentinel) {
		t.Errorf("err = %v, want the insert failure", err)
	}
	if got != nil {
		t.Errorf("salt = %x, want nil on error", got)
	}
}
