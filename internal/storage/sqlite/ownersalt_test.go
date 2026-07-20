package sqlite

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

// TestEnsureOwnerSaltAdoptsRaceWinner drives the conflict-retry path directly.
// It simulates a concurrent caller that committed between this caller's
// existence check and its insert: the check finds nothing, the insert conflicts,
// and the salt already stored must be adopted rather than the losing caller
// keeping its own. If the loser kept its salt, the winner's tombstones would be
// left with no key able to verify them.
func TestEnsureOwnerSaltAdoptsRaceWinner(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	winner := &raceExecer{execer: s.db, ownerID: "owner-hot", t: t}
	got, err := ensureOwnerSalt(ctx, winner, "owner-hot")
	if err != nil {
		t.Fatalf("ensureOwnerSalt: %v", err)
	}
	if !winner.conflicted {
		t.Fatal("the insert never conflicted: the retry path was not exercised")
	}
	if !bytes.Equal(got, winner.stored) {
		t.Errorf("adopted salt = %x, want the race winner's %x", got, winner.stored)
	}
}

// raceExecer inserts a competing salt row immediately before forwarding the
// caller's INSERT, so that INSERT hits a primary-key conflict.
type raceExecer struct {
	execer
	ownerID    string
	t          *testing.T
	stored     []byte
	conflicted bool
	raced      bool
}

func (e *raceExecer) ExecContext(ctx context.Context, q string, args ...any) (sql.Result, error) {
	if !e.raced && strings.HasPrefix(q, "INSERT INTO owner_erasure_salts") {
		e.raced = true
		e.stored = newSalt()
		const ins = `INSERT INTO owner_erasure_salts (owner_id, salt, created_at) VALUES (?, ?, ?)`
		if _, err := e.execer.ExecContext(ctx, ins, e.ownerID, e.stored, encTime(testClock)); err != nil {
			e.t.Fatalf("seed racing row: %v", err)
		}
	}
	res, err := e.execer.ExecContext(ctx, q, args...)
	if err != nil && errors.Is(mapError(err), domain.ErrConflict) {
		e.conflicted = true
	}
	return res, err
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
