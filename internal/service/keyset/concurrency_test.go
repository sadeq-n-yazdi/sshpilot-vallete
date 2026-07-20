package keyset_test

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/service/keyset"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/storage/sqlite"
)

// TestCapHoldsUnderConcurrentCreates is the test the cap's transaction exists
// to satisfy.
//
// A check-then-insert is raceable by construction: several goroutines read a
// count of cap-1 before any of them inserts, every one concludes it is under
// the limit, and the owner lands above the cap with no signal that anything
// went wrong. Enforcing the pair inside one Store.WithTx is what removes that
// interleaving — SQLite takes a BEGIN IMMEDIATE write lock, so the read and the
// insert are serialized against every other writer.
//
// Two details make this a real test rather than a hopeful one.
//
// It runs on a FILE-backed store. The in-memory store pins the pool to one
// connection to keep its data alive, which serializes every statement and would
// let a raceable implementation pass for lack of any concurrency at all.
//
// It releases every goroutine from a barrier, so the creates actually overlap
// rather than queueing behind each other's setup.
func TestCapHoldsUnderConcurrentCreates(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	const (
		cap     = 5
		racers  = 24
		timeout = 30 * time.Second
	)

	db, err := sqlite.Open(sqlite.Options{Path: filepath.Join(t.TempDir(), "keyset.db")})
	if err != nil {
		t.Fatalf("sqlite.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	migrateUp(t, db)

	store := sqlite.NewStore(db)
	if err := store.Repos().Owners.Create(ctx, &domain.Owner{
		ID: ownerA, Status: domain.OwnerStatusActive, CreatedAt: fixedNow, UpdatedAt: fixedNow,
	}); err != nil {
		t.Fatalf("Owners.Create: %v", err)
	}

	svc, err := keyset.New(store, mustGuard(t), &recordingAuditor{},
		keyset.WithClock(func() time.Time { return fixedNow }),
		keyset.WithMaxSets(cap))
	if err != nil {
		t.Fatalf("keyset.New: %v", err)
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var (
		start   = make(chan struct{})
		wg      sync.WaitGroup
		mu      sync.Mutex
		created int
	)
	for i := range racers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			// Each goroutine claims a distinct name, so nothing here is refused
			// for being a duplicate; the only thing that can refuse a create is
			// the cap itself.
			_, err := svc.Create(ctx, ownerA, fmt.Sprintf("set-%02d", i), "")
			switch {
			case err == nil:
				mu.Lock()
				created++
				mu.Unlock()
			case errors.Is(err, keyset.ErrLimitExceeded):
				// The expected refusal.
			default:
				t.Errorf("Create: unexpected error %v", err)
			}
		}()
	}
	close(start)
	wg.Wait()

	if created != cap {
		t.Errorf("creates that succeeded = %d, want exactly %d", created, cap)
	}
	// The stored count is the assertion that matters: even if the tally above
	// were miscounted, the database must never hold more than the cap.
	n, err := store.Repos().KeySets.CountByOwner(context.Background(), ownerA)
	if err != nil {
		t.Fatalf("CountByOwner: %v", err)
	}
	if n > cap {
		t.Errorf("stored key sets = %d, which is past the cap of %d", n, cap)
	}
}
