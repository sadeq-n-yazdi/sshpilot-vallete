package postgres

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/audit"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/nameguard"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/service/keyset"
)

// The per-owner key set cap had been proven to hold under concurrency only on
// SQLite (see TestCapHoldsUnderConcurrentCreates in internal/service/keyset).
// That proof does not carry: SQLite opens transactions as BEGIN IMMEDIATE and
// serializes writers database-wide, so the cap's check-then-insert cannot
// interleave there no matter how it is written. PostgreSQL runs at READ
// COMMITTED, where SELECT COUNT(*) takes no lock, and the same code is racy.
//
// These tests drive the real keyset service against the real PostgreSQL
// adapter, because the invariant is a property of the two together: the service
// decides to count before inserting, and only the adapter can make that pair
// atomic. A fake repository would serialize the race away and report success.
//
// They skip when VALLET_TEST_POSTGRES_DSN is unset, like every test in this
// package. A green run on a machine without a database says nothing about the
// cap; verify the skip count, not the ok line.

// capTestClock is the fixed clock these tests stamp rows with.
var capTestClock = time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)

// silentAuditor accepts every event. The cap's correctness does not depend on
// what is audited, and a recording stand-in would only add a mutex to contend
// on in the concurrent test.
type silentAuditor struct{}

func (silentAuditor) Emit(context.Context, audit.Event) error { return nil }

// newCapService builds a keyset service on the given store with the supplied
// cap, and creates the owner rows it will be asked to create sets for.
// key_sets.owner_id is NOT NULL REFERENCES owners(id), so the owners must exist
// before any create -- and, for the concurrency test, so the row that
// LockOwnerForCreate locks must exist too.
func newCapService(t *testing.T, store *Store, maxSets int, owners ...domain.OwnerID) *keyset.Service {
	t.Helper()
	ctx := context.Background()
	for _, id := range owners {
		if err := store.Repos().Owners.Create(ctx, &domain.Owner{
			ID: id, Status: domain.OwnerStatusActive,
			CreatedAt: capTestClock, UpdatedAt: capTestClock,
		}); err != nil {
			t.Fatalf("Owners.Create(%s): %v", id, err)
		}
	}
	guard, err := nameguard.Default()
	if err != nil {
		t.Fatalf("nameguard.Default: %v", err)
	}
	svc, err := keyset.New(store, guard, silentAuditor{},
		keyset.WithClock(func() time.Time { return capTestClock }),
		keyset.WithMaxSets(maxSets))
	if err != nil {
		t.Fatalf("keyset.New: %v", err)
	}
	return svc
}

// countSets returns how many key set rows the owner holds.
func countSets(t *testing.T, store *Store, owner domain.OwnerID) int {
	t.Helper()
	n, err := store.Repos().KeySets.CountByOwner(context.Background(), owner)
	if err != nil {
		t.Fatalf("CountByOwner(%s): %v", owner, err)
	}
	return n
}

// TestKeySetCapHoldsUnderConcurrentCreatesPostgres is the test the per-owner
// lock exists to satisfy.
//
// Every racer asks for a distinct name, so a duplicate name can never be what
// refuses a create; the cap is the only thing that may. All of them are
// released from one barrier so the creates genuinely overlap rather than
// queueing behind each other's setup, and there are far more racers than the
// cap allows, so a lost update shows up as a count above the cap rather than as
// a near miss.
//
// The assertion is on the stored row count and is an equality, not a bound. A
// test that only checked that some creates failed would pass against an
// implementation that refused the wrong ones, and a test that only checked
// "not more than the cap" would pass against one that refused every create.
func TestKeySetCapHoldsUnderConcurrentCreatesPostgres(t *testing.T) {
	t.Parallel()
	store := newStore(t)

	const (
		maxSets = 5
		racers  = 24
		timeout = 60 * time.Second
	)
	const owner domain.OwnerID = "cap-owner-a"
	svc := newCapService(t, store, maxSets, owner)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
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
			_, err := svc.Create(ctx, owner, fmt.Sprintf("set-%02d", i), "")
			switch {
			case err == nil:
				mu.Lock()
				created++
				mu.Unlock()
			case errors.Is(err, keyset.ErrLimitExceeded):
				// The expected refusal once the owner is at the cap.
			default:
				t.Errorf("Create: unexpected error %v", err)
			}
		}()
	}
	close(start)
	wg.Wait()

	if created != maxSets {
		t.Errorf("creates that succeeded = %d, want exactly %d", created, maxSets)
	}
	// The stored count is the assertion that matters: even if the tally above
	// were miscounted, the database must hold exactly the cap.
	if n := countSets(t, store, owner); n != maxSets {
		t.Errorf("stored key sets = %d, want exactly %d", n, maxSets)
	}
}

// TestKeySetCapIsPerOwnerUnderConcurrencyPostgres races two owners against each
// other at the same cap.
//
// Owner scoping and the cap are separable failures, and this is the one that
// the single-owner test above cannot see: a count that dropped its owner_id
// predicate would still hold a global total at the cap and still look correct
// there. Here each owner must reach the cap independently, so a shared count
// lands them at half the cap apiece and fails.
func TestKeySetCapIsPerOwnerUnderConcurrencyPostgres(t *testing.T) {
	t.Parallel()
	store := newStore(t)

	const (
		maxSets = 4
		perUser = 12
		timeout = 60 * time.Second
	)
	const (
		ownerA domain.OwnerID = "cap-owner-a"
		ownerB domain.OwnerID = "cap-owner-b"
	)
	svc := newCapService(t, store, maxSets, ownerA, ownerB)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var (
		start = make(chan struct{})
		wg    sync.WaitGroup
	)
	for _, owner := range []domain.OwnerID{ownerA, ownerB} {
		for i := range perUser {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				// Both owners use the SAME set names. The unique index is on
				// (owner_id, name), so this is legal and makes the test fail if
				// that index ever loses its owner column.
				_, err := svc.Create(ctx, owner, fmt.Sprintf("set-%02d", i), "")
				if err != nil && !errors.Is(err, keyset.ErrLimitExceeded) {
					t.Errorf("Create(%s): unexpected error %v", owner, err)
				}
			}()
		}
	}
	close(start)
	wg.Wait()

	for _, owner := range []domain.OwnerID{ownerA, ownerB} {
		if n := countSets(t, store, owner); n != maxSets {
			t.Errorf("owner %s holds %d key sets, want exactly %d", owner, n, maxSets)
		}
	}
}

// TestKeySetCapFreedByDeletePostgres pins the cap as a live count rather than a
// lifetime quota.
//
// This is the property an ordinal-based enforcement scheme would have quietly
// broken: handing every set a monotonically increasing per-owner number and
// bounding it would cap creates-ever instead of sets-held, so an owner who
// deleted a set could never replace it. Deleting one set must let exactly one
// more create through, at the cap and not above it.
func TestKeySetCapFreedByDeletePostgres(t *testing.T) {
	t.Parallel()
	store := newStore(t)

	const maxSets = 3
	const owner domain.OwnerID = "cap-owner-a"
	svc := newCapService(t, store, maxSets, owner)
	ctx := context.Background()

	var first domain.KeySetID
	for i := range maxSets {
		set, err := svc.Create(ctx, owner, fmt.Sprintf("set-%02d", i), "")
		if err != nil {
			t.Fatalf("Create(set-%02d): %v", i, err)
		}
		if i == 0 {
			first = set.ID
		}
	}
	if _, err := svc.Create(ctx, owner, "one-too-many", ""); !errors.Is(err, keyset.ErrLimitExceeded) {
		t.Fatalf("Create past the cap: got %v, want ErrLimitExceeded", err)
	}

	// Delete removes the row outright -- unlike a rename, which leaves a
	// quarantined tombstone that keeps occupying the owner's namespace -- so
	// the count drops and a slot opens.
	if err := svc.Delete(ctx, owner, first, false, ""); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := svc.Create(ctx, owner, "replacement", ""); err != nil {
		t.Errorf("Create after freeing a slot: %v", err)
	}
	// One slot was freed and one was taken, so the owner is back at the cap and
	// the refusal is in force again.
	if n := countSets(t, store, owner); n != maxSets {
		t.Errorf("stored key sets = %d, want exactly %d", n, maxSets)
	}
	if _, err := svc.Create(ctx, owner, "still-too-many", ""); !errors.Is(err, keyset.ErrLimitExceeded) {
		t.Errorf("Create past the refilled cap: got %v, want ErrLimitExceeded", err)
	}
}
