package redisstore_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/counter"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/redisstore"
)

// dsnEnv gates the live-server tests. Like the Postgres suite, they skip when it
// is unset so `go test ./...` stays green with no server, and exercise a real
// Redis/Valkey when it is set, e.g.
//
//	VALLET_TEST_REDIS_DSN=redis://localhost:6379/0
const dsnEnv = "VALLET_TEST_REDIS_DSN"

func liveStore(t *testing.T) *redisstore.Store {
	t.Helper()
	dsn := os.Getenv(dsnEnv)
	if dsn == "" {
		t.Skipf("%s not set; skipping live Redis test", dsnEnv)
	}
	s, err := redisstore.New(dsn, "")
	if err != nil {
		t.Fatalf("New(%s): %v", dsnEnv, err)
	}
	t.Cleanup(func() { _ = s.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.Ping(ctx); err != nil {
		t.Fatalf("Ping: %v", err)
	}
	return s
}

// uniqueKey keeps parallel runs and repeated runs from colliding on the shared
// server; every key created here also carries a TTL, so nothing leaks.
func uniqueKey(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf("vallet-test:%s:%d", t.Name(), time.Now().UnixNano())
}

// TestLiveContractParity drives the live store through the same behaviors the
// MemoryStore reference test pins, so the two adapters agree on the port.
func TestLiveContractParity(t *testing.T) {
	s := liveStore(t)
	ctx := context.Background()
	key := uniqueKey(t)

	// Absent key reads as the zero Count, not an error.
	if got, err := s.Get(ctx, key); err != nil || got != (counter.Count{}) {
		t.Fatalf("Get(absent) = %+v, %v; want zero Count, nil", got, err)
	}

	// Creation sets value=delta and a TTL.
	first, err := s.Increment(ctx, key, 2, time.Hour)
	if err != nil {
		t.Fatalf("Increment(create): %v", err)
	}
	if first.Value != 2 || first.TTL <= 0 {
		t.Fatalf("create = %+v, want Value 2 and a positive TTL", first)
	}

	// A second increment adds delta and LEAVES THE TTL ALONE: the new ttl arg
	// is ignored and the remaining life does not grow. This is the fixed-window
	// property the port requires.
	second, err := s.Increment(ctx, key, 3, 10*time.Hour)
	if err != nil {
		t.Fatalf("Increment(bump): %v", err)
	}
	if second.Value != 5 {
		t.Fatalf("bump value = %d, want 5", second.Value)
	}
	if second.TTL > first.TTL {
		t.Fatalf("TTL grew from %s to %s; a live key's expiry must never be extended", first.TTL, second.TTL)
	}

	// Get reflects the live value.
	if got, err := s.Get(ctx, key); err != nil || got.Value != 5 {
		t.Fatalf("Get = %+v, %v; want Value 5", got, err)
	}

	// Delete removes it, and deleting again is not an error.
	if err := s.Delete(ctx, key); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if err := s.Delete(ctx, key); err != nil {
		t.Fatalf("Delete(absent): %v", err)
	}
	if got, err := s.Get(ctx, key); err != nil || got != (counter.Count{}) {
		t.Fatalf("Get(after delete) = %+v, %v; want zero Count, nil", got, err)
	}
}

// TestLiveExpiry proves expiry is active: a key created with a short TTL reads
// back as absent once it lapses.
func TestLiveExpiry(t *testing.T) {
	s := liveStore(t)
	ctx := context.Background()
	key := uniqueKey(t)

	if _, err := s.Increment(ctx, key, 1, 200*time.Millisecond); err != nil {
		t.Fatalf("Increment: %v", err)
	}
	time.Sleep(400 * time.Millisecond)
	if got, err := s.Get(ctx, key); err != nil || got != (counter.Count{}) {
		t.Fatalf("Get(expired) = %+v, %v; want zero Count, nil", got, err)
	}
}

// TestLiveValidationParity confirms the live adapter refuses the same inputs
// with the same error classes as MemoryStore, before any server round trip.
func TestLiveValidationParity(t *testing.T) {
	s := liveStore(t)
	ctx := context.Background()

	if _, err := s.Increment(ctx, "", 1, time.Minute); !errors.Is(err, counter.ErrInvalidKey) {
		t.Fatalf("empty key = %v, want Is ErrInvalidKey", err)
	}
	if _, err := s.Increment(ctx, uniqueKey(t), 0, time.Minute); !errors.Is(err, domain.ErrInvalidInput) {
		t.Fatalf("zero delta = %v, want Is domain.ErrInvalidInput", err)
	}
	if _, err := s.Increment(ctx, uniqueKey(t), 1, 0); !errors.Is(err, domain.ErrInvalidInput) {
		t.Fatalf("zero ttl = %v, want Is domain.ErrInvalidInput", err)
	}
}
