package redisstore

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/counter"
)

// The tests in this file run the REAL Lua scripts and the REAL go-redis reply
// decoding against an in-process miniredis, with no external service and no DSN
// gate -- so the parity properties the port promises (atomic increment, a fixed
// TTL that a later increment never extends, absent-key-reads-zero, expiry) are
// proven in CI, not only when a live server happens to be configured. The
// DSN-gated integration_test.go covers the same properties against a genuine
// Redis/Valkey when one is available.

func newMiniStore(t *testing.T) (*Store, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	s, err := New("redis://"+mr.Addr(), "")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, mr
}

// TestMiniredisFixedTTLNeverExtended is the load-bearing script test: the second
// increment passes a much larger ttl, and the stored TTL must not grow. Because
// miniredis holds its clock still, an implementation that wrongly re-applied the
// TTL would report the larger window here and fail.
func TestMiniredisFixedTTLNeverExtended(t *testing.T) {
	t.Parallel()
	s, _ := newMiniStore(t)
	ctx := context.Background()

	first, err := s.Increment(ctx, "k", 1, time.Minute)
	if err != nil {
		t.Fatalf("first Increment: %v", err)
	}
	if first.Value != 1 {
		t.Fatalf("first value = %d, want 1", first.Value)
	}
	if first.TTL <= 0 || first.TTL > time.Minute {
		t.Fatalf("first TTL = %v, want (0, 1m]", first.TTL)
	}

	second, err := s.Increment(ctx, "k", 1, time.Hour)
	if err != nil {
		t.Fatalf("second Increment: %v", err)
	}
	if second.Value != 2 {
		t.Fatalf("second value = %d, want 2", second.Value)
	}
	if second.TTL > first.TTL {
		t.Fatalf("TTL was extended: first = %v, second = %v (a later increment must not renew the window)", first.TTL, second.TTL)
	}
}

// TestMiniredisGetAbsentAndExpiry proves absent keys read as the zero Count and
// that a key gone past its window reads as zero again -- exercised through the
// real GET/PTTL reply decode.
func TestMiniredisGetAbsentAndExpiry(t *testing.T) {
	t.Parallel()
	s, mr := newMiniStore(t)
	ctx := context.Background()

	got, err := s.Get(ctx, "missing")
	if err != nil {
		t.Fatalf("Get absent: %v", err)
	}
	if got.Value != 0 || got.TTL != 0 {
		t.Fatalf("absent Get = %+v, want zero Count", got)
	}

	if _, err := s.Increment(ctx, "k", 5, time.Minute); err != nil {
		t.Fatalf("Increment: %v", err)
	}
	got, err = s.Get(ctx, "k")
	if err != nil {
		t.Fatalf("Get present: %v", err)
	}
	if got.Value != 5 {
		t.Fatalf("present Get value = %d, want 5", got.Value)
	}

	mr.FastForward(2 * time.Minute) // past the one-minute window.
	got, err = s.Get(ctx, "k")
	if err != nil {
		t.Fatalf("Get after expiry: %v", err)
	}
	if got.Value != 0 {
		t.Fatalf("expired Get value = %d, want 0", got.Value)
	}
}

// TestMiniredisDeleteIdempotent proves Delete removes a key and that deleting an
// absent key is not an error, against the real client.
func TestMiniredisDeleteIdempotent(t *testing.T) {
	t.Parallel()
	s, _ := newMiniStore(t)
	ctx := context.Background()

	if _, err := s.Increment(ctx, "k", 3, time.Minute); err != nil {
		t.Fatalf("Increment: %v", err)
	}
	if err := s.Delete(ctx, "k"); err != nil {
		t.Fatalf("Delete present: %v", err)
	}
	if err := s.Delete(ctx, "k"); err != nil {
		t.Fatalf("Delete absent must be a no-op, got: %v", err)
	}
	got, err := s.Get(ctx, "k")
	if err != nil {
		t.Fatalf("Get after delete: %v", err)
	}
	if got.Value != 0 {
		t.Fatalf("value after delete = %d, want 0", got.Value)
	}
}

var _ counter.Store = (*Store)(nil)
