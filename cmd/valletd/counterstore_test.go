package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/config"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/secrets"
)

func TestNewSharedCounterStoreSelection(t *testing.T) {
	t.Parallel()

	t.Run("memory store yields no shared store", func(t *testing.T) {
		t.Parallel()
		cfg := config.Default() // Store defaults to "memory".
		store, closer, err := newSharedCounterStore(&cfg, nil, nil)
		if err != nil {
			t.Fatalf("newSharedCounterStore: %v", err)
		}
		if store != nil {
			t.Fatal("memory store must not build a shared counter store")
		}
		if err := closer(); err != nil {
			t.Fatalf("closer: %v", err)
		}
	})

	t.Run("disabled yields no shared store", func(t *testing.T) {
		t.Parallel()
		cfg := config.Default()
		cfg.RateLimit.Store = "shared"
		cfg.RateLimit.Enabled = false
		store, _, err := newSharedCounterStore(&cfg, nil, nil)
		if err != nil {
			t.Fatalf("newSharedCounterStore: %v", err)
		}
		if store != nil {
			t.Fatal("disabled rate limiting must not build a shared counter store")
		}
	})

	t.Run("invalid address fails startup", func(t *testing.T) {
		t.Parallel()
		cfg := config.Default()
		cfg.RateLimit.Store = "shared"
		cfg.RateLimit.Shared.Address = "http://not-a-redis-url"
		if _, _, err := newSharedCounterStore(&cfg, nil, nil); err == nil {
			t.Fatal("an unparseable address must fail startup")
		}
	})
}

// TestSharedCounterStoreDegradesToMemory proves the whole wiring end to end:
// a shared store pointed at a closed port serves rate-limit increments from the
// in-memory fallback instead of surfacing the outage, so limiting keeps working
// with no reachable Redis. It uses the real client, no server.
func TestSharedCounterStoreDegradesToMemory(t *testing.T) {
	t.Parallel()
	cfg := config.Default()
	cfg.RateLimit.Store = "shared"
	// 127.0.0.1:1 is reserved and refuses fast, so the failover is prompt.
	cfg.RateLimit.Shared.Address = "redis://127.0.0.1:1"

	store, closer, err := newSharedCounterStore(&cfg, slog.New(slog.DiscardHandler), nil)
	if err != nil {
		t.Fatalf("newSharedCounterStore: %v", err)
	}
	t.Cleanup(func() { _ = closer() })
	if store == nil {
		t.Fatal("shared config produced no store")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	got, err := store.Increment(ctx, "k", 1, time.Minute)
	if err != nil {
		t.Fatalf("Increment surfaced the outage instead of degrading: %v", err)
	}
	if got.Value != 1 {
		t.Fatalf("degraded Increment value = %d, want 1 from the memory fallback", got.Value)
	}
	// A second increment accumulates in memory: the limit is still enforced.
	got, err = store.Increment(ctx, "k", 1, time.Minute)
	if err != nil || got.Value != 2 {
		t.Fatalf("second Increment = %+v, %v; want Value 2, nil", got, err)
	}
}

// TestSharedCounterStorePasswordNotLogged proves the AUTH secret is not rendered
// through the store the wiring hands to the handler.
func TestSharedCounterStorePasswordNotLogged(t *testing.T) {
	t.Parallel()
	const secret = "redis-auth-secret-value"
	cfg := config.Default()
	cfg.RateLimit.Store = "shared"
	cfg.RateLimit.Shared.Address = "redis://127.0.0.1:6379"
	resolved := map[string]secrets.Redacted{sharedPasswordField: secrets.Redacted(secret)}

	store, closer, err := newSharedCounterStore(&cfg, nil, resolved)
	if err != nil {
		t.Fatalf("newSharedCounterStore: %v", err)
	}
	t.Cleanup(func() { _ = closer() })

	for _, verb := range []string{"%v", "%+v", "%#v"} {
		if out := fmt.Sprintf(verb, store); strings.Contains(out, secret) {
			t.Fatalf("store rendered with %q leaked the password", verb)
		}
	}
}

// TestSharedCounterStoreCloseIdempotent guards the closer the composition root
// defers.
func TestSharedCounterStoreCloseIdempotent(t *testing.T) {
	t.Parallel()
	cfg := config.Default()
	cfg.RateLimit.Store = "shared"
	cfg.RateLimit.Shared.Address = "redis://127.0.0.1:6379"

	_, closer, err := newSharedCounterStore(&cfg, nil, nil)
	if err != nil {
		t.Fatalf("newSharedCounterStore: %v", err)
	}
	if err := closer(); err != nil {
		t.Fatalf("first close: %v", err)
	}
	if err := closer(); err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("second close: %v", err)
	}
}
