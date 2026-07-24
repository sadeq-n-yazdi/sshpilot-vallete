package main

import (
	"errors"
	"log/slog"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/config"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/counter"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/redisstore"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/secrets"
)

// sharedPasswordField is the config field under which the resolved shared
// rate-limit store password is keyed. It matches the string
// config.RequiredSecretRefs reports, so a rename there is a compile-time concern
// here rather than a silently absent secret.
const sharedPasswordField = "rate_limit.shared.password_ref"

// newSharedCounterStore builds the shared rate-limit counter store -- the
// Redis/Valkey backend wrapped in an in-memory failover -- or returns a nil
// store when the deployment runs single-node counters. The returned closer is
// always non-nil and safe to call; it stops the reprobe goroutine and releases
// the connection pool.
//
// # An unreachable backend is NOT a startup failure
//
// The whole point of the failover store is that rate limiting keeps working
// when Redis is down, so this deliberately does NOT probe connectivity at
// startup: an unreachable backend is degraded to memory on first use, not a
// refusal to start. Only an operator error -- an unparseable address, or a nil
// clock -- fails startup here, which is the fail-closed direction for a
// misconfiguration the operator can fix.
//
// # The password is resolved once, upstream
//
// The AUTH secret comes from the already-resolved secrets map, keyed by field,
// so no key material is re-read here. A deployment that set no password gets the
// zero Redacted, which redisstore treats as "no AUTH".
func newSharedCounterStore(cfg *config.Config, logger *slog.Logger, resolved map[string]secrets.Redacted) (counter.Store, func() error, error) {
	noop := func() error { return nil }
	if cfg == nil || !cfg.RateLimit.Enabled || cfg.RateLimit.Store != "shared" {
		return nil, noop, nil
	}

	primary, err := redisstore.New(cfg.RateLimit.Shared.Address, resolved[sharedPasswordField])
	if err != nil {
		return nil, noop, err
	}

	fallback, err := counter.NewMemoryStore(time.Now)
	if err != nil {
		return nil, noop, errors.Join(err, primary.Close())
	}

	store, err := counter.NewFailoverStore(primary, fallback)
	if err != nil {
		return nil, noop, errors.Join(err, primary.Close())
	}

	if logger != nil {
		// The address is credential-bearing: a Redis URL may embed the AUTH
		// password inline (redis://:pass@host), so it is redacted before it
		// reaches the log. The separate password_ref secret is never rendered
		// either (see redisstore).
		logger.Info("rate limit: shared counter store enabled with in-memory failover",
			slog.String("component", "ratelimit"),
			slog.String("address", redisstore.RedactAddress(cfg.RateLimit.Shared.Address)))
	}
	return store, store.Close, nil
}
