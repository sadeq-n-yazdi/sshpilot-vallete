// Package redisstore is the Redis/Valkey-backed adapter for the shared counter
// port (internal/counter).
//
// It is a leaf adapter: this is the ONLY package that imports the Redis client
// library, so the dependency stays out of the core counter package that the
// rate limiter and the auth denylist import. FailoverStore
// (internal/counter.FailoverStore) composes a *Store with the in-process
// MemoryStore and depends on neither this package nor the client library.
//
// # Contract
//
// *Store honors counter.Store byte-for-byte with MemoryStore: the same key
// validation (counter.ErrInvalidKey wrapped with domain.ErrInvalidInput), the
// same delta>0 / ttl>0 rule, the same fixed-window TTL that is set once at key
// creation and NEVER extended by a later increment, and the same "absent key
// reads as the zero Count, not an error" for Get and Delete.
//
// # Atomicity and fixed TTL
//
// counter.Store REQUIRES the read-modify-write of Increment to be one
// indivisible operation, and REQUIRES the TTL to be set only when a key is
// created. Both are met with a single server-side Lua script: INCRBY, then
// PEXPIRE only when the key currently carries no expiry (PTTL == -1). Testing
// PTTL rather than "did the value come back equal to delta" is deliberate --
// it also sets the TTL on a key left without one by a crash between a previous
// INCRBY and its PEXPIRE, so a key can never end up immortal.
//
// # Outage mapping
//
// Any failure to reach the server -- a refused connection, a timeout, a closed
// client, a canceled context -- is mapped to a wrap of
// counter.ErrStoreUnavailable, which is the class FailoverStore watches for to
// degrade to memory and which the denylist's fail-closed rule turns on. A
// validation error (bad key, non-positive delta or ttl) is returned as the
// domain.ErrInvalidInput class instead, before any network call, so a caller
// bug is never disguised as an outage.
package redisstore

import (
	"context"
	"crypto/tls"
	"fmt"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/counter"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/secrets"
)

// incrementScript atomically adds ARGV[1] to KEYS[1] and, only when the key
// carries no expiry yet (a freshly created key, or one orphaned by a crash
// between INCRBY and PEXPIRE), sets its TTL to ARGV[2] milliseconds. It returns
// {value, pttl_ms}. A live key's expiry is never touched, which is what makes
// the window fixed rather than sliding.
const incrementScript = `
local v = redis.call('INCRBY', KEYS[1], ARGV[1])
local p = redis.call('PTTL', KEYS[1])
if p == -1 then
  redis.call('PEXPIRE', KEYS[1], ARGV[2])
  p = tonumber(ARGV[2])
end
return {v, p}
`

// getScript returns {value, pttl_ms} for KEYS[1], or {0, 0} when the key is
// absent. A missing or absent TTL is reported as 0, matching the zero Count a
// caller reads for a key with nothing left to live.
const getScript = `
local v = redis.call('GET', KEYS[1])
if not v then return {0, 0} end
local p = redis.call('PTTL', KEYS[1])
if p < 0 then p = 0 end
return {tonumber(v), p}
`

// client is the minimal Redis surface Store depends on, declared here at the
// point of use so a test can drive Store without a live server. The production
// implementation (redisClient) wraps *redis.Client; every method that talks to
// the server returns an error that Store maps to counter.ErrStoreUnavailable.
type client interface {
	// eval runs a Lua script and returns its raw reply.
	eval(ctx context.Context, script string, keys []string, args ...any) (any, error)
	// del removes keys, reporting only transport failure (a missing key is not
	// one).
	del(ctx context.Context, keys ...string) error
	// ping reports whether the server is reachable.
	ping(ctx context.Context) error
	// close releases the connection pool.
	close() error
}

// Store is the Redis/Valkey-backed counter.Store.
//
// It holds only the client, never the AUTH password: the secret is revealed
// exactly once, into redis.Options at the dial site in New, and is retained in
// no field, so no fmt/log/json rendering of a Store can leak it.
type Store struct {
	c client
}

// New dials address and returns a Store.
//
// address is a Redis URL. A bare "host:port" is treated as "redis://host:port"
// (no TLS). The "rediss://" scheme selects TLS with full certificate
// verification -- the server's certificate is checked against the system roots
// and its name against the URL host, and this package never sets
// InsecureSkipVerify, so a misissued or self-signed certificate fails the
// handshake rather than being trusted.
//
// password is the AUTH secret, or the zero Redacted for a server that needs
// none. It is revealed into redis.Options here and nowhere else.
func New(address string, password secrets.Redacted) (*Store, error) {
	opt, err := buildOptions(address, password)
	if err != nil {
		return nil, err
	}
	return newStore(&redisClient{rc: redis.NewClient(opt)}), nil
}

// buildOptions parses address and applies the AUTH secret and the TLS posture.
// It is the sole site where the password is revealed, and it is separate from
// New so the parsing and the TLS hardening are testable without dialing.
func buildOptions(address string, password secrets.Redacted) (*redis.Options, error) {
	if address == "" {
		return nil, fmt.Errorf("redisstore: empty address: %w", domain.ErrInvalidInput)
	}

	url := address
	if !strings.Contains(url, "://") {
		url = "redis://" + url
	}
	opt, err := redis.ParseURL(url)
	if err != nil {
		// Fail closed at startup: an unparseable address is an operator error,
		// not something to discover at the first request. The address may name
		// a host but carries no secret, so it is safe to echo.
		return nil, fmt.Errorf("redisstore: invalid address %q: %w: %w", address, err, domain.ErrInvalidInput)
	}
	// The sole reveal site. Reveal returns the underlying string, which is
	// handed straight to redis.Options and retained in no field of Store.
	if raw := password.Reveal(); raw != "" {
		opt.Password = raw
	}
	// Fail fast rather than retry: this store sits behind a FailoverStore whose
	// job is to notice an outage promptly and degrade to memory. A retry storm
	// on every command would only delay that and multiply the dial logging
	// during an outage, so command retries are disabled and the failover layer
	// owns the recovery cadence instead.
	opt.MaxRetries = -1
	// A rediss:// URL sets opt.TLSConfig with the host as ServerName and
	// verification on. Guard against a future ParseURL that leaves it nil for a
	// TLS scheme, and never weaken it: InsecureSkipVerify stays false so a
	// misissued or self-signed certificate fails the handshake.
	if opt.TLSConfig != nil {
		opt.TLSConfig.InsecureSkipVerify = false
		if opt.TLSConfig.MinVersion == 0 {
			opt.TLSConfig.MinVersion = tls.VersionTLS12
		}
	}
	return opt, nil
}

// newStore wraps a client. It is the seam the tests construct Store through.
func newStore(c client) *Store { return &Store{c: c} }

// Increment implements counter.Store.
func (s *Store) Increment(ctx context.Context, key string, delta int64, ttl time.Duration) (counter.Count, error) {
	if err := validKey(key); err != nil {
		return counter.Count{}, err
	}
	if delta <= 0 {
		return counter.Count{}, fmt.Errorf("counter: delta must be positive: %w", domain.ErrInvalidInput)
	}
	if ttl <= 0 {
		return counter.Count{}, fmt.Errorf("counter: ttl must be positive: %w", domain.ErrInvalidInput)
	}
	if err := ctx.Err(); err != nil {
		return counter.Count{}, unavailable(err)
	}

	reply, err := s.c.eval(ctx, incrementScript, []string{key}, delta, ttl.Milliseconds())
	if err != nil {
		return counter.Count{}, unavailable(err)
	}
	return countFromReply(reply)
}

// Get implements counter.Store.
func (s *Store) Get(ctx context.Context, key string) (counter.Count, error) {
	if err := validKey(key); err != nil {
		return counter.Count{}, err
	}
	if err := ctx.Err(); err != nil {
		return counter.Count{}, unavailable(err)
	}

	reply, err := s.c.eval(ctx, getScript, []string{key})
	if err != nil {
		return counter.Count{}, unavailable(err)
	}
	return countFromReply(reply)
}

// Delete implements counter.Store. Deleting an absent key is not an error.
func (s *Store) Delete(ctx context.Context, key string) error {
	if err := validKey(key); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return unavailable(err)
	}
	if err := s.c.del(ctx, key); err != nil {
		return unavailable(err)
	}
	return nil
}

// Ping reports whether the server is reachable, mapping any failure to
// counter.ErrStoreUnavailable. FailoverStore uses it to decide when to switch
// back from the memory fallback.
func (s *Store) Ping(ctx context.Context) error {
	if err := s.c.ping(ctx); err != nil {
		return unavailable(err)
	}
	return nil
}

// Close releases the client's connection pool.
func (s *Store) Close() error { return s.c.close() }

// countFromReply decodes the {value, pttl_ms} table both scripts return. A
// reply in any other shape is a store that answered in a way this code does not
// understand, which is treated as unavailable rather than guessed at.
func countFromReply(reply any) (counter.Count, error) {
	arr, ok := reply.([]any)
	if !ok || len(arr) != 2 {
		return counter.Count{}, unavailable(fmt.Errorf("unexpected reply shape %T", reply))
	}
	value, ok := arr[0].(int64)
	if !ok {
		return counter.Count{}, unavailable(fmt.Errorf("unexpected value type %T", arr[0]))
	}
	pttl, ok := arr[1].(int64)
	if !ok {
		return counter.Count{}, unavailable(fmt.Errorf("unexpected ttl type %T", arr[1]))
	}
	if value == 0 {
		// Absent key: the zero Count, never carrying a stray TTL.
		return counter.Count{}, nil
	}
	if pttl < 0 {
		pttl = 0
	}
	return counter.Count{Value: value, TTL: time.Duration(pttl) * time.Millisecond}, nil
}

// validKey mirrors internal/counter's unexported validator so the adapter
// refuses exactly the keys the port refuses, with the identical error classes.
func validKey(key string) error {
	if key == "" {
		return fmt.Errorf("counter: empty key: %w: %w", counter.ErrInvalidKey, domain.ErrInvalidInput)
	}
	return nil
}

// unavailable wraps a transport failure as counter.ErrStoreUnavailable while
// preserving the cause for logs.
func unavailable(err error) error {
	return fmt.Errorf("redisstore: %w: %w", counter.ErrStoreUnavailable, err)
}

// redisClient adapts *redis.Client to the client interface.
type redisClient struct {
	rc *redis.Client
}

func (c *redisClient) eval(ctx context.Context, script string, keys []string, args ...any) (any, error) {
	return redis.NewScript(script).Run(ctx, c.rc, keys, args...).Result()
}

func (c *redisClient) del(ctx context.Context, keys ...string) error {
	return c.rc.Del(ctx, keys...).Err()
}

func (c *redisClient) ping(ctx context.Context) error { return c.rc.Ping(ctx).Err() }

func (c *redisClient) close() error { return c.rc.Close() }

// Compile-time proof that Store satisfies the port.
var _ counter.Store = (*Store)(nil)
