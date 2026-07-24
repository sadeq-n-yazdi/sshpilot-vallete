package redisstore

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/counter"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/secrets"
)

// fakeClient is an in-memory stand-in for the Redis client. It lets the store's
// validation, reply decoding and error mapping be exercised with no server.
type fakeClient struct {
	// evalFn, when set, answers eval; otherwise a canned reply is returned.
	evalFn func(ctx context.Context, script string, keys []string, args ...any) (any, error)
	// evalReply is returned when evalFn is nil.
	evalReply any
	// err, when non-nil, is returned by every method to simulate an outage.
	err error

	delKeys []string
	closed  bool
	pinged  bool
}

func (f *fakeClient) eval(ctx context.Context, script string, keys []string, args ...any) (any, error) {
	if f.err != nil {
		return nil, f.err
	}
	if f.evalFn != nil {
		return f.evalFn(ctx, script, keys, args...)
	}
	return f.evalReply, nil
}

func (f *fakeClient) del(ctx context.Context, keys ...string) error {
	if f.err != nil {
		return f.err
	}
	f.delKeys = append(f.delKeys, keys...)
	return nil
}

func (f *fakeClient) ping(ctx context.Context) error {
	f.pinged = true
	return f.err
}

func (f *fakeClient) close() error {
	f.closed = true
	return f.err
}

func TestIncrementValidation(t *testing.T) {
	t.Parallel()
	s := newStore(&fakeClient{err: errors.New("client must not be reached")})
	ctx := context.Background()

	tests := []struct {
		name  string
		key   string
		delta int64
		ttl   time.Duration
		want  error
	}{
		{"empty key", "", 1, time.Minute, counter.ErrInvalidKey},
		{"zero delta", "k", 0, time.Minute, domain.ErrInvalidInput},
		{"negative delta", "k", -1, time.Minute, domain.ErrInvalidInput},
		{"zero ttl", "k", 1, 0, domain.ErrInvalidInput},
		{"negative ttl", "k", 1, -time.Second, domain.ErrInvalidInput},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			// The invalid input is refused BEFORE the network: the fake's err
			// would surface as ErrStoreUnavailable if the client were reached.
			_, err := s.Increment(ctx, tt.key, tt.delta, tt.ttl)
			if !errors.Is(err, tt.want) {
				t.Fatalf("Increment error = %v, want Is %v", err, tt.want)
			}
			if errors.Is(err, counter.ErrStoreUnavailable) {
				t.Fatalf("validation error must not be reported as unavailable: %v", err)
			}
			// Every invalid input is also the domain.ErrInvalidInput class, the
			// same as MemoryStore reports.
			if !errors.Is(err, domain.ErrInvalidInput) {
				t.Fatalf("Increment error = %v, want Is domain.ErrInvalidInput", err)
			}
		})
	}
}

func TestIncrementSuccess(t *testing.T) {
	t.Parallel()
	var gotArgs []any
	fc := &fakeClient{evalFn: func(_ context.Context, script string, keys []string, args ...any) (any, error) {
		if script != incrementScript {
			t.Errorf("Increment used script %q", script)
		}
		if len(keys) != 1 || keys[0] != "k" {
			t.Errorf("keys = %v, want [k]", keys)
		}
		gotArgs = args
		return []any{int64(3), int64(45000)}, nil
	}}
	got, err := newStore(fc).Increment(context.Background(), "k", 3, time.Minute)
	if err != nil {
		t.Fatalf("Increment: %v", err)
	}
	if got.Value != 3 || got.TTL != 45*time.Second {
		t.Fatalf("got %+v, want {Value:3 TTL:45s}", got)
	}
	// The ttl is passed to the script in milliseconds so PEXPIRE can set it.
	if len(gotArgs) != 2 || gotArgs[0] != int64(3) || gotArgs[1] != int64(60000) {
		t.Fatalf("args = %v, want [3 60000]", gotArgs)
	}
}

func TestGetAbsentIsZeroCount(t *testing.T) {
	t.Parallel()
	// The get script returns {0,0} for an absent key; that must decode to the
	// zero Count and NOT an error, exactly as MemoryStore.Get does.
	got, err := newStore(&fakeClient{evalReply: []any{int64(0), int64(0)}}).
		Get(context.Background(), "missing")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got != (counter.Count{}) {
		t.Fatalf("got %+v, want zero Count", got)
	}
}

func TestGetPresent(t *testing.T) {
	t.Parallel()
	got, err := newStore(&fakeClient{evalReply: []any{int64(7), int64(1500)}}).
		Get(context.Background(), "k")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Value != 7 || got.TTL != 1500*time.Millisecond {
		t.Fatalf("got %+v, want {Value:7 TTL:1.5s}", got)
	}
}

func TestDeleteIdempotentAndValidated(t *testing.T) {
	t.Parallel()
	fc := &fakeClient{}
	s := newStore(fc)
	if err := s.Delete(context.Background(), "k"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if len(fc.delKeys) != 1 || fc.delKeys[0] != "k" {
		t.Fatalf("del keys = %v, want [k]", fc.delKeys)
	}
	// An empty key is refused before the client is touched.
	if err := s.Delete(context.Background(), ""); !errors.Is(err, counter.ErrInvalidKey) {
		t.Fatalf("Delete empty key = %v, want Is ErrInvalidKey", err)
	}
}

func TestOutageMapping(t *testing.T) {
	t.Parallel()
	boom := errors.New("connection refused")
	fc := &fakeClient{err: boom}
	s := newStore(fc)
	ctx := context.Background()

	if _, err := s.Increment(ctx, "k", 1, time.Minute); !errors.Is(err, counter.ErrStoreUnavailable) || !errors.Is(err, boom) {
		t.Fatalf("Increment outage = %v, want Is both ErrStoreUnavailable and cause", err)
	}
	if _, err := s.Get(ctx, "k"); !errors.Is(err, counter.ErrStoreUnavailable) {
		t.Fatalf("Get outage = %v, want Is ErrStoreUnavailable", err)
	}
	if err := s.Delete(ctx, "k"); !errors.Is(err, counter.ErrStoreUnavailable) {
		t.Fatalf("Delete outage = %v, want Is ErrStoreUnavailable", err)
	}
	if err := s.Ping(ctx); !errors.Is(err, counter.ErrStoreUnavailable) {
		t.Fatalf("Ping outage = %v, want Is ErrStoreUnavailable", err)
	}
}

func TestCanceledContextIsUnavailable(t *testing.T) {
	t.Parallel()
	// A canceled context is refused before any call, mirroring MemoryStore.
	fc := &fakeClient{err: errors.New("client must not be reached")}
	s := newStore(fc)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := s.Increment(ctx, "k", 1, time.Minute); !errors.Is(err, counter.ErrStoreUnavailable) {
		t.Fatalf("Increment canceled = %v, want Is ErrStoreUnavailable", err)
	}
	if _, err := s.Get(ctx, "k"); !errors.Is(err, counter.ErrStoreUnavailable) {
		t.Fatalf("Get canceled = %v, want Is ErrStoreUnavailable", err)
	}
}

func TestMalformedReplyIsUnavailable(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		reply any
	}{
		{"not a slice", "nope"},
		{"wrong length", []any{int64(1)}},
		{"bad value type", []any{"x", int64(1)}},
		{"bad ttl type", []any{int64(1), "x"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := newStore(&fakeClient{evalReply: tt.reply}).Get(context.Background(), "k")
			if !errors.Is(err, counter.ErrStoreUnavailable) {
				t.Fatalf("reply %v: err = %v, want Is ErrStoreUnavailable", tt.reply, err)
			}
		})
	}
}

func TestClose(t *testing.T) {
	t.Parallel()
	fc := &fakeClient{}
	if err := newStore(fc).Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !fc.closed {
		t.Fatal("Close did not reach the client")
	}
}

func TestBuildOptionsAddressForms(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		address string
		wantTLS bool
		wantErr bool
	}{
		{"bare host:port -> no tls", "localhost:6379", false, false},
		{"redis scheme -> no tls", "redis://localhost:6379", false, false},
		{"rediss scheme -> verified tls", "rediss://redis.example.com:6379", true, false},
		{"empty", "", false, true},
		{"garbage scheme", "http://localhost", false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			opt, err := buildOptions(tt.address, "")
			if tt.wantErr {
				if err == nil {
					t.Fatalf("buildOptions(%q) err = nil, want error", tt.address)
				}
				if !errors.Is(err, domain.ErrInvalidInput) {
					t.Fatalf("buildOptions(%q) err = %v, want Is domain.ErrInvalidInput", tt.address, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("buildOptions(%q): %v", tt.address, err)
			}
			if tt.wantTLS {
				if opt.TLSConfig == nil {
					t.Fatalf("buildOptions(%q) TLSConfig = nil, want configured", tt.address)
				}
				if opt.TLSConfig.InsecureSkipVerify {
					t.Fatal("InsecureSkipVerify is true; certificate verification must never be disabled")
				}
				if opt.TLSConfig.ServerName == "" {
					t.Fatal("ServerName empty; verified TLS needs the host name")
				}
			} else if opt.TLSConfig != nil {
				t.Fatalf("buildOptions(%q) set TLSConfig for a non-TLS scheme", tt.address)
			}
		})
	}
}

// TestBuildOptionsBoundsTimeouts proves every network wait is bounded, so a
// hung backend cannot stall a request on the rate-limit critical path. It
// pins that the retries are off and each timeout is positive and no larger than
// a couple of seconds -- far below go-redis's multi-second defaults.
func TestBuildOptionsBoundsTimeouts(t *testing.T) {
	t.Parallel()
	opt, err := buildOptions("redis://localhost:6379", "")
	if err != nil {
		t.Fatalf("buildOptions: %v", err)
	}
	if opt.MaxRetries != -1 {
		t.Fatalf("MaxRetries = %d, want -1 (retries off so failover is prompt)", opt.MaxRetries)
	}
	for _, tc := range []struct {
		name string
		got  time.Duration
	}{
		{"DialTimeout", opt.DialTimeout},
		{"ReadTimeout", opt.ReadTimeout},
		{"WriteTimeout", opt.WriteTimeout},
	} {
		if tc.got <= 0 || tc.got > 2*time.Second {
			t.Fatalf("%s = %v, want a bound in (0, 2s]", tc.name, tc.got)
		}
	}
}

// TestPasswordNeverRendered proves the AUTH secret is unreachable through any
// fmt verb on the Store: it is revealed only into redis.Options at the dial
// site and is retained in no field.
func TestPasswordNeverRendered(t *testing.T) {
	t.Parallel()
	const secret = "super-secret-redis-password"
	s, err := New("redis://localhost:6379", secrets.Redacted(secret))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
		out := fmt.Sprintf(verb, s)
		if strings.Contains(out, secret) {
			t.Fatalf("Store rendered with %q leaked the password: %s", verb, out)
		}
	}
	// The reveal does reach redis.Options, which is the one place it is allowed.
	opt, err := buildOptions("redis://localhost:6379", secrets.Redacted(secret))
	if err != nil {
		t.Fatalf("buildOptions: %v", err)
	}
	if opt.Password != secret {
		t.Fatal("password was not applied to redis.Options at the dial site")
	}
}

// TestRedactAddress proves an inline AUTH password in the address is masked, and
// that a bare host or a credential-free URL passes through unharmed.
func TestRedactAddress(t *testing.T) {
	t.Parallel()
	const secret = "inline-secret"
	tests := []struct {
		name, in         string
		wantNotContains  string
		wantContainsMask bool
	}{
		{"inline password redis", "redis://:" + secret + "@host:6379", secret, true},
		{"inline user and password", "redis://user:" + secret + "@host:6379/0", secret, true},
		{"inline password rediss", "rediss://:" + secret + "@host:6379", secret, true},
		{"bare host password", "user:" + secret + "@host:6379", secret, true},
		{"no credentials", "redis://host:6379", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := RedactAddress(tt.in)
			if tt.wantNotContains != "" && strings.Contains(got, tt.wantNotContains) {
				t.Fatalf("RedactAddress(%q) = %q, leaked %q", tt.in, got, tt.wantNotContains)
			}
			if tt.wantContainsMask && !strings.Contains(got, "xxxxx") {
				t.Fatalf("RedactAddress(%q) = %q, want a masked password", tt.in, got)
			}
		})
	}
}

// TestBuildOptionsErrorRedactsInlinePassword proves the fail-closed parse-error
// path -- reached by an address that carries an inline password AND is otherwise
// malformed -- never echoes the secret, neither through the redacted address nor
// through the underlying parse error.
func TestBuildOptionsErrorRedactsInlinePassword(t *testing.T) {
	t.Parallel()
	const secret = "malformed-url-secret"
	// A bad database number makes redis.ParseURL fail while net/url still parses
	// it, so the error path runs with a password-bearing address.
	addr := "redis://:" + secret + "@host:6379/notanumber"
	_, err := buildOptions(addr, "")
	if err == nil {
		t.Fatal("buildOptions accepted a malformed address")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("parse error leaked the inline password: %v", err)
	}
	if !errors.Is(err, domain.ErrInvalidInput) {
		t.Fatalf("err = %v, want Is domain.ErrInvalidInput", err)
	}
}
